use std::{
    cmp::Reverse,
    collections::{BTreeMap, BinaryHeap, VecDeque},
    future,
    sync::{
        Arc,
        mpsc::{self as std_mpsc, SyncSender},
    },
    thread,
    time::Instant,
};

use bondry_delivery_store::{
    DeliveryFailure, DeliveryId, DeliveryIntent, DeliveryLog, DeliveryLogError, DeliveryOutcome,
    DeliveryRecord, DeliveryResultMetadata, DeliveryState, RouteId, StoreDurability,
};
use bondry_egress::{
    AdmissionError, AdmittedDeliveryParts, DeliveryAction, DeliveryEvent, DeliveryLifecycle,
    DeliveryPersistenceAction, EgressInstant, Route, RouteRegistry, RouteRegistryError,
    RouteSummary, TransitionTime,
};
use bondry_secrets::SecretProvider;
use bondry_transport::{Deadline, HttpTransport};
use bytes::Bytes;
use thiserror::Error;
use tokio::{
    sync::{mpsc, watch},
    task::{AbortHandle, JoinSet},
};

use crate::{EgressRuntimeLimits, attempt::execute_attempt, attempt::unix_milliseconds};

/// A running egress scheduler isolated on one current-thread executor.
pub struct EgressRuntime {
    commands: mpsc::Sender<Command>,
    shutdown: watch::Sender<bool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl EgressRuntime {
    /// Starts an empty runtime around the supplied registry, persistence, and host services.
    pub fn start(
        registry: RouteRegistry,
        limits: EgressRuntimeLimits,
        log: Arc<dyn DeliveryLog>,
        secrets: Arc<dyn SecretProvider>,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, EgressRuntimeStartError> {
        let (commands, receiver) = mpsc::channel(usize::from(limits.global_pending_deliveries()));
        let (shutdown, shutdown_receiver) = watch::channel(false);
        let (startup_sender, startup_receiver) = std_mpsc::sync_channel(0);
        let thread = thread::Builder::new()
            .name("bondry-egress".to_owned())
            .spawn(move || {
                let mut builder = tokio::runtime::Builder::new_current_thread();
                builder.enable_time();
                #[cfg(feature = "network-io")]
                builder.enable_io();
                let runtime = match builder.build() {
                    Ok(runtime) => runtime,
                    Err(_) => {
                        let _ = startup_sender.send(Err(RuntimeStartupSignal::Runtime));
                        return;
                    }
                };
                if log.durability() == StoreDurability::Persistent {
                    if let Err(error) = log.recover_unfinished(unix_milliseconds()) {
                        let _ = startup_sender.send(Err(RuntimeStartupSignal::Recovery(error)));
                        return;
                    }
                }
                let engine = Engine::new(registry, limits, log, secrets, transport);
                if startup_sender.send(Ok(())).is_err() {
                    return;
                }
                runtime.block_on(engine.run(receiver, shutdown_receiver));
            })
            .map_err(|_| EgressRuntimeStartError::Thread)?;
        match startup_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                commands,
                shutdown,
                thread: Some(thread),
            }),
            Ok(Err(RuntimeStartupSignal::Runtime)) => {
                let _ = thread.join();
                Err(EgressRuntimeStartError::Runtime)
            }
            Ok(Err(RuntimeStartupSignal::Recovery(error))) => {
                let _ = thread.join();
                Err(EgressRuntimeStartError::Recovery(error))
            }
            Err(_) => {
                let _ = thread.join();
                Err(EgressRuntimeStartError::Startup)
            }
        }
    }

    /// Registers one validated route without starting route-owned tasks.
    pub fn register_route(&self, route: Route) -> Result<(), EgressRuntimeError> {
        self.request(|reply| Command::Register { route, reply })
    }

    /// Reopens admission for a disabled route that is not draining.
    pub fn enable_route(&self, route: RouteId) -> Result<(), EgressRuntimeError> {
        self.request(|reply| Command::Enable { route, reply })
    }

    /// Closes admission and waits for pending work to drain or cancel at the deadline.
    pub fn disable_route(&self, route: RouteId) -> Result<(), EgressRuntimeError> {
        self.request(|reply| Command::Drain {
            route,
            remove: false,
            reply,
        })
    }

    /// Closes admission, drains pending work, and removes the route configuration.
    pub fn unregister_route(&self, route: RouteId) -> Result<(), EgressRuntimeError> {
        self.request(|reply| Command::Drain {
            route,
            remove: true,
            reply,
        })
    }

    /// Returns stable, non-secret summaries in route identifier order.
    pub fn routes(&self) -> Result<Vec<RouteSummary>, EgressRuntimeError> {
        self.request(|reply| Command::Routes { reply })
    }

    /// Validates, persists, and accepts one bounded event without waiting for delivery.
    pub fn emit(
        &self,
        route: RouteId,
        delivery: DeliveryId,
        payload: Bytes,
    ) -> Result<DeliveryReceipt, EgressRuntimeError> {
        self.request(|reply| Command::Emit {
            route,
            delivery,
            payload,
            reply,
        })
    }

    /// Executes one MCP-only call in the independent bounded call lane.
    pub fn call(
        &self,
        route: RouteId,
        delivery: DeliveryId,
        payload: Bytes,
    ) -> Result<CallResult, EgressRuntimeError> {
        self.request(|reply| Command::Call {
            route,
            delivery,
            payload,
            reply,
        })
    }

    /// Returns persisted or fail-closed process-local status without payload data.
    pub fn delivery(
        &self,
        delivery: DeliveryId,
    ) -> Result<Option<DeliveryRecord>, EgressRuntimeError> {
        self.request(|reply| Command::Delivery { delivery, reply })
    }

    /// Stops admission, drains for the configured deadline, and joins the executor.
    pub fn stop(&mut self) -> Result<(), EgressRuntimeStopError> {
        let _ = self.shutdown.send(true);
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        thread
            .join()
            .map_err(|_| EgressRuntimeStopError::ThreadPanicked)
    }

    fn request<T>(
        &self,
        command: impl FnOnce(SyncSender<Result<T, EgressRuntimeError>>) -> Command,
    ) -> Result<T, EgressRuntimeError> {
        let (reply, receiver) = std_mpsc::sync_channel(0);
        self.commands
            .try_send(command(reply))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => EgressRuntimeError::Busy,
                mpsc::error::TrySendError::Closed(_) => EgressRuntimeError::Stopped,
            })?;
        receiver.recv().unwrap_or(Err(EgressRuntimeError::Stopped))
    }
}

impl Drop for EgressRuntime {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Confirmation that an event has entered bounded in-process delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryReceipt {
    delivery: DeliveryId,
}

/// One bounded untrusted JSON result returned by a host `call`.
#[derive(Clone, Eq, PartialEq)]
pub struct CallResult {
    delivery: DeliveryId,
    metadata: DeliveryResultMetadata,
    json: Bytes,
}

impl std::fmt::Debug for CallResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CallResult")
            .field("delivery", &self.delivery)
            .field("metadata", &self.metadata)
            .field("json_bytes", &self.json.len())
            .finish()
    }
}

impl CallResult {
    /// Returns the persisted delivery identifier.
    #[must_use]
    pub const fn delivery(&self) -> &DeliveryId {
        &self.delivery
    }

    /// Returns the non-sensitive result category and size.
    #[must_use]
    pub const fn metadata(&self) -> DeliveryResultMetadata {
        self.metadata
    }

    /// Returns the bounded untrusted raw JSON result.
    #[must_use]
    pub const fn json(&self) -> &Bytes {
        &self.json
    }

    /// Moves the identifier, metadata, and untrusted result bytes to a host boundary.
    #[must_use]
    pub fn into_parts(self) -> (DeliveryId, DeliveryResultMetadata, Bytes) {
        (self.delivery, self.metadata, self.json)
    }
}

impl DeliveryReceipt {
    /// Returns the accepted delivery identifier.
    #[must_use]
    pub const fn delivery(&self) -> &DeliveryId {
        &self.delivery
    }
}

/// Failure to create the runtime thread or recover durable state.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EgressRuntimeStartError {
    /// The executor thread could not be created.
    #[error("egress runtime thread could not start")]
    Thread,
    /// Tokio could not build the current-thread executor.
    #[error("egress current-thread executor could not start")]
    Runtime,
    /// Durable unfinished intents could not be classified safely.
    #[error("egress delivery log recovery failed")]
    Recovery(DeliveryLogError),
    /// The executor ended before reporting startup state.
    #[error("egress runtime startup failed")]
    Startup,
}

/// Stable host-facing egress operation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EgressRuntimeError {
    /// The bounded command ingress is temporarily full.
    #[error("egress runtime is busy")]
    Busy,
    /// The runtime is stopping or no longer available.
    #[error("egress runtime is stopped")]
    Stopped,
    /// The route registry rejected a configuration operation.
    #[error("egress route configuration was rejected")]
    Route(#[from] RouteRegistryError),
    /// Core route or payload admission rejected the event.
    #[error("egress event admission was rejected")]
    Admission(#[from] AdmissionError),
    /// A route is already completing a disable or removal drain.
    #[error("egress route is draining")]
    RouteDraining,
    /// The pending delivery-count budget is exhausted.
    #[error("egress pending delivery capacity is exhausted")]
    PendingCapacity,
    /// The retained payload-byte budget is exhausted.
    #[error("egress pending byte capacity is exhausted")]
    PendingBytes,
    /// The independent host-call lane is full.
    #[error("egress call lane capacity is exhausted")]
    CallCapacity,
    /// An accepted host call reached a terminal delivery failure.
    #[error("egress call failed")]
    CallFailed(DeliveryFailure),
    /// Delivery persistence could not safely accept or report the operation.
    #[error("egress delivery log is unavailable")]
    DeliveryLog(#[from] DeliveryLogError),
}

/// Failure while joining the runtime executor.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EgressRuntimeStopError {
    /// The executor thread unwound unexpectedly.
    #[error("egress runtime thread panicked")]
    ThreadPanicked,
}

enum RuntimeStartupSignal {
    Runtime,
    Recovery(DeliveryLogError),
}

enum Command {
    Register {
        route: Route,
        reply: Reply<()>,
    },
    Enable {
        route: RouteId,
        reply: Reply<()>,
    },
    Drain {
        route: RouteId,
        remove: bool,
        reply: Reply<()>,
    },
    Routes {
        reply: Reply<Vec<RouteSummary>>,
    },
    Emit {
        route: RouteId,
        delivery: DeliveryId,
        payload: Bytes,
        reply: Reply<DeliveryReceipt>,
    },
    Call {
        route: RouteId,
        delivery: DeliveryId,
        payload: Bytes,
        reply: Reply<CallResult>,
    },
    Delivery {
        delivery: DeliveryId,
        reply: Reply<Option<DeliveryRecord>>,
    },
}

type Reply<T> = SyncSender<Result<T, EgressRuntimeError>>;

struct Engine {
    registry: RouteRegistry,
    limits: EgressRuntimeLimits,
    log: Arc<dyn DeliveryLog>,
    secrets: Arc<dyn SecretProvider>,
    transport: Arc<dyn HttpTransport>,
    clock: RuntimeClock,
    active: BTreeMap<DeliveryId, ActiveDelivery>,
    usage: BTreeMap<RouteId, RouteUsage>,
    ready: BTreeMap<RouteId, VecDeque<DeliveryId>>,
    ready_routes: VecDeque<RouteId>,
    retries: BinaryHeap<Reverse<(EgressInstant, DeliveryId)>>,
    attempts: JoinSet<(DeliveryId, crate::attempt::AttemptCompletion)>,
    active_calls: BTreeMap<DeliveryId, ActiveCall>,
    calls: JoinSet<(DeliveryId, crate::attempt::AttemptCompletion)>,
    drains: BTreeMap<RouteId, RouteDrain>,
    overrides: BTreeMap<DeliveryId, DeliveryRecord>,
    persistence_degraded: bool,
    global_pending: u16,
    global_bytes: usize,
    global_in_flight: u8,
    call_in_flight: u8,
}

impl Engine {
    fn new(
        registry: RouteRegistry,
        limits: EgressRuntimeLimits,
        log: Arc<dyn DeliveryLog>,
        secrets: Arc<dyn SecretProvider>,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        Self {
            registry,
            limits,
            log,
            secrets,
            transport,
            clock: RuntimeClock::new(),
            active: BTreeMap::new(),
            usage: BTreeMap::new(),
            ready: BTreeMap::new(),
            ready_routes: VecDeque::new(),
            retries: BinaryHeap::new(),
            attempts: JoinSet::new(),
            active_calls: BTreeMap::new(),
            calls: JoinSet::new(),
            drains: BTreeMap::new(),
            overrides: BTreeMap::new(),
            persistence_degraded: false,
            global_pending: 0,
            global_bytes: 0,
            global_in_flight: 0,
            call_in_flight: 0,
        }
    }

    async fn run(
        mut self,
        mut commands: mpsc::Receiver<Command>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut stopping = false;
        let mut shutdown_deadline = None;
        loop {
            self.dispatch_ready();
            self.complete_empty_drains();
            self.discard_stale_retries();
            if stopping && self.active.is_empty() && self.active_calls.is_empty() {
                break;
            }
            let next_deadline = self.next_deadline(shutdown_deadline);
            tokio::select! {
                changed = shutdown.changed(), if !stopping => {
                    if changed.is_err() || *shutdown.borrow() {
                        stopping = true;
                        shutdown_deadline = Some(
                            self.clock.now().saturating_add(self.limits.drain_timeout())
                        );
                        commands.close();
                        self.reject_pending_commands(&mut commands);
                        self.reject_drains_for_shutdown();
                    }
                }
                command = commands.recv(), if !stopping => {
                    match command {
                        Some(command) => self.handle_command(command),
                        None => {
                            stopping = true;
                            shutdown_deadline = Some(
                                self.clock.now().saturating_add(self.limits.drain_timeout())
                            );
                            self.reject_drains_for_shutdown();
                        }
                    }
                }
                completed = self.attempts.join_next(), if !self.attempts.is_empty() => {
                    self.handle_attempt_join(completed);
                }
                completed = self.calls.join_next(), if !self.calls.is_empty() => {
                    self.handle_call_join(completed);
                }
                () = wait_for_deadline(self.clock, next_deadline) => {
                    self.process_retry_deadlines();
                    self.process_drain_deadlines();
                    if shutdown_deadline.is_some_and(|deadline| self.clock.now() >= deadline) {
                        self.expire_shutdown();
                    }
                }
            }
        }
    }

    fn handle_command(&mut self, command: Command) {
        match command {
            Command::Register { route, reply } => {
                let _ = reply.send(self.registry.register(route).map_err(Into::into));
            }
            Command::Enable { route, reply } => {
                let result = if self.drains.contains_key(&route) {
                    Err(EgressRuntimeError::RouteDraining)
                } else {
                    self.registry.set_enabled(&route, true).map_err(Into::into)
                };
                let _ = reply.send(result);
            }
            Command::Drain {
                route,
                remove,
                reply,
            } => self.begin_drain(route, remove, reply),
            Command::Routes { reply } => {
                let _ = reply.send(Ok(self.registry.routes()));
            }
            Command::Emit {
                route,
                delivery,
                payload,
                reply,
            } => {
                let result = self.admit_emit(route, delivery, payload);
                let _ = reply.send(result);
            }
            Command::Call {
                route,
                delivery,
                payload,
                reply,
            } => self.admit_call(route, delivery, payload, reply),
            Command::Delivery { delivery, reply } => {
                let result = self.delivery_status(&delivery);
                let _ = reply.send(result);
            }
        }
    }

    fn admit_emit(
        &mut self,
        route: RouteId,
        delivery: DeliveryId,
        payload: Bytes,
    ) -> Result<DeliveryReceipt, EgressRuntimeError> {
        if self.persistence_degraded {
            return Err(EgressRuntimeError::DeliveryLog(
                DeliveryLogError::Unavailable,
            ));
        }
        let time = self.clock.transition_time();
        let admitted =
            self.registry
                .admit_emit(&route, delivery.clone(), payload, time.monotonic())?;
        let bytes = admitted.payload_bytes();
        self.check_pending_capacity(&route, bytes)?;
        let action = admitted.persistence_action(time.unix_ms());
        self.persist(&action)?;
        let parts = admitted.into_parts();
        let lifecycle =
            DeliveryLifecycle::new(parts.route.clone(), parts.delivery.clone(), parts.retry);
        self.active.insert(
            delivery.clone(),
            ActiveDelivery {
                accepted_at_unix_ms: time.unix_ms(),
                parts,
                lifecycle,
                abort: None,
            },
        );
        self.global_pending += 1;
        self.global_bytes += bytes;
        let usage = self.usage.entry(route.clone()).or_default();
        usage.pending += 1;
        usage.bytes += bytes;
        self.enqueue_ready(route, delivery.clone());
        Ok(DeliveryReceipt { delivery })
    }

    fn admit_call(
        &mut self,
        route: RouteId,
        delivery: DeliveryId,
        payload: Bytes,
        reply: Reply<CallResult>,
    ) {
        let result = self.prepare_call(route, delivery, payload, reply.clone());
        if let Err(error) = result {
            let _ = reply.send(Err(error));
        }
    }

    fn prepare_call(
        &mut self,
        route: RouteId,
        delivery: DeliveryId,
        payload: Bytes,
        reply: Reply<CallResult>,
    ) -> Result<(), EgressRuntimeError> {
        if self.persistence_degraded {
            return Err(EgressRuntimeError::DeliveryLog(
                DeliveryLogError::Unavailable,
            ));
        }
        self.registry.validate_call_route(&route)?;
        if self.active_calls.len() >= usize::from(self.limits.call_in_flight()) {
            return Err(EgressRuntimeError::CallCapacity);
        }
        let time = self.clock.transition_time();
        let admitted =
            self.registry
                .admit_call(&route, delivery.clone(), payload, time.monotonic())?;
        let action = admitted.persistence_action(time.unix_ms());
        self.persist(&action)?;
        let parts = admitted.into_parts();
        let lifecycle =
            DeliveryLifecycle::new(parts.route.clone(), parts.delivery.clone(), parts.retry);
        self.active_calls.insert(
            delivery.clone(),
            ActiveCall {
                accepted_at_unix_ms: time.unix_ms(),
                parts,
                lifecycle,
                abort: None,
                reply,
            },
        );
        self.usage.entry(route).or_default().calls += 1;
        self.start_call(delivery);
        Ok(())
    }

    fn check_pending_capacity(
        &self,
        route: &RouteId,
        bytes: usize,
    ) -> Result<(), EgressRuntimeError> {
        let usage = self.usage.get(route).copied().unwrap_or_default();
        if self.global_pending >= self.limits.global_pending_deliveries()
            || usage.pending >= self.limits.route_pending_deliveries()
        {
            return Err(EgressRuntimeError::PendingCapacity);
        }
        if self.global_bytes.saturating_add(bytes) > self.limits.global_pending_bytes()
            || usage.bytes.saturating_add(bytes) > self.limits.route_pending_bytes()
        {
            return Err(EgressRuntimeError::PendingBytes);
        }
        Ok(())
    }

    fn delivery_status(
        &self,
        delivery: &DeliveryId,
    ) -> Result<Option<DeliveryRecord>, EgressRuntimeError> {
        if let Some(record) = self.overrides.get(delivery) {
            return Ok(Some(record.clone()));
        }
        self.log.delivery(delivery).map_err(Into::into)
    }

    fn begin_drain(&mut self, route: RouteId, remove: bool, reply: Reply<()>) {
        if self.drains.contains_key(&route) {
            let _ = reply.send(Err(EgressRuntimeError::RouteDraining));
            return;
        }
        if let Err(error) = self.registry.set_enabled(&route, false) {
            let _ = reply.send(Err(error.into()));
            return;
        }
        if self.usage.get(&route).is_none_or(RouteUsage::is_idle) {
            if remove {
                self.registry.unregister(&route);
            }
            let _ = reply.send(Ok(()));
            return;
        }
        self.drains.insert(
            route,
            RouteDrain {
                deadline: self.clock.now().saturating_add(self.limits.drain_timeout()),
                remove,
                reply,
            },
        );
    }

    fn dispatch_ready(&mut self) {
        while self.global_in_flight < self.limits.global_in_flight() {
            let Some(delivery) = self.take_fair_ready() else {
                break;
            };
            self.start_attempt(delivery);
        }
    }

    fn take_fair_ready(&mut self) -> Option<DeliveryId> {
        let routes = self.ready_routes.len();
        for _ in 0..routes {
            let route = self.ready_routes.pop_front()?;
            let route_in_flight = self.usage.get(&route).map_or(0, |usage| usage.in_flight);
            if route_in_flight >= self.limits.route_in_flight() {
                self.ready_routes.push_back(route);
                continue;
            }
            let mut selected = None;
            let mut empty = false;
            if let Some(queue) = self.ready.get_mut(&route) {
                while let Some(delivery) = queue.pop_front() {
                    if self
                        .active
                        .get(&delivery)
                        .is_some_and(|active| active.abort.is_none())
                    {
                        selected = Some(delivery);
                        break;
                    }
                }
                empty = queue.is_empty();
            }
            if empty {
                self.ready.remove(&route);
            } else {
                self.ready_routes.push_back(route);
            }
            if selected.is_some() {
                return selected;
            }
        }
        None
    }

    fn start_attempt(&mut self, delivery: DeliveryId) {
        let time = self.clock.transition_time();
        let transition = match self
            .active
            .get_mut(&delivery)
            .map(|active| active.lifecycle.transition(time, DeliveryEvent::Drive))
        {
            Some(Ok(transition)) => transition,
            _ => {
                self.force_terminal(
                    &delivery,
                    DeliveryOutcome::Failed(bondry_delivery_store::DeliveryFailure::Internal),
                    None,
                );
                return;
            }
        };
        let Some(persistence) = transition.persistence().cloned() else {
            return;
        };
        if self.persist(&persistence).is_err() {
            self.persistence_degraded = true;
            self.apply_terminal_event(
                &delivery,
                DeliveryEvent::Failed(bondry_delivery_store::DeliveryFailure::Internal),
            );
            return;
        }
        if !matches!(transition.action(), DeliveryAction::StartAttempt { .. }) {
            self.force_terminal(
                &delivery,
                DeliveryOutcome::Failed(bondry_delivery_store::DeliveryFailure::Internal),
                None,
            );
            return;
        }
        let Some(active) = self.active.get(&delivery) else {
            return;
        };
        let route = active.parts.route.clone();
        let kind = Arc::clone(&active.parts.kind);
        let mode = active.parts.mode;
        let payload = active.parts.payload.clone();
        let timeout = active.parts.timeout.get();
        let deadline = Deadline::at(Instant::now() + timeout);
        let secrets = Arc::clone(&self.secrets);
        let transport = Arc::clone(&self.transport);
        let task_delivery = delivery.clone();
        let abort = self.attempts.spawn(async move {
            let completion = execute_attempt(
                kind,
                mode,
                task_delivery.clone(),
                payload,
                deadline,
                secrets,
                transport,
            )
            .await;
            (task_delivery, completion)
        });
        if let Some(active) = self.active.get_mut(&delivery) {
            active.abort = Some(abort);
        }
        self.global_in_flight += 1;
        self.usage.entry(route).or_default().in_flight += 1;
    }

    fn start_call(&mut self, delivery: DeliveryId) {
        let time = self.clock.transition_time();
        let transition = match self
            .active_calls
            .get_mut(&delivery)
            .map(|active| active.lifecycle.transition(time, DeliveryEvent::Drive))
        {
            Some(Ok(transition)) => transition,
            _ => {
                self.force_call_terminal(
                    &delivery,
                    DeliveryOutcome::Failed(DeliveryFailure::Internal),
                    None,
                    Err(EgressRuntimeError::CallFailed(DeliveryFailure::Internal)),
                );
                return;
            }
        };
        let Some(persistence) = transition.persistence().cloned() else {
            self.force_call_terminal(
                &delivery,
                DeliveryOutcome::Failed(DeliveryFailure::Internal),
                None,
                Err(EgressRuntimeError::CallFailed(DeliveryFailure::Internal)),
            );
            return;
        };
        if self.persist(&persistence).is_err() {
            self.persistence_degraded = true;
            self.force_call_terminal(
                &delivery,
                DeliveryOutcome::Failed(DeliveryFailure::Internal),
                None,
                Err(EgressRuntimeError::DeliveryLog(
                    DeliveryLogError::Unavailable,
                )),
            );
            return;
        }
        if !matches!(transition.action(), DeliveryAction::StartAttempt { .. }) {
            self.force_call_terminal(
                &delivery,
                DeliveryOutcome::Failed(DeliveryFailure::Internal),
                None,
                Err(EgressRuntimeError::CallFailed(DeliveryFailure::Internal)),
            );
            return;
        }
        let Some(active) = self.active_calls.get(&delivery) else {
            return;
        };
        let kind = Arc::clone(&active.parts.kind);
        let mode = active.parts.mode;
        let payload = active.parts.payload.clone();
        let deadline = Deadline::at(Instant::now() + active.parts.timeout.get());
        let secrets = Arc::clone(&self.secrets);
        let transport = Arc::clone(&self.transport);
        let task_delivery = delivery.clone();
        let abort = self.calls.spawn(async move {
            let completion = execute_attempt(
                kind,
                mode,
                task_delivery.clone(),
                payload,
                deadline,
                secrets,
                transport,
            )
            .await;
            (task_delivery, completion)
        });
        if let Some(active) = self.active_calls.get_mut(&delivery) {
            active.abort = Some(abort);
        }
        self.call_in_flight += 1;
    }

    fn handle_attempt_join(
        &mut self,
        completed: Option<
            Result<(DeliveryId, crate::attempt::AttemptCompletion), tokio::task::JoinError>,
        >,
    ) {
        match completed {
            Some(Ok((delivery, completion))) => self.complete_attempt(delivery, completion),
            Some(Err(error)) if error.is_cancelled() => {}
            Some(Err(_)) => {
                let deliveries = self
                    .active
                    .iter()
                    .filter(|(_, active)| active.abort.is_some())
                    .map(|(delivery, _)| delivery.clone())
                    .collect::<Vec<_>>();
                for delivery in deliveries {
                    self.abort_in_flight(&delivery);
                    self.apply_terminal_event(
                        &delivery,
                        DeliveryEvent::Failed(bondry_delivery_store::DeliveryFailure::Internal),
                    );
                }
            }
            None => {}
        }
    }

    fn handle_call_join(
        &mut self,
        completed: Option<
            Result<(DeliveryId, crate::attempt::AttemptCompletion), tokio::task::JoinError>,
        >,
    ) {
        match completed {
            Some(Ok((delivery, completion))) => self.complete_call(delivery, completion),
            Some(Err(error)) if error.is_cancelled() => {}
            Some(Err(_)) => {
                let deliveries = self
                    .active_calls
                    .iter()
                    .filter(|(_, active)| active.abort.is_some())
                    .map(|(delivery, _)| delivery.clone())
                    .collect::<Vec<_>>();
                for delivery in deliveries {
                    self.abort_call(&delivery);
                    self.force_call_terminal(
                        &delivery,
                        DeliveryOutcome::Failed(DeliveryFailure::Internal),
                        None,
                        Err(EgressRuntimeError::CallFailed(DeliveryFailure::Internal)),
                    );
                }
            }
            None => {}
        }
    }

    fn complete_attempt(
        &mut self,
        delivery: DeliveryId,
        completion: crate::attempt::AttemptCompletion,
    ) {
        if !self.clear_in_flight(&delivery) {
            return;
        }
        drop(completion.result);
        let event = match completion.disposition {
            bondry_egress::AttemptDisposition::Delivered(result) => {
                DeliveryEvent::Delivered(result)
            }
            bondry_egress::AttemptDisposition::Retryable(failure) => {
                DeliveryEvent::Retryable(failure)
            }
            bondry_egress::AttemptDisposition::Failed(failure) => DeliveryEvent::Failed(failure),
            bondry_egress::AttemptDisposition::FailedWithResult { failure, result } => {
                DeliveryEvent::FailedWithResult { failure, result }
            }
        };
        let time = self.clock.transition_time();
        let transition = match self
            .active
            .get_mut(&delivery)
            .map(|active| active.lifecycle.transition(time, event))
        {
            Some(Ok(transition)) => transition,
            _ => {
                self.force_terminal(
                    &delivery,
                    DeliveryOutcome::Failed(bondry_delivery_store::DeliveryFailure::Internal),
                    None,
                );
                return;
            }
        };
        match transition.action() {
            DeliveryAction::Wait => {
                if let Some(deadline) = transition.next_deadline() {
                    self.retries.push(Reverse((deadline, delivery)));
                }
            }
            DeliveryAction::Terminal { outcome, result } => {
                self.persist_terminal(&delivery, outcome, result, transition.persistence());
            }
            DeliveryAction::None | DeliveryAction::StartAttempt { .. } => {
                self.force_terminal(
                    &delivery,
                    DeliveryOutcome::Failed(bondry_delivery_store::DeliveryFailure::Internal),
                    None,
                );
            }
        }
    }

    fn complete_call(
        &mut self,
        delivery: DeliveryId,
        completion: crate::attempt::AttemptCompletion,
    ) {
        if !self.clear_call_in_flight(&delivery) {
            return;
        }
        let raw_result = completion.result;
        let event = disposition_event(completion.disposition);
        let time = self.clock.transition_time();
        let transition = match self
            .active_calls
            .get_mut(&delivery)
            .map(|active| active.lifecycle.transition(time, event))
        {
            Some(Ok(transition)) => transition,
            _ => {
                self.force_call_terminal(
                    &delivery,
                    DeliveryOutcome::Failed(DeliveryFailure::Internal),
                    None,
                    Err(EgressRuntimeError::CallFailed(DeliveryFailure::Internal)),
                );
                return;
            }
        };
        let DeliveryAction::Terminal { outcome, result } = transition.action() else {
            self.force_call_terminal(
                &delivery,
                DeliveryOutcome::Failed(DeliveryFailure::Internal),
                None,
                Err(EgressRuntimeError::CallFailed(DeliveryFailure::Internal)),
            );
            return;
        };
        self.persist_call_terminal(&delivery, outcome, result, transition.persistence());
        let response = match (outcome, result, raw_result) {
            (DeliveryOutcome::Delivered, Some(metadata), Some(json)) => Ok(CallResult {
                delivery: delivery.clone(),
                metadata,
                json,
            }),
            (DeliveryOutcome::Failed(failure), _, _) => {
                Err(EgressRuntimeError::CallFailed(failure))
            }
            (DeliveryOutcome::LostOnShutdown, _, _)
            | (DeliveryOutcome::UnknownAfterCrash, _, _) => Err(EgressRuntimeError::Stopped),
            (DeliveryOutcome::Delivered, _, _) => {
                Err(EgressRuntimeError::CallFailed(DeliveryFailure::Internal))
            }
        };
        self.finish_call(&delivery, response);
    }

    fn clear_in_flight(&mut self, delivery: &DeliveryId) -> bool {
        let Some(active) = self.active.get_mut(delivery) else {
            return false;
        };
        if active.abort.take().is_none() {
            return false;
        }
        self.global_in_flight = self.global_in_flight.saturating_sub(1);
        if let Some(usage) = self.usage.get_mut(&active.parts.route) {
            usage.in_flight = usage.in_flight.saturating_sub(1);
        }
        true
    }

    fn abort_in_flight(&mut self, delivery: &DeliveryId) -> bool {
        let Some(active) = self.active.get_mut(delivery) else {
            return false;
        };
        let Some(abort) = active.abort.take() else {
            return false;
        };
        abort.abort();
        self.global_in_flight = self.global_in_flight.saturating_sub(1);
        if let Some(usage) = self.usage.get_mut(&active.parts.route) {
            usage.in_flight = usage.in_flight.saturating_sub(1);
        }
        true
    }

    fn clear_call_in_flight(&mut self, delivery: &DeliveryId) -> bool {
        let Some(active) = self.active_calls.get_mut(delivery) else {
            return false;
        };
        if active.abort.take().is_none() {
            return false;
        }
        self.call_in_flight = self.call_in_flight.saturating_sub(1);
        true
    }

    fn abort_call(&mut self, delivery: &DeliveryId) -> bool {
        let Some(active) = self.active_calls.get_mut(delivery) else {
            return false;
        };
        let Some(abort) = active.abort.take() else {
            return false;
        };
        abort.abort();
        self.call_in_flight = self.call_in_flight.saturating_sub(1);
        true
    }

    fn process_retry_deadlines(&mut self) {
        let now = self.clock.now();
        while self
            .retries
            .peek()
            .is_some_and(|Reverse((deadline, _))| *deadline <= now)
        {
            let Some(Reverse((deadline, delivery))) = self.retries.pop() else {
                break;
            };
            let Some(active) = self.active.get(&delivery) else {
                continue;
            };
            if active.lifecycle.next_deadline() == Some(deadline) {
                self.enqueue_ready(active.parts.route.clone(), delivery);
            }
        }
    }

    fn process_drain_deadlines(&mut self) {
        let now = self.clock.now();
        let expired = self
            .drains
            .iter()
            .filter(|(_, drain)| drain.deadline <= now)
            .map(|(route, _)| route.clone())
            .collect::<Vec<_>>();
        for route in expired {
            let deliveries = self
                .active
                .iter()
                .filter(|(_, active)| active.parts.route == route)
                .map(|(delivery, _)| delivery.clone())
                .collect::<Vec<_>>();
            for delivery in deliveries {
                self.apply_terminal_event(&delivery, DeliveryEvent::Cancel);
            }
            let calls = self
                .active_calls
                .iter()
                .filter(|(_, active)| active.parts.route == route)
                .map(|(delivery, _)| delivery.clone())
                .collect::<Vec<_>>();
            for delivery in calls {
                self.apply_call_terminal_event(
                    &delivery,
                    DeliveryEvent::Cancel,
                    Err(EgressRuntimeError::CallFailed(DeliveryFailure::Cancelled)),
                );
            }
        }
    }

    fn expire_shutdown(&mut self) {
        let deliveries = self.active.keys().cloned().collect::<Vec<_>>();
        for delivery in deliveries {
            self.apply_terminal_event(&delivery, DeliveryEvent::ShutdownDeadline);
        }
        let calls = self.active_calls.keys().cloned().collect::<Vec<_>>();
        for delivery in calls {
            self.apply_call_terminal_event(
                &delivery,
                DeliveryEvent::ShutdownDeadline,
                Err(EgressRuntimeError::Stopped),
            );
        }
    }

    fn apply_terminal_event(&mut self, delivery: &DeliveryId, event: DeliveryEvent) {
        let time = self.clock.transition_time();
        let transition = match self
            .active
            .get_mut(delivery)
            .map(|active| active.lifecycle.transition(time, event))
        {
            Some(Ok(transition)) => transition,
            _ => {
                self.force_terminal(
                    delivery,
                    DeliveryOutcome::Failed(bondry_delivery_store::DeliveryFailure::Internal),
                    None,
                );
                return;
            }
        };
        if let DeliveryAction::Terminal { outcome, result } = transition.action() {
            self.persist_terminal(delivery, outcome, result, transition.persistence());
        } else {
            self.force_terminal(
                delivery,
                DeliveryOutcome::Failed(bondry_delivery_store::DeliveryFailure::Internal),
                None,
            );
        }
    }

    fn apply_call_terminal_event(
        &mut self,
        delivery: &DeliveryId,
        event: DeliveryEvent,
        response: Result<CallResult, EgressRuntimeError>,
    ) {
        let time = self.clock.transition_time();
        let transition = match self
            .active_calls
            .get_mut(delivery)
            .map(|active| active.lifecycle.transition(time, event))
        {
            Some(Ok(transition)) => transition,
            _ => {
                self.force_call_terminal(
                    delivery,
                    DeliveryOutcome::Failed(DeliveryFailure::Internal),
                    None,
                    Err(EgressRuntimeError::CallFailed(DeliveryFailure::Internal)),
                );
                return;
            }
        };
        let DeliveryAction::Terminal { outcome, result } = transition.action() else {
            self.force_call_terminal(
                delivery,
                DeliveryOutcome::Failed(DeliveryFailure::Internal),
                None,
                Err(EgressRuntimeError::CallFailed(DeliveryFailure::Internal)),
            );
            return;
        };
        self.persist_call_terminal(delivery, outcome, result, transition.persistence());
        self.finish_call(delivery, response);
    }

    fn persist_terminal(
        &mut self,
        delivery: &DeliveryId,
        outcome: DeliveryOutcome,
        result: Option<DeliveryResultMetadata>,
        persistence: Option<&DeliveryPersistenceAction>,
    ) {
        let persisted = persistence.is_some_and(|action| self.persist(action).is_ok());
        if !persisted && !self.persisted_terminal_matches(delivery, outcome, result) {
            self.persistence_degraded = true;
            self.insert_override(delivery, outcome, result);
        }
        self.finish_delivery(delivery);
    }

    fn persist_call_terminal(
        &mut self,
        delivery: &DeliveryId,
        outcome: DeliveryOutcome,
        result: Option<DeliveryResultMetadata>,
        persistence: Option<&DeliveryPersistenceAction>,
    ) {
        let persisted = persistence.is_some_and(|action| self.persist(action).is_ok());
        if !persisted && !self.persisted_terminal_matches(delivery, outcome, result) {
            self.persistence_degraded = true;
            self.insert_call_override(delivery, outcome, result);
        }
    }

    fn force_call_terminal(
        &mut self,
        delivery: &DeliveryId,
        outcome: DeliveryOutcome,
        result: Option<DeliveryResultMetadata>,
        response: Result<CallResult, EgressRuntimeError>,
    ) {
        let persisted = self
            .log
            .record_outcome(delivery, outcome, unix_milliseconds(), result)
            .is_ok();
        if !persisted && !self.persisted_terminal_matches(delivery, outcome, result) {
            self.persistence_degraded = true;
            self.insert_call_override(delivery, outcome, result);
        }
        self.finish_call(delivery, response);
    }

    fn force_terminal(
        &mut self,
        delivery: &DeliveryId,
        outcome: DeliveryOutcome,
        result: Option<DeliveryResultMetadata>,
    ) {
        let updated_at = unix_milliseconds();
        let persisted = self
            .log
            .record_outcome(delivery, outcome, updated_at, result)
            .is_ok();
        if !persisted && !self.persisted_terminal_matches(delivery, outcome, result) {
            self.persistence_degraded = true;
            self.insert_override(delivery, outcome, result);
        }
        self.finish_delivery(delivery);
    }

    fn persisted_terminal_matches(
        &self,
        delivery: &DeliveryId,
        outcome: DeliveryOutcome,
        result: Option<DeliveryResultMetadata>,
    ) -> bool {
        self.log.delivery(delivery).is_ok_and(|record| {
            record.is_some_and(|record| {
                record.state() == DeliveryState::Terminal(outcome) && record.result() == result
            })
        })
    }

    fn insert_override(
        &mut self,
        delivery: &DeliveryId,
        outcome: DeliveryOutcome,
        result: Option<DeliveryResultMetadata>,
    ) {
        let Some(active) = self.active.get(delivery) else {
            return;
        };
        let intent = DeliveryIntent::new(
            active.parts.route.clone(),
            delivery.clone(),
            active.accepted_at_unix_ms,
        );
        self.overrides.insert(
            delivery.clone(),
            DeliveryRecord::from_stored_parts(
                intent,
                active.lifecycle.attempts(),
                DeliveryState::Terminal(outcome),
                unix_milliseconds(),
                result,
            ),
        );
    }

    fn insert_call_override(
        &mut self,
        delivery: &DeliveryId,
        outcome: DeliveryOutcome,
        result: Option<DeliveryResultMetadata>,
    ) {
        let Some(active) = self.active_calls.get(delivery) else {
            return;
        };
        let intent = DeliveryIntent::new(
            active.parts.route.clone(),
            delivery.clone(),
            active.accepted_at_unix_ms,
        );
        self.overrides.insert(
            delivery.clone(),
            DeliveryRecord::from_stored_parts(
                intent,
                active.lifecycle.attempts(),
                DeliveryState::Terminal(outcome),
                unix_milliseconds(),
                result,
            ),
        );
    }

    fn finish_delivery(&mut self, delivery: &DeliveryId) {
        let Some(mut active) = self.active.remove(delivery) else {
            return;
        };
        if let Some(abort) = active.abort.take() {
            abort.abort();
            self.global_in_flight = self.global_in_flight.saturating_sub(1);
            if let Some(usage) = self.usage.get_mut(&active.parts.route) {
                usage.in_flight = usage.in_flight.saturating_sub(1);
            }
        }
        let bytes = active.parts.payload.len();
        self.global_pending = self.global_pending.saturating_sub(1);
        self.global_bytes = self.global_bytes.saturating_sub(bytes);
        if let Some(usage) = self.usage.get_mut(&active.parts.route) {
            usage.pending = usage.pending.saturating_sub(1);
            usage.bytes = usage.bytes.saturating_sub(bytes);
            if usage.is_idle() {
                self.usage.remove(&active.parts.route);
            }
        }
    }

    fn finish_call(
        &mut self,
        delivery: &DeliveryId,
        response: Result<CallResult, EgressRuntimeError>,
    ) {
        let Some(mut active) = self.active_calls.remove(delivery) else {
            return;
        };
        if let Some(abort) = active.abort.take() {
            abort.abort();
            self.call_in_flight = self.call_in_flight.saturating_sub(1);
        }
        if let Some(usage) = self.usage.get_mut(&active.parts.route) {
            usage.calls = usage.calls.saturating_sub(1);
            if usage.pending == 0 && usage.in_flight == 0 && usage.calls == 0 {
                self.usage.remove(&active.parts.route);
            }
        }
        let _ = active.reply.send(response);
    }

    fn enqueue_ready(&mut self, route: RouteId, delivery: DeliveryId) {
        let queue = self.ready.entry(route.clone()).or_default();
        if queue.is_empty() {
            self.ready_routes.push_back(route);
        }
        queue.push_back(delivery);
    }

    fn persist(&self, action: &DeliveryPersistenceAction) -> Result<(), DeliveryLogError> {
        match action {
            DeliveryPersistenceAction::InsertIntent { intent } => {
                self.log.insert_intent(intent.clone())
            }
            DeliveryPersistenceAction::RecordAttempt {
                delivery,
                attempts,
                updated_at_unix_ms,
            } => self
                .log
                .record_attempt(delivery, *attempts, *updated_at_unix_ms),
            DeliveryPersistenceAction::RecordOutcome {
                delivery,
                outcome,
                updated_at_unix_ms,
                result,
            } => self
                .log
                .record_outcome(delivery, *outcome, *updated_at_unix_ms, *result),
        }
    }

    fn complete_empty_drains(&mut self) {
        let complete = self
            .drains
            .keys()
            .filter(|route| self.usage.get(*route).is_none_or(RouteUsage::is_idle))
            .cloned()
            .collect::<Vec<_>>();
        for route in complete {
            if let Some(drain) = self.drains.remove(&route) {
                if drain.remove {
                    self.registry.unregister(&route);
                }
                let _ = drain.reply.send(Ok(()));
            }
        }
    }

    fn reject_drains_for_shutdown(&mut self) {
        for (_, drain) in std::mem::take(&mut self.drains) {
            let _ = drain.reply.send(Err(EgressRuntimeError::Stopped));
        }
    }

    fn reject_pending_commands(&mut self, commands: &mut mpsc::Receiver<Command>) {
        while let Ok(command) = commands.try_recv() {
            reject_command(command);
        }
    }

    fn discard_stale_retries(&mut self) {
        while let Some(Reverse((deadline, delivery))) = self.retries.peek() {
            let valid = self
                .active
                .get(delivery)
                .is_some_and(|active| active.lifecycle.next_deadline() == Some(*deadline));
            if valid {
                break;
            }
            self.retries.pop();
        }
    }

    fn next_deadline(&self, shutdown: Option<EgressInstant>) -> Option<EgressInstant> {
        self.retries
            .peek()
            .map(|Reverse((deadline, _))| *deadline)
            .into_iter()
            .chain(self.drains.values().map(|drain| drain.deadline))
            .chain(shutdown)
            .min()
    }
}

#[derive(Default, Clone, Copy)]
struct RouteUsage {
    pending: u16,
    bytes: usize,
    in_flight: u8,
    calls: u8,
}

impl RouteUsage {
    const fn is_idle(&self) -> bool {
        self.pending == 0 && self.in_flight == 0 && self.calls == 0
    }
}

struct ActiveDelivery {
    accepted_at_unix_ms: u64,
    parts: AdmittedDeliveryParts,
    lifecycle: DeliveryLifecycle,
    abort: Option<AbortHandle>,
}

struct ActiveCall {
    accepted_at_unix_ms: u64,
    parts: AdmittedDeliveryParts,
    lifecycle: DeliveryLifecycle,
    abort: Option<AbortHandle>,
    reply: Reply<CallResult>,
}

struct RouteDrain {
    deadline: EgressInstant,
    remove: bool,
    reply: Reply<()>,
}

#[derive(Clone, Copy)]
struct RuntimeClock {
    origin: Instant,
}

impl RuntimeClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }

    fn now(self) -> EgressInstant {
        EgressInstant::at(self.origin.elapsed())
    }

    fn transition_time(self) -> TransitionTime {
        TransitionTime::new(self.now(), unix_milliseconds())
    }
}

async fn wait_for_deadline(clock: RuntimeClock, deadline: Option<EgressInstant>) {
    match deadline {
        Some(deadline) => {
            let remaining = deadline.elapsed().saturating_sub(clock.now().elapsed());
            tokio::time::sleep(remaining).await;
        }
        None => future::pending().await,
    }
}

fn reject_command(command: Command) {
    match command {
        Command::Register { reply, .. }
        | Command::Enable { reply, .. }
        | Command::Drain { reply, .. } => {
            let _ = reply.send(Err(EgressRuntimeError::Stopped));
        }
        Command::Routes { reply } => {
            let _ = reply.send(Err(EgressRuntimeError::Stopped));
        }
        Command::Emit { reply, .. } => {
            let _ = reply.send(Err(EgressRuntimeError::Stopped));
        }
        Command::Call { reply, .. } => {
            let _ = reply.send(Err(EgressRuntimeError::Stopped));
        }
        Command::Delivery { reply, .. } => {
            let _ = reply.send(Err(EgressRuntimeError::Stopped));
        }
    }
}

fn disposition_event(disposition: bondry_egress::AttemptDisposition) -> DeliveryEvent {
    match disposition {
        bondry_egress::AttemptDisposition::Delivered(result) => DeliveryEvent::Delivered(result),
        bondry_egress::AttemptDisposition::Retryable(failure) => DeliveryEvent::Retryable(failure),
        bondry_egress::AttemptDisposition::Failed(failure) => DeliveryEvent::Failed(failure),
        bondry_egress::AttemptDisposition::FailedWithResult { failure, result } => {
            DeliveryEvent::FailedWithResult { failure, result }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex, mpsc},
        thread,
        time::{Duration, Instant},
    };

    use bondry_delivery_store::{
        DeliveryFailure, DeliveryId, DeliveryIntent, DeliveryLog, DeliveryLogError,
        DeliveryOutcome, DeliveryRecord, DeliveryResultMetadata, DeliveryState, RouteId,
        StoreDurability,
    };
    use bondry_egress::{
        PayloadContract, PayloadField, PayloadFieldName, PayloadFieldType, PayloadLimit,
        RequestTimeout, RetryPolicy, Route, RouteAdmissionLimit, RouteRegistry,
    };
    use bondry_egress_mcp::{McpAuthentication, McpDeliveryKind, McpLimits, McpToolBinding};
    use bondry_egress_webhook::{WebhookAuthentication, WebhookDeliveryKind, WebhookLimits};
    use bondry_mcp_proto::{McpClient, McpClientInfo, McpProtocolVersion};
    use bondry_secrets::{SecretProvider, SecretProviderError};
    use bondry_transport::{
        ConnectionEvidence, HttpRequest, HttpResponse, HttpTransport, TlsConnectionEvidence,
        TransportError, TransportFuture,
    };
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, StatusCode, header};
    use serde_json::{Value, json};

    use super::{EgressRuntime, EgressRuntimeError};
    use crate::{EgressRuntimeLimits, InMemoryDeliveryLog};

    struct NoSecrets;

    impl SecretProvider for NoSecrets {
        fn resolve(
            &self,
            _reference: &bondry_secrets::SecretRef,
        ) -> Result<bondry_secrets::ResolvedSecret, SecretProviderError> {
            Err(SecretProviderError::NotFound)
        }
    }

    struct FailingOutcomeLog {
        inner: InMemoryDeliveryLog,
    }

    struct FailingIntentLog {
        inner: InMemoryDeliveryLog,
    }

    struct RecordingLog {
        inner: InMemoryDeliveryLog,
        events: mpsc::Sender<String>,
    }

    macro_rules! delegate_delivery_log {
        () => {
            fn durability(&self) -> StoreDurability {
                self.inner.durability()
            }

            fn delivery(
                &self,
                delivery: &DeliveryId,
            ) -> Result<Option<DeliveryRecord>, DeliveryLogError> {
                self.inner.delivery(delivery)
            }

            fn recover_unfinished(&self, updated_at_unix_ms: u64) -> Result<u64, DeliveryLogError> {
                self.inner.recover_unfinished(updated_at_unix_ms)
            }
        };
    }

    impl DeliveryLog for FailingOutcomeLog {
        delegate_delivery_log!();

        fn insert_intent(&self, intent: DeliveryIntent) -> Result<(), DeliveryLogError> {
            self.inner.insert_intent(intent)
        }

        fn record_attempt(
            &self,
            delivery: &DeliveryId,
            attempts: u16,
            updated_at_unix_ms: u64,
        ) -> Result<(), DeliveryLogError> {
            self.inner
                .record_attempt(delivery, attempts, updated_at_unix_ms)
        }

        fn record_outcome(
            &self,
            _delivery: &DeliveryId,
            _outcome: DeliveryOutcome,
            _updated_at_unix_ms: u64,
            _result: Option<DeliveryResultMetadata>,
        ) -> Result<(), DeliveryLogError> {
            Err(DeliveryLogError::Unavailable)
        }
    }

    impl DeliveryLog for FailingIntentLog {
        delegate_delivery_log!();

        fn insert_intent(&self, _intent: DeliveryIntent) -> Result<(), DeliveryLogError> {
            Err(DeliveryLogError::Unavailable)
        }

        fn record_attempt(
            &self,
            delivery: &DeliveryId,
            attempts: u16,
            updated_at_unix_ms: u64,
        ) -> Result<(), DeliveryLogError> {
            self.inner
                .record_attempt(delivery, attempts, updated_at_unix_ms)
        }

        fn record_outcome(
            &self,
            delivery: &DeliveryId,
            outcome: DeliveryOutcome,
            updated_at_unix_ms: u64,
            result: Option<DeliveryResultMetadata>,
        ) -> Result<(), DeliveryLogError> {
            self.inner
                .record_outcome(delivery, outcome, updated_at_unix_ms, result)
        }
    }

    impl DeliveryLog for RecordingLog {
        delegate_delivery_log!();

        fn insert_intent(&self, intent: DeliveryIntent) -> Result<(), DeliveryLogError> {
            self.inner.insert_intent(intent)?;
            let _ = self.events.send("intent".to_owned());
            Ok(())
        }

        fn record_attempt(
            &self,
            delivery: &DeliveryId,
            attempts: u16,
            updated_at_unix_ms: u64,
        ) -> Result<(), DeliveryLogError> {
            self.inner
                .record_attempt(delivery, attempts, updated_at_unix_ms)?;
            let _ = self.events.send("attempt".to_owned());
            Ok(())
        }

        fn record_outcome(
            &self,
            delivery: &DeliveryId,
            outcome: DeliveryOutcome,
            updated_at_unix_ms: u64,
            result: Option<DeliveryResultMetadata>,
        ) -> Result<(), DeliveryLogError> {
            self.inner
                .record_outcome(delivery, outcome, updated_at_unix_ms, result)?;
            let _ = self.events.send("outcome".to_owned());
            Ok(())
        }
    }

    struct MockTransport {
        delay: Duration,
        outcomes: Mutex<VecDeque<Result<StatusCode, TransportError>>>,
        sends: mpsc::Sender<String>,
    }

    struct McpTransport {
        delay: Duration,
        sends: mpsc::Sender<String>,
        response: Bytes,
    }

    impl McpTransport {
        fn new(delay: Duration, sends: mpsc::Sender<String>) -> Self {
            let mut response: Value = serde_json::from_str(include_str!(
                "../../../../fixtures/protocol-v1/mcp/tools-call.response.json"
            ))
            .unwrap_or_else(|error| unreachable!("valid MCP fixture: {error}"));
            response["id"] = Value::from(1);
            Self {
                delay,
                sends,
                response: Bytes::from(
                    serde_json::to_vec(&response)
                        .unwrap_or_else(|error| unreachable!("encodable MCP fixture: {error}")),
                ),
            }
        }
    }

    impl HttpTransport for McpTransport {
        fn send(
            &self,
            request: HttpRequest,
        ) -> TransportFuture<'_, Result<HttpResponse, TransportError>> {
            let parts = request.into_parts();
            let delay = self.delay;
            let sends = self.sends.clone();
            let response = self.response.clone();
            Box::pin(async move {
                let _ = sends.send(parts.endpoint.path_and_query().to_owned());
                tokio::time::sleep(delay).await;
                let connection = parts.policy.verify_connection(
                    &parts.endpoint,
                    ConnectionEvidence::Tls(TlsConnectionEvidence::verified(parts.endpoint.host())),
                )?;
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                HttpResponse::new(StatusCode::OK, headers, response, connection, parts.limits)
            })
        }
    }

    impl MockTransport {
        fn new(
            delay: Duration,
            outcomes: impl IntoIterator<Item = Result<StatusCode, TransportError>>,
            sends: mpsc::Sender<String>,
        ) -> Self {
            Self {
                delay,
                outcomes: Mutex::new(outcomes.into_iter().collect()),
                sends,
            }
        }
    }

    impl HttpTransport for MockTransport {
        fn send(
            &self,
            request: HttpRequest,
        ) -> TransportFuture<'_, Result<HttpResponse, TransportError>> {
            let parts = request.into_parts();
            let outcome = self
                .outcomes
                .lock()
                .ok()
                .and_then(|mut outcomes| outcomes.pop_front())
                .unwrap_or(Ok(StatusCode::NO_CONTENT));
            let delay = self.delay;
            let sends = self.sends.clone();
            Box::pin(async move {
                let _ = sends.send(parts.endpoint.path_and_query().to_owned());
                tokio::time::sleep(delay).await;
                let status = outcome?;
                let connection = parts.policy.verify_connection(
                    &parts.endpoint,
                    ConnectionEvidence::Tls(TlsConnectionEvidence::verified(parts.endpoint.host())),
                )?;
                HttpResponse::new(
                    status,
                    HeaderMap::new(),
                    Bytes::new(),
                    connection,
                    parts.limits,
                )
            })
        }
    }

    fn limits(
        route_pending: u16,
        global_in_flight: u8,
        drain: Duration,
    ) -> Result<EgressRuntimeLimits, Box<dyn std::error::Error>> {
        Ok(EgressRuntimeLimits::new(
            16,
            route_pending,
            1024 * 1024,
            64 * 1024,
            global_in_flight,
            1,
            1,
            drain,
        )?)
    }

    fn route(id: &str, retry: RetryPolicy) -> Result<Route, Box<dyn std::error::Error>> {
        let payload = PayloadContract::new(
            [PayloadField::new(
                PayloadFieldName::new("event")?,
                PayloadFieldType::String,
                true,
            )],
            PayloadLimit::default(),
        )?;
        let endpoint =
            bondry_transport::NetworkEndpoint::new(format!("https://example.com/{id}").parse()?)?;
        let kind = WebhookDeliveryKind::new(
            endpoint,
            WebhookAuthentication::None,
            bondry_transport::EndpointPolicy::default(),
            WebhookLimits::default(),
        )?;
        Ok(Route::new(
            RouteId::new(id)?,
            true,
            payload,
            RequestTimeout::new(Duration::from_secs(10))?,
            retry,
            RouteAdmissionLimit::default(),
            Arc::new(kind),
        ))
    }

    fn mcp_route(id: &str) -> Result<Route, Box<dyn std::error::Error>> {
        let payload = PayloadContract::new(
            [PayloadField::new(
                PayloadFieldName::new("detail")?,
                PayloadFieldType::Any,
                true,
            )],
            PayloadLimit::default(),
        )?;
        let tool = McpToolBinding::from_parts(
            "battery:status",
            json!({
                "type": "object",
                "properties": { "detail": { "type": "boolean" } },
                "required": ["detail"],
                "additionalProperties": false,
            }),
            McpLimits::default(),
        )?;
        let kind = McpDeliveryKind::new(
            bondry_transport::NetworkEndpoint::new(format!("https://example.com/{id}").parse()?)?,
            McpAuthentication::None,
            bondry_transport::EndpointPolicy::default(),
            McpClient::new(McpClientInfo::new("runtime-test", "0.2.0")?),
            McpProtocolVersion::V2026_07_28,
            tool,
            McpLimits::default(),
        )?;
        Ok(Route::new(
            RouteId::new(id)?,
            true,
            payload,
            RequestTimeout::new(Duration::from_secs(10))?,
            RetryPolicy::default(),
            RouteAdmissionLimit::default(),
            Arc::new(kind),
        ))
    }

    fn event(marker: &str) -> Bytes {
        Bytes::from(format!("{{\"event\":\"{marker}\"}}"))
    }

    fn mcp_input(detail: bool) -> Bytes {
        Bytes::from(format!("{{\"detail\":{detail}}}"))
    }

    fn start_runtime(
        limits: EgressRuntimeLimits,
        log: Arc<InMemoryDeliveryLog>,
        transport: Arc<MockTransport>,
    ) -> Result<EgressRuntime, Box<dyn std::error::Error>> {
        Ok(EgressRuntime::start(
            RouteRegistry::default(),
            limits,
            log,
            Arc::new(NoSecrets),
            transport,
        )?)
    }

    fn wait_for_terminal(
        runtime: &EgressRuntime,
        delivery: &DeliveryId,
        timeout: Duration,
    ) -> Result<DeliveryRecord, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(record) = runtime.delivery(delivery.clone())? {
                if record.state().is_terminal() {
                    return Ok(record);
                }
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::other("delivery did not become terminal").into());
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn persists_before_send_and_reports_exact_terminal_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let (events, received) = mpsc::channel();
        let transport = Arc::new(MockTransport::new(Duration::ZERO, [], events.clone()));
        let log = Arc::new(RecordingLog {
            inner: InMemoryDeliveryLog::default(),
            events,
        });
        let mut runtime = EgressRuntime::start(
            RouteRegistry::default(),
            limits(8, 2, Duration::from_secs(1))?,
            log,
            Arc::new(NoSecrets),
            transport,
        )?;
        runtime.register_route(route("watchdog", RetryPolicy::without_retries())?)?;
        let delivery = DeliveryId::new("delivery_success")?;
        let receipt = runtime.emit(
            RouteId::new("watchdog")?,
            delivery.clone(),
            event("power_lost"),
        )?;
        assert_eq!(receipt.delivery(), &delivery);
        assert_eq!(received.recv_timeout(Duration::from_secs(1))?, "intent");
        assert_eq!(received.recv_timeout(Duration::from_secs(1))?, "attempt");
        assert_eq!(received.recv_timeout(Duration::from_secs(1))?, "/watchdog");
        let record = wait_for_terminal(&runtime, &delivery, Duration::from_secs(1))?;
        assert_eq!(record.attempts(), 1);
        assert_eq!(
            record.state(),
            DeliveryState::Terminal(DeliveryOutcome::Delivered)
        );
        runtime.stop()?;
        Ok(())
    }

    #[test]
    fn refuses_transport_when_intent_persistence_fails() -> Result<(), Box<dyn std::error::Error>> {
        let (sends, sent) = mpsc::channel();
        let transport = Arc::new(MockTransport::new(Duration::ZERO, [], sends));
        let log = Arc::new(FailingIntentLog {
            inner: InMemoryDeliveryLog::default(),
        });
        let mut runtime = EgressRuntime::start(
            RouteRegistry::default(),
            limits(8, 2, Duration::from_secs(1))?,
            log,
            Arc::new(NoSecrets),
            transport,
        )?;
        runtime.register_route(route("closed", RetryPolicy::without_retries())?)?;
        assert_eq!(
            runtime.emit(
                RouteId::new("closed")?,
                DeliveryId::new("not_persisted")?,
                event("blocked"),
            ),
            Err(EgressRuntimeError::DeliveryLog(
                DeliveryLogError::Unavailable
            ))
        );
        assert!(sent.recv_timeout(Duration::from_millis(50)).is_err());
        runtime.stop()?;
        Ok(())
    }

    #[test]
    fn enforces_pending_capacity_while_transport_is_in_flight()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sends, _sent) = mpsc::channel();
        let transport = Arc::new(MockTransport::new(Duration::from_millis(100), [], sends));
        let log = Arc::new(InMemoryDeliveryLog::default());
        let mut runtime = start_runtime(limits(1, 1, Duration::from_secs(1))?, log, transport)?;
        runtime.register_route(route("limited", RetryPolicy::without_retries())?)?;
        runtime.emit(
            RouteId::new("limited")?,
            DeliveryId::new("first")?,
            event("first"),
        )?;
        assert_eq!(
            runtime.emit(
                RouteId::new("limited")?,
                DeliveryId::new("second")?,
                event("second"),
            ),
            Err(EgressRuntimeError::PendingCapacity)
        );
        runtime.stop()?;
        Ok(())
    }

    #[test]
    fn round_robin_prevents_a_hot_route_from_starving_another()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sends, sent) = mpsc::channel();
        let transport = Arc::new(MockTransport::new(Duration::from_millis(20), [], sends));
        let log = Arc::new(InMemoryDeliveryLog::default());
        let mut runtime = start_runtime(limits(8, 1, Duration::from_secs(1))?, log, transport)?;
        runtime.register_route(route("hot", RetryPolicy::without_retries())?)?;
        runtime.register_route(route("cold", RetryPolicy::without_retries())?)?;
        for index in 0..3 {
            runtime.emit(
                RouteId::new("hot")?,
                DeliveryId::new(format!("hot_{index}"))?,
                event("hot"),
            )?;
        }
        runtime.emit(
            RouteId::new("cold")?,
            DeliveryId::new("cold_0")?,
            event("cold"),
        )?;
        let order = (0..4)
            .map(|_| sent.recv_timeout(Duration::from_secs(1)))
            .collect::<Result<Vec<_>, _>>()?;
        let cold = order
            .iter()
            .position(|path| path == "/cold")
            .ok_or(std::io::Error::other("cold route was not dispatched"))?;
        assert!(cold <= 2, "unexpected dispatch order: {order:?}");
        runtime.stop()?;
        Ok(())
    }

    #[test]
    fn schedules_bounded_retry_and_then_delivers() -> Result<(), Box<dyn std::error::Error>> {
        let (sends, sent) = mpsc::channel();
        let transport = Arc::new(MockTransport::new(
            Duration::ZERO,
            [
                Err(TransportError::ConnectionFailed),
                Ok(StatusCode::NO_CONTENT),
            ],
            sends,
        ));
        let log = Arc::new(InMemoryDeliveryLog::default());
        let mut runtime = start_runtime(limits(8, 1, Duration::from_secs(1))?, log, transport)?;
        runtime.register_route(route(
            "retry",
            RetryPolicy::new(1, Duration::from_millis(500), Duration::from_secs(30))?,
        )?)?;
        let delivery = DeliveryId::new("delivery_retry")?;
        runtime.emit(RouteId::new("retry")?, delivery.clone(), event("retry"))?;
        let record = wait_for_terminal(&runtime, &delivery, Duration::from_secs(2))?;
        assert_eq!(record.attempts(), 2);
        assert_eq!(
            record.state(),
            DeliveryState::Terminal(DeliveryOutcome::Delivered)
        );
        assert_eq!(
            (0..2)
                .map(|_| sent.recv_timeout(Duration::from_secs(1)))
                .collect::<Result<Vec<_>, _>>()?,
            ["/retry", "/retry"]
        );
        runtime.stop()?;
        Ok(())
    }

    #[test]
    fn disable_drains_and_shutdown_records_unfinished_loss()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sends, _sent) = mpsc::channel();
        let transport = Arc::new(MockTransport::new(Duration::from_millis(50), [], sends));
        let log = Arc::new(InMemoryDeliveryLog::default());
        let mut runtime = start_runtime(
            limits(8, 1, Duration::from_secs(1))?,
            Arc::clone(&log),
            transport,
        )?;
        runtime.register_route(route("drain", RetryPolicy::without_retries())?)?;
        runtime.emit(
            RouteId::new("drain")?,
            DeliveryId::new("drained")?,
            event("drain"),
        )?;
        runtime.disable_route(RouteId::new("drain")?)?;
        assert!(matches!(
            runtime.emit(
                RouteId::new("drain")?,
                DeliveryId::new("after_disable")?,
                event("disabled"),
            ),
            Err(EgressRuntimeError::Admission(
                bondry_egress::AdmissionError::RouteDisabled
            ))
        ));
        runtime.stop()?;

        let (sends, _sent) = mpsc::channel();
        let transport = Arc::new(MockTransport::new(Duration::from_secs(5), [], sends));
        let cancellation_log = Arc::new(InMemoryDeliveryLog::default());
        let mut runtime = start_runtime(
            limits(8, 1, Duration::from_secs(1))?,
            Arc::clone(&cancellation_log),
            transport,
        )?;
        runtime.register_route(route("cancel", RetryPolicy::without_retries())?)?;
        let cancelled = DeliveryId::new("cancelled_on_disable")?;
        runtime.emit(RouteId::new("cancel")?, cancelled.clone(), event("cancel"))?;
        runtime.disable_route(RouteId::new("cancel")?)?;
        let record = runtime
            .delivery(cancelled)?
            .ok_or(std::io::Error::other("cancelled status missing"))?;
        assert_eq!(
            record.state(),
            DeliveryState::Terminal(DeliveryOutcome::Failed(DeliveryFailure::Cancelled))
        );
        runtime.stop()?;

        let (sends, _sent) = mpsc::channel();
        let transport = Arc::new(MockTransport::new(Duration::from_secs(5), [], sends));
        let mut runtime = start_runtime(
            limits(8, 1, Duration::from_secs(1))?,
            Arc::clone(&log),
            transport,
        )?;
        runtime.register_route(route("shutdown", RetryPolicy::without_retries())?)?;
        let delivery = DeliveryId::new("lost_on_shutdown")?;
        runtime.emit(
            RouteId::new("shutdown")?,
            delivery.clone(),
            event("shutdown"),
        )?;
        runtime.stop()?;
        let record = log
            .delivery(&delivery)?
            .ok_or(std::io::Error::other("shutdown status missing"))?;
        assert_eq!(
            record.state(),
            DeliveryState::Terminal(DeliveryOutcome::LostOnShutdown)
        );
        Ok(())
    }

    #[test]
    fn outcome_persistence_failure_stops_admission_and_keeps_local_terminal_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sends, _sent) = mpsc::channel();
        let transport = Arc::new(MockTransport::new(Duration::ZERO, [], sends));
        let log = Arc::new(FailingOutcomeLog {
            inner: InMemoryDeliveryLog::default(),
        });
        let mut runtime = EgressRuntime::start(
            RouteRegistry::default(),
            limits(8, 1, Duration::from_secs(1))?,
            log,
            Arc::new(NoSecrets),
            transport,
        )?;
        runtime.register_route(route("degraded", RetryPolicy::without_retries())?)?;
        let delivery = DeliveryId::new("degraded_terminal")?;
        runtime.emit(
            RouteId::new("degraded")?,
            delivery.clone(),
            event("degraded"),
        )?;
        let record = wait_for_terminal(&runtime, &delivery, Duration::from_secs(1))?;
        assert_eq!(
            record.state(),
            DeliveryState::Terminal(DeliveryOutcome::Delivered)
        );
        assert_eq!(
            runtime.emit(
                RouteId::new("degraded")?,
                DeliveryId::new("rejected_after_degradation")?,
                event("rejected"),
            ),
            Err(EgressRuntimeError::DeliveryLog(
                DeliveryLogError::Unavailable
            ))
        );
        runtime.stop()?;
        Ok(())
    }

    #[test]
    fn call_returns_bounded_result_and_persists_only_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sends, sent) = mpsc::channel();
        let transport = Arc::new(McpTransport::new(Duration::ZERO, sends));
        let log = Arc::new(InMemoryDeliveryLog::default());
        let mut runtime = EgressRuntime::start(
            RouteRegistry::default(),
            limits(8, 1, Duration::from_secs(1))?,
            Arc::clone(&log) as Arc<dyn DeliveryLog>,
            Arc::new(NoSecrets),
            transport,
        )?;
        runtime.register_route(mcp_route("rpc")?)?;
        let rejected = DeliveryId::new("mcp_schema_rejected")?;
        assert!(matches!(
            runtime.call(
                RouteId::new("rpc")?,
                rejected.clone(),
                Bytes::from_static(br#"{"detail":"yes"}"#),
            ),
            Err(EgressRuntimeError::Admission(
                bondry_egress::AdmissionError::Kind(
                    bondry_egress::KindOperationError::InvalidEvent
                )
            ))
        ));
        assert!(log.delivery(&rejected)?.is_none());
        assert!(sent.recv_timeout(Duration::from_millis(50)).is_err());
        let delivery = DeliveryId::new("mcp_call")?;
        let result = runtime.call(RouteId::new("rpc")?, delivery.clone(), mcp_input(true))?;
        assert_eq!(sent.recv_timeout(Duration::from_secs(1))?, "/rpc");
        assert_eq!(result.delivery(), &delivery);
        assert_eq!(
            result.metadata().category(),
            bondry_delivery_store::DeliveryResultCategory::Succeeded
        );
        assert!(!result.json().is_empty());
        assert!(!format!("{result:?}").contains("charging"));

        let record = log
            .delivery(&delivery)?
            .ok_or(std::io::Error::other("call status missing"))?;
        assert_eq!(
            record.state(),
            DeliveryState::Terminal(DeliveryOutcome::Delivered)
        );
        assert_eq!(record.result(), Some(result.metadata()));
        assert!(!format!("{record:?}").contains("charging"));

        runtime.register_route(route("webhook", RetryPolicy::without_retries())?)?;
        assert!(matches!(
            runtime.call(
                RouteId::new("webhook")?,
                DeliveryId::new("unsupported_call")?,
                event("blocked"),
            ),
            Err(EgressRuntimeError::Admission(
                bondry_egress::AdmissionError::UnsupportedOperation
            ))
        ));
        runtime.stop()?;
        Ok(())
    }

    #[test]
    fn route_drain_cancels_active_calls_with_one_terminal_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sends, sent) = mpsc::channel();
        let transport = Arc::new(McpTransport::new(Duration::from_secs(5), sends));
        let log = Arc::new(InMemoryDeliveryLog::default());
        let runtime = Arc::new(EgressRuntime::start(
            RouteRegistry::default(),
            limits(8, 1, Duration::from_secs(1))?,
            log.clone(),
            Arc::new(NoSecrets),
            transport,
        )?);
        runtime.register_route(mcp_route("drain_call")?)?;
        let call_runtime = Arc::clone(&runtime);
        let call = thread::spawn(move || {
            call_runtime.call(
                RouteId::new("drain_call")
                    .unwrap_or_else(|error| unreachable!("valid route: {error}")),
                DeliveryId::new("drained_call")
                    .unwrap_or_else(|error| unreachable!("valid delivery: {error}")),
                mcp_input(true),
            )
        });
        assert_eq!(sent.recv_timeout(Duration::from_secs(1))?, "/drain_call");
        runtime.disable_route(RouteId::new("drain_call")?)?;
        assert_eq!(
            call.join()
                .map_err(|_| std::io::Error::other("call thread panicked"))?,
            Err(EgressRuntimeError::CallFailed(DeliveryFailure::Cancelled))
        );
        let delivery = DeliveryId::new("drained_call")?;
        let record = log
            .delivery(&delivery)?
            .ok_or(std::io::Error::other("cancelled call status missing"))?;
        assert_eq!(
            record.state(),
            DeliveryState::Terminal(DeliveryOutcome::Failed(DeliveryFailure::Cancelled))
        );

        let mut runtime =
            Arc::try_unwrap(runtime).map_err(|_| std::io::Error::other("runtime still shared"))?;
        runtime.stop()?;
        Ok(())
    }

    #[test]
    fn call_lane_rejects_immediately_and_bypasses_emit_backlog()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sends, sent) = mpsc::channel();
        let transport = Arc::new(McpTransport::new(Duration::from_millis(150), sends));
        let runtime = Arc::new(EgressRuntime::start(
            RouteRegistry::default(),
            limits(8, 1, Duration::from_secs(1))?,
            Arc::new(InMemoryDeliveryLog::default()),
            Arc::new(NoSecrets),
            transport,
        )?);
        runtime.register_route(mcp_route("rpc_lane")?)?;
        runtime.register_route(route("slow", RetryPolicy::without_retries())?)?;
        runtime.emit(
            RouteId::new("slow")?,
            DeliveryId::new("slow_first")?,
            event("first"),
        )?;
        runtime.emit(
            RouteId::new("slow")?,
            DeliveryId::new("slow_second")?,
            event("second"),
        )?;
        assert_eq!(sent.recv_timeout(Duration::from_secs(1))?, "/slow");

        let first_runtime = Arc::clone(&runtime);
        let first = thread::spawn(move || {
            first_runtime.call(
                RouteId::new("rpc_lane")
                    .unwrap_or_else(|error| unreachable!("valid route: {error}")),
                DeliveryId::new("lane_first")
                    .unwrap_or_else(|error| unreachable!("valid delivery: {error}")),
                mcp_input(true),
            )
        });
        assert_eq!(sent.recv_timeout(Duration::from_secs(1))?, "/rpc_lane");
        let started = Instant::now();
        assert_eq!(
            runtime.call(
                RouteId::new("rpc_lane")?,
                DeliveryId::new("lane_second")?,
                mcp_input(true),
            ),
            Err(EgressRuntimeError::CallCapacity)
        );
        assert!(started.elapsed() < Duration::from_millis(50));
        let result = first
            .join()
            .map_err(|_| std::io::Error::other("call thread panicked"))??;
        assert!(!result.json().is_empty());

        let mut runtime =
            Arc::try_unwrap(runtime).map_err(|_| std::io::Error::other("runtime still shared"))?;
        runtime.stop()?;
        Ok(())
    }

    #[test]
    fn mcp_emit_does_not_retry_without_explicit_kind_opt_in()
    -> Result<(), Box<dyn std::error::Error>> {
        let (sends, sent) = mpsc::channel();
        let transport = Arc::new(MockTransport::new(
            Duration::ZERO,
            [Err(TransportError::ConnectionFailed)],
            sends,
        ));
        let log = Arc::new(InMemoryDeliveryLog::default());
        let mut runtime = EgressRuntime::start(
            RouteRegistry::default(),
            limits(8, 1, Duration::from_secs(1))?,
            Arc::clone(&log) as Arc<dyn DeliveryLog>,
            Arc::new(NoSecrets),
            transport,
        )?;
        runtime.register_route(mcp_route("no_retry")?)?;
        let delivery = DeliveryId::new("mcp_no_retry")?;
        runtime.emit(
            RouteId::new("no_retry")?,
            delivery.clone(),
            mcp_input(false),
        )?;
        let record = wait_for_terminal(&runtime, &delivery, Duration::from_secs(1))?;
        assert_eq!(record.attempts(), 1);
        assert_eq!(
            record.state(),
            DeliveryState::Terminal(DeliveryOutcome::Failed(
                DeliveryFailure::TransportUnavailable
            ))
        );
        assert_eq!(sent.recv_timeout(Duration::from_secs(1))?, "/no_retry");
        assert!(sent.recv_timeout(Duration::from_millis(50)).is_err());
        runtime.stop()?;
        Ok(())
    }
}
