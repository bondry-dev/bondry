use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{Arc, Condvar, Mutex, Weak},
    time::{Duration, Instant},
};

use http::{HeaderName, Method, StatusCode, uri::PathAndQuery};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

use crate::rate_limit::{RateLimitDecision, SlidingWindow};

const MAX_RAW_BODY_BYTES: usize = 4 * 1_024 * 1_024;
const MIN_RAW_BODY_BYTES: usize = 1_024;
const MAX_REQUEST_RETAINED_BYTES: usize = 10 * 1_024 * 1_024;
const MAX_RETAINED_BYTES: usize = 32 * 1_024 * 1_024;
const MIN_RETAINED_BYTES: usize = 1_024 * 1_024;
pub(crate) const MAX_SELECTED_HEADERS: usize = 32;
const MAX_SELECTED_HEADER_BYTES: usize = 8 * 1_024;
const MAX_SELECTED_HEADERS_BYTES: usize = 64 * 1_024;
const MAX_PRE_AUTHENTICATION_PEER_RATE: u32 = 600;
const MAX_PRE_AUTHENTICATION_ROUTE_RATE: u32 = 1_200;
const MAX_REGISTERED_HANDLERS: usize = 16;
const MAX_DRAIN_DEADLINE: Duration = Duration::from_secs(60);
const MIN_DRAIN_DEADLINE: Duration = Duration::from_secs(1);

/// Server-wide resource limits for raw-body handlers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawBodyServerLimits {
    aggregate_retained_bytes: usize,
    shutdown_drain_deadline: Duration,
}

impl RawBodyServerLimits {
    /// Creates limits within the accepted ingress ranges.
    pub fn new(
        aggregate_retained_bytes: usize,
        shutdown_drain_deadline: Duration,
    ) -> Result<Self, RawBodyRouteError> {
        if !(MIN_RETAINED_BYTES..=MAX_RETAINED_BYTES).contains(&aggregate_retained_bytes) {
            return Err(RawBodyRouteError::InvalidAggregateRetainedBytes);
        }
        if shutdown_drain_deadline < MIN_DRAIN_DEADLINE
            || shutdown_drain_deadline > MAX_DRAIN_DEADLINE
        {
            return Err(RawBodyRouteError::InvalidDrainDeadline);
        }
        Ok(Self {
            aggregate_retained_bytes,
            shutdown_drain_deadline,
        })
    }

    pub(crate) const fn aggregate_retained_bytes(self) -> usize {
        self.aggregate_retained_bytes
    }

    pub(crate) const fn shutdown_drain_deadline(self) -> Duration {
        self.shutdown_drain_deadline
    }
}

impl Default for RawBodyServerLimits {
    fn default() -> Self {
        Self {
            aggregate_retained_bytes: 8 * 1_024 * 1_024,
            shutdown_drain_deadline: Duration::from_secs(10),
        }
    }
}

/// Per-route limits enforced before or during raw-body collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawBodyHandlerLimits {
    body_bytes: usize,
    retained_bytes: usize,
    selected_header_bytes: usize,
    selected_headers_bytes: usize,
    pre_authentication_requests_per_peer_minute: u32,
    pre_authentication_requests_per_route_minute: u32,
}

impl RawBodyHandlerLimits {
    /// Creates one complete route limit set.
    pub const fn new(
        body_bytes: usize,
        retained_bytes: usize,
        selected_header_bytes: usize,
        selected_headers_bytes: usize,
        pre_authentication_requests_per_peer_minute: u32,
        pre_authentication_requests_per_route_minute: u32,
    ) -> Result<Self, RawBodyRouteError> {
        if body_bytes < MIN_RAW_BODY_BYTES || body_bytes > MAX_RAW_BODY_BYTES {
            return Err(RawBodyRouteError::InvalidBodyLimit);
        }
        if retained_bytes < body_bytes || retained_bytes > MAX_REQUEST_RETAINED_BYTES {
            return Err(RawBodyRouteError::InvalidRetainedBytes);
        }
        if selected_header_bytes == 0 || selected_header_bytes > MAX_SELECTED_HEADER_BYTES {
            return Err(RawBodyRouteError::InvalidSelectedHeaderLimit);
        }
        if selected_headers_bytes == 0 || selected_headers_bytes > MAX_SELECTED_HEADERS_BYTES {
            return Err(RawBodyRouteError::InvalidSelectedHeadersLimit);
        }
        if pre_authentication_requests_per_peer_minute == 0
            || pre_authentication_requests_per_peer_minute > MAX_PRE_AUTHENTICATION_PEER_RATE
        {
            return Err(RawBodyRouteError::InvalidPeerRateLimit);
        }
        if pre_authentication_requests_per_route_minute == 0
            || pre_authentication_requests_per_route_minute > MAX_PRE_AUTHENTICATION_ROUTE_RATE
        {
            return Err(RawBodyRouteError::InvalidRouteRateLimit);
        }
        Ok(Self {
            body_bytes,
            retained_bytes,
            selected_header_bytes,
            selected_headers_bytes,
            pre_authentication_requests_per_peer_minute,
            pre_authentication_requests_per_route_minute,
        })
    }

    pub(crate) const fn body_bytes(self) -> usize {
        self.body_bytes
    }

    pub(crate) const fn retained_bytes(self) -> usize {
        self.retained_bytes
    }

    pub(crate) const fn selected_header_bytes(self) -> usize {
        self.selected_header_bytes
    }

    pub(crate) const fn selected_headers_bytes(self) -> usize {
        self.selected_headers_bytes
    }

    pub(crate) const fn peer_rate(self) -> u32 {
        self.pre_authentication_requests_per_peer_minute
    }

    pub(crate) const fn route_rate(self) -> u32 {
        self.pre_authentication_requests_per_route_minute
    }
}

impl Default for RawBodyHandlerLimits {
    fn default() -> Self {
        Self {
            body_bytes: 1_048_576,
            retained_bytes: 3 * 1_048_576,
            selected_header_bytes: 2 * 1_024,
            selected_headers_bytes: 32 * 1_024,
            pre_authentication_requests_per_peer_minute: 60,
            pre_authentication_requests_per_route_minute: 120,
        }
    }
}

/// Exact metadata route for one raw-body handler generation.
#[derive(Clone, Debug)]
pub struct RawBodyRoute {
    path: Arc<str>,
    selected_headers: Arc<[HeaderName]>,
    limits: RawBodyHandlerLimits,
}

impl RawBodyRoute {
    /// Creates one exact POST route and validates its selected-header allowlist.
    pub fn post(
        path: impl Into<String>,
        selected_headers: impl IntoIterator<Item = HeaderName>,
        limits: RawBodyHandlerLimits,
    ) -> Result<Self, RawBodyRouteError> {
        let path = path.into();
        let parsed = PathAndQuery::from_str(&path).map_err(|_| RawBodyRouteError::InvalidPath)?;
        if path.len() <= 1 || parsed.query().is_some() || parsed.path() != path {
            return Err(RawBodyRouteError::InvalidPath);
        }
        let selected_headers = selected_headers.into_iter().collect::<Vec<_>>();
        if selected_headers.len() > MAX_SELECTED_HEADERS {
            return Err(RawBodyRouteError::TooManySelectedHeaders);
        }
        let mut unique = HashSet::with_capacity(selected_headers.len());
        if selected_headers
            .iter()
            .any(|header| !unique.insert(header.clone()))
        {
            return Err(RawBodyRouteError::DuplicateSelectedHeader);
        }
        Ok(Self {
            path: Arc::from(path),
            selected_headers: selected_headers.into(),
            limits,
        })
    }

    /// Returns the exact registered path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the route limits.
    #[must_use]
    pub const fn limits(&self) -> RawBodyHandlerLimits {
        self.limits
    }

    pub(crate) fn selected_headers(&self) -> &[HeaderName] {
        &self.selected_headers
    }
}

/// One selected request header borrowed only for a handler invocation.
#[derive(Clone)]
pub struct RawBodyHeader<'a> {
    name: HeaderName,
    value: &'a [u8],
}

impl<'a> RawBodyHeader<'a> {
    pub(crate) fn new(name: &HeaderName, value: &'a [u8]) -> Self {
        Self {
            name: name.clone(),
            value,
        }
    }

    /// Returns the normalized header name.
    #[must_use]
    pub const fn name(&self) -> &HeaderName {
        &self.name
    }

    /// Returns the exact header value bytes.
    #[must_use]
    pub const fn value(&self) -> &'a [u8] {
        self.value
    }
}

/// A bounded request whose borrowed fields are valid only during `handle`.
pub struct RawBodyRequest<'a> {
    target: &'a str,
    headers: &'a [RawBodyHeader<'a>],
    body: &'a [u8],
    peer: SocketAddr,
}

impl<'a> RawBodyRequest<'a> {
    pub(crate) const fn new(
        target: &'a str,
        headers: &'a [RawBodyHeader<'a>],
        body: &'a [u8],
        peer: SocketAddr,
    ) -> Self {
        Self {
            target,
            headers,
            body,
            peer,
        }
    }

    /// Returns the parsed request target without normalization by Bondry.
    #[must_use]
    pub const fn target(&self) -> &'a str {
        self.target
    }

    /// Returns only the registered selected headers, preserving duplicates.
    #[must_use]
    pub const fn headers(&self) -> &'a [RawBodyHeader<'a>] {
        self.headers
    }

    /// Returns the exact bounded request body bytes.
    #[must_use]
    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    /// Returns the connected peer address.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }
}

/// A validated status-only response from a raw-body handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawBodyResponse {
    status: StatusCode,
    retry_after_seconds: Option<u64>,
    error_code: Option<Arc<str>>,
}

impl RawBodyResponse {
    /// Creates a non-informational response with an optional retry delay.
    pub fn new(
        status: StatusCode,
        retry_after_seconds: Option<u64>,
    ) -> Result<Self, RawBodyRouteError> {
        if status.is_informational() || status == StatusCode::SWITCHING_PROTOCOLS {
            return Err(RawBodyRouteError::InvalidResponse);
        }
        if retry_after_seconds == Some(0) {
            return Err(RawBodyRouteError::InvalidResponse);
        }
        Ok(Self {
            status,
            retry_after_seconds,
            error_code: None,
        })
    }

    /// Adds one bounded stable error code for server-owned JSON serialization.
    pub fn with_error_code(
        mut self,
        error_code: impl Into<Arc<str>>,
    ) -> Result<Self, RawBodyRouteError> {
        let error_code = error_code.into();
        if self.status.is_success()
            || error_code.is_empty()
            || error_code.len() > 128
            || !error_code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(RawBodyRouteError::InvalidResponse);
        }
        self.error_code = Some(error_code);
        Ok(self)
    }

    /// Returns a successful empty response.
    #[must_use]
    pub const fn no_content() -> Self {
        Self {
            status: StatusCode::NO_CONTENT,
            retry_after_seconds: None,
            error_code: None,
        }
    }

    /// Returns a safe empty response for an invalid or failed foreign handler.
    #[must_use]
    pub fn internal_server_error() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            retry_after_seconds: None,
            error_code: Some(Arc::from("raw_body_handler_failed")),
        }
    }

    pub(crate) const fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) const fn retry_after_seconds(&self) -> Option<u64> {
        self.retry_after_seconds
    }

    pub(crate) fn error_code(&self) -> Option<&str> {
        self.error_code.as_deref()
    }
}

/// Completes one accepted raw-body request exactly once.
pub struct RawBodyCompletion {
    state: Arc<CompletionState>,
}

impl RawBodyCompletion {
    /// Completes the request. Repeated completion attempts are impossible without violating
    /// ownership.
    pub fn complete(self, response: RawBodyResponse) {
        if let Some(sender) = lock(&self.state.sender).take() {
            let _ = sender.send(response);
        }
    }
}

/// Synchronous entry point for a handler that may move completion to asynchronous work.
pub trait RawBodyHandler: Send + Sync {
    /// Borrows the request only for this call and transfers one completion ownership unit.
    fn handle(&self, request: RawBodyRequest<'_>, completion: RawBodyCompletion);
}

/// Lifecycle state of one immutable handler generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawBodyLifecycle {
    /// New requests may enter the generation.
    Enabled,
    /// Admission is closed while accepted requests complete.
    Draining,
    /// The handler context has been detached and released.
    Detached,
}

/// Handle for disabling and observing one raw-body handler generation.
pub struct RawBodyRegistration {
    generation: Arc<Generation>,
}

impl RawBodyRegistration {
    /// Atomically closes admission and waits up to the supplied deadline for detachment.
    pub fn disable(&self, deadline: Duration) -> Result<(), RawBodyRegistrationError> {
        if deadline < MIN_DRAIN_DEADLINE || deadline > MAX_DRAIN_DEADLINE {
            return Err(RawBodyRegistrationError::InvalidDrainDeadline);
        }
        self.generation.begin_draining();
        if self.generation.wait_detached(deadline) {
            Ok(())
        } else {
            Err(RawBodyRegistrationError::DrainTimedOut)
        }
    }

    /// Returns the current generation lifecycle.
    #[must_use]
    pub fn lifecycle(&self) -> RawBodyLifecycle {
        self.generation.lifecycle()
    }
}

impl Drop for RawBodyRegistration {
    fn drop(&mut self) {
        self.generation.begin_draining();
    }
}

pub(crate) struct RawBodyRegistry {
    inner: Arc<RegistryInner>,
}

impl RawBodyRegistry {
    pub(crate) fn new(limits: RawBodyServerLimits) -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                state: Mutex::new(RegistryState::default()),
                retained_bytes: Arc::new(Semaphore::new(limits.aggregate_retained_bytes())),
                peer_limits: SlidingWindow::new(),
                route_limits: SlidingWindow::new(),
                limits,
            }),
        }
    }

    pub(crate) fn register(
        &self,
        route: RawBodyRoute,
        handler: Arc<dyn RawBodyHandler>,
    ) -> Result<RawBodyRegistration, RawBodyRegistrationError> {
        if route.limits.retained_bytes() > self.inner.limits.aggregate_retained_bytes() {
            return Err(RawBodyRegistrationError::BodyLimitExceedsAggregate);
        }
        let mut state = lock(&self.inner.state);
        if state.stopping {
            return Err(RawBodyRegistrationError::ServerStopping);
        }
        if let Some(existing) = state.routes.get(&route.path) {
            if existing.lifecycle() != RawBodyLifecycle::Detached {
                return Err(RawBodyRegistrationError::AlreadyRegistered);
            }
        }
        state
            .routes
            .retain(|_, generation| generation.lifecycle() != RawBodyLifecycle::Detached);
        if state.routes.len() >= MAX_REGISTERED_HANDLERS {
            return Err(RawBodyRegistrationError::CapacityExhausted);
        }
        let path = Arc::clone(&route.path);
        let registry = Arc::downgrade(&self.inner);
        let generation = Arc::new(Generation {
            path: Arc::clone(&path),
            registry,
            state: Mutex::new(GenerationState {
                lifecycle: RawBodyLifecycle::Enabled,
                active_requests: 0,
                handler: Some(handler),
            }),
            detached: Condvar::new(),
            route,
        });
        state.routes.insert(path, Arc::clone(&generation));
        Ok(RawBodyRegistration { generation })
    }

    pub(crate) fn match_request(&self, method: &Method, path: &str) -> RawBodyMatch {
        if method != Method::POST {
            return RawBodyMatch::NotRegistered;
        }
        let generation = lock(&self.inner.state).routes.get(path).cloned();
        let Some(generation) = generation else {
            return RawBodyMatch::NotRegistered;
        };
        generation.accept().map_or(RawBodyMatch::Closed, |request| {
            RawBodyMatch::Accepted(AcceptedRawBodyRequest { request })
        })
    }

    pub(crate) fn admit(
        &self,
        request: &AcceptedRawBodyRequest,
        peer: IpAddr,
        now: Instant,
    ) -> RateLimitDecision {
        let limits = request.route().limits;
        let peer_decision = self
            .inner
            .peer_limits
            .consume(peer, limits.peer_rate(), now);
        if peer_decision != RateLimitDecision::Allowed {
            return peer_decision;
        }
        self.inner
            .route_limits
            .consume(Arc::clone(&request.route().path), limits.route_rate(), now)
    }

    pub(crate) fn retained_bytes(&self) -> Arc<Semaphore> {
        Arc::clone(&self.inner.retained_bytes)
    }

    pub(crate) fn begin_shutdown(&self) {
        let generations = {
            let mut state = lock(&self.inner.state);
            state.stopping = true;
            state.routes.values().cloned().collect::<Vec<_>>()
        };
        for generation in generations {
            generation.begin_draining();
        }
    }

    pub(crate) async fn wait_for_shutdown(&self) -> bool {
        let generations = lock(&self.inner.state)
            .routes
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let drain_deadline = self.inner.limits.shutdown_drain_deadline();
        (tokio::task::spawn_blocking(move || {
            let deadline = Instant::now() + drain_deadline;
            generations.into_iter().all(|generation| {
                let remaining = deadline.saturating_duration_since(Instant::now());
                !remaining.is_zero() && generation.wait_detached(remaining)
            })
        })
        .await)
            .unwrap_or_default()
    }
}

pub(crate) enum RawBodyMatch {
    NotRegistered,
    Closed,
    Accepted(AcceptedRawBodyRequest),
}

pub(crate) struct AcceptedRawBodyRequest {
    request: ActiveRequest,
}

impl AcceptedRawBodyRequest {
    pub(crate) fn route(&self) -> &RawBodyRoute {
        &self.request.generation.route
    }

    pub(crate) fn invocation(
        self,
        retained_bytes: Vec<OwnedSemaphorePermit>,
    ) -> (
        RawBodyInvocation,
        RawBodyCompletion,
        oneshot::Receiver<RawBodyResponse>,
    ) {
        let (sender, receiver) = oneshot::channel();
        let state = Arc::new(CompletionState {
            sender: Mutex::new(Some(sender)),
            _request: self.request,
            _retained_bytes: retained_bytes,
        });
        (
            RawBodyInvocation {
                state: Arc::clone(&state),
            },
            RawBodyCompletion {
                state: Arc::clone(&state),
            },
            receiver,
        )
    }
}

pub(crate) struct RawBodyInvocation {
    state: Arc<CompletionState>,
}

impl RawBodyInvocation {
    pub(crate) fn invoke(&self, request: RawBodyRequest<'_>, completion: RawBodyCompletion) {
        if let Some(handler) = &self.state._request.handler {
            handler.handle(request, completion);
        }
    }
}

struct RegistryInner {
    state: Mutex<RegistryState>,
    retained_bytes: Arc<Semaphore>,
    peer_limits: SlidingWindow<IpAddr>,
    route_limits: SlidingWindow<Arc<str>>,
    limits: RawBodyServerLimits,
}

#[derive(Default)]
struct RegistryState {
    routes: HashMap<Arc<str>, Arc<Generation>>,
    stopping: bool,
}

struct Generation {
    path: Arc<str>,
    registry: Weak<RegistryInner>,
    state: Mutex<GenerationState>,
    detached: Condvar,
    route: RawBodyRoute,
}

impl Generation {
    fn accept(self: &Arc<Self>) -> Option<ActiveRequest> {
        let mut state = lock(&self.state);
        if state.lifecycle != RawBodyLifecycle::Enabled {
            return None;
        }
        let handler = Arc::clone(state.handler.as_ref()?);
        state.active_requests = state.active_requests.checked_add(1)?;
        Some(ActiveRequest {
            generation: Arc::clone(self),
            handler: Some(handler),
        })
    }

    fn begin_draining(self: &Arc<Self>) {
        let handler = {
            let mut state = lock(&self.state);
            if state.lifecycle == RawBodyLifecycle::Enabled {
                state.lifecycle = RawBodyLifecycle::Draining;
            }
            detach_if_idle(&mut state)
        };
        if let Some(handler) = handler {
            self.finish_detachment(handler);
        }
    }

    fn finish_request(self: &Arc<Self>) {
        let handler = {
            let mut state = lock(&self.state);
            state.active_requests = state.active_requests.saturating_sub(1);
            detach_if_idle(&mut state)
        };
        if let Some(handler) = handler {
            self.finish_detachment(handler);
        }
    }

    fn finish_detachment(&self, handler: Arc<dyn RawBodyHandler>) {
        drop(handler);
        if let Some(registry) = self.registry.upgrade() {
            let mut registry_state = lock(&registry.state);
            let mut generation_state = lock(&self.state);
            if registry_state
                .routes
                .get(&self.path)
                .is_some_and(|registered| std::ptr::eq(Arc::as_ptr(registered), self))
            {
                registry_state.routes.remove(&self.path);
            }
            generation_state.lifecycle = RawBodyLifecycle::Detached;
        } else {
            lock(&self.state).lifecycle = RawBodyLifecycle::Detached;
        }
        self.detached.notify_all();
    }

    fn wait_detached(&self, deadline: Duration) -> bool {
        let state = lock(&self.state);
        if state.lifecycle == RawBodyLifecycle::Detached {
            return true;
        }
        let (state, _) = match self.detached.wait_timeout_while(state, deadline, |state| {
            state.lifecycle != RawBodyLifecycle::Detached
        }) {
            Ok(result) => result,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.lifecycle == RawBodyLifecycle::Detached
    }

    fn lifecycle(&self) -> RawBodyLifecycle {
        lock(&self.state).lifecycle
    }
}

struct GenerationState {
    lifecycle: RawBodyLifecycle,
    active_requests: usize,
    handler: Option<Arc<dyn RawBodyHandler>>,
}

fn detach_if_idle(state: &mut GenerationState) -> Option<Arc<dyn RawBodyHandler>> {
    if state.lifecycle == RawBodyLifecycle::Draining && state.active_requests == 0 {
        return state.handler.take();
    }
    None
}

struct ActiveRequest {
    generation: Arc<Generation>,
    handler: Option<Arc<dyn RawBodyHandler>>,
}

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        drop(self.handler.take());
        self.generation.finish_request();
    }
}

struct CompletionState {
    sender: Mutex<Option<oneshot::Sender<RawBodyResponse>>>,
    _request: ActiveRequest,
    _retained_bytes: Vec<OwnedSemaphorePermit>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Invalid raw-body route configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RawBodyRouteError {
    /// The raw body limit is outside one KiB through four MiB.
    #[error("raw body limit is outside the accepted range")]
    InvalidBodyLimit,
    /// The request lifecycle budget is smaller than the body or larger than ten MiB.
    #[error("request retained-byte limit is outside the accepted range")]
    InvalidRetainedBytes,
    /// The aggregate retained-byte limit is outside one through 32 MiB.
    #[error("aggregate retained-byte limit is outside the accepted range")]
    InvalidAggregateRetainedBytes,
    /// The drain deadline is outside one through 60 seconds.
    #[error("handler drain deadline is outside the accepted range")]
    InvalidDrainDeadline,
    /// A selected header value limit is invalid.
    #[error("selected header value limit is outside the accepted range")]
    InvalidSelectedHeaderLimit,
    /// The aggregate selected-header limit is invalid.
    #[error("selected header aggregate limit is outside the accepted range")]
    InvalidSelectedHeadersLimit,
    /// The pre-authentication peer rate is invalid.
    #[error("pre-authentication peer rate is outside the accepted range")]
    InvalidPeerRateLimit,
    /// The pre-authentication route rate is invalid.
    #[error("pre-authentication route rate is outside the accepted range")]
    InvalidRouteRateLimit,
    /// The route path is not one exact absolute path.
    #[error("raw-body handler path must be one exact absolute path")]
    InvalidPath,
    /// The route selects more than 32 header names.
    #[error("raw-body handler selects too many headers")]
    TooManySelectedHeaders,
    /// A selected header name appears more than once.
    #[error("raw-body handler selects a duplicate header")]
    DuplicateSelectedHeader,
    /// The response status or retry delay is invalid.
    #[error("raw-body handler response is invalid")]
    InvalidResponse,
}

/// Raw-body registration or drain failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RawBodyRegistrationError {
    /// The route is already owned by an enabled or draining generation.
    #[error("raw-body handler route is already registered")]
    AlreadyRegistered,
    /// All 16 raw-body handler slots are occupied.
    #[error("raw-body handler capacity is exhausted")]
    CapacityExhausted,
    /// The server has begun shutdown and rejects new generations.
    #[error("server is stopping")]
    ServerStopping,
    /// A route cannot admit a body larger than the server aggregate budget.
    #[error("raw-body route limit exceeds the aggregate retained-byte budget")]
    BodyLimitExceedsAggregate,
    /// The requested drain deadline is invalid.
    #[error("handler drain deadline is outside the accepted range")]
    InvalidDrainDeadline,
    /// The entry is closed but accepted work has not completed by the deadline.
    #[error("raw-body handler drain timed out")]
    DrainTimedOut,
    /// The route overlaps a built-in REST or MCP path.
    #[error("raw-body handler route conflicts with a built-in protocol")]
    ProtocolConflict,
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::Duration,
    };

    use http::{HeaderName, StatusCode};

    use super::{
        RawBodyHandler, RawBodyHandlerLimits, RawBodyLifecycle, RawBodyRegistrationError,
        RawBodyRegistry, RawBodyRequest, RawBodyResponse, RawBodyRoute, RawBodyServerLimits,
    };

    struct DeferredHandler {
        completion: Mutex<Option<super::RawBodyCompletion>>,
        releases: Arc<AtomicUsize>,
    }

    impl RawBodyHandler for DeferredHandler {
        fn handle(&self, _request: RawBodyRequest<'_>, completion: super::RawBodyCompletion) {
            *super::lock(&self.completion) = Some(completion);
        }
    }

    impl Drop for DeferredHandler {
        fn drop(&mut self) {
            self.releases.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct BlockingDropHandler {
        release_started: mpsc::SyncSender<()>,
        release_continue: Mutex<mpsc::Receiver<()>>,
    }

    impl RawBodyHandler for BlockingDropHandler {
        fn handle(&self, _request: RawBodyRequest<'_>, completion: super::RawBodyCompletion) {
            completion.complete(RawBodyResponse::no_content());
        }
    }

    impl Drop for BlockingDropHandler {
        fn drop(&mut self) {
            let _ = self.release_started.send(());
            if let Ok(receiver) = self.release_continue.lock() {
                let _ = receiver.recv();
            }
        }
    }

    #[test]
    fn validates_route_and_server_limit_boundaries() {
        assert!(RawBodyServerLimits::new(1_048_576, Duration::from_secs(1)).is_ok());
        assert!(RawBodyServerLimits::new(1_048_575, Duration::from_secs(1)).is_err());
        assert!(RawBodyHandlerLimits::new(1_024, 1_024, 1, 1, 1, 1).is_ok());
        assert!(RawBodyHandlerLimits::new(1_023, 1_024, 1, 1, 1, 1).is_err());
        assert!(RawBodyHandlerLimits::new(1_024, 1_023, 1, 1, 1, 1).is_err());
        assert!(RawBodyRoute::post("/hook", [], RawBodyHandlerLimits::default()).is_ok());
        assert!(RawBodyRoute::post("/hook?query", [], RawBodyHandlerLimits::default()).is_err());
        assert!(
            RawBodyRoute::post(
                "/hook",
                [
                    HeaderName::from_static("x-signature"),
                    HeaderName::from_static("x-signature")
                ],
                RawBodyHandlerLimits::default(),
            )
            .is_err()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn draining_closes_admission_and_releases_after_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = RawBodyRegistry::new(RawBodyServerLimits::default());
        let releases = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(DeferredHandler {
            completion: Mutex::new(None),
            releases: Arc::clone(&releases),
        });
        let registration = registry.register(
            RawBodyRoute::post("/hook", [], RawBodyHandlerLimits::default())?,
            handler.clone(),
        )?;
        let request = match registry.match_request(&http::Method::POST, "/hook") {
            super::RawBodyMatch::Accepted(request) => request,
            _ => return Err(std::io::Error::other("route is not enabled").into()),
        };
        let (invocation, completion, receiver) = request.invocation(Vec::new());
        invocation.invoke(
            RawBodyRequest::new("/hook", &[], b"{}", "127.0.0.1:1".parse()?),
            completion,
        );
        drop(invocation);
        registration.generation.begin_draining();
        assert!(
            !registration
                .generation
                .wait_detached(Duration::from_millis(1))
        );
        assert_eq!(registration.lifecycle(), RawBodyLifecycle::Draining);
        assert!(matches!(
            registry.match_request(&http::Method::POST, "/hook"),
            super::RawBodyMatch::Closed
        ));
        let completion = super::lock(&handler.completion)
            .take()
            .ok_or_else(|| std::io::Error::other("handler did not retain completion"))?;
        completion.complete(RawBodyResponse::no_content());
        assert_eq!(receiver.await, Ok(RawBodyResponse::no_content()));
        assert!(registration.disable(Duration::from_secs(1)).is_ok());
        drop(handler);
        assert_eq!(releases.load(Ordering::SeqCst), 1);
        assert!(matches!(
            registry.match_request(&http::Method::POST, "/hook"),
            super::RawBodyMatch::NotRegistered
        ));
        assert!(RawBodyResponse::new(StatusCode::CONTINUE, None).is_err());
        assert_eq!(
            registration.disable(Duration::from_millis(1)),
            Err(RawBodyRegistrationError::InvalidDrainDeadline)
        );
        Ok(())
    }

    #[test]
    fn publishes_detached_only_after_handler_release_returns()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = Arc::new(RawBodyRegistry::new(RawBodyServerLimits::default()));
        let (release_started_sender, release_started_receiver) = mpsc::sync_channel(1);
        let (release_continue_sender, release_continue_receiver) = mpsc::sync_channel(1);
        let registration = Arc::new(registry.register(
            RawBodyRoute::post("/hook", [], RawBodyHandlerLimits::default())?,
            Arc::new(BlockingDropHandler {
                release_started: release_started_sender,
                release_continue: Mutex::new(release_continue_receiver),
            }),
        )?);
        let disabling = Arc::clone(&registration);
        let disable_thread = thread::spawn(move || disabling.disable(Duration::from_secs(1)));
        release_started_receiver.recv_timeout(Duration::from_secs(1))?;

        assert_eq!(registration.lifecycle(), RawBodyLifecycle::Draining);
        assert!(matches!(
            registry.match_request(&http::Method::POST, "/hook"),
            super::RawBodyMatch::Closed
        ));
        let releases = Arc::new(AtomicUsize::new(0));
        let replacement = registry.register(
            RawBodyRoute::post("/hook", [], RawBodyHandlerLimits::default())?,
            Arc::new(DeferredHandler {
                completion: Mutex::new(None),
                releases,
            }),
        );
        assert!(matches!(
            replacement,
            Err(RawBodyRegistrationError::AlreadyRegistered)
        ));

        release_continue_sender.send(())?;
        disable_thread
            .join()
            .map_err(|_| std::io::Error::other("disable thread panicked"))??;
        assert_eq!(registration.lifecycle(), RawBodyLifecycle::Detached);
        Ok(())
    }
}
