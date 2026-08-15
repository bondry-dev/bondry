use std::{collections::BTreeMap, fmt, sync::Arc};

use bondry_delivery_store::{DeliveryId, DeliveryIntent, RouteId};
use bytes::Bytes;
use thiserror::Error;

use crate::{
    DeliveryKind, DeliveryPersistenceAction, EgressInstant, EventPayload, GlobalAdmissionLimit,
    KindOperationError, OperationMode, PayloadContract, PayloadError, RequestTimeout, RetryPolicy,
    RouteAdmissionLimit, RouteRegistryLimit,
};

/// Trusted local route configuration.
pub struct Route {
    id: RouteId,
    enabled: bool,
    payload: PayloadContract,
    timeout: RequestTimeout,
    retry: RetryPolicy,
    admission: RouteAdmissionLimit,
    kind: Arc<dyn DeliveryKind>,
}

impl Route {
    /// Creates a route from already validated policy and kind configuration.
    #[must_use]
    pub fn new(
        id: RouteId,
        enabled: bool,
        payload: PayloadContract,
        timeout: RequestTimeout,
        retry: RetryPolicy,
        admission: RouteAdmissionLimit,
        kind: Arc<dyn DeliveryKind>,
    ) -> Self {
        Self {
            id,
            enabled,
            payload,
            timeout,
            retry,
            admission,
            kind,
        }
    }

    /// Returns the stable route identifier.
    #[must_use]
    pub const fn id(&self) -> &RouteId {
        &self.id
    }
}

impl fmt::Debug for Route {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Route")
            .field("id", &self.id)
            .field("enabled", &self.enabled)
            .field("payload", &self.payload)
            .field("timeout", &self.timeout)
            .field("retry", &self.retry)
            .field("admission", &self.admission)
            .field("kind", &self.kind.name())
            .field("target", &self.kind.target_summary())
            .finish()
    }
}

/// Inspectable route state returned without secret material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteSummary {
    id: RouteId,
    enabled: bool,
    kind: &'static str,
    target: Arc<str>,
}

impl RouteSummary {
    /// Returns the route identifier.
    #[must_use]
    pub const fn id(&self) -> &RouteId {
        &self.id
    }

    /// Returns whether new operations may be admitted.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the stable delivery-kind name.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        self.kind
    }

    /// Returns the configured redacted target.
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }
}

struct RouteEntry {
    route: Route,
    admission: TokenBucket,
}

/// Process-local route registry and pure admission state.
pub struct RouteRegistry {
    limit: RouteRegistryLimit,
    global_admission: TokenBucket,
    routes: BTreeMap<RouteId, RouteEntry>,
}

impl RouteRegistry {
    /// Creates an empty bounded registry.
    #[must_use]
    pub fn new(limit: RouteRegistryLimit, global_admission: GlobalAdmissionLimit) -> Self {
        Self {
            limit,
            global_admission: TokenBucket::new(
                global_admission.refill_per_second(),
                global_admission.capacity(),
            ),
            routes: BTreeMap::new(),
        }
    }

    /// Registers one route without starting tasks or performing I/O.
    pub fn register(&mut self, route: Route) -> Result<(), RouteRegistryError> {
        if self.routes.contains_key(route.id()) {
            return Err(RouteRegistryError::AlreadyExists);
        }
        if self.routes.len() >= usize::from(self.limit.get()) {
            return Err(RouteRegistryError::CapacityExhausted);
        }
        if route.payload.limit().get() > route.kind.max_payload_bytes() {
            return Err(RouteRegistryError::PayloadLimitUnsupported);
        }
        let admission = TokenBucket::new(
            route.admission.refill_per_second(),
            route.admission.capacity(),
        );
        self.routes
            .insert(route.id.clone(), RouteEntry { route, admission });
        Ok(())
    }

    /// Atomically opens or closes admission for one route.
    pub fn set_enabled(&mut self, id: &RouteId, enabled: bool) -> Result<(), RouteRegistryError> {
        let route = self
            .routes
            .get_mut(id)
            .ok_or(RouteRegistryError::NotFound)?;
        route.route.enabled = enabled;
        Ok(())
    }

    /// Removes a fully drained route.
    pub fn unregister(&mut self, id: &RouteId) -> bool {
        self.routes.remove(id).is_some()
    }

    /// Returns route summaries in stable identifier order.
    #[must_use]
    pub fn routes(&self) -> Vec<RouteSummary> {
        self.routes
            .values()
            .map(|entry| entry.route.summary())
            .collect()
    }

    /// Validates and admits a one-way event.
    pub fn admit_emit(
        &mut self,
        route: &RouteId,
        delivery: DeliveryId,
        payload: Bytes,
        now: EgressInstant,
    ) -> Result<AdmittedDelivery, AdmissionError> {
        self.admit(route, delivery, payload, OperationMode::Emit, now)
    }

    /// Validates and admits an RPC-style call only for a supporting kind.
    pub fn admit_call(
        &mut self,
        route: &RouteId,
        delivery: DeliveryId,
        payload: Bytes,
        now: EgressInstant,
    ) -> Result<AdmittedDelivery, AdmissionError> {
        self.admit(route, delivery, payload, OperationMode::Call, now)
    }

    /// Validates call routing before an independent runtime lane capacity check.
    pub fn validate_call_route(&self, route: &RouteId) -> Result<(), AdmissionError> {
        let entry = self
            .routes
            .get(route)
            .ok_or(AdmissionError::RouteNotFound)?;
        if !entry.route.enabled {
            return Err(AdmissionError::RouteDisabled);
        }
        if !entry.route.kind.supports_call() {
            return Err(AdmissionError::UnsupportedOperation);
        }
        Ok(())
    }

    fn admit(
        &mut self,
        route: &RouteId,
        delivery: DeliveryId,
        payload: Bytes,
        mode: OperationMode,
        now: EgressInstant,
    ) -> Result<AdmittedDelivery, AdmissionError> {
        let entry = self
            .routes
            .get_mut(route)
            .ok_or(AdmissionError::RouteNotFound)?;
        if !entry.route.enabled {
            return Err(AdmissionError::RouteDisabled);
        }
        if mode == OperationMode::Call && !entry.route.kind.supports_call() {
            return Err(AdmissionError::UnsupportedOperation);
        }
        let payload = entry.route.payload.validate(payload)?;
        entry.route.kind.validate_payload(mode, &payload)?;
        if mode == OperationMode::Emit {
            self.global_admission.refill(now);
            entry.admission.refill(now);
            if !self.global_admission.has_token() {
                return Err(AdmissionError::GlobalRateLimited);
            }
            if !entry.admission.has_token() {
                return Err(AdmissionError::RouteRateLimited);
            }
            self.global_admission.take();
            entry.admission.take();
        }
        Ok(AdmittedDelivery {
            route: route.clone(),
            delivery,
            mode,
            payload,
            timeout: entry.route.timeout,
            retry: if mode == OperationMode::Call {
                RetryPolicy::without_retries()
            } else {
                entry.route.retry
            },
            kind: Arc::clone(&entry.route.kind),
        })
    }
}

impl Default for RouteRegistry {
    fn default() -> Self {
        Self::new(
            RouteRegistryLimit::default(),
            GlobalAdmissionLimit::default(),
        )
    }
}

impl Route {
    fn summary(&self) -> RouteSummary {
        RouteSummary {
            id: self.id.clone(),
            enabled: self.enabled,
            kind: self.kind.name(),
            target: Arc::from(self.kind.target_summary()),
        }
    }
}

/// Validated admission passed to the runtime for persistence and queueing.
pub struct AdmittedDelivery {
    route: RouteId,
    delivery: DeliveryId,
    mode: OperationMode,
    payload: EventPayload,
    timeout: RequestTimeout,
    retry: RetryPolicy,
    kind: Arc<dyn DeliveryKind>,
}

impl AdmittedDelivery {
    /// Creates the minimal persistence intent that must be recorded before queueing.
    #[must_use]
    pub fn intent(&self, accepted_at_unix_ms: u64) -> DeliveryIntent {
        DeliveryIntent::new(
            self.route.clone(),
            self.delivery.clone(),
            accepted_at_unix_ms,
        )
    }

    /// Returns the first persistence action required before queueing.
    #[must_use]
    pub fn persistence_action(&self, accepted_at_unix_ms: u64) -> DeliveryPersistenceAction {
        DeliveryPersistenceAction::InsertIntent {
            intent: self.intent(accepted_at_unix_ms),
        }
    }

    /// Returns retained bytes for queue accounting.
    #[must_use]
    pub const fn payload_bytes(&self) -> usize {
        self.payload.len()
    }

    /// Moves validated admission into runtime-owned parts.
    #[must_use]
    pub fn into_parts(self) -> AdmittedDeliveryParts {
        AdmittedDeliveryParts {
            route: self.route,
            delivery: self.delivery,
            mode: self.mode,
            payload: self.payload,
            timeout: self.timeout,
            retry: self.retry,
            kind: self.kind,
        }
    }
}

impl fmt::Debug for AdmittedDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedDelivery")
            .field("route", &self.route)
            .field("delivery", &self.delivery)
            .field("mode", &self.mode)
            .field("payload_bytes", &self.payload.len())
            .field("kind", &self.kind.name())
            .finish()
    }
}

/// Runtime-owned validated admission fields.
pub struct AdmittedDeliveryParts {
    /// Configured route identifier.
    pub route: RouteId,
    /// Unique delivery identifier.
    pub delivery: DeliveryId,
    /// Requested host operation.
    pub mode: OperationMode,
    /// Exact validated payload bytes.
    pub payload: EventPayload,
    /// Validated deadline duration for each attempt.
    pub timeout: RequestTimeout,
    /// Pure retry policy.
    pub retry: RetryPolicy,
    /// Configured delivery-kind implementation.
    pub kind: Arc<dyn DeliveryKind>,
}

/// A route registry mutation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RouteRegistryError {
    /// A route with the same identifier already exists.
    #[error("route already exists")]
    AlreadyExists,
    /// The configured route capacity is exhausted.
    #[error("route registry capacity is exhausted")]
    CapacityExhausted,
    /// The route can admit payloads its delivery kind cannot submit.
    #[error("route payload limit exceeds the delivery kind limit")]
    PayloadLimitUnsupported,
    /// The route does not exist.
    #[error("route was not found")]
    NotFound,
}

/// Stable rejection before an event enters a runtime queue.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdmissionError {
    /// The selected route does not exist.
    #[error("egress route was not found")]
    RouteNotFound,
    /// The route has atomically closed new admission.
    #[error("egress route is disabled")]
    RouteDisabled,
    /// The selected kind does not support the requested verb.
    #[error("egress route does not support the requested operation")]
    UnsupportedOperation,
    /// The event violates the declared payload contract.
    #[error("egress payload was rejected")]
    Payload(#[from] PayloadError),
    /// Process-wide admission tokens are exhausted.
    #[error("egress global admission rate is exceeded")]
    GlobalRateLimited,
    /// Per-route admission tokens are exhausted.
    #[error("egress route admission rate is exceeded")]
    RouteRateLimited,
    /// The kind could not create valid sans-I/O operation state.
    #[error("egress delivery kind rejected the operation")]
    Kind(#[from] KindOperationError),
}

const TOKEN_UNITS: u128 = 1_000_000_000;

struct TokenBucket {
    refill_per_second: u16,
    capacity_units: u128,
    available_units: u128,
    last_refill: EgressInstant,
}

impl TokenBucket {
    fn new(refill_per_second: u16, capacity: u16) -> Self {
        let capacity_units = u128::from(capacity) * TOKEN_UNITS;
        Self {
            refill_per_second,
            capacity_units,
            available_units: capacity_units,
            last_refill: EgressInstant::ZERO,
        }
    }

    fn refill(&mut self, now: EgressInstant) {
        if now <= self.last_refill {
            return;
        }
        let elapsed = now.elapsed().saturating_sub(self.last_refill.elapsed());
        let added = elapsed
            .as_nanos()
            .saturating_mul(u128::from(self.refill_per_second));
        self.available_units = self
            .available_units
            .saturating_add(added)
            .min(self.capacity_units);
        self.last_refill = now;
    }

    const fn has_token(&self) -> bool {
        self.available_units >= TOKEN_UNITS
    }

    fn take(&mut self) {
        self.available_units = self.available_units.saturating_sub(TOKEN_UNITS);
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use bondry_delivery_store::DeliveryId;
    use bytes::Bytes;

    use super::{AdmissionError, Route, RouteRegistry, RouteRegistryError};
    use crate::{
        DeliveryKind, DeliveryOperation, DeliveryPersistenceAction, EgressInstant, EventPayload,
        GlobalAdmissionLimit, KindOperationError, OperationMode, PayloadContract, PayloadField,
        PayloadFieldName, PayloadFieldType, PayloadLimit, RequestTimeout, RetryPolicy,
        RouteAdmissionLimit, RouteId, RouteRegistryLimit,
    };

    struct MockKind {
        supports_call: bool,
        max_payload_bytes: usize,
    }

    impl DeliveryKind for MockKind {
        fn name(&self) -> &'static str {
            "mock"
        }

        fn target_summary(&self) -> &str {
            "https://receiver.invalid/redacted"
        }

        fn supports_call(&self) -> bool {
            self.supports_call
        }

        fn permits_automatic_retry(&self) -> bool {
            true
        }

        fn max_payload_bytes(&self) -> usize {
            self.max_payload_bytes
        }

        fn validate_payload(
            &self,
            mode: OperationMode,
            _payload: &EventPayload,
        ) -> Result<(), KindOperationError> {
            if mode == OperationMode::Call && !self.supports_call {
                return Err(KindOperationError::UnsupportedOperation);
            }
            Ok(())
        }

        fn operation(
            &self,
            _mode: OperationMode,
            _delivery: DeliveryId,
            _payload: EventPayload,
        ) -> Result<Box<dyn DeliveryOperation>, KindOperationError> {
            Err(KindOperationError::Unavailable)
        }
    }

    fn route(
        id: &str,
        supports_call: bool,
        admission: RouteAdmissionLimit,
    ) -> Result<Route, Box<dyn std::error::Error>> {
        let payload = PayloadContract::new(
            [PayloadField::new(
                PayloadFieldName::new("event")?,
                PayloadFieldType::String,
                true,
            )],
            PayloadLimit::default(),
        )?;
        Ok(Route::new(
            RouteId::new(id)?,
            true,
            payload,
            RequestTimeout::default(),
            RetryPolicy::default(),
            admission,
            Arc::new(MockKind {
                supports_call,
                max_payload_bytes: crate::MAX_EVENT_PAYLOAD_BYTES,
            }),
        ))
    }

    fn payload() -> Bytes {
        Bytes::from_static(br#"{"event":"private-marker"}"#)
    }

    #[test]
    fn registry_is_bounded_ordered_and_atomically_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let admission = RouteAdmissionLimit::default();
        let mut registry =
            RouteRegistry::new(RouteRegistryLimit::new(2)?, GlobalAdmissionLimit::default());
        registry.register(route("z-route", false, admission)?)?;
        registry.register(route("a-route", false, admission)?)?;
        assert_eq!(
            registry.register(route("a-route", false, admission)?),
            Err(RouteRegistryError::AlreadyExists)
        );
        assert_eq!(
            registry.register(route("overflow", false, admission)?),
            Err(RouteRegistryError::CapacityExhausted)
        );
        assert_eq!(registry.routes()[0].id().as_str(), "a-route");
        assert_eq!(
            registry.routes()[0].target(),
            "https://receiver.invalid/redacted"
        );

        let disabled = RouteId::new("a-route")?;
        registry.set_enabled(&disabled, false)?;
        assert!(matches!(
            registry.admit_emit(
                &disabled,
                DeliveryId::new("disabled")?,
                payload(),
                EgressInstant::ZERO,
            ),
            Err(AdmissionError::RouteDisabled)
        ));
        assert!(registry.unregister(&disabled));
        assert!(!registry.unregister(&disabled));
        Ok(())
    }

    #[test]
    fn registry_rejects_incoherent_kind_payload_limits() -> Result<(), Box<dyn std::error::Error>> {
        let payload = PayloadContract::new(
            [PayloadField::new(
                PayloadFieldName::new("event")?,
                PayloadFieldType::String,
                true,
            )],
            PayloadLimit::default(),
        )?;
        let route = Route::new(
            RouteId::new("undersized-kind")?,
            true,
            payload,
            RequestTimeout::default(),
            RetryPolicy::default(),
            RouteAdmissionLimit::default(),
            Arc::new(MockKind {
                supports_call: false,
                max_payload_bytes: 1024,
            }),
        );
        assert_eq!(
            RouteRegistry::default().register(route),
            Err(RouteRegistryError::PayloadLimitUnsupported)
        );
        Ok(())
    }

    #[test]
    fn webhook_call_is_rejected_before_payload_validation() -> Result<(), Box<dyn std::error::Error>>
    {
        let route_id = RouteId::new("webhook")?;
        let mut registry = RouteRegistry::default();
        registry.register(route(
            route_id.as_str(),
            false,
            RouteAdmissionLimit::default(),
        )?)?;
        assert!(matches!(
            registry.admit_call(
                &route_id,
                DeliveryId::new("unsupported")?,
                Bytes::from_static(b"not-json"),
                EgressInstant::ZERO,
            ),
            Err(AdmissionError::UnsupportedOperation)
        ));

        let rpc_route = RouteId::new("rpc")?;
        registry.register(route(
            rpc_route.as_str(),
            true,
            RouteAdmissionLimit::default(),
        )?)?;
        let admitted = registry.admit_call(
            &rpc_route,
            DeliveryId::new("call")?,
            payload(),
            EgressInstant::ZERO,
        )?;
        let parts = admitted.into_parts();
        assert_eq!(parts.retry.retries(), 0);
        assert_eq!(parts.timeout, RequestTimeout::default());
        Ok(())
    }

    #[test]
    fn route_bucket_is_exact_and_refills_from_explicit_time()
    -> Result<(), Box<dyn std::error::Error>> {
        let route_id = RouteId::new("limited")?;
        let mut registry = RouteRegistry::default();
        registry.register(route(
            route_id.as_str(),
            false,
            RouteAdmissionLimit::new(1, 8)?,
        )?)?;
        for index in 0..8 {
            registry.admit_emit(
                &route_id,
                DeliveryId::new(format!("delivery_{index}"))?,
                payload(),
                EgressInstant::ZERO,
            )?;
        }
        assert!(matches!(
            registry.admit_emit(
                &route_id,
                DeliveryId::new("delivery_limited")?,
                payload(),
                EgressInstant::ZERO,
            ),
            Err(AdmissionError::RouteRateLimited)
        ));
        registry.admit_emit(
            &route_id,
            DeliveryId::new("delivery_refilled")?,
            payload(),
            EgressInstant::at(Duration::from_secs(1)),
        )?;
        Ok(())
    }

    #[test]
    fn global_bucket_rejects_without_consuming_route_capacity()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut registry = RouteRegistry::new(
            RouteRegistryLimit::default(),
            GlobalAdmissionLimit::new(1, 64)?,
        );
        let routes = (0..9)
            .map(|index| {
                let route_id = RouteId::new(format!("route_{index}"))?;
                registry.register(route(
                    route_id.as_str(),
                    false,
                    RouteAdmissionLimit::default(),
                )?)?;
                Ok(route_id)
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        for index in 0..64 {
            let route_id = &routes[index % 8];
            registry.admit_emit(
                route_id,
                DeliveryId::new(format!("global_{index}"))?,
                payload(),
                EgressInstant::ZERO,
            )?;
        }
        assert!(matches!(
            registry.admit_emit(
                &routes[8],
                DeliveryId::new("global_limited")?,
                payload(),
                EgressInstant::ZERO,
            ),
            Err(AdmissionError::GlobalRateLimited)
        ));
        registry.admit_emit(
            &routes[8],
            DeliveryId::new("global_refilled")?,
            payload(),
            EgressInstant::at(Duration::from_secs(1)),
        )?;
        Ok(())
    }

    #[test]
    fn admission_emits_redacted_persistence_intent() -> Result<(), Box<dyn std::error::Error>> {
        let route_id = RouteId::new("audit")?;
        let delivery_id = DeliveryId::new("delivery_audit")?;
        let mut registry = RouteRegistry::default();
        registry.register(route(
            route_id.as_str(),
            false,
            RouteAdmissionLimit::default(),
        )?)?;
        let admitted = registry.admit_emit(
            &route_id,
            delivery_id.clone(),
            payload(),
            EgressInstant::ZERO,
        )?;
        assert!(!format!("{admitted:?}").contains("private-marker"));
        let DeliveryPersistenceAction::InsertIntent { intent } = admitted.persistence_action(42)
        else {
            return Err(std::io::Error::other("unexpected persistence action").into());
        };
        assert_eq!(intent.route(), &route_id);
        assert_eq!(intent.delivery(), &delivery_id);
        assert_eq!(intent.accepted_at_unix_ms(), 42);
        assert!(!format!("{intent:?}").contains("private-marker"));
        Ok(())
    }
}
