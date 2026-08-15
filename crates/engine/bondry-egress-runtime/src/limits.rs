use std::time::Duration;

use thiserror::Error;

/// Default process-wide pending delivery count.
pub const DEFAULT_GLOBAL_PENDING_DELIVERIES: u16 = 1024;
const MIN_GLOBAL_PENDING_DELIVERIES: u16 = 16;
const MAX_GLOBAL_PENDING_DELIVERIES: u16 = 4096;
/// Default per-route pending delivery count.
pub const DEFAULT_ROUTE_PENDING_DELIVERIES: u16 = 64;
const MIN_ROUTE_PENDING_DELIVERIES: u16 = 1;
const MAX_ROUTE_PENDING_DELIVERIES: u16 = 256;
/// Default process-wide retained payload bytes.
pub const DEFAULT_GLOBAL_PENDING_BYTES: usize = 8 * 1024 * 1024;
const MIN_GLOBAL_PENDING_BYTES: usize = 1024 * 1024;
const MAX_GLOBAL_PENDING_BYTES: usize = 32 * 1024 * 1024;
/// Default per-route retained payload bytes.
pub const DEFAULT_ROUTE_PENDING_BYTES: usize = 1024 * 1024;
const MIN_ROUTE_PENDING_BYTES: usize = 64 * 1024;
const MAX_ROUTE_PENDING_BYTES: usize = 4 * 1024 * 1024;
/// Default process-wide in-flight transport operations.
pub const DEFAULT_GLOBAL_IN_FLIGHT: u8 = 4;
const MIN_GLOBAL_IN_FLIGHT: u8 = 1;
const MAX_GLOBAL_IN_FLIGHT: u8 = 16;
/// Default per-route in-flight transport operations.
pub const DEFAULT_ROUTE_IN_FLIGHT: u8 = 2;
const MIN_ROUTE_IN_FLIGHT: u8 = 1;
/// Default independent host-call lane capacity.
pub const DEFAULT_CALL_IN_FLIGHT: u8 = 4;
const MIN_CALL_IN_FLIGHT: u8 = 1;
const MAX_CALL_IN_FLIGHT: u8 = 16;
/// Default route-disable and graceful-shutdown drain timeout.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_DRAIN_TIMEOUT: Duration = Duration::from_secs(60);
/// Default process-local delivery-log entry capacity.
pub const DEFAULT_IN_MEMORY_LOG_ENTRIES: u16 = 1024;
/// Minimum process-local delivery-log entry capacity.
pub const MIN_IN_MEMORY_LOG_ENTRIES: u16 = 64;
/// Maximum process-local delivery-log entry capacity.
pub const MAX_IN_MEMORY_LOG_ENTRIES: u16 = 8192;

/// Validated runtime queue, concurrency, and lifecycle bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressRuntimeLimits {
    global_pending_deliveries: u16,
    route_pending_deliveries: u16,
    global_pending_bytes: usize,
    route_pending_bytes: usize,
    global_in_flight: u8,
    route_in_flight: u8,
    call_in_flight: u8,
    drain_timeout: Duration,
}

impl EgressRuntimeLimits {
    /// Validates the complete egress runtime limit set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        global_pending_deliveries: u16,
        route_pending_deliveries: u16,
        global_pending_bytes: usize,
        route_pending_bytes: usize,
        global_in_flight: u8,
        route_in_flight: u8,
        call_in_flight: u8,
        drain_timeout: Duration,
    ) -> Result<Self, EgressRuntimeLimitError> {
        if !(MIN_GLOBAL_PENDING_DELIVERIES..=MAX_GLOBAL_PENDING_DELIVERIES)
            .contains(&global_pending_deliveries)
        {
            return Err(EgressRuntimeLimitError::GlobalPendingDeliveries);
        }
        if !(MIN_ROUTE_PENDING_DELIVERIES..=MAX_ROUTE_PENDING_DELIVERIES)
            .contains(&route_pending_deliveries)
            || route_pending_deliveries > global_pending_deliveries
        {
            return Err(EgressRuntimeLimitError::RoutePendingDeliveries);
        }
        if !(MIN_GLOBAL_PENDING_BYTES..=MAX_GLOBAL_PENDING_BYTES).contains(&global_pending_bytes) {
            return Err(EgressRuntimeLimitError::GlobalPendingBytes);
        }
        if !(MIN_ROUTE_PENDING_BYTES..=MAX_ROUTE_PENDING_BYTES).contains(&route_pending_bytes)
            || route_pending_bytes > global_pending_bytes
        {
            return Err(EgressRuntimeLimitError::RoutePendingBytes);
        }
        if !(MIN_GLOBAL_IN_FLIGHT..=MAX_GLOBAL_IN_FLIGHT).contains(&global_in_flight) {
            return Err(EgressRuntimeLimitError::GlobalInFlight);
        }
        if route_in_flight < MIN_ROUTE_IN_FLIGHT || route_in_flight > global_in_flight {
            return Err(EgressRuntimeLimitError::RouteInFlight);
        }
        if !(MIN_CALL_IN_FLIGHT..=MAX_CALL_IN_FLIGHT).contains(&call_in_flight) {
            return Err(EgressRuntimeLimitError::CallInFlight);
        }
        if !(MIN_DRAIN_TIMEOUT..=MAX_DRAIN_TIMEOUT).contains(&drain_timeout) {
            return Err(EgressRuntimeLimitError::DrainTimeout);
        }
        Ok(Self {
            global_pending_deliveries,
            route_pending_deliveries,
            global_pending_bytes,
            route_pending_bytes,
            global_in_flight,
            route_in_flight,
            call_in_flight,
            drain_timeout,
        })
    }

    /// Returns the process-wide pending delivery cap.
    #[must_use]
    pub const fn global_pending_deliveries(self) -> u16 {
        self.global_pending_deliveries
    }

    /// Returns the per-route pending delivery cap.
    #[must_use]
    pub const fn route_pending_deliveries(self) -> u16 {
        self.route_pending_deliveries
    }

    /// Returns the process-wide retained payload byte cap.
    #[must_use]
    pub const fn global_pending_bytes(self) -> usize {
        self.global_pending_bytes
    }

    /// Returns the per-route retained payload byte cap.
    #[must_use]
    pub const fn route_pending_bytes(self) -> usize {
        self.route_pending_bytes
    }

    /// Returns the process-wide transport concurrency cap.
    #[must_use]
    pub const fn global_in_flight(self) -> u8 {
        self.global_in_flight
    }

    /// Returns the per-route transport concurrency cap.
    #[must_use]
    pub const fn route_in_flight(self) -> u8 {
        self.route_in_flight
    }

    /// Returns the independent host-call lane cap reserved for Phase 3.
    #[must_use]
    pub const fn call_in_flight(self) -> u8 {
        self.call_in_flight
    }

    /// Returns the route and process drain timeout.
    #[must_use]
    pub const fn drain_timeout(self) -> Duration {
        self.drain_timeout
    }
}

impl Default for EgressRuntimeLimits {
    fn default() -> Self {
        Self {
            global_pending_deliveries: DEFAULT_GLOBAL_PENDING_DELIVERIES,
            route_pending_deliveries: DEFAULT_ROUTE_PENDING_DELIVERIES,
            global_pending_bytes: DEFAULT_GLOBAL_PENDING_BYTES,
            route_pending_bytes: DEFAULT_ROUTE_PENDING_BYTES,
            global_in_flight: DEFAULT_GLOBAL_IN_FLIGHT,
            route_in_flight: DEFAULT_ROUTE_IN_FLIGHT,
            call_in_flight: DEFAULT_CALL_IN_FLIGHT,
            drain_timeout: DEFAULT_DRAIN_TIMEOUT,
        }
    }
}

/// A runtime resource limit outside the accepted contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EgressRuntimeLimitError {
    /// Process-wide pending count is outside 16 through 4096.
    #[error("global pending delivery limit is outside the allowed range")]
    GlobalPendingDeliveries,
    /// Per-route pending count is invalid or exceeds the global cap.
    #[error("route pending delivery limit is outside the allowed range")]
    RoutePendingDeliveries,
    /// Process-wide retained bytes are outside 1 MiB through 32 MiB.
    #[error("global pending byte limit is outside the allowed range")]
    GlobalPendingBytes,
    /// Per-route retained bytes are invalid or exceed the global cap.
    #[error("route pending byte limit is outside the allowed range")]
    RoutePendingBytes,
    /// Process-wide in-flight count is outside 1 through 16.
    #[error("global in-flight limit is outside the allowed range")]
    GlobalInFlight,
    /// Per-route in-flight count is invalid or exceeds the global cap.
    #[error("route in-flight limit is outside the allowed range")]
    RouteInFlight,
    /// Host-call lane count is outside 1 through 16.
    #[error("call in-flight limit is outside the allowed range")]
    CallInFlight,
    /// Drain timeout is outside 1 through 60 seconds.
    #[error("egress drain timeout is outside the allowed range")]
    DrainTimeout,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{EgressRuntimeLimitError, EgressRuntimeLimits};

    #[test]
    fn validates_cross_dimension_bounds() {
        assert!(EgressRuntimeLimits::default().global_pending_deliveries() >= 500);
        assert_eq!(
            EgressRuntimeLimits::new(
                16,
                17,
                1024 * 1024,
                64 * 1024,
                4,
                2,
                4,
                Duration::from_secs(10),
            ),
            Err(EgressRuntimeLimitError::RoutePendingDeliveries)
        );
        assert_eq!(
            EgressRuntimeLimits::new(
                16,
                1,
                1024 * 1024,
                64 * 1024,
                2,
                3,
                4,
                Duration::from_secs(10),
            ),
            Err(EgressRuntimeLimitError::RouteInFlight)
        );
    }
}
