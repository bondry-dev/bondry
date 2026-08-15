use thiserror::Error;

use crate::{DeliveryId, RouteId, StoreDurability};

/// Logical capacity reserved for each persistent delivery record.
pub const PERSISTENT_DELIVERY_RECORD_CHARGE_BYTES: u64 = 512;

/// Stable, non-sensitive terminal delivery failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryFailure {
    /// Route shutdown or disable cancelled the delivery.
    Cancelled,
    /// The request exceeded its absolute deadline.
    DeadlineExceeded,
    /// Endpoint policy rejected the destination or established peer.
    EndpointPolicy,
    /// Required secret material could not be resolved safely.
    SecretUnavailable,
    /// The transport could not complete the request.
    TransportUnavailable,
    /// The receiver returned a terminal rejection.
    ReceiverRejected,
    /// The bounded retry policy was exhausted.
    RetryExhausted,
    /// An internal invariant prevented safe delivery.
    Internal,
}

/// Optional bounded result metadata retained for host `call` operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryResultMetadata {
    category: DeliveryResultCategory,
    bytes: u32,
}

impl DeliveryResultMetadata {
    /// Creates result metadata without retaining result bytes.
    #[must_use]
    pub const fn new(category: DeliveryResultCategory, bytes: u32) -> Self {
        Self { category, bytes }
    }

    /// Returns the stable result category.
    #[must_use]
    pub const fn category(self) -> DeliveryResultCategory {
        self.category
    }

    /// Returns the discarded or returned result size.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.bytes
    }
}

/// Stable result categories that never include result contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryResultCategory {
    /// The remote operation returned a valid success result.
    Succeeded,
    /// The remote operation returned a valid error result.
    Failed,
    /// The response could not be accepted as a bounded result.
    Invalid,
}

/// Exactly one terminal outcome for an accepted delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryOutcome {
    /// The receiver accepted the delivery.
    Delivered,
    /// Delivery terminated with a stable failure category.
    Failed(DeliveryFailure),
    /// Graceful shutdown ended before delivery could finish.
    LostOnShutdown,
    /// A durable intent was unfinished when the process restarted.
    UnknownAfterCrash,
}

/// Persisted lifecycle state for an accepted delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryState {
    /// The intent is queued, retrying, or in flight.
    Pending,
    /// The delivery reached exactly one terminal outcome.
    Terminal(DeliveryOutcome),
}

impl DeliveryState {
    /// Returns whether no further transition is permitted.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Terminal(_))
    }
}

/// Minimal delivery intent written before transport submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryIntent {
    route: RouteId,
    delivery: DeliveryId,
    accepted_at_unix_ms: u64,
}

impl DeliveryIntent {
    /// Creates an intent containing no payload, destination, or credential data.
    #[must_use]
    pub const fn new(route: RouteId, delivery: DeliveryId, accepted_at_unix_ms: u64) -> Self {
        Self {
            route,
            delivery,
            accepted_at_unix_ms,
        }
    }

    /// Returns the route identifier.
    #[must_use]
    pub const fn route(&self) -> &RouteId {
        &self.route
    }

    /// Returns the delivery identifier.
    #[must_use]
    pub const fn delivery(&self) -> &DeliveryId {
        &self.delivery
    }

    /// Returns the acceptance wall-clock time.
    #[must_use]
    pub const fn accepted_at_unix_ms(&self) -> u64 {
        self.accepted_at_unix_ms
    }
}

/// A delivery status record that intentionally excludes sensitive data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryRecord {
    intent: DeliveryIntent,
    attempts: u16,
    state: DeliveryState,
    updated_at_unix_ms: u64,
    result: Option<DeliveryResultMetadata>,
}

impl DeliveryRecord {
    /// Reconstructs a validated record from trusted storage.
    #[must_use]
    pub const fn from_stored_parts(
        intent: DeliveryIntent,
        attempts: u16,
        state: DeliveryState,
        updated_at_unix_ms: u64,
        result: Option<DeliveryResultMetadata>,
    ) -> Self {
        Self {
            intent,
            attempts,
            state,
            updated_at_unix_ms,
            result,
        }
    }

    /// Returns the original intent metadata.
    #[must_use]
    pub const fn intent(&self) -> &DeliveryIntent {
        &self.intent
    }

    /// Returns the number of transport attempts started.
    #[must_use]
    pub const fn attempts(&self) -> u16 {
        self.attempts
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> DeliveryState {
        self.state
    }

    /// Returns the most recent persisted transition time.
    #[must_use]
    pub const fn updated_at_unix_ms(&self) -> u64 {
        self.updated_at_unix_ms
    }

    /// Returns optional result category and size without result contents.
    #[must_use]
    pub const fn result(&self) -> Option<DeliveryResultMetadata> {
        self.result
    }
}

/// Storage operations driven exclusively by the egress runtime.
pub trait DeliveryLog: Send + Sync {
    /// Reports whether this log survives process termination.
    fn durability(&self) -> StoreDurability;

    /// Atomically inserts an intent before any transport submission.
    fn insert_intent(&self, intent: DeliveryIntent) -> Result<(), DeliveryLogError>;

    /// Atomically records a strictly increasing attempt count while pending.
    fn record_attempt(
        &self,
        delivery: &DeliveryId,
        attempts: u16,
        updated_at_unix_ms: u64,
    ) -> Result<(), DeliveryLogError>;

    /// Atomically moves one pending delivery to exactly one terminal outcome.
    fn record_outcome(
        &self,
        delivery: &DeliveryId,
        outcome: DeliveryOutcome,
        updated_at_unix_ms: u64,
        result: Option<DeliveryResultMetadata>,
    ) -> Result<(), DeliveryLogError>;

    /// Loads one delivery record for host status inspection.
    fn delivery(&self, delivery: &DeliveryId) -> Result<Option<DeliveryRecord>, DeliveryLogError>;

    /// Atomically marks every unfinished durable intent unknown after restart.
    fn recover_unfinished(&self, updated_at_unix_ms: u64) -> Result<u64, DeliveryLogError>;
}

/// Stable, non-sensitive delivery-log failure categories.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DeliveryLogError {
    /// A delivery identifier already exists.
    #[error("delivery log record already exists")]
    Conflict,
    /// The configured record or logical-byte capacity is exhausted.
    #[error("delivery log capacity is exhausted")]
    CapacityExhausted,
    /// The target delivery record does not exist.
    #[error("delivery log record was not found")]
    NotFound,
    /// The requested lifecycle transition is invalid.
    #[error("delivery log transition is invalid")]
    InvalidTransition,
    /// Storage cannot safely complete the operation.
    #[error("delivery log is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::{DeliveryIntent, DeliveryOutcome, DeliveryState};
    use crate::{DeliveryId, RouteId};

    #[test]
    fn intent_debug_contains_no_payload_or_destination() -> Result<(), Box<dyn std::error::Error>> {
        let intent = DeliveryIntent::new(
            RouteId::new("watchdog")?,
            DeliveryId::new("delivery_1")?,
            42,
        );
        let rendered = format!("{intent:?}");
        assert!(rendered.contains("watchdog"));
        assert!(rendered.contains("delivery_1"));
        assert!(!rendered.contains("payload"));
        assert!(!rendered.contains("endpoint"));
        Ok(())
    }

    #[test]
    fn terminal_state_is_explicit() {
        assert!(!DeliveryState::Pending.is_terminal());
        assert!(DeliveryState::Terminal(DeliveryOutcome::Delivered).is_terminal());
    }
}
