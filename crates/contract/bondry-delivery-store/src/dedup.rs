use std::fmt;

use thiserror::Error;

use crate::{RouteId, StoreDurability, VerifierNamespace};

/// Fixed SHA-256 hash of a verifier-normalized trusted delivery identifier.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct TrustedDeliveryIdHash([u8; 32]);

impl TrustedDeliveryIdHash {
    /// Wraps a verifier-produced SHA-256 identifier hash.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed hash for persistence comparisons.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TrustedDeliveryIdHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrustedDeliveryIdHash([REDACTED])")
    }
}

/// Composite replay-protection key produced only after verification.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DedupKey {
    route: RouteId,
    namespace: VerifierNamespace,
    delivery_hash: TrustedDeliveryIdHash,
}

impl DedupKey {
    /// Creates a route- and verifier-scoped trusted identifier key.
    #[must_use]
    pub const fn new(
        route: RouteId,
        namespace: VerifierNamespace,
        delivery_hash: TrustedDeliveryIdHash,
    ) -> Self {
        Self {
            route,
            namespace,
            delivery_hash,
        }
    }

    /// Returns the configured route.
    #[must_use]
    pub const fn route(&self) -> &RouteId {
        &self.route
    }

    /// Returns the verifier or sender namespace.
    #[must_use]
    pub const fn namespace(&self) -> &VerifierNamespace {
        &self.namespace
    }

    /// Returns the normalized identifier hash.
    #[must_use]
    pub const fn delivery_hash(&self) -> &TrustedDeliveryIdHash {
        &self.delivery_hash
    }
}

/// Persistent replay-protection state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DedupState {
    /// Dispatch was claimed and may still be executing.
    InFlight,
    /// Dispatch completed and must not execute again.
    Completed,
    /// The previous dispatch outcome is uncertain and must not auto-redispatch.
    Unknown,
}

/// Stored deduplication state without request or response contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DedupRecord {
    key: DedupKey,
    state: DedupState,
    updated_at_unix_ms: u64,
}

impl DedupRecord {
    /// Reconstructs a record loaded from trusted storage.
    #[must_use]
    pub const fn from_stored_parts(
        key: DedupKey,
        state: DedupState,
        updated_at_unix_ms: u64,
    ) -> Self {
        Self {
            key,
            state,
            updated_at_unix_ms,
        }
    }

    /// Returns the composite trusted identity key.
    #[must_use]
    pub const fn key(&self) -> &DedupKey {
        &self.key
    }

    /// Returns the replay-protection state.
    #[must_use]
    pub const fn state(&self) -> DedupState {
        self.state
    }

    /// Returns the most recent transition time.
    #[must_use]
    pub const fn updated_at_unix_ms(&self) -> u64 {
        self.updated_at_unix_ms
    }
}

/// Atomic claim result used to prevent duplicate dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DedupClaim {
    /// The caller created the in-flight claim and may dispatch once.
    Claimed,
    /// Existing state forbids a second dispatch.
    Duplicate(DedupState),
}

/// Retention behavior fixed atomically with a newly claimed delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DedupClaimPolicy {
    /// Completed state remains until an explicit administration action.
    RetainCompleted,
    /// Completed state may expire after retention because repetition is safe or freshness rejects it.
    ExpireCompleted,
}

/// Explicit administration decision for an uncertain dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DedupResolution {
    /// Preserve a tombstone and treat the uncertain dispatch as completed.
    Completed,
    /// Remove the uncertain claim so a later delivery may dispatch.
    RetryAllowed,
}

/// Replay-protection persistence called exclusively by the ingress adapter.
pub trait DedupStore: Send + Sync {
    /// Reports whether replay state survives process termination.
    fn durability(&self) -> StoreDurability;

    /// Atomically claims a verified identity and its safe retention policy or reports existing state.
    fn claim(
        &self,
        key: DedupKey,
        policy: DedupClaimPolicy,
        updated_at_unix_ms: u64,
    ) -> Result<DedupClaim, DedupStoreError>;

    /// Atomically marks an in-flight dispatch completed.
    fn complete(&self, key: &DedupKey, updated_at_unix_ms: u64) -> Result<(), DedupStoreError>;

    /// Atomically marks an in-flight dispatch uncertain.
    fn mark_unknown(&self, key: &DedupKey, updated_at_unix_ms: u64) -> Result<(), DedupStoreError>;

    /// Atomically removes a claim after a known pre-dispatch retryable failure.
    fn release_claim(&self, key: &DedupKey) -> Result<(), DedupStoreError>;

    /// Loads one replay-protection record.
    fn record(&self, key: &DedupKey) -> Result<Option<DedupRecord>, DedupStoreError>;

    /// Atomically converts every leftover in-flight claim to unknown after restart.
    fn recover_in_flight(&self, updated_at_unix_ms: u64) -> Result<u64, DedupStoreError>;

    /// Applies an explicit administration decision to one unknown record.
    fn resolve_unknown(
        &self,
        key: &DedupKey,
        resolution: DedupResolution,
        updated_at_unix_ms: u64,
    ) -> Result<(), DedupStoreError>;

    /// Visits unknown records in key order without holding a store lock during callbacks.
    fn visit_unknown(
        &self,
        visitor: &mut dyn FnMut(&DedupRecord) -> bool,
    ) -> Result<(), DedupStoreError>;

    /// Explicitly removes completed records before a host-selected cutoff, never unknown records.
    fn clear_completed_before(&self, updated_before_unix_ms: u64) -> Result<u64, DedupStoreError>;
}

/// Stable, non-sensitive replay-storage failure categories.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DedupStoreError {
    /// The configured record or logical-byte capacity is exhausted.
    #[error("deduplication storage capacity is exhausted")]
    CapacityExhausted,
    /// The requested record does not exist.
    #[error("deduplication record was not found")]
    NotFound,
    /// The requested replay-state transition is invalid.
    #[error("deduplication state transition is invalid")]
    InvalidTransition,
    /// Storage cannot safely complete the operation.
    #[error("deduplication storage is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::{DedupKey, TrustedDeliveryIdHash};
    use crate::{RouteId, VerifierNamespace};

    #[test]
    fn debug_redacts_the_normalized_identifier_hash() -> Result<(), Box<dyn std::error::Error>> {
        let key = DedupKey::new(
            RouteId::new("webhook")?,
            VerifierNamespace::new("github:v1")?,
            TrustedDeliveryIdHash::from_bytes([0x5a; 32]),
        );
        let rendered = format!("{key:?}");
        assert!(rendered.contains("github:v1"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("5a"));
        Ok(())
    }
}
