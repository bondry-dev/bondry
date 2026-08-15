#![doc = "Persistence contracts for Bondry delivery and deduplication state."]

mod dedup;
mod delivery;
mod identifier;
mod limits;

pub use dedup::{
    DedupClaim, DedupRecord, DedupResolution, DedupState, DedupStore, DedupStoreError,
    TrustedDeliveryIdHash,
};
pub use delivery::{
    DeliveryFailure, DeliveryIntent, DeliveryLog, DeliveryLogError, DeliveryOutcome,
    DeliveryRecord, DeliveryResultCategory, DeliveryResultMetadata, DeliveryState,
    PERSISTENT_DELIVERY_RECORD_CHARGE_BYTES,
};
pub use identifier::{
    DeliveryId, MAX_DELIVERY_ID_BYTES, MAX_ROUTE_ID_BYTES, MAX_VERIFIER_NAMESPACE_BYTES,
    PersistenceIdentifierError, RouteId, VerifierNamespace,
};
pub use limits::{
    DEFAULT_PERSISTENT_DELIVERY_LOG_BYTES, DEFAULT_PERSISTENT_DELIVERY_LOG_RECORDS,
    DEFAULT_PERSISTENT_DELIVERY_LOG_RETENTION, MAX_PERSISTENT_DELIVERY_LOG_BYTES,
    MAX_PERSISTENT_DELIVERY_LOG_RECORDS, MAX_PERSISTENT_DELIVERY_LOG_RETENTION,
    MIN_PERSISTENT_DELIVERY_LOG_BYTES, MIN_PERSISTENT_DELIVERY_LOG_RECORDS,
    MIN_PERSISTENT_DELIVERY_LOG_RETENTION, PersistentDeliveryLogLimits,
    PersistentDeliveryLogLimitsError,
};

/// Whether storage survives the current process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreDurability {
    /// State exists only for the lifetime of the process.
    ProcessLocal,
    /// State is committed to durable storage.
    Persistent,
}
