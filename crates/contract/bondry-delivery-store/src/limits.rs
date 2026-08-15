use std::time::Duration;

use thiserror::Error;

/// Default persistent deduplication record capacity.
pub const DEFAULT_DEDUP_STORE_RECORDS: u32 = 100_000;
/// Minimum persistent deduplication record capacity.
pub const MIN_DEDUP_STORE_RECORDS: u32 = 1_000;
/// Maximum persistent deduplication record capacity.
pub const MAX_DEDUP_STORE_RECORDS: u32 = 1_000_000;
/// Default persistent deduplication logical byte capacity.
pub const DEFAULT_DEDUP_STORE_BYTES: u64 = 16 * 1024 * 1024;
/// Minimum persistent deduplication logical byte capacity.
pub const MIN_DEDUP_STORE_BYTES: u64 = 1024 * 1024;
/// Maximum persistent deduplication logical byte capacity.
pub const MAX_DEDUP_STORE_BYTES: u64 = 128 * 1024 * 1024;
/// Default completed-tombstone retention.
pub const DEFAULT_DEDUP_STORE_RETENTION: Duration = Duration::from_secs(7 * 86_400);
/// Minimum completed-tombstone retention.
pub const MIN_DEDUP_STORE_RETENTION: Duration = Duration::from_secs(86_400);
/// Maximum completed-tombstone retention.
pub const MAX_DEDUP_STORE_RETENTION: Duration = Duration::from_secs(90 * 86_400);

/// Validated persistent replay-protection resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DedupStoreLimits {
    records: u32,
    bytes: u64,
    retention: Duration,
}

impl DedupStoreLimits {
    /// Validates the complete persistent deduplication limit set.
    pub fn new(
        records: u32,
        bytes: u64,
        retention: Duration,
    ) -> Result<Self, DedupStoreLimitsError> {
        if !(MIN_DEDUP_STORE_RECORDS..=MAX_DEDUP_STORE_RECORDS).contains(&records) {
            return Err(DedupStoreLimitsError::Records);
        }
        if !(MIN_DEDUP_STORE_BYTES..=MAX_DEDUP_STORE_BYTES).contains(&bytes) {
            return Err(DedupStoreLimitsError::Bytes);
        }
        if !(MIN_DEDUP_STORE_RETENTION..=MAX_DEDUP_STORE_RETENTION).contains(&retention) {
            return Err(DedupStoreLimitsError::Retention);
        }
        Ok(Self {
            records,
            bytes,
            retention,
        })
    }

    /// Returns the maximum retained record count.
    #[must_use]
    pub const fn records(self) -> u32 {
        self.records
    }

    /// Returns the maximum logical bytes charged to retained records.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    /// Returns completed-tombstone retention.
    #[must_use]
    pub const fn retention(self) -> Duration {
        self.retention
    }
}

impl Default for DedupStoreLimits {
    fn default() -> Self {
        Self {
            records: DEFAULT_DEDUP_STORE_RECORDS,
            bytes: DEFAULT_DEDUP_STORE_BYTES,
            retention: DEFAULT_DEDUP_STORE_RETENTION,
        }
    }
}

/// A persistent replay-protection limit outside the accepted contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DedupStoreLimitsError {
    /// Record capacity is outside its allowed range.
    #[error("deduplication record capacity is outside the allowed range")]
    Records,
    /// Logical byte capacity is outside its allowed range.
    #[error("deduplication byte capacity is outside the allowed range")]
    Bytes,
    /// Retention is outside its safety-critical range.
    #[error("deduplication retention is outside the allowed range")]
    Retention,
}

/// Default persistent delivery-log record capacity.
pub const DEFAULT_PERSISTENT_DELIVERY_LOG_RECORDS: u32 = 100_000;
/// Minimum persistent delivery-log record capacity.
pub const MIN_PERSISTENT_DELIVERY_LOG_RECORDS: u32 = 1_000;
/// Maximum persistent delivery-log record capacity.
pub const MAX_PERSISTENT_DELIVERY_LOG_RECORDS: u32 = 1_000_000;
/// Default persistent delivery-log logical byte capacity.
pub const DEFAULT_PERSISTENT_DELIVERY_LOG_BYTES: u64 = 64 * 1024 * 1024;
/// Minimum persistent delivery-log logical byte capacity.
pub const MIN_PERSISTENT_DELIVERY_LOG_BYTES: u64 = 1024 * 1024;
/// Maximum persistent delivery-log logical byte capacity.
pub const MAX_PERSISTENT_DELIVERY_LOG_BYTES: u64 = 512 * 1024 * 1024;
/// Default terminal-record retention.
pub const DEFAULT_PERSISTENT_DELIVERY_LOG_RETENTION: Duration = Duration::from_secs(7 * 86_400);
/// Minimum terminal-record retention.
pub const MIN_PERSISTENT_DELIVERY_LOG_RETENTION: Duration = Duration::from_secs(86_400);
/// Maximum terminal-record retention.
pub const MAX_PERSISTENT_DELIVERY_LOG_RETENTION: Duration = Duration::from_secs(90 * 86_400);

/// Validated persistent delivery-log resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistentDeliveryLogLimits {
    records: u32,
    bytes: u64,
    retention: Duration,
}

impl PersistentDeliveryLogLimits {
    /// Validates the complete persistent delivery-log limit set.
    pub fn new(
        records: u32,
        bytes: u64,
        retention: Duration,
    ) -> Result<Self, PersistentDeliveryLogLimitsError> {
        if !(MIN_PERSISTENT_DELIVERY_LOG_RECORDS..=MAX_PERSISTENT_DELIVERY_LOG_RECORDS)
            .contains(&records)
        {
            return Err(PersistentDeliveryLogLimitsError::Records);
        }
        if !(MIN_PERSISTENT_DELIVERY_LOG_BYTES..=MAX_PERSISTENT_DELIVERY_LOG_BYTES).contains(&bytes)
        {
            return Err(PersistentDeliveryLogLimitsError::Bytes);
        }
        if !(MIN_PERSISTENT_DELIVERY_LOG_RETENTION..=MAX_PERSISTENT_DELIVERY_LOG_RETENTION)
            .contains(&retention)
        {
            return Err(PersistentDeliveryLogLimitsError::Retention);
        }
        Ok(Self {
            records,
            bytes,
            retention,
        })
    }

    /// Returns the maximum retained record count.
    #[must_use]
    pub const fn records(self) -> u32 {
        self.records
    }

    /// Returns the maximum logical bytes charged to retained records.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    /// Returns terminal-record retention.
    #[must_use]
    pub const fn retention(self) -> Duration {
        self.retention
    }
}

impl Default for PersistentDeliveryLogLimits {
    fn default() -> Self {
        Self {
            records: DEFAULT_PERSISTENT_DELIVERY_LOG_RECORDS,
            bytes: DEFAULT_PERSISTENT_DELIVERY_LOG_BYTES,
            retention: DEFAULT_PERSISTENT_DELIVERY_LOG_RETENTION,
        }
    }
}

/// A persistent delivery-log limit outside the accepted contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PersistentDeliveryLogLimitsError {
    /// Record capacity is outside its allowed range.
    #[error("persistent delivery-log record capacity is outside the allowed range")]
    Records,
    /// Logical byte capacity is outside its allowed range.
    #[error("persistent delivery-log byte capacity is outside the allowed range")]
    Bytes,
    /// Retention is outside its safety-critical range.
    #[error("persistent delivery-log retention is outside the allowed range")]
    Retention,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        DedupStoreLimits, DedupStoreLimitsError, MAX_DEDUP_STORE_BYTES, MAX_DEDUP_STORE_RECORDS,
        MAX_DEDUP_STORE_RETENTION, MAX_PERSISTENT_DELIVERY_LOG_BYTES,
        MAX_PERSISTENT_DELIVERY_LOG_RECORDS, MAX_PERSISTENT_DELIVERY_LOG_RETENTION,
        MIN_DEDUP_STORE_BYTES, MIN_DEDUP_STORE_RECORDS, MIN_DEDUP_STORE_RETENTION,
        MIN_PERSISTENT_DELIVERY_LOG_BYTES, MIN_PERSISTENT_DELIVERY_LOG_RECORDS,
        MIN_PERSISTENT_DELIVERY_LOG_RETENTION, PersistentDeliveryLogLimits,
        PersistentDeliveryLogLimitsError,
    };

    #[test]
    fn validates_each_deduplication_limit_dimension() {
        assert!(DedupStoreLimits::default().records() > 0);
        assert!(
            DedupStoreLimits::new(
                MIN_DEDUP_STORE_RECORDS,
                MIN_DEDUP_STORE_BYTES,
                MIN_DEDUP_STORE_RETENTION,
            )
            .is_ok()
        );
        assert!(
            DedupStoreLimits::new(
                MAX_DEDUP_STORE_RECORDS,
                MAX_DEDUP_STORE_BYTES,
                MAX_DEDUP_STORE_RETENTION,
            )
            .is_ok()
        );
        assert_eq!(
            DedupStoreLimits::new(
                MIN_DEDUP_STORE_RECORDS - 1,
                MIN_DEDUP_STORE_BYTES,
                MIN_DEDUP_STORE_RETENTION,
            ),
            Err(DedupStoreLimitsError::Records)
        );
        assert_eq!(
            DedupStoreLimits::new(
                MIN_DEDUP_STORE_RECORDS,
                MIN_DEDUP_STORE_BYTES - 1,
                MIN_DEDUP_STORE_RETENTION,
            ),
            Err(DedupStoreLimitsError::Bytes)
        );
        assert_eq!(
            DedupStoreLimits::new(
                MIN_DEDUP_STORE_RECORDS,
                MIN_DEDUP_STORE_BYTES,
                Duration::from_secs(MIN_DEDUP_STORE_RETENTION.as_secs() - 1),
            ),
            Err(DedupStoreLimitsError::Retention)
        );
    }

    #[test]
    fn validates_each_persistent_limit_dimension() {
        assert!(PersistentDeliveryLogLimits::default().records() > 0);
        assert!(
            PersistentDeliveryLogLimits::new(
                MIN_PERSISTENT_DELIVERY_LOG_RECORDS,
                MIN_PERSISTENT_DELIVERY_LOG_BYTES,
                MIN_PERSISTENT_DELIVERY_LOG_RETENTION,
            )
            .is_ok()
        );
        assert!(
            PersistentDeliveryLogLimits::new(
                MAX_PERSISTENT_DELIVERY_LOG_RECORDS,
                MAX_PERSISTENT_DELIVERY_LOG_BYTES,
                MAX_PERSISTENT_DELIVERY_LOG_RETENTION,
            )
            .is_ok()
        );
        assert_eq!(
            PersistentDeliveryLogLimits::new(
                MIN_PERSISTENT_DELIVERY_LOG_RECORDS - 1,
                MIN_PERSISTENT_DELIVERY_LOG_BYTES,
                MIN_PERSISTENT_DELIVERY_LOG_RETENTION,
            ),
            Err(PersistentDeliveryLogLimitsError::Records)
        );
        assert_eq!(
            PersistentDeliveryLogLimits::new(
                MIN_PERSISTENT_DELIVERY_LOG_RECORDS,
                MIN_PERSISTENT_DELIVERY_LOG_BYTES - 1,
                MIN_PERSISTENT_DELIVERY_LOG_RETENTION,
            ),
            Err(PersistentDeliveryLogLimitsError::Bytes)
        );
        assert_eq!(
            PersistentDeliveryLogLimits::new(
                MIN_PERSISTENT_DELIVERY_LOG_RECORDS,
                MIN_PERSISTENT_DELIVERY_LOG_BYTES,
                Duration::from_secs(MIN_PERSISTENT_DELIVERY_LOG_RETENTION.as_secs() - 1),
            ),
            Err(PersistentDeliveryLogLimitsError::Retention)
        );
    }
}
