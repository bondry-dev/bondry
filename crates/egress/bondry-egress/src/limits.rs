use std::time::Duration;

use thiserror::Error;

/// Default simultaneously registered routes.
pub const DEFAULT_ROUTE_REGISTRY_LIMIT: u16 = 64;
const MIN_ROUTE_REGISTRY_LIMIT: u16 = 1;
const MAX_ROUTE_REGISTRY_LIMIT: u16 = 256;
/// Default event payload maximum.
pub const DEFAULT_EVENT_PAYLOAD_BYTES: usize = 16 * 1024;
const MIN_EVENT_PAYLOAD_BYTES: usize = 1024;
/// Maximum event payload from the limits contract.
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 224 * 1024;
/// Fixed maximum number of declared top-level payload fields.
pub const MAX_PAYLOAD_FIELDS: usize = 64;
/// Fixed maximum encoded payload field-name length.
pub const MAX_PAYLOAD_FIELD_NAME_BYTES: usize = 128;
/// Fixed maximum JSON container nesting depth.
pub const MAX_JSON_NESTING_DEPTH: usize = 32;
/// Default global admission refill rate.
pub const DEFAULT_GLOBAL_ADMISSION_REFILL_PER_SECOND: u16 = 200;
/// Default global admission burst capacity.
pub const DEFAULT_GLOBAL_ADMISSION_CAPACITY: u16 = 512;
const MIN_GLOBAL_ADMISSION_REFILL_PER_SECOND: u16 = 1;
const MAX_GLOBAL_ADMISSION_REFILL_PER_SECOND: u16 = 1_000;
const MIN_GLOBAL_ADMISSION_CAPACITY: u16 = 64;
const MAX_GLOBAL_ADMISSION_CAPACITY: u16 = 1_024;
/// Default per-route admission refill rate.
pub const DEFAULT_ROUTE_ADMISSION_REFILL_PER_SECOND: u16 = 50;
/// Default per-route admission burst capacity.
pub const DEFAULT_ROUTE_ADMISSION_CAPACITY: u16 = 64;
const MIN_ROUTE_ADMISSION_REFILL_PER_SECOND: u16 = 1;
const MAX_ROUTE_ADMISSION_REFILL_PER_SECOND: u16 = 500;
const MIN_ROUTE_ADMISSION_CAPACITY: u16 = 8;
const MAX_ROUTE_ADMISSION_CAPACITY: u16 = 256;
/// Default retry count after the initial attempt.
pub const DEFAULT_RETRY_ATTEMPTS: u8 = 5;
const MAX_RETRY_ATTEMPTS: u8 = 16;
/// Default deadline for one delivery attempt.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_REQUEST_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_RETRY_BASE: Duration = Duration::from_secs(1);
const DEFAULT_RETRY_CAP: Duration = Duration::from_secs(60);
const MIN_RETRY_BASE: Duration = Duration::from_millis(500);
const MAX_RETRY_BASE: Duration = Duration::from_secs(5);
const MIN_RETRY_CAP: Duration = Duration::from_secs(30);
const MAX_RETRY_CAP: Duration = Duration::from_secs(300);

/// Validated route registry capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteRegistryLimit(u16);

impl RouteRegistryLimit {
    /// Creates a route capacity inside the limits contract.
    pub const fn new(value: u16) -> Result<Self, LimitError> {
        if value < MIN_ROUTE_REGISTRY_LIMIT || value > MAX_ROUTE_REGISTRY_LIMIT {
            return Err(LimitError::RouteRegistry);
        }
        Ok(Self(value))
    }

    /// Returns the route capacity.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl Default for RouteRegistryLimit {
    fn default() -> Self {
        Self(DEFAULT_ROUTE_REGISTRY_LIMIT)
    }
}

/// Validated maximum event payload bytes for one route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PayloadLimit(usize);

impl PayloadLimit {
    /// Creates a payload limit inside the limits contract.
    pub const fn new(value: usize) -> Result<Self, LimitError> {
        if value < MIN_EVENT_PAYLOAD_BYTES || value > MAX_EVENT_PAYLOAD_BYTES {
            return Err(LimitError::Payload);
        }
        Ok(Self(value))
    }

    /// Returns the maximum encoded payload bytes.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }
}

impl Default for PayloadLimit {
    fn default() -> Self {
        Self(DEFAULT_EVENT_PAYLOAD_BYTES)
    }
}

macro_rules! admission_limit {
    (
        $name:ident,
        $default_refill:ident,
        $default_capacity:ident,
        $min_refill:ident,
        $max_refill:ident,
        $min_capacity:ident,
        $max_capacity:ident,
        $error:ident,
        $documentation:literal
    ) => {
        #[doc = $documentation]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name {
            refill_per_second: u16,
            capacity: u16,
        }

        impl $name {
            /// Creates a token-bucket policy inside the limits contract.
            pub const fn new(refill_per_second: u16, capacity: u16) -> Result<Self, LimitError> {
                if refill_per_second < $min_refill
                    || refill_per_second > $max_refill
                    || capacity < $min_capacity
                    || capacity > $max_capacity
                {
                    return Err(LimitError::$error);
                }
                Ok(Self {
                    refill_per_second,
                    capacity,
                })
            }

            /// Returns tokens replenished per second.
            #[must_use]
            pub const fn refill_per_second(self) -> u16 {
                self.refill_per_second
            }

            /// Returns maximum burst tokens.
            #[must_use]
            pub const fn capacity(self) -> u16 {
                self.capacity
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self {
                    refill_per_second: $default_refill,
                    capacity: $default_capacity,
                }
            }
        }
    };
}

admission_limit!(
    GlobalAdmissionLimit,
    DEFAULT_GLOBAL_ADMISSION_REFILL_PER_SECOND,
    DEFAULT_GLOBAL_ADMISSION_CAPACITY,
    MIN_GLOBAL_ADMISSION_REFILL_PER_SECOND,
    MAX_GLOBAL_ADMISSION_REFILL_PER_SECOND,
    MIN_GLOBAL_ADMISSION_CAPACITY,
    MAX_GLOBAL_ADMISSION_CAPACITY,
    GlobalAdmission,
    "Validated process-wide emit admission policy."
);
admission_limit!(
    RouteAdmissionLimit,
    DEFAULT_ROUTE_ADMISSION_REFILL_PER_SECOND,
    DEFAULT_ROUTE_ADMISSION_CAPACITY,
    MIN_ROUTE_ADMISSION_REFILL_PER_SECOND,
    MAX_ROUTE_ADMISSION_REFILL_PER_SECOND,
    MIN_ROUTE_ADMISSION_CAPACITY,
    MAX_ROUTE_ADMISSION_CAPACITY,
    RouteAdmission,
    "Validated per-route emit admission policy."
);

/// Validated bounded exponential retry policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    retries: u8,
    base: Duration,
    cap: Duration,
}

impl RetryPolicy {
    /// Creates a retry policy inside the limits contract.
    pub fn new(retries: u8, base: Duration, cap: Duration) -> Result<Self, LimitError> {
        if retries > MAX_RETRY_ATTEMPTS {
            return Err(LimitError::RetryAttempts);
        }
        if !(MIN_RETRY_BASE..=MAX_RETRY_BASE).contains(&base) {
            return Err(LimitError::RetryBase);
        }
        if !(MIN_RETRY_CAP..=MAX_RETRY_CAP).contains(&cap) {
            return Err(LimitError::RetryCap);
        }
        Ok(Self { retries, base, cap })
    }

    /// Creates the fixed no-retry policy used by host calls.
    #[must_use]
    pub const fn without_retries() -> Self {
        Self {
            retries: 0,
            base: DEFAULT_RETRY_BASE,
            cap: DEFAULT_RETRY_CAP,
        }
    }

    /// Returns retries allowed after the initial attempt.
    #[must_use]
    pub const fn retries(self) -> u8 {
        self.retries
    }

    /// Returns the exponential backoff base.
    #[must_use]
    pub const fn base(self) -> Duration {
        self.base
    }

    /// Returns the exponential backoff cap.
    #[must_use]
    pub const fn cap(self) -> Duration {
        self.cap
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            retries: DEFAULT_RETRY_ATTEMPTS,
            base: DEFAULT_RETRY_BASE,
            cap: DEFAULT_RETRY_CAP,
        }
    }
}

/// Validated deadline duration for one delivery attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestTimeout(Duration);

impl RequestTimeout {
    /// Creates an attempt timeout inside the limits contract.
    pub fn new(value: Duration) -> Result<Self, LimitError> {
        if !(MIN_REQUEST_TIMEOUT..=MAX_REQUEST_TIMEOUT).contains(&value) {
            return Err(LimitError::RequestTimeout);
        }
        Ok(Self(value))
    }

    /// Returns the configured timeout duration.
    #[must_use]
    pub const fn get(self) -> Duration {
        self.0
    }
}

impl Default for RequestTimeout {
    fn default() -> Self {
        Self(DEFAULT_REQUEST_TIMEOUT)
    }
}

/// A configuration value outside the limits contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LimitError {
    /// Route registry capacity is outside its range.
    #[error("route registry capacity is outside the allowed range")]
    RouteRegistry,
    /// Event payload size is outside its range.
    #[error("event payload limit is outside the allowed range")]
    Payload,
    /// Global token-bucket values are outside their ranges.
    #[error("global admission limit is outside the allowed range")]
    GlobalAdmission,
    /// Per-route token-bucket values are outside their ranges.
    #[error("route admission limit is outside the allowed range")]
    RouteAdmission,
    /// Retry count exceeds the contract maximum.
    #[error("retry attempts exceed the allowed range")]
    RetryAttempts,
    /// Retry base violates the safety-critical range.
    #[error("retry backoff base is outside the allowed range")]
    RetryBase,
    /// Retry cap violates the safety-critical range.
    #[error("retry backoff cap is outside the allowed range")]
    RetryCap,
    /// Request timeout is outside its contract range.
    #[error("request timeout is outside the allowed range")]
    RequestTimeout,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        GlobalAdmissionLimit, LimitError, PayloadLimit, RequestTimeout, RetryPolicy,
        RouteAdmissionLimit, RouteRegistryLimit,
    };

    #[test]
    fn validates_limit_boundaries() {
        assert!(RouteRegistryLimit::new(1).is_ok());
        assert_eq!(RouteRegistryLimit::new(0), Err(LimitError::RouteRegistry));
        assert!(PayloadLimit::new(224 * 1024).is_ok());
        assert_eq!(PayloadLimit::new(224 * 1024 + 1), Err(LimitError::Payload));
        assert!(GlobalAdmissionLimit::new(1_000, 1_024).is_ok());
        assert_eq!(
            GlobalAdmissionLimit::new(1_001, 1_024),
            Err(LimitError::GlobalAdmission)
        );
        assert!(RouteAdmissionLimit::new(500, 256).is_ok());
        assert_eq!(
            RouteAdmissionLimit::new(500, 257),
            Err(LimitError::RouteAdmission)
        );
        assert!(RetryPolicy::new(16, Duration::from_millis(500), Duration::from_secs(300)).is_ok());
        assert_eq!(
            RetryPolicy::new(17, Duration::from_secs(1), Duration::from_secs(60)),
            Err(LimitError::RetryAttempts)
        );
        assert!(RequestTimeout::new(Duration::from_secs(1)).is_ok());
        assert!(RequestTimeout::new(Duration::from_secs(120)).is_ok());
        assert_eq!(
            RequestTimeout::new(Duration::from_millis(999)),
            Err(LimitError::RequestTimeout)
        );
    }
}
