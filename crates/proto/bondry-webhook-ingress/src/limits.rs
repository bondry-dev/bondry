use thiserror::Error;

/// Default maximum exact raw webhook body size.
pub const DEFAULT_WEBHOOK_BODY_BYTES: usize = 1_048_576;
/// Minimum configurable exact raw webhook body size.
pub const MIN_WEBHOOK_BODY_BYTES: usize = 1_024;
/// Maximum configurable exact raw webhook body size.
pub const MAX_WEBHOOK_BODY_BYTES: usize = 4 * 1_048_576;
/// Default retained-byte budget for one webhook request lifecycle.
pub const DEFAULT_WEBHOOK_RETAINED_BYTES: usize = 3 * 1_048_576;
/// Maximum retained-byte budget for one webhook request lifecycle.
pub const MAX_WEBHOOK_RETAINED_BYTES: usize = 10 * 1_048_576;

/// Validated raw-body and retained-memory limits for one webhook route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebhookIngressLimits {
    body_bytes: usize,
    retained_bytes: usize,
}

impl WebhookIngressLimits {
    /// Creates limits within the accepted ingress ranges.
    pub const fn new(
        body_bytes: usize,
        retained_bytes: usize,
    ) -> Result<Self, WebhookIngressLimitError> {
        if body_bytes < MIN_WEBHOOK_BODY_BYTES || body_bytes > MAX_WEBHOOK_BODY_BYTES {
            return Err(WebhookIngressLimitError::InvalidBodyBytes);
        }
        if retained_bytes < body_bytes || retained_bytes > MAX_WEBHOOK_RETAINED_BYTES {
            return Err(WebhookIngressLimitError::InvalidRetainedBytes);
        }
        Ok(Self {
            body_bytes,
            retained_bytes,
        })
    }

    /// Returns the exact raw-body limit.
    #[must_use]
    pub const fn body_bytes(self) -> usize {
        self.body_bytes
    }

    /// Returns the retained-memory budget for raw and mapped payload data.
    #[must_use]
    pub const fn retained_bytes(self) -> usize {
        self.retained_bytes
    }
}

impl Default for WebhookIngressLimits {
    fn default() -> Self {
        Self {
            body_bytes: DEFAULT_WEBHOOK_BODY_BYTES,
            retained_bytes: DEFAULT_WEBHOOK_RETAINED_BYTES,
        }
    }
}

/// A webhook route limit outside the accepted contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WebhookIngressLimitError {
    /// The exact body limit is outside 1 KiB through 4 MiB.
    #[error("webhook body limit is outside the accepted range")]
    InvalidBodyBytes,
    /// The retained budget is smaller than the body limit or above 10 MiB.
    #[error("webhook retained-byte limit is outside the accepted range")]
    InvalidRetainedBytes,
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_WEBHOOK_BODY_BYTES, MAX_WEBHOOK_RETAINED_BYTES, MIN_WEBHOOK_BODY_BYTES,
        WebhookIngressLimitError, WebhookIngressLimits,
    };

    #[test]
    fn enforces_body_and_retained_ranges() {
        assert!(WebhookIngressLimits::new(MIN_WEBHOOK_BODY_BYTES, MIN_WEBHOOK_BODY_BYTES).is_ok());
        assert!(
            WebhookIngressLimits::new(MAX_WEBHOOK_BODY_BYTES, MAX_WEBHOOK_RETAINED_BYTES).is_ok()
        );
        assert_eq!(
            WebhookIngressLimits::new(MIN_WEBHOOK_BODY_BYTES - 1, MIN_WEBHOOK_BODY_BYTES),
            Err(WebhookIngressLimitError::InvalidBodyBytes)
        );
        assert_eq!(
            WebhookIngressLimits::new(MAX_WEBHOOK_BODY_BYTES, MAX_WEBHOOK_BODY_BYTES - 1),
            Err(WebhookIngressLimitError::InvalidRetainedBytes)
        );
    }
}
