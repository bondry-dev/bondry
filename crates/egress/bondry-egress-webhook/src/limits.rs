use bondry_transport::{HttpLimits, MAX_HTTP_REQUEST_BODY_BYTES, MAX_NETWORK_ENDPOINT_BYTES};
use thiserror::Error;

/// Default maximum exact webhook body size.
pub const DEFAULT_WEBHOOK_BODY_BYTES: usize = 32 * 1024;
/// Minimum configurable exact webhook body size.
pub const MIN_WEBHOOK_BODY_BYTES: usize = 1024;
/// Maximum configurable exact webhook body size.
pub const MAX_WEBHOOK_BODY_BYTES: usize = MAX_HTTP_REQUEST_BODY_BYTES;
/// Default maximum redacted URL-template size.
pub const DEFAULT_URL_TEMPLATE_BYTES: usize = 1024;
/// Maximum configurable redacted URL-template size.
pub const MAX_URL_TEMPLATE_BYTES: usize = 2 * 1024;
/// Default maximum expanded URL size.
pub const DEFAULT_EXPANDED_URL_BYTES: usize = 2 * 1024;
/// Maximum configurable expanded URL size.
pub const MAX_EXPANDED_URL_BYTES: usize = MAX_NETWORK_ENDPOINT_BYTES;

/// Validated URL-template limits from the egress contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UrlTemplateLimits {
    template_bytes: usize,
    expanded_bytes: usize,
}

impl UrlTemplateLimits {
    /// Creates template and expanded URL limits inside their allowed ranges.
    pub const fn new(
        template_bytes: usize,
        expanded_bytes: usize,
    ) -> Result<Self, WebhookLimitError> {
        if template_bytes == 0 || template_bytes > MAX_URL_TEMPLATE_BYTES {
            return Err(WebhookLimitError::UrlTemplate);
        }
        if expanded_bytes == 0 || expanded_bytes > MAX_EXPANDED_URL_BYTES {
            return Err(WebhookLimitError::ExpandedUrl);
        }
        Ok(Self {
            template_bytes,
            expanded_bytes,
        })
    }

    /// Returns the redacted template byte limit.
    #[must_use]
    pub const fn template_bytes(self) -> usize {
        self.template_bytes
    }

    /// Returns the expanded URL byte limit.
    #[must_use]
    pub const fn expanded_bytes(self) -> usize {
        self.expanded_bytes
    }
}

impl Default for UrlTemplateLimits {
    fn default() -> Self {
        Self {
            template_bytes: DEFAULT_URL_TEMPLATE_BYTES,
            expanded_bytes: DEFAULT_EXPANDED_URL_BYTES,
        }
    }
}

/// Validated request and response bounds for a webhook route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebhookLimits {
    body_bytes: usize,
    response: HttpLimits,
}

impl WebhookLimits {
    /// Creates webhook limits and delegates response bounds to the transport contract.
    pub fn new(body_bytes: usize, response_body_bytes: usize) -> Result<Self, WebhookLimitError> {
        if !(MIN_WEBHOOK_BODY_BYTES..=MAX_WEBHOOK_BODY_BYTES).contains(&body_bytes) {
            return Err(WebhookLimitError::Body);
        }
        let response =
            HttpLimits::new(response_body_bytes).map_err(|_| WebhookLimitError::ResponseBody)?;
        Ok(Self {
            body_bytes,
            response,
        })
    }

    /// Returns the exact request body cap.
    #[must_use]
    pub const fn body_bytes(self) -> usize {
        self.body_bytes
    }

    /// Returns transport-level response limits.
    #[must_use]
    pub const fn response(self) -> HttpLimits {
        self.response
    }
}

impl Default for WebhookLimits {
    fn default() -> Self {
        Self {
            body_bytes: DEFAULT_WEBHOOK_BODY_BYTES,
            response: HttpLimits::default(),
        }
    }
}

/// A webhook limit outside the accepted contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WebhookLimitError {
    /// Exact body bytes are outside 1 KiB through 256 KiB.
    #[error("webhook body limit is outside the allowed range")]
    Body,
    /// Response body bytes violate the transport range.
    #[error("webhook response body limit is outside the allowed range")]
    ResponseBody,
    /// Redacted template bytes exceed 2 KiB or are empty.
    #[error("URL template limit is outside the allowed range")]
    UrlTemplate,
    /// Expanded URL bytes exceed 4 KiB or are empty.
    #[error("expanded URL limit is outside the allowed range")]
    ExpandedUrl,
}

#[cfg(test)]
mod tests {
    use bondry_transport::{MAX_HTTP_RESPONSE_BODY_BYTES, MIN_HTTP_RESPONSE_BODY_BYTES};

    use super::{
        MAX_EXPANDED_URL_BYTES, MAX_URL_TEMPLATE_BYTES, MAX_WEBHOOK_BODY_BYTES,
        MIN_WEBHOOK_BODY_BYTES, UrlTemplateLimits, WebhookLimitError, WebhookLimits,
    };

    #[test]
    fn validates_all_limit_boundaries() {
        assert!(WebhookLimits::new(MIN_WEBHOOK_BODY_BYTES, MIN_HTTP_RESPONSE_BODY_BYTES).is_ok());
        assert!(WebhookLimits::new(MAX_WEBHOOK_BODY_BYTES, MAX_HTTP_RESPONSE_BODY_BYTES).is_ok());
        assert_eq!(
            WebhookLimits::new(MIN_WEBHOOK_BODY_BYTES - 1, MIN_HTTP_RESPONSE_BODY_BYTES),
            Err(WebhookLimitError::Body)
        );
        assert!(UrlTemplateLimits::new(MAX_URL_TEMPLATE_BYTES, MAX_EXPANDED_URL_BYTES).is_ok());
        assert_eq!(
            UrlTemplateLimits::new(MAX_URL_TEMPLATE_BYTES + 1, MAX_EXPANDED_URL_BYTES),
            Err(WebhookLimitError::UrlTemplate)
        );
    }
}
