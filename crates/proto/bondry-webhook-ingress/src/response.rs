use http::StatusCode;

/// Status-only ingress response with one optional safe error code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebhookIngressResponse {
    status: StatusCode,
    retry_after_seconds: Option<u64>,
    error_code: Option<&'static str>,
}

impl WebhookIngressResponse {
    pub(crate) const fn success(status: StatusCode) -> Self {
        Self {
            status,
            retry_after_seconds: None,
            error_code: None,
        }
    }

    pub(crate) const fn error(status: StatusCode, error_code: &'static str) -> Self {
        Self {
            status,
            retry_after_seconds: None,
            error_code: Some(error_code),
        }
    }

    pub(crate) const fn retryable(
        status: StatusCode,
        error_code: &'static str,
        retry_after_seconds: u64,
    ) -> Self {
        Self {
            status,
            retry_after_seconds: Some(retry_after_seconds),
            error_code: Some(error_code),
        }
    }

    /// Returns the HTTP status.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        self.status
    }

    /// Returns a retry delay when retrying may make progress.
    #[must_use]
    pub const fn retry_after_seconds(self) -> Option<u64> {
        self.retry_after_seconds
    }

    /// Returns one stable non-sensitive error code.
    #[must_use]
    pub const fn error_code(self) -> Option<&'static str> {
        self.error_code
    }
}
