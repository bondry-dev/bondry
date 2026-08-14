use std::fmt;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use thiserror::Error;

use crate::{
    Deadline, EndpointPolicy, NetworkEndpoint, NetworkScheme, PolicyError, TransportFuture,
    VerifiedConnection,
};

/// Maximum request body from the egress limits contract.
pub const MAX_HTTP_REQUEST_BODY_BYTES: usize = 256 * 1024;
/// Fixed maximum aggregate header size for requests and responses.
pub const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
/// Fixed maximum header count for requests and responses.
pub const MAX_HTTP_HEADERS: usize = 64;
/// Minimum configurable response body size.
pub const MIN_HTTP_RESPONSE_BODY_BYTES: usize = 4 * 1024;
/// Maximum configurable response body size.
pub const MAX_HTTP_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_HTTP_RESPONSE_BODY_BYTES: usize = 64 * 1024;

/// Per-request HTTP response limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpLimits {
    max_response_body_bytes: usize,
}

impl HttpLimits {
    /// Configures a response body bound inside the limits contract.
    pub const fn new(max_response_body_bytes: usize) -> Result<Self, TransportError> {
        if max_response_body_bytes < MIN_HTTP_RESPONSE_BODY_BYTES
            || max_response_body_bytes > MAX_HTTP_RESPONSE_BODY_BYTES
        {
            return Err(TransportError::InvalidLimits);
        }
        Ok(Self {
            max_response_body_bytes,
        })
    }

    /// Returns the response body cap.
    #[must_use]
    pub const fn max_response_body_bytes(self) -> usize {
        self.max_response_body_bytes
    }
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            max_response_body_bytes: DEFAULT_HTTP_RESPONSE_BODY_BYTES,
        }
    }
}

/// A bounded one-shot HTTP request.
pub struct HttpRequest {
    method: Method,
    endpoint: NetworkEndpoint,
    headers: HeaderMap,
    body: Bytes,
    deadline: Deadline,
    policy: EndpointPolicy,
    limits: HttpLimits,
}

impl HttpRequest {
    /// Validates request bounds and the endpoint protocol.
    pub fn new(
        method: Method,
        endpoint: NetworkEndpoint,
        headers: HeaderMap,
        body: Bytes,
        deadline: Deadline,
        policy: EndpointPolicy,
        limits: HttpLimits,
    ) -> Result<Self, TransportError> {
        if !matches!(
            endpoint.scheme(),
            NetworkScheme::Http | NetworkScheme::Https
        ) {
            return Err(TransportError::UnsupportedEndpoint);
        }
        if body.len() > MAX_HTTP_REQUEST_BODY_BYTES {
            return Err(TransportError::RequestTooLarge);
        }
        validate_headers(&headers, TransportError::RequestTooLarge)?;
        Ok(Self {
            method,
            endpoint,
            headers,
            body,
            deadline,
            policy,
            limits,
        })
    }

    /// Returns the endpoint without exposing it through debug output.
    #[must_use]
    pub const fn endpoint(&self) -> &NetworkEndpoint {
        &self.endpoint
    }

    /// Returns the endpoint policy.
    #[must_use]
    pub const fn policy(&self) -> &EndpointPolicy {
        &self.policy
    }

    /// Returns the absolute deadline.
    #[must_use]
    pub const fn deadline(&self) -> Deadline {
        self.deadline
    }

    /// Moves the validated request into implementation-facing parts.
    #[must_use]
    pub fn into_parts(self) -> HttpRequestParts {
        HttpRequestParts {
            method: self.method,
            endpoint: self.endpoint,
            headers: self.headers,
            body: self.body,
            deadline: self.deadline,
            policy: self.policy,
            limits: self.limits,
        }
    }
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("endpoint", &self.endpoint)
            .field("headers", &"[REDACTED]")
            .field("body_bytes", &self.body.len())
            .field("deadline", &self.deadline)
            .field("policy", &self.policy)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Validated request fields consumed by an implementation.
pub struct HttpRequestParts {
    /// HTTP method.
    pub method: Method,
    /// Validated endpoint.
    pub endpoint: NetworkEndpoint,
    /// Bounded request headers.
    pub headers: HeaderMap,
    /// Bounded exact body bytes.
    pub body: Bytes,
    /// Absolute deadline.
    pub deadline: Deadline,
    /// Connection-time endpoint policy.
    pub policy: EndpointPolicy,
    /// Response limits.
    pub limits: HttpLimits,
}

/// A bounded response with verified connection metadata.
pub struct HttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    connection: VerifiedConnection,
}

impl HttpResponse {
    /// Validates the response against the request's configured limits.
    pub fn new(
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
        connection: VerifiedConnection,
        limits: HttpLimits,
    ) -> Result<Self, TransportError> {
        validate_headers(&headers, TransportError::ResponseTooLarge)?;
        if body.len() > limits.max_response_body_bytes() {
            return Err(TransportError::ResponseTooLarge);
        }
        Ok(Self {
            status,
            headers,
            body,
            connection,
        })
    }

    /// Returns the response status.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the bounded headers.
    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the bounded exact body.
    #[must_use]
    pub const fn body(&self) -> &Bytes {
        &self.body
    }

    /// Returns the connection evidence accepted by policy.
    #[must_use]
    pub const fn connection(&self) -> &VerifiedConnection {
        &self.connection
    }
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &"[REDACTED]")
            .field("body_bytes", &self.body.len())
            .field("connection", &self.connection)
            .finish()
    }
}

/// One-shot HTTP transport implemented by Rust networking or a host callback.
pub trait HttpTransport: Send + Sync {
    /// Sends one validated request before its absolute deadline.
    fn send(
        &self,
        request: HttpRequest,
    ) -> TransportFuture<'_, Result<HttpResponse, TransportError>>;
}

/// A stable, non-sensitive transport failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TransportError {
    /// Request or response limits are outside the limits contract.
    #[error("invalid transport limits")]
    InvalidLimits,
    /// The endpoint protocol is unsupported by this transport.
    #[error("unsupported transport endpoint")]
    UnsupportedEndpoint,
    /// The bounded request is too large.
    #[error("transport request is too large")]
    RequestTooLarge,
    /// The response exceeded a declared bound.
    #[error("transport response is too large")]
    ResponseTooLarge,
    /// Endpoint policy rejected the established connection.
    #[error("transport endpoint policy rejected the connection")]
    Policy(PolicyError),
    /// No connection completed before the deadline.
    #[error("transport deadline exceeded")]
    DeadlineExceeded,
    /// Name resolution or connection establishment failed.
    #[error("transport connection failed")]
    ConnectionFailed,
    /// TLS setup, identity, or chain validation failed.
    #[error("transport TLS validation failed")]
    TlsFailed,
    /// The peer produced malformed HTTP.
    #[error("transport received an invalid response")]
    InvalidResponse,
    /// A caller supplied a malformed protocol message.
    #[error("transport message is invalid")]
    InvalidMessage,
}

impl From<PolicyError> for TransportError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

pub(crate) fn validate_headers(
    headers: &HeaderMap,
    overflow: TransportError,
) -> Result<(), TransportError> {
    if headers.len() > MAX_HTTP_HEADERS {
        return Err(overflow);
    }
    let bytes = headers.iter().fold(0_usize, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
            .saturating_add(4)
    });
    if bytes > MAX_HTTP_HEADER_BYTES {
        return Err(overflow);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use http::{HeaderMap, HeaderName, HeaderValue, Method};

    use super::{
        HttpLimits, HttpRequest, MAX_HTTP_HEADERS, MAX_HTTP_REQUEST_BODY_BYTES,
        MAX_HTTP_RESPONSE_BODY_BYTES, TransportError,
    };
    use crate::{Deadline, EndpointPolicy, NetworkEndpoint};

    fn endpoint(value: &str) -> NetworkEndpoint {
        NetworkEndpoint::new(
            value
                .parse()
                .unwrap_or_else(|error| unreachable!("valid URI: {error}")),
        )
        .unwrap_or_else(|error| unreachable!("valid endpoint: {error}"))
    }

    #[test]
    fn validates_request_and_response_bounds() {
        let deadline = Deadline::at(Instant::now() + Duration::from_secs(1));
        assert!(
            HttpRequest::new(
                Method::POST,
                endpoint("https://example.com"),
                HeaderMap::new(),
                Bytes::from(vec![0; MAX_HTTP_REQUEST_BODY_BYTES]),
                deadline,
                EndpointPolicy::default(),
                HttpLimits::default(),
            )
            .is_ok()
        );
        assert!(matches!(
            HttpRequest::new(
                Method::POST,
                endpoint("https://example.com"),
                HeaderMap::new(),
                Bytes::from(vec![0; MAX_HTTP_REQUEST_BODY_BYTES + 1]),
                deadline,
                EndpointPolicy::default(),
                HttpLimits::default(),
            ),
            Err(TransportError::RequestTooLarge)
        ));
        assert_eq!(
            HttpLimits::new(MAX_HTTP_RESPONSE_BODY_BYTES + 1),
            Err(TransportError::InvalidLimits)
        );

        let mut headers = HeaderMap::new();
        for index in 0..=MAX_HTTP_HEADERS {
            let name = HeaderName::from_bytes(format!("x-bound-{index}").as_bytes())
                .unwrap_or_else(|error| unreachable!("valid fixture header: {error}"));
            headers.insert(name, HeaderValue::from_static("value"));
        }
        assert!(matches!(
            HttpRequest::new(
                Method::GET,
                endpoint("https://example.com"),
                headers,
                Bytes::new(),
                deadline,
                EndpointPolicy::default(),
                HttpLimits::default(),
            ),
            Err(TransportError::RequestTooLarge)
        ));
    }

    #[test]
    fn rejects_websocket_endpoint_for_http() {
        let result = HttpRequest::new(
            Method::GET,
            endpoint("wss://example.com"),
            HeaderMap::new(),
            Bytes::new(),
            Deadline::at(Instant::now() + Duration::from_secs(1)),
            EndpointPolicy::default(),
            HttpLimits::default(),
        );
        assert!(matches!(result, Err(TransportError::UnsupportedEndpoint)));
    }
}
