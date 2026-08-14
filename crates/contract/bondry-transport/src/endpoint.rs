use std::fmt;

use http::Uri;
use thiserror::Error;

/// Maximum expanded endpoint length from the egress limits contract.
pub const MAX_NETWORK_ENDPOINT_BYTES: usize = 4 * 1024;

/// A network protocol supported by the transport contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NetworkScheme {
    /// Cleartext HTTP.
    Http,
    /// HTTP over TLS.
    Https,
    /// Cleartext WebSocket.
    WebSocket,
    /// WebSocket over TLS.
    WebSocketSecure,
}

impl NetworkScheme {
    /// Returns whether the scheme requires authenticated TLS.
    #[must_use]
    pub const fn requires_tls(self) -> bool {
        matches!(self, Self::Https | Self::WebSocketSecure)
    }

    /// Returns the default port for the scheme.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http | Self::WebSocket => 80,
            Self::Https | Self::WebSocketSecure => 443,
        }
    }

    /// Returns the URI spelling of the scheme.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::WebSocket => "ws",
            Self::WebSocketSecure => "wss",
        }
    }
}

/// A validated HTTP or WebSocket endpoint.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct NetworkEndpoint {
    uri: Uri,
    scheme: NetworkScheme,
}

impl NetworkEndpoint {
    /// Validates an absolute URI with no user information.
    pub fn new(uri: Uri) -> Result<Self, EndpointError> {
        if uri.to_string().len() > MAX_NETWORK_ENDPOINT_BYTES {
            return Err(EndpointError::TooLong);
        }
        let scheme = match uri.scheme_str() {
            Some("http") => NetworkScheme::Http,
            Some("https") => NetworkScheme::Https,
            Some("ws") => NetworkScheme::WebSocket,
            Some("wss") => NetworkScheme::WebSocketSecure,
            _ => return Err(EndpointError::UnsupportedScheme),
        };
        let authority = uri.authority().ok_or(EndpointError::MissingAuthority)?;
        if authority.host().is_empty() {
            return Err(EndpointError::MissingAuthority);
        }
        if uri.port_u16() == Some(0) {
            return Err(EndpointError::InvalidPort);
        }
        if authority.as_str().contains('@') {
            return Err(EndpointError::UserInformation);
        }
        Ok(Self { uri, scheme })
    }

    /// Returns the complete URI for transport submission.
    #[must_use]
    pub const fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Returns the endpoint scheme.
    #[must_use]
    pub const fn scheme(&self) -> NetworkScheme {
        self.scheme
    }

    /// Returns the host used for TLS identity and connection establishment.
    #[must_use]
    pub fn host(&self) -> &str {
        self.uri.host().unwrap_or_default()
    }

    /// Returns the explicit or scheme-default port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.uri.port_u16().unwrap_or(self.scheme.default_port())
    }

    /// Returns the path and optional query used as the request target.
    #[must_use]
    pub fn path_and_query(&self) -> &str {
        self.uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str)
    }

    fn redacted_origin(&self) -> String {
        let port = self
            .uri
            .port_u16()
            .map_or_else(String::new, |port| format!(":{port}"));
        format!("{}://{}{}", self.scheme.as_str(), self.host(), port)
    }
}

impl fmt::Debug for NetworkEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NetworkEndpoint")
            .field("origin", &self.redacted_origin())
            .field("path_and_query", &"[REDACTED]")
            .finish()
    }
}

/// An invalid transport endpoint.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EndpointError {
    /// The expanded endpoint exceeds the limits contract.
    #[error("endpoint exceeds the maximum length")]
    TooLong,
    /// The URI scheme is absent or unsupported.
    #[error("unsupported endpoint scheme")]
    UnsupportedScheme,
    /// The URI has no network authority.
    #[error("endpoint authority is required")]
    MissingAuthority,
    /// Credentials are forbidden in endpoint authorities.
    #[error("endpoint user information is forbidden")]
    UserInformation,
    /// Port zero cannot identify a remote service.
    #[error("endpoint port must be nonzero")]
    InvalidPort,
}

#[cfg(test)]
mod tests {
    use super::{EndpointError, NetworkEndpoint, NetworkScheme};

    #[test]
    fn accepts_supported_absolute_endpoints() {
        let endpoint = NetworkEndpoint::new(
            "https://example.com:8443/private?token=value"
                .parse()
                .unwrap_or_else(|error| unreachable!("valid URI: {error}")),
        )
        .unwrap_or_else(|error| unreachable!("valid endpoint: {error}"));
        assert_eq!(endpoint.scheme(), NetworkScheme::Https);
        assert_eq!(endpoint.host(), "example.com");
        assert_eq!(endpoint.port(), 8443);
        assert_eq!(endpoint.path_and_query(), "/private?token=value");
        assert!(!format!("{endpoint:?}").contains("token=value"));
    }

    #[test]
    fn rejects_relative_and_credentialed_endpoints() {
        let relative = "/path"
            .parse()
            .unwrap_or_else(|error| unreachable!("valid relative URI: {error}"));
        assert_eq!(
            NetworkEndpoint::new(relative),
            Err(EndpointError::UnsupportedScheme)
        );
        let credentialed = "https://user@example.com/path"
            .parse()
            .unwrap_or_else(|error| unreachable!("valid URI syntax: {error}"));
        assert_eq!(
            NetworkEndpoint::new(credentialed),
            Err(EndpointError::UserInformation)
        );
        let oversized = format!("https://example.com/{}", "a".repeat(4 * 1024))
            .parse()
            .unwrap_or_else(|error| unreachable!("valid URI syntax: {error}"));
        assert_eq!(NetworkEndpoint::new(oversized), Err(EndpointError::TooLong));
        let zero_port = "https://example.com:0/"
            .parse()
            .unwrap_or_else(|error| unreachable!("valid URI syntax: {error}"));
        assert_eq!(
            NetworkEndpoint::new(zero_port),
            Err(EndpointError::InvalidPort)
        );
    }
}
