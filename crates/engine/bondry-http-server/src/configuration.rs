use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU32,
    time::Duration,
};

use http::{HeaderMap, HeaderValue, Uri, header};
use thiserror::Error;

use crate::Authentication;

const MAX_BODY_BYTES: usize = 8 * 1_048_576;
const MAX_CONNECTIONS: usize = 1_024;
const MAX_REQUESTS_PER_MINUTE: u32 = 60_000;
const MAX_TIMEOUT: Duration = Duration::from_secs(300);

/// Exact browser origins permitted to access the local server.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OriginPolicy {
    allowed: BTreeSet<HeaderValue>,
}

impl OriginPolicy {
    /// Rejects every request that contains an Origin header.
    #[must_use]
    pub const fn deny_browser_origins() -> Self {
        Self {
            allowed: BTreeSet::new(),
        }
    }

    /// Adds one exact serialized origin.
    pub fn allowing(mut self, origin: &str) -> Result<Self, OriginPolicyError> {
        let uri = origin.parse::<Uri>().map_err(|_| OriginPolicyError)?;
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || uri.authority().is_none()
            || origin.ends_with('/')
            || uri
                .path_and_query()
                .is_some_and(|path| path.as_str() != "/")
        {
            return Err(OriginPolicyError);
        }
        let value = HeaderValue::from_str(origin).map_err(|_| OriginPolicyError)?;
        self.allowed.insert(value);
        Ok(self)
    }

    pub(crate) fn permits(&self, headers: &HeaderMap) -> bool {
        let mut origins = headers.get_all(header::ORIGIN).iter();
        let Some(origin) = origins.next() else {
            return true;
        };
        origins.next().is_none() && self.allowed.contains(origin)
    }
}

/// An invalid browser origin policy value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("an allowed origin must be one serialized HTTP or HTTPS origin without a path")]
pub struct OriginPolicyError;

/// Per-principal request and per-address authentication-failure limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RateLimits {
    requests_per_minute: NonZeroU32,
    authentication_failures_per_minute: NonZeroU32,
}

impl RateLimits {
    /// Creates rate limits between one and 60,000 events per minute.
    pub const fn new(
        requests_per_minute: u32,
        authentication_failures_per_minute: u32,
    ) -> Result<Self, ServerConfigurationError> {
        let Some(requests_per_minute) = NonZeroU32::new(requests_per_minute) else {
            return Err(ServerConfigurationError::InvalidRateLimit);
        };
        let Some(authentication_failures_per_minute) =
            NonZeroU32::new(authentication_failures_per_minute)
        else {
            return Err(ServerConfigurationError::InvalidRateLimit);
        };
        if requests_per_minute.get() > MAX_REQUESTS_PER_MINUTE
            || authentication_failures_per_minute.get() > MAX_REQUESTS_PER_MINUTE
        {
            return Err(ServerConfigurationError::InvalidRateLimit);
        }
        Ok(Self {
            requests_per_minute,
            authentication_failures_per_minute,
        })
    }

    /// Returns the authenticated request limit per principal and minute.
    #[must_use]
    pub const fn requests_per_minute(self) -> u32 {
        self.requests_per_minute.get()
    }

    /// Returns the rejected-authentication limit per peer address and minute.
    #[must_use]
    pub const fn authentication_failures_per_minute(self) -> u32 {
        self.authentication_failures_per_minute.get()
    }
}

impl Default for RateLimits {
    fn default() -> Self {
        Self {
            requests_per_minute: NonZeroU32::new(120).unwrap_or(NonZeroU32::MIN),
            authentication_failures_per_minute: NonZeroU32::new(30).unwrap_or(NonZeroU32::MIN),
        }
    }
}

/// Shared local HTTP server configuration.
#[derive(Clone)]
pub struct ServerConfiguration {
    pub(crate) bind_address: IpAddr,
    pub(crate) port: u16,
    pub(crate) authentication: Authentication,
    pub(crate) origins: OriginPolicy,
    pub(crate) rate_limits: RateLimits,
    pub(crate) max_body_bytes: usize,
    pub(crate) max_connections: usize,
    pub(crate) header_read_timeout: Duration,
    pub(crate) request_timeout: Duration,
    pub(crate) shutdown_grace_period: Duration,
    pub(crate) allow_cleartext_network: bool,
    pub(crate) allow_unauthenticated_network: bool,
}

impl ServerConfiguration {
    /// Creates a localhost-only configuration on an operating-system-selected port.
    #[must_use]
    pub fn new(authentication: Authentication) -> Self {
        Self {
            bind_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 0,
            authentication,
            origins: OriginPolicy::default(),
            rate_limits: RateLimits::default(),
            max_body_bytes: 1_048_576,
            max_connections: 64,
            header_read_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            shutdown_grace_period: Duration::from_secs(2),
            allow_cleartext_network: false,
            allow_unauthenticated_network: false,
        }
    }

    /// Sets the listening IP address.
    #[must_use]
    pub const fn with_bind_address(mut self, address: IpAddr) -> Self {
        self.bind_address = address;
        self
    }

    /// Sets the listening port. Zero asks the operating system to select a free port.
    #[must_use]
    pub const fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Sets exact browser-origin policy.
    #[must_use]
    pub fn with_origin_policy(mut self, policy: OriginPolicy) -> Self {
        self.origins = policy;
        self
    }

    /// Sets request rate limits.
    #[must_use]
    pub const fn with_rate_limits(mut self, limits: RateLimits) -> Self {
        self.rate_limits = limits;
        self
    }

    /// Sets the maximum decoded request body size.
    pub fn with_max_body_bytes(mut self, bytes: usize) -> Result<Self, ServerConfigurationError> {
        if bytes == 0 || bytes > MAX_BODY_BYTES {
            return Err(ServerConfigurationError::InvalidBodyLimit);
        }
        self.max_body_bytes = bytes;
        Ok(self)
    }

    /// Sets the maximum concurrent connections.
    pub fn with_max_connections(
        mut self,
        connections: usize,
    ) -> Result<Self, ServerConfigurationError> {
        if connections == 0 || connections > MAX_CONNECTIONS {
            return Err(ServerConfigurationError::InvalidConnectionLimit);
        }
        self.max_connections = connections;
        Ok(self)
    }

    /// Sets header, request, and graceful-shutdown timeouts.
    pub fn with_timeouts(
        mut self,
        header_read: Duration,
        request: Duration,
        shutdown_grace_period: Duration,
    ) -> Result<Self, ServerConfigurationError> {
        if !valid_timeout(header_read)
            || !valid_timeout(request)
            || !valid_timeout(shutdown_grace_period)
        {
            return Err(ServerConfigurationError::InvalidTimeout);
        }
        self.header_read_timeout = header_read;
        self.request_timeout = request;
        self.shutdown_grace_period = shutdown_grace_period;
        Ok(self)
    }

    /// Explicitly permits disabled authentication on a non-loopback address.
    #[must_use]
    pub const fn allowing_unauthenticated_network(mut self) -> Self {
        self.allow_unauthenticated_network = true;
        self
    }

    /// Explicitly permits cleartext HTTP on a non-loopback address.
    #[must_use]
    pub const fn allowing_cleartext_network(mut self) -> Self {
        self.allow_cleartext_network = true;
        self
    }

    /// Returns the configured listening IP address.
    #[must_use]
    pub const fn bind_address(&self) -> IpAddr {
        self.bind_address
    }

    /// Returns the configured port, where zero means automatic selection.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns the request rate limits.
    #[must_use]
    pub const fn rate_limits(&self) -> RateLimits {
        self.rate_limits
    }

    pub(crate) fn validate(&self) -> Result<(), ServerConfigurationError> {
        if !self.bind_address.is_loopback() && !self.allow_cleartext_network {
            return Err(ServerConfigurationError::CleartextNetworkExposure);
        }
        if !self.bind_address.is_loopback()
            && self.authentication.is_disabled()
            && !self.allow_unauthenticated_network
        {
            return Err(ServerConfigurationError::UnauthenticatedNetworkExposure);
        }
        Ok(())
    }
}

fn valid_timeout(timeout: Duration) -> bool {
    !timeout.is_zero() && timeout <= MAX_TIMEOUT
}

/// An invalid local HTTP server configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ServerConfigurationError {
    /// A body limit must be between one byte and eight MiB.
    #[error("request body limit must be between one byte and eight MiB")]
    InvalidBodyLimit,
    /// A connection limit must be between one and 1,024.
    #[error("connection limit must be between one and 1,024")]
    InvalidConnectionLimit,
    /// A rate limit must be between one and 60,000 events per minute.
    #[error("rate limit must be between one and 60,000 events per minute")]
    InvalidRateLimit,
    /// A timeout must be greater than zero and no longer than five minutes.
    #[error("timeouts must be greater than zero and no longer than five minutes")]
    InvalidTimeout,
    /// Disabled authentication on a network address requires explicit acknowledgement.
    #[error("unauthenticated non-loopback listening requires explicit acknowledgement")]
    UnauthenticatedNetworkExposure,
    /// Cleartext HTTP on a network address requires explicit acknowledgement.
    #[error("cleartext non-loopback listening requires explicit acknowledgement")]
    CleartextNetworkExposure,
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_BODY_BYTES, MAX_CONNECTIONS, MAX_REQUESTS_PER_MINUTE, MAX_TIMEOUT, RateLimits,
        ServerConfiguration,
    };
    use crate::Authentication;
    use bondry_core::{Principal, PrincipalId, PrincipalKind};
    use std::time::Duration;

    fn configuration() -> Result<ServerConfiguration, Box<dyn std::error::Error>> {
        let principal = Principal::new(
            PrincipalId::new("configuration_test")?,
            PrincipalKind::Application,
        );
        Ok(ServerConfiguration::new(Authentication::disabled(
            principal,
        )))
    }

    #[test]
    fn preserves_server_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let configuration = configuration()?;

        assert!(configuration.bind_address.is_loopback());
        assert_eq!(configuration.port, 0);
        assert_eq!(configuration.max_body_bytes, 1_048_576);
        assert_eq!(configuration.max_connections, 64);
        assert_eq!(configuration.rate_limits.requests_per_minute(), 120);
        assert_eq!(
            configuration
                .rate_limits
                .authentication_failures_per_minute(),
            30
        );
        assert_eq!(configuration.header_read_timeout, Duration::from_secs(5));
        assert_eq!(configuration.request_timeout, Duration::from_secs(30));
        assert_eq!(configuration.shutdown_grace_period, Duration::from_secs(2));
        assert!(!configuration.allow_cleartext_network);
        assert!(!configuration.allow_unauthenticated_network);
        Ok(())
    }

    #[test]
    fn preserves_configuration_ceilings() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(MAX_BODY_BYTES, 8 * 1_048_576);
        assert_eq!(MAX_CONNECTIONS, 1_024);
        assert_eq!(MAX_REQUESTS_PER_MINUTE, 60_000);
        assert_eq!(MAX_TIMEOUT, Duration::from_secs(300));

        assert!(configuration()?.with_max_body_bytes(MAX_BODY_BYTES).is_ok());
        assert!(
            configuration()?
                .with_max_body_bytes(MAX_BODY_BYTES + 1)
                .is_err()
        );
        assert!(
            configuration()?
                .with_max_connections(MAX_CONNECTIONS)
                .is_ok()
        );
        assert!(
            configuration()?
                .with_max_connections(MAX_CONNECTIONS + 1)
                .is_err()
        );
        assert!(RateLimits::new(MAX_REQUESTS_PER_MINUTE, MAX_REQUESTS_PER_MINUTE).is_ok());
        assert!(RateLimits::new(MAX_REQUESTS_PER_MINUTE + 1, 1).is_err());
        assert!(RateLimits::new(1, MAX_REQUESTS_PER_MINUTE + 1).is_err());
        assert!(
            configuration()?
                .with_timeouts(MAX_TIMEOUT, MAX_TIMEOUT, MAX_TIMEOUT)
                .is_ok()
        );
        assert!(
            configuration()?
                .with_timeouts(
                    MAX_TIMEOUT + Duration::from_secs(1),
                    MAX_TIMEOUT,
                    MAX_TIMEOUT,
                )
                .is_err()
        );
        Ok(())
    }
}
