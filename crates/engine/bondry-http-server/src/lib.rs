#![doc = "Secure shared local HTTP engine for Bondry protocols."]

mod authentication;
mod configuration;
mod protocol;
mod rate_limit;
mod raw_body;
mod server;
#[cfg(feature = "tls")]
mod tls;
#[cfg(feature = "unix-socket")]
mod unix_socket;

pub use authentication::{
    Authentication, AuthenticationError, AuthenticationRequest, BearerAuthenticator,
    BearerTokenVerifier, HttpAuthenticator,
};
#[cfg(feature = "unix-socket")]
pub use configuration::UnixServerConfigurationError;
pub use configuration::{
    OriginPolicy, OriginPolicyError, RateLimits, ServerConfiguration, ServerConfigurationError,
};
#[cfg(any(feature = "mcp", feature = "rest"))]
pub use protocol::MountedProtocol;
pub use protocol::{HttpProtocol, HttpProtocolFuture};
pub use raw_body::{
    RawBodyCompletion, RawBodyHandler, RawBodyHandlerLimits, RawBodyHeader, RawBodyLifecycle,
    RawBodyRegistration, RawBodyRegistrationError, RawBodyRequest, RawBodyResponse, RawBodyRoute,
    RawBodyRouteError, RawBodyServerLimits,
};
pub use server::{LocalHttpServer, ServerStartError, ServerStopError};
#[cfg(feature = "unix-socket")]
pub use server::{LocalUnixHttpServer, UnixServerStartError};
#[cfg(feature = "tls")]
pub use tls::{
    MAX_TLS_CERTIFICATE_CHAIN_BYTES, MAX_TLS_PRIVATE_KEY_BYTES, TlsServerConfiguration,
    TlsServerConfigurationError,
};
#[cfg(feature = "unix-socket")]
pub use unix_socket::{
    MAX_UNIX_SOCKET_PATH_BYTES, UnixSocketConfiguration, UnixSocketConfigurationError,
};
