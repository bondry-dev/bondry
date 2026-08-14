#![doc = "Secure shared local HTTP engine for Bondry protocols."]

mod authentication;
mod configuration;
mod protocol;
mod rate_limit;
mod server;

pub use authentication::{
    Authentication, AuthenticationError, AuthenticationRequest, BearerAuthenticator,
    BearerTokenVerifier, HttpAuthenticator,
};
pub use configuration::{
    OriginPolicy, OriginPolicyError, RateLimits, ServerConfiguration, ServerConfigurationError,
};
pub use protocol::MountedProtocol;
pub use server::{LocalHttpServer, ServerStartError, ServerStopError};
