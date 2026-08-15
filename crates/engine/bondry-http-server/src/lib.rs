#![doc = "Secure shared local HTTP engine for Bondry protocols."]

mod authentication;
mod configuration;
mod protocol;
mod rate_limit;
mod raw_body;
mod server;

pub use authentication::{
    Authentication, AuthenticationError, AuthenticationRequest, BearerAuthenticator,
    BearerTokenVerifier, HttpAuthenticator,
};
pub use configuration::{
    OriginPolicy, OriginPolicyError, RateLimits, ServerConfiguration, ServerConfigurationError,
};
pub use protocol::MountedProtocol;
pub use raw_body::{
    RawBodyCompletion, RawBodyHandler, RawBodyHandlerLimits, RawBodyHeader, RawBodyLifecycle,
    RawBodyRegistration, RawBodyRegistrationError, RawBodyRequest, RawBodyResponse, RawBodyRoute,
    RawBodyRouteError, RawBodyServerLimits,
};
pub use server::{LocalHttpServer, ServerStartError, ServerStopError};
