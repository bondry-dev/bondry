#![doc = "Secure shared local HTTP transport for Bondry protocol adapters."]

mod adapter;
mod authentication;
mod configuration;
mod invocation_id;
mod rate_limit;
mod server;

pub use adapter::{AdapterFuture, AdapterRequest, HttpAdapter};
pub use authentication::{
    Authentication, AuthenticationError, AuthenticationRequest, BearerAuthenticator,
    BearerTokenVerifier, HttpAuthenticator,
};
pub use configuration::{
    OriginPolicy, OriginPolicyError, RateLimits, ServerConfiguration, ServerConfigurationError,
};
pub use invocation_id::{
    InvocationIdGenerationError, InvocationIdGenerator, SystemInvocationIdGenerator,
};
pub use server::{LocalHttpServer, ServerStartError, ServerStopError};
