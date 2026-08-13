#![doc = "Protocol-neutral automation dispatch and policy primitives for Bondry."]

mod audit;
mod capability;
mod dispatch;
mod identifier;
mod identity;
mod invocation;
mod policy;
mod registry;

pub use audit::{AuditError, AuditEvent, AuditOutcome, AuditSink, NoopAuditSink};
pub use capability::{
    CapabilityDescriptor, CapabilityEffect, CapabilityHandler, CapabilitySchemaError,
    CapabilitySummaryError, HandlerError, HandlerFuture, MAX_CAPABILITY_SCHEMA_LENGTH,
    MAX_CAPABILITY_SUMMARY_LENGTH,
};
pub use dispatch::{
    AutomationService, CapabilityDiscoveryError, DispatchError, DispatchFuture, Dispatcher,
};
pub use identifier::{
    AdapterId, CapabilityId, HandlerErrorCode, IdentifierError, InvocationId, PrincipalId,
};
pub use identity::{Principal, PrincipalKind};
pub use invocation::{Invocation, InvocationContext};
pub use policy::{
    AuthorizationDecision, AuthorizationPolicy, AuthorizationRequest, CapabilityGrant,
    DenialReason, DenyAllPolicy, GrantPolicy, GrantStore, GrantStoreError, PolicyUpdateError,
    StoredGrantPolicy,
};
pub use registry::{CapabilityRegistry, RegistrationError};
