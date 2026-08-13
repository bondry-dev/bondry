#![doc = "Protocol-neutral automation dispatch and policy primitives for Bondry."]

mod audit;
mod capability;
mod dispatch;
mod identifier;
mod identity;
mod invocation;
mod policy;
mod registry;

pub use audit::{AuditEvent, AuditOutcome, AuditSink, NoopAuditSink};
pub use capability::{
    CapabilityDescriptor, CapabilityEffect, CapabilityHandler, HandlerError, HandlerFuture,
};
pub use dispatch::{DispatchError, Dispatcher};
pub use identifier::{
    AdapterId, CapabilityId, HandlerErrorCode, IdentifierError, InvocationId, PrincipalId,
};
pub use identity::{Principal, PrincipalKind};
pub use invocation::{Invocation, InvocationContext};
pub use policy::{
    AuthorizationDecision, AuthorizationPolicy, AuthorizationRequest, DenialReason, DenyAllPolicy,
    GrantPolicy, PolicyUpdateError,
};
pub use registry::{CapabilityRegistry, RegistrationError};
