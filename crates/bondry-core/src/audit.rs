use std::time::SystemTime;

use crate::{
    AdapterId, CapabilityId, DenialReason, HandlerErrorCode, InvocationContext, InvocationId,
    PrincipalId,
};

/// The protocol-neutral result recorded for an invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    /// The requested capability was not registered.
    CapabilityNotFound,
    /// Authorization policy rejected the invocation.
    Denied(DenialReason),
    /// The capability handler completed successfully.
    Succeeded,
    /// The capability handler returned a safe error code.
    HandlerFailed(HandlerErrorCode),
}

/// An audit event that intentionally excludes credentials and payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    occurred_at: SystemTime,
    invocation: InvocationId,
    principal: PrincipalId,
    adapter: AdapterId,
    capability: CapabilityId,
    outcome: AuditOutcome,
}

impl AuditEvent {
    pub(crate) fn new(context: &InvocationContext, outcome: AuditOutcome) -> Self {
        Self {
            occurred_at: SystemTime::now(),
            invocation: context.id().clone(),
            principal: context.principal().id().clone(),
            adapter: context.adapter().clone(),
            capability: context.capability().clone(),
            outcome,
        }
    }

    /// Returns when the event was created.
    #[must_use]
    pub const fn occurred_at(&self) -> SystemTime {
        self.occurred_at
    }

    /// Returns the invocation identifier.
    #[must_use]
    pub const fn invocation(&self) -> &InvocationId {
        &self.invocation
    }

    /// Returns the principal identifier.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns the adapter identifier.
    #[must_use]
    pub const fn adapter(&self) -> &AdapterId {
        &self.adapter
    }

    /// Returns the requested capability identifier.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    /// Returns the invocation outcome.
    #[must_use]
    pub const fn outcome(&self) -> &AuditOutcome {
        &self.outcome
    }
}

/// Receives audit events produced by the dispatcher.
pub trait AuditSink: Send + Sync {
    /// Records a completed invocation outcome.
    fn record(&self, event: AuditEvent);
}

/// An explicit audit sink for hosts that do not retain audit events.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn record(&self, _event: AuditEvent) {}
}
