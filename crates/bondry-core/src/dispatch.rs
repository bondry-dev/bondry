use std::{future::Future, pin::Pin, sync::Arc};

use serde_json::Value;
use thiserror::Error;

use crate::{
    AuditError, AuditEvent, AuditOutcome, AuditSink, AuthorizationDecision, AuthorizationPolicy,
    AuthorizationRequest, CapabilityDescriptor, CapabilityId, CapabilityRegistry, DenialReason,
    HandlerError, Invocation, InvocationContext, Principal,
};

/// A future returned by a protocol-neutral automation service.
pub type DispatchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Value, DispatchError>> + Send + 'a>>;

/// The capability operations consumed by protocol adapters.
pub trait AutomationService: Send + Sync {
    /// Returns capabilities currently authorized for one principal and adapter.
    fn capabilities(
        &self,
        principal: &Principal,
        adapter: &crate::AdapterId,
    ) -> Result<Vec<CapabilityDescriptor>, CapabilityDiscoveryError>;

    /// Dispatches one authenticated invocation.
    fn dispatch(&self, invocation: Invocation) -> DispatchFuture<'_>;
}

/// Resolves, authorizes, executes, and audits capability invocations.
pub struct Dispatcher {
    registry: CapabilityRegistry,
    policy: Arc<dyn AuthorizationPolicy>,
    audit: Arc<dyn AuditSink>,
}

impl Dispatcher {
    /// Creates a dispatcher from owned policy and audit implementations.
    #[must_use]
    pub fn new<P, A>(registry: CapabilityRegistry, policy: P, audit: A) -> Self
    where
        P: AuthorizationPolicy + 'static,
        A: AuditSink + 'static,
    {
        Self::from_shared(registry, Arc::new(policy), Arc::new(audit))
    }

    /// Creates a dispatcher from shared policy and audit implementations.
    #[must_use]
    pub const fn from_shared(
        registry: CapabilityRegistry,
        policy: Arc<dyn AuthorizationPolicy>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            registry,
            policy,
            audit,
        }
    }

    /// Dispatches one invocation after resolving and authorizing its capability.
    pub async fn dispatch(&self, invocation: Invocation) -> Result<Value, DispatchError> {
        let context = InvocationContext::from_invocation(&invocation);
        let Some((descriptor, handler)) = self.registry.resolve(invocation.capability()) else {
            self.audit
                .record(AuditEvent::new(&context, AuditOutcome::CapabilityNotFound))?;
            return Err(DispatchError::CapabilityNotFound(
                invocation.capability().clone(),
            ));
        };

        let authorization = self.policy.evaluate(AuthorizationRequest::new(
            invocation.principal(),
            invocation.adapter(),
            descriptor,
        ));
        if let AuthorizationDecision::Deny(reason) = authorization {
            self.audit
                .record(AuditEvent::new(&context, AuditOutcome::Denied(reason)))?;
            return Err(DispatchError::AccessDenied(reason));
        }

        if !descriptor.accepts_input(invocation.input()) {
            self.audit
                .record(AuditEvent::new(&context, AuditOutcome::InvalidInput))?;
            return Err(DispatchError::InvalidInput);
        }

        self.audit
            .record(AuditEvent::new(&context, AuditOutcome::Started))?;
        match handler.invoke(context.clone(), invocation.input).await {
            Ok(output) => {
                self.audit
                    .record(AuditEvent::new(&context, AuditOutcome::Succeeded))?;
                Ok(output)
            }
            Err(error) => {
                self.audit.record(AuditEvent::new(
                    &context,
                    AuditOutcome::HandlerFailed(error.code().clone()),
                ))?;
                Err(DispatchError::Handler(error))
            }
        }
    }

    /// Returns registered capabilities authorized for one principal and adapter.
    pub fn capabilities(
        &self,
        principal: &Principal,
        adapter: &crate::AdapterId,
    ) -> Result<Vec<CapabilityDescriptor>, CapabilityDiscoveryError> {
        let mut allowed = Vec::new();
        for descriptor in self.registry.descriptors() {
            match self
                .policy
                .evaluate(AuthorizationRequest::new(principal, adapter, descriptor))
            {
                AuthorizationDecision::Allow => allowed.push(descriptor.clone()),
                AuthorizationDecision::Deny(DenialReason::NotGranted) => {}
                AuthorizationDecision::Deny(DenialReason::PolicyUnavailable) => {
                    return Err(CapabilityDiscoveryError::PolicyUnavailable);
                }
            }
        }
        Ok(allowed)
    }
}

impl AutomationService for Dispatcher {
    fn capabilities(
        &self,
        principal: &Principal,
        adapter: &crate::AdapterId,
    ) -> Result<Vec<CapabilityDescriptor>, CapabilityDiscoveryError> {
        self.capabilities(principal, adapter)
    }

    fn dispatch(&self, invocation: Invocation) -> DispatchFuture<'_> {
        Box::pin(self.dispatch(invocation))
    }
}

/// A safe capability-discovery failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CapabilityDiscoveryError {
    /// Authorization policy state could not be read safely.
    #[error("authorization policy is unavailable")]
    PolicyUnavailable,
}

/// An invocation failure safe to map into an adapter-specific response.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DispatchError {
    /// Required audit recording failed.
    #[error(transparent)]
    Audit(#[from] AuditError),
    /// The requested capability is not registered.
    #[error("capability {0} was not found")]
    CapabilityNotFound(CapabilityId),
    /// Authorization policy rejected the invocation.
    #[error("access denied: {0:?}")]
    AccessDenied(DenialReason),
    /// Invocation input did not satisfy the capability's declared schema.
    #[error("capability input is invalid")]
    InvalidInput,
    /// The capability handler returned a stable failure code.
    #[error(transparent)]
    Handler(#[from] HandlerError),
}
