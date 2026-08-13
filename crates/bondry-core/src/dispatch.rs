use std::sync::Arc;

use serde_json::Value;
use thiserror::Error;

use crate::{
    AuditError, AuditEvent, AuditOutcome, AuditSink, AuthorizationDecision, AuthorizationPolicy,
    AuthorizationRequest, CapabilityId, CapabilityRegistry, DenialReason, HandlerError, Invocation,
    InvocationContext,
};

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
    /// The capability handler returned a stable failure code.
    #[error(transparent)]
    Handler(#[from] HandlerError),
}
