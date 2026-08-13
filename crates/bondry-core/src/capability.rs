use std::{future::Future, pin::Pin};

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::{CapabilityId, HandlerErrorCode, InvocationContext};

/// Describes whether a capability may change observable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityEffect {
    /// The capability only reads state.
    ReadOnly,
    /// The capability may change state.
    Mutating,
}

/// Protocol-neutral metadata describing a capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapabilityDescriptor {
    id: CapabilityId,
    summary: String,
    effect: CapabilityEffect,
}

impl CapabilityDescriptor {
    /// Creates a capability descriptor.
    #[must_use]
    pub fn new(id: CapabilityId, summary: impl Into<String>, effect: CapabilityEffect) -> Self {
        Self {
            id,
            summary: summary.into(),
            effect,
        }
    }

    /// Returns the stable capability identifier.
    #[must_use]
    pub fn id(&self) -> &CapabilityId {
        &self.id
    }

    /// Returns the human-readable capability summary.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// Returns the capability's declared effect.
    #[must_use]
    pub const fn effect(&self) -> CapabilityEffect {
        self.effect
    }
}

/// A future returned by a capability handler.
pub type HandlerFuture = Pin<Box<dyn Future<Output = Result<Value, HandlerError>> + Send>>;

/// Executes a capability after authorization succeeds.
pub trait CapabilityHandler: Send + Sync {
    /// Invokes the capability with protocol-neutral JSON input.
    fn invoke(&self, context: InvocationContext, input: Value) -> HandlerFuture;
}

impl<F, Fut> CapabilityHandler for F
where
    F: Fn(InvocationContext, Value) -> Fut + Send + Sync,
    Fut: Future<Output = Result<Value, HandlerError>> + Send + 'static,
{
    fn invoke(&self, context: InvocationContext, input: Value) -> HandlerFuture {
        Box::pin(self(context, input))
    }
}

/// A safe, protocol-neutral capability handler failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("capability handler failed with code {code}")]
pub struct HandlerError {
    code: HandlerErrorCode,
}

impl HandlerError {
    /// Creates a handler failure from a stable, non-sensitive code.
    #[must_use]
    pub const fn new(code: HandlerErrorCode) -> Self {
        Self { code }
    }

    /// Returns the stable failure code.
    #[must_use]
    pub const fn code(&self) -> &HandlerErrorCode {
        &self.code
    }
}
