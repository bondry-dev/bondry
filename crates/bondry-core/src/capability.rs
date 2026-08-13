use std::{future::Future, pin::Pin};

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::{CapabilityId, HandlerErrorCode, InvocationContext};

/// The maximum UTF-8 encoded length of a capability summary.
pub const MAX_CAPABILITY_SUMMARY_LENGTH: usize = 256;

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
    summary: CapabilitySummary,
    effect: CapabilityEffect,
}

impl CapabilityDescriptor {
    /// Creates a capability descriptor.
    pub fn new(
        id: CapabilityId,
        summary: impl Into<String>,
        effect: CapabilityEffect,
    ) -> Result<Self, CapabilitySummaryError> {
        Ok(Self {
            id,
            summary: CapabilitySummary::new(summary)?,
            effect,
        })
    }

    /// Returns the stable capability identifier.
    #[must_use]
    pub fn id(&self) -> &CapabilityId {
        &self.id
    }

    /// Returns the human-readable capability summary.
    #[must_use]
    pub fn summary(&self) -> &str {
        self.summary.as_str()
    }

    /// Returns the capability's declared effect.
    #[must_use]
    pub const fn effect(&self) -> CapabilityEffect {
        self.effect
    }
}

/// A validated human-readable capability summary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
struct CapabilitySummary(String);

impl CapabilitySummary {
    fn new(value: impl Into<String>) -> Result<Self, CapabilitySummaryError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(CapabilitySummaryError::Empty);
        }
        if value.len() > MAX_CAPABILITY_SUMMARY_LENGTH {
            return Err(CapabilitySummaryError::TooLong);
        }
        if value.chars().any(char::is_control) {
            return Err(CapabilitySummaryError::ControlCharacter);
        }
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

/// An error produced when capability summary metadata is invalid.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CapabilitySummaryError {
    /// The summary is empty or contains only whitespace.
    #[error("a capability summary cannot be empty")]
    Empty,
    /// The summary exceeds the maximum UTF-8 encoded length.
    #[error("a capability summary cannot exceed {MAX_CAPABILITY_SUMMARY_LENGTH} bytes")]
    TooLong,
    /// The summary contains a control character.
    #[error("a capability summary cannot contain control characters")]
    ControlCharacter,
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
