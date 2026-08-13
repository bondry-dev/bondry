use std::{fmt, future::Future, pin::Pin, sync::Arc};

use serde::{Serialize, Serializer};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{CapabilityId, HandlerErrorCode, InvocationContext};

/// The maximum UTF-8 encoded length of a capability summary.
pub const MAX_CAPABILITY_SUMMARY_LENGTH: usize = 256;

/// The maximum encoded length of a capability input schema.
pub const MAX_CAPABILITY_SCHEMA_LENGTH: usize = 65_536;

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
    input_schema: CapabilityInputSchema,
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
            input_schema: CapabilityInputSchema::default(),
        })
    }

    /// Replaces the permissive default input schema with a JSON Schema 2020-12 document.
    pub fn with_input_schema(mut self, schema: Value) -> Result<Self, CapabilitySchemaError> {
        self.input_schema = CapabilityInputSchema::new(schema)?;
        Ok(self)
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

    /// Returns the JSON Schema 2020-12 document describing accepted input.
    #[must_use]
    pub const fn input_schema(&self) -> &Value {
        self.input_schema.document()
    }

    pub(crate) fn accepts_input(&self, input: &Value) -> bool {
        self.input_schema.accepts(input)
    }
}

#[derive(Clone)]
struct CapabilityInputSchema {
    document: Value,
    validator: Option<Arc<jsonschema::Validator>>,
}

impl CapabilityInputSchema {
    fn new(document: Value) -> Result<Self, CapabilitySchemaError> {
        if !document.is_object() {
            return Err(CapabilitySchemaError::NotObject);
        }
        if serde_json::to_vec(&document)
            .map_or(true, |encoded| encoded.len() > MAX_CAPABILITY_SCHEMA_LENGTH)
        {
            return Err(CapabilitySchemaError::TooLarge);
        }
        if !jsonschema::draft202012::meta::is_valid(&document) {
            return Err(CapabilitySchemaError::Invalid);
        }
        let validator =
            jsonschema::draft202012::new(&document).map_err(|_| CapabilitySchemaError::Invalid)?;
        Ok(Self {
            document,
            validator: Some(Arc::new(validator)),
        })
    }

    const fn document(&self) -> &Value {
        &self.document
    }

    fn accepts(&self, input: &Value) -> bool {
        self.validator
            .as_ref()
            .is_none_or(|validator| validator.is_valid(input))
    }
}

impl Default for CapabilityInputSchema {
    fn default() -> Self {
        Self {
            document: Value::Object(Map::new()),
            validator: None,
        }
    }
}

impl fmt::Debug for CapabilityInputSchema {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.document.fmt(formatter)
    }
}

impl PartialEq for CapabilityInputSchema {
    fn eq(&self, other: &Self) -> bool {
        self.document == other.document
    }
}

impl Eq for CapabilityInputSchema {}

impl Serialize for CapabilityInputSchema {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.document.serialize(serializer)
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

/// An invalid capability input schema.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CapabilitySchemaError {
    /// MCP tool input schemas must be JSON objects.
    #[error("a capability input schema must be a JSON object")]
    NotObject,
    /// The encoded schema exceeds the supported limit.
    #[error("a capability input schema cannot exceed {MAX_CAPABILITY_SCHEMA_LENGTH} bytes")]
    TooLarge,
    /// The schema is not a self-contained JSON Schema 2020-12 document.
    #[error("a capability input schema must be a self-contained JSON Schema 2020-12 document")]
    Invalid,
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
