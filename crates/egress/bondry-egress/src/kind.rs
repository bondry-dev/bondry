use bondry_delivery_store::{DeliveryFailure, DeliveryId, DeliveryResultMetadata};
use bondry_secrets::{ResolvedSecret, SecretRef};
use bondry_transport::{Deadline, HttpRequest, HttpResponse, TransportError};
use thiserror::Error;

use crate::{EventPayload, RetryableFailure};

/// Host operation requested for one configured route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationMode {
    /// One-way delivery that returns only delivery status.
    Emit,
    /// RPC-style delivery that returns a bounded untrusted result.
    Call,
}

/// Exact time and deadline supplied when an attempt begins or resumes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptContext {
    unix_ms: u64,
    deadline: Deadline,
}

impl AttemptContext {
    /// Creates attempt context without reading a clock.
    #[must_use]
    pub const fn new(unix_ms: u64, deadline: Deadline) -> Self {
        Self { unix_ms, deadline }
    }

    /// Returns Unix milliseconds used by signing protocols.
    #[must_use]
    pub const fn unix_ms(self) -> u64 {
        self.unix_ms
    }

    /// Returns the absolute transport deadline.
    #[must_use]
    pub const fn deadline(self) -> Deadline {
        self.deadline
    }
}

/// Pure delivery-kind configuration and operation factory.
pub trait DeliveryKind: Send + Sync {
    /// Returns a stable kind name.
    fn name(&self) -> &'static str;

    /// Returns an inspectable target containing no resolved secret.
    fn target_summary(&self) -> &str;

    /// Returns whether this kind supports the host `call` verb.
    fn supports_call(&self) -> bool;

    /// Creates fresh sans-I/O attempt state from validated exact bytes.
    fn operation(
        &self,
        mode: OperationMode,
        delivery: DeliveryId,
        payload: EventPayload,
    ) -> Result<Box<dyn DeliveryOperation>, KindOperationError>;
}

/// One sans-I/O delivery-kind attempt, potentially spanning several requests.
pub trait DeliveryOperation: Send {
    /// Returns secret references the runtime must resolve for this attempt.
    fn secret_references(&self) -> &[SecretRef];

    /// Starts the operation after the runtime resolves secrets in the declared order.
    fn start(&mut self, context: AttemptContext, secrets: Vec<ResolvedSecret>) -> KindTransition;

    /// Resumes the operation after the runtime completes the requested transport action.
    fn resume(
        &mut self,
        context: AttemptContext,
        completion: TransportCompletion,
    ) -> KindTransition;
}

/// Transport completion returned to a delivery-kind state machine.
pub enum TransportCompletion {
    /// A bounded HTTP response or stable transport failure.
    Http(Result<HttpResponse, TransportError>),
}

/// Next pure action requested by a delivery-kind operation.
pub enum KindTransition {
    /// Submit one already bounded HTTP request.
    Http(Box<HttpRequest>),
    /// Finish the current attempt.
    Complete(AttemptDisposition),
}

/// Delivery-kind classification consumed by the generic retry lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptDisposition {
    /// The receiver accepted the operation.
    Delivered(Option<DeliveryResultMetadata>),
    /// The failure may be retried under the route policy.
    Retryable(RetryableFailure),
    /// The failure is terminal regardless of remaining retries.
    Failed(DeliveryFailure),
}

/// Stable failure to create a delivery-kind operation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KindOperationError {
    /// The kind does not support the requested host verb.
    #[error("delivery kind does not support the requested operation")]
    UnsupportedOperation,
    /// Validated route state cannot compose this event safely.
    #[error("delivery kind rejected the event")]
    InvalidEvent,
    /// Internal kind state cannot continue safely.
    #[error("delivery kind operation is unavailable")]
    Unavailable,
}
