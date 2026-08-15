use std::{sync::Arc, time::Instant};

use bondry_delivery_store::{DeliveryFailure, DeliveryId};
use bondry_egress::{
    AttemptContext, AttemptDisposition, DeliveryKind, EventPayload, KindTransition, OperationMode,
    RetryableFailure, TransportCompletion,
};
use bondry_secrets::{SecretProvider, SecretProviderError};
use bondry_transport::{Deadline, HttpTransport};

pub(crate) async fn execute_attempt(
    kind: Arc<dyn DeliveryKind>,
    mode: OperationMode,
    delivery: DeliveryId,
    payload: EventPayload,
    deadline: Deadline,
    secrets: Arc<dyn SecretProvider>,
    transport: Arc<dyn HttpTransport>,
) -> AttemptDisposition {
    let mut operation = match kind.operation(mode, delivery, payload) {
        Ok(operation) => operation,
        Err(_) => return AttemptDisposition::Failed(DeliveryFailure::Internal),
    };
    let resolved = match operation
        .secret_references()
        .iter()
        .map(|reference| secrets.resolve(reference))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(resolved) => resolved,
        Err(SecretProviderError::Unavailable) => {
            return AttemptDisposition::Retryable(RetryableFailure::SecretUnavailable);
        }
        Err(SecretProviderError::NotFound | SecretProviderError::InvalidMaterial) => {
            return AttemptDisposition::Failed(DeliveryFailure::SecretUnavailable);
        }
    };
    let mut transition = operation.start(attempt_context(deadline), resolved);
    loop {
        match transition {
            KindTransition::Complete(disposition) => return disposition,
            KindTransition::Http(request) => {
                let remaining = deadline.instant().saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return AttemptDisposition::Retryable(RetryableFailure::DeadlineExceeded);
                }
                let completion = match tokio::time::timeout(remaining, transport.send(*request))
                    .await
                {
                    Ok(completion) => completion,
                    Err(_) => {
                        return AttemptDisposition::Retryable(RetryableFailure::DeadlineExceeded);
                    }
                };
                transition = operation.resume(
                    attempt_context(deadline),
                    TransportCompletion::Http(completion),
                );
            }
        }
    }
}

fn attempt_context(deadline: Deadline) -> AttemptContext {
    AttemptContext::new(unix_milliseconds(), deadline)
}

pub(crate) fn unix_milliseconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
