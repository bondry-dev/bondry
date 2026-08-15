use std::{sync::Arc, time::Instant};

use bondry_delivery_store::{DeliveryFailure, DeliveryId};
use bondry_egress::{
    AttemptContext, AttemptDisposition, DeliveryKind, EventPayload, KindTransition, OperationMode,
    RetryableFailure, TransportCompletion,
};
use bondry_secrets::{SecretProvider, SecretProviderError};
use bondry_transport::{Deadline, HttpTransport};
use bytes::Bytes;

pub(crate) struct AttemptCompletion {
    pub(crate) disposition: AttemptDisposition,
    pub(crate) result: Option<Bytes>,
}

pub(crate) async fn execute_attempt(
    kind: Arc<dyn DeliveryKind>,
    mode: OperationMode,
    delivery: DeliveryId,
    payload: EventPayload,
    deadline: Deadline,
    secrets: Arc<dyn SecretProvider>,
    transport: Arc<dyn HttpTransport>,
) -> AttemptCompletion {
    let permits_retry = kind.permits_automatic_retry();
    let mut operation = match kind.operation(mode, delivery, payload) {
        Ok(operation) => operation,
        Err(_) => {
            return completion(
                permits_retry,
                AttemptDisposition::Failed(DeliveryFailure::Internal),
            );
        }
    };
    let resolved = match operation
        .secret_references()
        .iter()
        .map(|reference| secrets.resolve(reference))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(resolved) => resolved,
        Err(SecretProviderError::Unavailable) => {
            return completion(
                permits_retry,
                AttemptDisposition::Retryable(RetryableFailure::SecretUnavailable),
            );
        }
        Err(SecretProviderError::NotFound | SecretProviderError::InvalidMaterial) => {
            return completion(
                permits_retry,
                AttemptDisposition::Failed(DeliveryFailure::SecretUnavailable),
            );
        }
    };
    let mut transition = operation.start(attempt_context(deadline), resolved);
    loop {
        match transition {
            KindTransition::Complete(disposition) => {
                return completion(permits_retry, disposition);
            }
            KindTransition::CompleteWithResult {
                disposition,
                result,
            } => {
                let valid = matches!(
                    disposition,
                    AttemptDisposition::Delivered(Some(metadata))
                        if usize::try_from(metadata.bytes()) == Ok(result.len())
                );
                return if valid {
                    AttemptCompletion {
                        disposition,
                        result: Some(result),
                    }
                } else {
                    completion(
                        permits_retry,
                        AttemptDisposition::Failed(DeliveryFailure::Internal),
                    )
                };
            }
            KindTransition::Http(request) => {
                let remaining = deadline.instant().saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return completion(
                        permits_retry,
                        AttemptDisposition::Retryable(RetryableFailure::DeadlineExceeded),
                    );
                }
                let completion =
                    match tokio::time::timeout(remaining, transport.send(*request)).await {
                        Ok(completion) => completion,
                        Err(_) => {
                            return completion(
                                permits_retry,
                                AttemptDisposition::Retryable(RetryableFailure::DeadlineExceeded),
                            );
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

fn completion(permits_retry: bool, disposition: AttemptDisposition) -> AttemptCompletion {
    let disposition = match disposition {
        AttemptDisposition::Retryable(failure) if !permits_retry => {
            AttemptDisposition::Failed(failure.into())
        }
        disposition => disposition,
    };
    AttemptCompletion {
        disposition,
        result: None,
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
