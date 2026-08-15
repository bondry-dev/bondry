use std::time::Duration;

use bondry_delivery_store::{
    DeliveryFailure, DeliveryId, DeliveryIntent, DeliveryOutcome, DeliveryResultMetadata, RouteId,
};
use thiserror::Error;

use crate::{EgressInstant, RetryPolicy, TransitionTime};

/// Pure state for one accepted and durably logged delivery.
pub struct DeliveryLifecycle {
    route: RouteId,
    delivery: DeliveryId,
    retry: RetryPolicy,
    attempts: u16,
    state: State,
}

impl DeliveryLifecycle {
    /// Creates ready state after the runtime has recorded the delivery intent.
    #[must_use]
    pub const fn new(route: RouteId, delivery: DeliveryId, retry: RetryPolicy) -> Self {
        Self {
            route,
            delivery,
            retry,
            attempts: 0,
            state: State::Ready,
        }
    }

    /// Returns the configured route identifier.
    #[must_use]
    pub const fn route(&self) -> &RouteId {
        &self.route
    }

    /// Returns the unique delivery identifier.
    #[must_use]
    pub const fn delivery(&self) -> &DeliveryId {
        &self.delivery
    }

    /// Returns the number of attempts started so far.
    #[must_use]
    pub const fn attempts(&self) -> u16 {
        self.attempts
    }

    /// Consumes an explicit event and time without reading clocks or performing I/O.
    pub fn transition(
        &mut self,
        time: TransitionTime,
        event: DeliveryEvent,
    ) -> Result<DeliveryTransition, DeliveryLifecycleError> {
        if matches!(self.state, State::Terminal) {
            return Ok(DeliveryTransition::none());
        }
        match event {
            DeliveryEvent::Drive => self.drive(time),
            DeliveryEvent::Delivered(result) => {
                if !matches!(self.state, State::InFlight) {
                    return Err(DeliveryLifecycleError);
                }
                Ok(self.terminal(time, DeliveryOutcome::Delivered, result))
            }
            DeliveryEvent::Retryable(failure) => {
                if !matches!(self.state, State::InFlight) {
                    return Err(DeliveryLifecycleError);
                }
                if self.attempts <= u16::from(self.retry.retries()) {
                    let deadline = time
                        .monotonic()
                        .saturating_add(self.retry_delay(self.attempts));
                    self.state = State::WaitingRetry(deadline);
                    Ok(DeliveryTransition {
                        persistence: None,
                        action: DeliveryAction::Wait,
                        next_deadline: Some(deadline),
                    })
                } else {
                    Ok(self.terminal(time, DeliveryOutcome::Failed(failure.into()), None))
                }
            }
            DeliveryEvent::Failed(failure) => {
                if !matches!(self.state, State::InFlight) {
                    return Err(DeliveryLifecycleError);
                }
                Ok(self.terminal(time, DeliveryOutcome::Failed(failure), None))
            }
            DeliveryEvent::FailedWithResult { failure, result } => {
                if !matches!(self.state, State::InFlight) {
                    return Err(DeliveryLifecycleError);
                }
                Ok(self.terminal(time, DeliveryOutcome::Failed(failure), Some(result)))
            }
            DeliveryEvent::Cancel => Ok(self.terminal(
                time,
                DeliveryOutcome::Failed(DeliveryFailure::Cancelled),
                None,
            )),
            DeliveryEvent::ShutdownDeadline => {
                Ok(self.terminal(time, DeliveryOutcome::LostOnShutdown, None))
            }
        }
    }

    /// Returns a scheduled retry deadline, if any.
    #[must_use]
    pub const fn next_deadline(&self) -> Option<EgressInstant> {
        match self.state {
            State::WaitingRetry(deadline) => Some(deadline),
            State::Ready | State::InFlight | State::Terminal => None,
        }
    }

    /// Returns whether exactly one terminal outcome has been emitted.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self.state, State::Terminal)
    }

    fn drive(
        &mut self,
        time: TransitionTime,
    ) -> Result<DeliveryTransition, DeliveryLifecycleError> {
        match self.state {
            State::Ready => Ok(self.start_attempt(time)),
            State::WaitingRetry(deadline) if time.monotonic() >= deadline => {
                Ok(self.start_attempt(time))
            }
            State::WaitingRetry(deadline) => Ok(DeliveryTransition {
                persistence: None,
                action: DeliveryAction::Wait,
                next_deadline: Some(deadline),
            }),
            State::InFlight => Err(DeliveryLifecycleError),
            State::Terminal => Ok(DeliveryTransition::none()),
        }
    }

    fn start_attempt(&mut self, time: TransitionTime) -> DeliveryTransition {
        self.attempts = self.attempts.saturating_add(1);
        self.state = State::InFlight;
        DeliveryTransition {
            persistence: Some(DeliveryPersistenceAction::RecordAttempt {
                delivery: self.delivery.clone(),
                attempts: self.attempts,
                updated_at_unix_ms: time.unix_ms(),
            }),
            action: DeliveryAction::StartAttempt {
                attempts: self.attempts,
            },
            next_deadline: None,
        }
    }

    fn terminal(
        &mut self,
        time: TransitionTime,
        outcome: DeliveryOutcome,
        result: Option<DeliveryResultMetadata>,
    ) -> DeliveryTransition {
        self.state = State::Terminal;
        DeliveryTransition {
            persistence: Some(DeliveryPersistenceAction::RecordOutcome {
                delivery: self.delivery.clone(),
                outcome,
                updated_at_unix_ms: time.unix_ms(),
                result,
            }),
            action: DeliveryAction::Terminal { outcome, result },
            next_deadline: None,
        }
    }

    fn retry_delay(&self, attempts: u16) -> Duration {
        let shift = u32::from(attempts.saturating_sub(1)).min(31);
        let exponential = self
            .retry
            .base()
            .as_nanos()
            .saturating_mul(1_u128 << shift)
            .min(self.retry.cap().as_nanos());
        let multiplier = 8_000_u128 + u128::from(stable_jitter(&self.delivery, attempts));
        let jittered = exponential
            .saturating_mul(multiplier)
            .checked_div(10_000)
            .unwrap_or(exponential)
            .min(self.retry.cap().as_nanos());
        Duration::from_nanos(u64::try_from(jittered).unwrap_or(u64::MAX))
    }
}

#[derive(Clone, Copy)]
enum State {
    Ready,
    InFlight,
    WaitingRetry(EgressInstant),
    Terminal,
}

/// External event applied to one pure delivery lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryEvent {
    /// Start a ready attempt or a retry whose deadline has elapsed.
    Drive,
    /// The delivery kind reported success.
    Delivered(Option<DeliveryResultMetadata>),
    /// The delivery kind reported a retryable failure.
    Retryable(RetryableFailure),
    /// The delivery kind reported a terminal failure.
    Failed(DeliveryFailure),
    /// The delivery kind reported a bounded invalid result and terminal failure.
    FailedWithResult {
        /// Stable terminal delivery category.
        failure: DeliveryFailure,
        /// Non-sensitive invalid-result category and size.
        result: DeliveryResultMetadata,
    },
    /// Route disable or host cancellation terminates pending work.
    Cancel,
    /// The graceful shutdown deadline expired.
    ShutdownDeadline,
}

/// Failure categories that may safely enter bounded retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryableFailure {
    /// The current attempt exceeded its absolute deadline.
    DeadlineExceeded,
    /// The host secret provider may recover on a later attempt.
    SecretUnavailable,
    /// Name resolution, connection, or transport may recover.
    TransportUnavailable,
    /// The receiver produced an explicitly retryable response.
    ReceiverRejected,
}

impl From<RetryableFailure> for DeliveryFailure {
    fn from(failure: RetryableFailure) -> Self {
        match failure {
            RetryableFailure::DeadlineExceeded => Self::DeadlineExceeded,
            RetryableFailure::SecretUnavailable => Self::SecretUnavailable,
            RetryableFailure::TransportUnavailable => Self::TransportUnavailable,
            RetryableFailure::ReceiverRejected => Self::ReceiverRejected,
        }
    }
}

/// Runtime effect requested by a pure lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryAction {
    /// No effect; commonly a late callback after terminal completion.
    None,
    /// Persist the accompanying attempt action, then start one kind operation.
    StartAttempt {
        /// One-based total attempt count.
        attempts: u16,
    },
    /// Sleep until the returned next deadline without polling.
    Wait,
    /// Publish exactly one terminal status after persistence is attempted.
    Terminal {
        /// Stable terminal outcome.
        outcome: DeliveryOutcome,
        /// Optional result category and size without result contents.
        result: Option<DeliveryResultMetadata>,
    },
}

/// Persistence effect executed only by the egress runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryPersistenceAction {
    /// Insert the accepted delivery intent before queueing or transport work.
    InsertIntent {
        /// Minimal non-sensitive delivery metadata.
        intent: DeliveryIntent,
    },
    /// Record an increasing attempt count before transport submission.
    RecordAttempt {
        /// Delivery being attempted.
        delivery: DeliveryId,
        /// One-based total attempt count.
        attempts: u16,
        /// Wall-clock transition time.
        updated_at_unix_ms: u64,
    },
    /// Record exactly one terminal outcome.
    RecordOutcome {
        /// Delivery reaching terminal state.
        delivery: DeliveryId,
        /// Stable terminal outcome.
        outcome: DeliveryOutcome,
        /// Wall-clock transition time.
        updated_at_unix_ms: u64,
        /// Optional result category and size.
        result: Option<DeliveryResultMetadata>,
    },
}

/// Ordered persistence and runtime effects plus the next scheduler deadline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryTransition {
    persistence: Option<DeliveryPersistenceAction>,
    action: DeliveryAction,
    next_deadline: Option<EgressInstant>,
}

impl DeliveryTransition {
    /// Returns the persistence effect that must run before the runtime effect.
    #[must_use]
    pub const fn persistence(&self) -> Option<&DeliveryPersistenceAction> {
        self.persistence.as_ref()
    }

    /// Returns the requested runtime effect.
    #[must_use]
    pub const fn action(&self) -> DeliveryAction {
        self.action
    }

    /// Returns the next scheduler deadline without creating a timer.
    #[must_use]
    pub const fn next_deadline(&self) -> Option<EgressInstant> {
        self.next_deadline
    }

    const fn none() -> Self {
        Self {
            persistence: None,
            action: DeliveryAction::None,
            next_deadline: None,
        }
    }
}

/// An event cannot apply to the current delivery state.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("delivery lifecycle event is invalid for the current state")]
pub struct DeliveryLifecycleError;

fn stable_jitter(delivery: &DeliveryId, attempts: u16) -> u16 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in delivery.as_str().bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    for byte in attempts.to_le_bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash % 4_001) as u16
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bondry_delivery_store::{DeliveryFailure, DeliveryId, DeliveryOutcome, RouteId};

    use super::{DeliveryAction, DeliveryEvent, DeliveryLifecycle, RetryableFailure};
    use crate::{EgressInstant, RetryPolicy, TransitionTime};

    fn time(seconds: u64) -> TransitionTime {
        TransitionTime::new(
            EgressInstant::at(Duration::from_secs(seconds)),
            seconds * 1_000,
        )
    }

    fn lifecycle(retries: u8) -> Result<DeliveryLifecycle, Box<dyn std::error::Error>> {
        Ok(DeliveryLifecycle::new(
            RouteId::new("watchdog")?,
            DeliveryId::new("delivery_retry")?,
            RetryPolicy::new(retries, Duration::from_secs(1), Duration::from_secs(60))?,
        ))
    }

    #[test]
    fn records_attempt_before_start_and_terminal_outcome_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut lifecycle = lifecycle(5)?;
        let started = lifecycle.transition(time(0), DeliveryEvent::Drive)?;
        assert!(started.persistence().is_some());
        assert_eq!(
            started.action(),
            DeliveryAction::StartAttempt { attempts: 1 }
        );
        let terminal = lifecycle.transition(time(1), DeliveryEvent::Delivered(None))?;
        assert!(terminal.persistence().is_some());
        assert_eq!(
            terminal.action(),
            DeliveryAction::Terminal {
                outcome: DeliveryOutcome::Delivered,
                result: None,
            }
        );
        assert_eq!(
            lifecycle
                .transition(time(2), DeliveryEvent::Delivered(None))?
                .action(),
            DeliveryAction::None
        );
        Ok(())
    }

    #[test]
    fn retry_backoff_is_bounded_deterministic_and_mock_clock_driven()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut first = lifecycle(1)?;
        let mut second = lifecycle(1)?;
        first.transition(time(0), DeliveryEvent::Drive)?;
        second.transition(time(0), DeliveryEvent::Drive)?;
        let first_wait = first.transition(
            time(1),
            DeliveryEvent::Retryable(RetryableFailure::TransportUnavailable),
        )?;
        let second_wait = second.transition(
            time(1),
            DeliveryEvent::Retryable(RetryableFailure::TransportUnavailable),
        )?;
        assert_eq!(first_wait.next_deadline(), second_wait.next_deadline());
        let deadline = first_wait
            .next_deadline()
            .ok_or(std::io::Error::other("retry deadline missing"))?;
        assert!(deadline >= EgressInstant::at(Duration::from_millis(1_800)));
        assert!(deadline <= EgressInstant::at(Duration::from_millis(2_200)));
        assert_eq!(
            first.transition(time(1), DeliveryEvent::Drive)?.action(),
            DeliveryAction::Wait
        );
        let retry_time = TransitionTime::new(deadline, 2_000);
        assert_eq!(
            first.transition(retry_time, DeliveryEvent::Drive)?.action(),
            DeliveryAction::StartAttempt { attempts: 2 }
        );
        assert_eq!(
            first
                .transition(
                    time(3),
                    DeliveryEvent::Retryable(RetryableFailure::TransportUnavailable),
                )?
                .action(),
            DeliveryAction::Terminal {
                outcome: DeliveryOutcome::Failed(DeliveryFailure::TransportUnavailable),
                result: None,
            }
        );
        Ok(())
    }

    #[test]
    fn cancellation_and_shutdown_are_terminal_without_an_attempt()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut cancelled = lifecycle(5)?;
        assert_eq!(
            cancelled
                .transition(time(0), DeliveryEvent::Cancel)?
                .action(),
            DeliveryAction::Terminal {
                outcome: DeliveryOutcome::Failed(DeliveryFailure::Cancelled),
                result: None,
            }
        );
        let mut shutdown = lifecycle(5)?;
        assert_eq!(
            shutdown
                .transition(time(0), DeliveryEvent::ShutdownDeadline)?
                .action(),
            DeliveryAction::Terminal {
                outcome: DeliveryOutcome::LostOnShutdown,
                result: None,
            }
        );
        Ok(())
    }
}
