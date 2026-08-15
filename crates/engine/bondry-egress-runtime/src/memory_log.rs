use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    sync::Mutex,
};

use bondry_delivery_store::{
    DeliveryId, DeliveryIntent, DeliveryLog, DeliveryLogError, DeliveryOutcome, DeliveryRecord,
    DeliveryResultMetadata, DeliveryState, StoreDurability,
};
use thiserror::Error;

use crate::{DEFAULT_IN_MEMORY_LOG_ENTRIES, MAX_IN_MEMORY_LOG_ENTRIES, MIN_IN_MEMORY_LOG_ENTRIES};

/// Validated process-local delivery-log entry capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InMemoryDeliveryLogLimit(u16);

impl InMemoryDeliveryLogLimit {
    /// Creates a capacity inside the limits contract.
    pub const fn new(value: u16) -> Result<Self, InMemoryDeliveryLogLimitError> {
        if value < MIN_IN_MEMORY_LOG_ENTRIES || value > MAX_IN_MEMORY_LOG_ENTRIES {
            return Err(InMemoryDeliveryLogLimitError);
        }
        Ok(Self(value))
    }

    /// Returns the entry capacity.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl Default for InMemoryDeliveryLogLimit {
    fn default() -> Self {
        Self(DEFAULT_IN_MEMORY_LOG_ENTRIES)
    }
}

/// An in-memory log capacity outside 64 through 8192 entries.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("in-memory delivery-log capacity is outside the allowed range")]
pub struct InMemoryDeliveryLogLimitError;

/// Bounded process-local delivery status with terminal-first reclamation.
pub struct InMemoryDeliveryLog {
    limit: InMemoryDeliveryLogLimit,
    state: Mutex<MemoryLogState>,
}

impl InMemoryDeliveryLog {
    /// Creates an empty bounded process-local log.
    #[must_use]
    pub fn new(limit: InMemoryDeliveryLogLimit) -> Self {
        Self {
            limit,
            state: Mutex::new(MemoryLogState::default()),
        }
    }
}

impl Default for InMemoryDeliveryLog {
    fn default() -> Self {
        Self::new(InMemoryDeliveryLogLimit::default())
    }
}

impl fmt::Debug for InMemoryDeliveryLog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryDeliveryLog")
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

impl DeliveryLog for InMemoryDeliveryLog {
    fn durability(&self) -> StoreDurability {
        StoreDurability::ProcessLocal
    }

    fn insert_intent(&self, intent: DeliveryIntent) -> Result<(), DeliveryLogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DeliveryLogError::Unavailable)?;
        if state.records.contains_key(intent.delivery()) {
            return Err(DeliveryLogError::Conflict);
        }
        while state.records.len() >= usize::from(self.limit.get()) {
            let Some(expired) = state.terminal_order.pop_front() else {
                return Err(DeliveryLogError::CapacityExhausted);
            };
            if state
                .records
                .get(&expired)
                .is_some_and(|record| record.state().is_terminal())
            {
                state.records.remove(&expired);
            }
        }
        let accepted_at = intent.accepted_at_unix_ms();
        state.records.insert(
            intent.delivery().clone(),
            DeliveryRecord::from_stored_parts(intent, 0, DeliveryState::Pending, accepted_at, None),
        );
        Ok(())
    }

    fn record_attempt(
        &self,
        delivery: &DeliveryId,
        attempts: u16,
        updated_at_unix_ms: u64,
    ) -> Result<(), DeliveryLogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DeliveryLogError::Unavailable)?;
        let record = state
            .records
            .get(delivery)
            .ok_or(DeliveryLogError::NotFound)?;
        if record.state().is_terminal() || attempts <= record.attempts() {
            return Err(DeliveryLogError::InvalidTransition);
        }
        let updated = DeliveryRecord::from_stored_parts(
            record.intent().clone(),
            attempts,
            DeliveryState::Pending,
            updated_at_unix_ms,
            None,
        );
        state.records.insert(delivery.clone(), updated);
        Ok(())
    }

    fn record_outcome(
        &self,
        delivery: &DeliveryId,
        outcome: DeliveryOutcome,
        updated_at_unix_ms: u64,
        result: Option<DeliveryResultMetadata>,
    ) -> Result<(), DeliveryLogError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| DeliveryLogError::Unavailable)?;
        let record = state
            .records
            .get(delivery)
            .ok_or(DeliveryLogError::NotFound)?;
        if record.state().is_terminal() || outcome == DeliveryOutcome::UnknownAfterCrash {
            return Err(DeliveryLogError::InvalidTransition);
        }
        let updated = DeliveryRecord::from_stored_parts(
            record.intent().clone(),
            record.attempts(),
            DeliveryState::Terminal(outcome),
            updated_at_unix_ms,
            result,
        );
        state.records.insert(delivery.clone(), updated);
        state.terminal_order.push_back(delivery.clone());
        Ok(())
    }

    fn delivery(&self, delivery: &DeliveryId) -> Result<Option<DeliveryRecord>, DeliveryLogError> {
        let state = self
            .state
            .lock()
            .map_err(|_| DeliveryLogError::Unavailable)?;
        Ok(state.records.get(delivery).cloned())
    }

    fn recover_unfinished(&self, _updated_at_unix_ms: u64) -> Result<u64, DeliveryLogError> {
        Ok(0)
    }
}

#[derive(Default)]
struct MemoryLogState {
    records: BTreeMap<DeliveryId, DeliveryRecord>,
    terminal_order: VecDeque<DeliveryId>,
}

#[cfg(test)]
mod tests {
    use bondry_delivery_store::{
        DeliveryId, DeliveryIntent, DeliveryLog, DeliveryLogError, DeliveryOutcome, DeliveryState,
        RouteId, StoreDurability,
    };

    use super::{InMemoryDeliveryLog, InMemoryDeliveryLogLimit};

    fn intent(index: usize) -> Result<DeliveryIntent, Box<dyn std::error::Error>> {
        Ok(DeliveryIntent::new(
            RouteId::new("route")?,
            DeliveryId::new(format!("delivery_{index}"))?,
            u64::try_from(index)?,
        ))
    }

    #[test]
    fn records_strict_lifecycle_without_payloads() -> Result<(), Box<dyn std::error::Error>> {
        let log = InMemoryDeliveryLog::default();
        assert_eq!(log.durability(), StoreDurability::ProcessLocal);
        let intent = intent(1)?;
        let delivery = intent.delivery().clone();
        log.insert_intent(intent)?;
        log.record_attempt(&delivery, 1, 2)?;
        assert_eq!(
            log.record_attempt(&delivery, 1, 3),
            Err(DeliveryLogError::InvalidTransition)
        );
        log.record_outcome(&delivery, DeliveryOutcome::Delivered, 4, None)?;
        let record = log
            .delivery(&delivery)?
            .ok_or(std::io::Error::other("delivery missing"))?;
        assert_eq!(record.attempts(), 1);
        assert_eq!(
            record.state(),
            DeliveryState::Terminal(DeliveryOutcome::Delivered)
        );
        assert_eq!(
            log.record_outcome(&delivery, DeliveryOutcome::Delivered, 5, None),
            Err(DeliveryLogError::InvalidTransition)
        );
        Ok(())
    }

    #[test]
    fn reclaims_oldest_terminal_but_never_pending_records() -> Result<(), Box<dyn std::error::Error>>
    {
        let log = InMemoryDeliveryLog::new(InMemoryDeliveryLogLimit::new(64)?);
        for index in 0..64 {
            let intent = intent(index)?;
            let delivery = intent.delivery().clone();
            log.insert_intent(intent)?;
            if index == 0 {
                log.record_outcome(&delivery, DeliveryOutcome::Delivered, 1, None)?;
            }
        }
        log.insert_intent(intent(64)?)?;
        assert!(log.delivery(&DeliveryId::new("delivery_0")?)?.is_none());
        assert_eq!(
            log.insert_intent(intent(65)?),
            Err(DeliveryLogError::CapacityExhausted)
        );
        Ok(())
    }
}
