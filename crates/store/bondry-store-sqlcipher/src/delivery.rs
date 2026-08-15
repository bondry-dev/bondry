use std::sync::Arc;

use bondry_delivery_store::{
    DeliveryFailure, DeliveryId, DeliveryIntent, DeliveryLog, DeliveryLogError, DeliveryOutcome,
    DeliveryRecord, DeliveryResultCategory, DeliveryResultMetadata, DeliveryState,
    PERSISTENT_DELIVERY_RECORD_CHARGE_BYTES, PersistentDeliveryLogLimits, RouteId, StoreDurability,
};
use rusqlite::{OptionalExtension, Row, Transaction, TransactionBehavior, params};

use crate::SqlCipherStore;

/// A bounded persistent delivery log backed by an existing SQLCipher store.
pub struct SqlCipherDeliveryLog {
    store: Arc<SqlCipherStore>,
    limits: PersistentDeliveryLogLimits,
}

impl SqlCipherDeliveryLog {
    /// Creates a delivery log over a shared encrypted store.
    #[must_use]
    pub fn new(store: Arc<SqlCipherStore>, limits: PersistentDeliveryLogLimits) -> Self {
        Self { store, limits }
    }

    /// Returns the enforced persistent-log limits.
    #[must_use]
    pub const fn limits(&self) -> PersistentDeliveryLogLimits {
        self.limits
    }

    fn connection(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, DeliveryLogError> {
        self.store
            .connection
            .lock()
            .map_err(|_| DeliveryLogError::Unavailable)
    }
}

impl DeliveryLog for SqlCipherDeliveryLog {
    fn durability(&self) -> StoreDurability {
        StoreDurability::Persistent
    }

    fn insert_intent(&self, intent: DeliveryIntent) -> Result<(), DeliveryLogError> {
        let accepted_at = encoded_time(intent.accepted_at_unix_ms())?;
        let retention = i64::try_from(self.limits.retention().as_millis())
            .map_err(|_| DeliveryLogError::InvalidTransition)?;
        let cutoff = accepted_at.saturating_sub(retention);
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| DeliveryLogError::Unavailable)?;
        transaction
            .execute(
                "DELETE FROM delivery_log
                 WHERE state != 'pending' AND updated_at_ms < ?1",
                [cutoff],
            )
            .map_err(|_| DeliveryLogError::Unavailable)?;
        let exists = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM delivery_log WHERE delivery_id = ?1)",
                [intent.delivery().as_str()],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| DeliveryLogError::Unavailable)?;
        if exists {
            return Err(DeliveryLogError::Conflict);
        }
        let (records, bytes): (i64, i64) = transaction
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(charged_bytes), 0) FROM delivery_log",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| DeliveryLogError::Unavailable)?;
        let charged_bytes = i64::try_from(PERSISTENT_DELIVERY_RECORD_CHARGE_BYTES)
            .map_err(|_| DeliveryLogError::Unavailable)?;
        if records >= i64::from(self.limits.records())
            || bytes.saturating_add(charged_bytes)
                > i64::try_from(self.limits.bytes()).map_err(|_| DeliveryLogError::Unavailable)?
        {
            return Err(DeliveryLogError::CapacityExhausted);
        }
        let changed = transaction
            .execute(
                "INSERT OR IGNORE INTO delivery_log (
                     delivery_id, route_id, accepted_at_ms, attempts, state,
                     failure_kind, updated_at_ms, result_category, result_bytes,
                     charged_bytes
                 ) VALUES (?1, ?2, ?3, 0, 'pending', NULL, ?3, NULL, NULL, ?4)",
                params![
                    intent.delivery().as_str(),
                    intent.route().as_str(),
                    accepted_at,
                    charged_bytes,
                ],
            )
            .map_err(|_| DeliveryLogError::Unavailable)?;
        if changed != 1 {
            return Err(DeliveryLogError::Conflict);
        }
        transaction
            .commit()
            .map_err(|_| DeliveryLogError::Unavailable)
    }

    fn record_attempt(
        &self,
        delivery: &DeliveryId,
        attempts: u16,
        updated_at_unix_ms: u64,
    ) -> Result<(), DeliveryLogError> {
        if attempts == 0 {
            return Err(DeliveryLogError::InvalidTransition);
        }
        let updated_at = encoded_time(updated_at_unix_ms)?;
        self.transition(delivery, |transaction| {
            transaction.execute(
                "UPDATE delivery_log
                 SET attempts = ?2, updated_at_ms = ?3
                 WHERE delivery_id = ?1 AND state = 'pending' AND attempts < ?2",
                params![delivery.as_str(), i64::from(attempts), updated_at],
            )
        })
    }

    fn record_outcome(
        &self,
        delivery: &DeliveryId,
        outcome: DeliveryOutcome,
        updated_at_unix_ms: u64,
        result: Option<DeliveryResultMetadata>,
    ) -> Result<(), DeliveryLogError> {
        let updated_at = encoded_time(updated_at_unix_ms)?;
        let (state, failure) = encode_outcome(outcome);
        let (result_category, result_bytes) = encode_result(result);
        self.transition(delivery, |transaction| {
            transaction.execute(
                "UPDATE delivery_log
                 SET state = ?2, failure_kind = ?3, updated_at_ms = ?4,
                     result_category = ?5, result_bytes = ?6
                 WHERE delivery_id = ?1 AND state = 'pending'",
                params![
                    delivery.as_str(),
                    state,
                    failure,
                    updated_at,
                    result_category,
                    result_bytes,
                ],
            )
        })
    }

    fn delivery(&self, delivery: &DeliveryId) -> Result<Option<DeliveryRecord>, DeliveryLogError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT
                     delivery_id, route_id, accepted_at_ms, attempts, state,
                     failure_kind, updated_at_ms, result_category, result_bytes
                 FROM delivery_log
                 WHERE delivery_id = ?1",
                [delivery.as_str()],
                RawDeliveryRecord::read,
            )
            .optional()
            .map_err(|_| DeliveryLogError::Unavailable)?
            .map(RawDeliveryRecord::validate)
            .transpose()
    }

    fn recover_unfinished(&self, updated_at_unix_ms: u64) -> Result<u64, DeliveryLogError> {
        let updated_at = encoded_time(updated_at_unix_ms)?;
        let connection = self.connection()?;
        connection
            .execute(
                "UPDATE delivery_log
                 SET state = 'unknown_after_crash', updated_at_ms = ?1
                 WHERE state = 'pending'",
                [updated_at],
            )
            .map(|changed| changed as u64)
            .map_err(|_| DeliveryLogError::Unavailable)
    }
}

impl SqlCipherDeliveryLog {
    fn transition(
        &self,
        delivery: &DeliveryId,
        update: impl FnOnce(&Transaction<'_>) -> rusqlite::Result<usize>,
    ) -> Result<(), DeliveryLogError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| DeliveryLogError::Unavailable)?;
        let changed = update(&transaction).map_err(|_| DeliveryLogError::Unavailable)?;
        if changed == 1 {
            return transaction
                .commit()
                .map_err(|_| DeliveryLogError::Unavailable);
        }
        let exists = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM delivery_log WHERE delivery_id = ?1)",
                [delivery.as_str()],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| DeliveryLogError::Unavailable)?;
        if exists {
            Err(DeliveryLogError::InvalidTransition)
        } else {
            Err(DeliveryLogError::NotFound)
        }
    }
}

fn encoded_time(value: u64) -> Result<i64, DeliveryLogError> {
    i64::try_from(value).map_err(|_| DeliveryLogError::InvalidTransition)
}

fn encode_outcome(outcome: DeliveryOutcome) -> (&'static str, Option<&'static str>) {
    match outcome {
        DeliveryOutcome::Delivered => ("delivered", None),
        DeliveryOutcome::Failed(failure) => ("failed", Some(encode_failure(failure))),
        DeliveryOutcome::LostOnShutdown => ("lost_on_shutdown", None),
        DeliveryOutcome::UnknownAfterCrash => ("unknown_after_crash", None),
    }
}

fn encode_failure(failure: DeliveryFailure) -> &'static str {
    match failure {
        DeliveryFailure::Cancelled => "cancelled",
        DeliveryFailure::DeadlineExceeded => "deadline_exceeded",
        DeliveryFailure::EndpointPolicy => "endpoint_policy",
        DeliveryFailure::SecretUnavailable => "secret_unavailable",
        DeliveryFailure::TransportUnavailable => "transport_unavailable",
        DeliveryFailure::ReceiverRejected => "receiver_rejected",
        DeliveryFailure::RetryExhausted => "retry_exhausted",
        DeliveryFailure::Internal => "internal",
    }
}

fn encode_result(result: Option<DeliveryResultMetadata>) -> (Option<&'static str>, Option<i64>) {
    result.map_or((None, None), |result| {
        let category = match result.category() {
            DeliveryResultCategory::Succeeded => "succeeded",
            DeliveryResultCategory::Failed => "failed",
            DeliveryResultCategory::Invalid => "invalid",
        };
        (Some(category), Some(i64::from(result.bytes())))
    })
}

struct RawDeliveryRecord {
    delivery: String,
    route: String,
    accepted_at_ms: i64,
    attempts: i64,
    state: String,
    failure: Option<String>,
    updated_at_ms: i64,
    result_category: Option<String>,
    result_bytes: Option<i64>,
}

impl RawDeliveryRecord {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            delivery: row.get(0)?,
            route: row.get(1)?,
            accepted_at_ms: row.get(2)?,
            attempts: row.get(3)?,
            state: row.get(4)?,
            failure: row.get(5)?,
            updated_at_ms: row.get(6)?,
            result_category: row.get(7)?,
            result_bytes: row.get(8)?,
        })
    }

    fn validate(self) -> Result<DeliveryRecord, DeliveryLogError> {
        let delivery = DeliveryId::new(self.delivery).map_err(|_| DeliveryLogError::Unavailable)?;
        let route = RouteId::new(self.route).map_err(|_| DeliveryLogError::Unavailable)?;
        let accepted_at =
            u64::try_from(self.accepted_at_ms).map_err(|_| DeliveryLogError::Unavailable)?;
        let attempts = u16::try_from(self.attempts).map_err(|_| DeliveryLogError::Unavailable)?;
        let updated_at =
            u64::try_from(self.updated_at_ms).map_err(|_| DeliveryLogError::Unavailable)?;
        let state = decode_state(&self.state, self.failure.as_deref())?;
        let result = decode_result(self.result_category.as_deref(), self.result_bytes)?;
        Ok(DeliveryRecord::from_stored_parts(
            DeliveryIntent::new(route, delivery, accepted_at),
            attempts,
            state,
            updated_at,
            result,
        ))
    }
}

fn decode_state(state: &str, failure: Option<&str>) -> Result<DeliveryState, DeliveryLogError> {
    let state = match (state, failure) {
        ("pending", None) => DeliveryState::Pending,
        ("delivered", None) => DeliveryState::Terminal(DeliveryOutcome::Delivered),
        ("failed", Some(failure)) => {
            DeliveryState::Terminal(DeliveryOutcome::Failed(decode_failure(failure)?))
        }
        ("lost_on_shutdown", None) => DeliveryState::Terminal(DeliveryOutcome::LostOnShutdown),
        ("unknown_after_crash", None) => {
            DeliveryState::Terminal(DeliveryOutcome::UnknownAfterCrash)
        }
        _ => return Err(DeliveryLogError::Unavailable),
    };
    Ok(state)
}

fn decode_failure(value: &str) -> Result<DeliveryFailure, DeliveryLogError> {
    match value {
        "cancelled" => Ok(DeliveryFailure::Cancelled),
        "deadline_exceeded" => Ok(DeliveryFailure::DeadlineExceeded),
        "endpoint_policy" => Ok(DeliveryFailure::EndpointPolicy),
        "secret_unavailable" => Ok(DeliveryFailure::SecretUnavailable),
        "transport_unavailable" => Ok(DeliveryFailure::TransportUnavailable),
        "receiver_rejected" => Ok(DeliveryFailure::ReceiverRejected),
        "retry_exhausted" => Ok(DeliveryFailure::RetryExhausted),
        "internal" => Ok(DeliveryFailure::Internal),
        _ => Err(DeliveryLogError::Unavailable),
    }
}

fn decode_result(
    category: Option<&str>,
    bytes: Option<i64>,
) -> Result<Option<DeliveryResultMetadata>, DeliveryLogError> {
    match (category, bytes) {
        (None, None) => Ok(None),
        (Some(category), Some(bytes)) => {
            let category = match category {
                "succeeded" => DeliveryResultCategory::Succeeded,
                "failed" => DeliveryResultCategory::Failed,
                "invalid" => DeliveryResultCategory::Invalid,
                _ => return Err(DeliveryLogError::Unavailable),
            };
            let bytes = u32::try_from(bytes).map_err(|_| DeliveryLogError::Unavailable)?;
            Ok(Some(DeliveryResultMetadata::new(category, bytes)))
        }
        _ => Err(DeliveryLogError::Unavailable),
    }
}
