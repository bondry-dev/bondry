use std::sync::Arc;

use bondry_delivery_store::{
    DedupClaim, DedupClaimPolicy, DedupKey, DedupRecord, DedupResolution, DedupState, DedupStore,
    DedupStoreError, DedupStoreLimits, RouteId, StoreDurability, TrustedDeliveryIdHash,
    VerifierNamespace,
};
use rusqlite::{OptionalExtension, Row, Transaction, TransactionBehavior, params};

use crate::SqlCipherStore;

const DEDUP_RECORD_BASE_CHARGE_BYTES: u64 = 96;
const SELECT_FIRST_UNKNOWN: &str =
    "SELECT route_id, verifier_namespace, delivery_hash, state, updated_at_ms
     FROM webhook_dedup
     WHERE state = 'unknown' AND rowid <= ?1
     ORDER BY route_id, verifier_namespace, delivery_hash
     LIMIT 1";
const SELECT_NEXT_UNKNOWN: &str =
    "SELECT route_id, verifier_namespace, delivery_hash, state, updated_at_ms
     FROM webhook_dedup
     WHERE state = 'unknown' AND rowid <= ?4
         AND (route_id, verifier_namespace, delivery_hash) > (?1, ?2, ?3)
     ORDER BY route_id, verifier_namespace, delivery_hash
     LIMIT 1";

/// Bounded persistent webhook replay protection over an existing SQLCipher store.
pub struct SqlCipherDedupStore {
    store: Arc<SqlCipherStore>,
    limits: DedupStoreLimits,
}

impl SqlCipherDedupStore {
    /// Creates replay protection over one shared encrypted store.
    #[must_use]
    pub fn new(store: Arc<SqlCipherStore>, limits: DedupStoreLimits) -> Self {
        Self { store, limits }
    }

    /// Returns the enforced persistent replay-protection limits.
    #[must_use]
    pub const fn limits(&self) -> DedupStoreLimits {
        self.limits
    }

    fn connection(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, rusqlite::Connection>, DedupStoreError> {
        self.store
            .connection
            .lock()
            .map_err(|_| DedupStoreError::Unavailable)
    }

    fn transition(
        &self,
        key: &DedupKey,
        update: impl FnOnce(&Transaction<'_>) -> rusqlite::Result<usize>,
    ) -> Result<(), DedupStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| DedupStoreError::Unavailable)?;
        let changed = update(&transaction).map_err(|_| DedupStoreError::Unavailable)?;
        if changed == 1 {
            return transaction
                .commit()
                .map_err(|_| DedupStoreError::Unavailable);
        }
        if record_exists(&transaction, key)? {
            Err(DedupStoreError::InvalidTransition)
        } else {
            Err(DedupStoreError::NotFound)
        }
    }

    fn unknown_scan_bounds(&self) -> Result<(i64, i64), DedupStoreError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT COALESCE(MAX(rowid), 0), COUNT(*) FROM webhook_dedup
                 WHERE state = 'unknown'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| DedupStoreError::Unavailable)
    }

    fn next_unknown(
        &self,
        after: Option<&DedupKey>,
        rowid_ceiling: i64,
    ) -> Result<Option<DedupRecord>, DedupStoreError> {
        let connection = self.connection()?;
        let record = match after {
            Some(after) => connection
                .prepare_cached(SELECT_NEXT_UNKNOWN)
                .map_err(|_| DedupStoreError::Unavailable)?
                .query_row(
                    params![
                        after.route().as_str(),
                        after.namespace().as_str(),
                        after.delivery_hash().as_bytes().as_slice(),
                        rowid_ceiling,
                    ],
                    RawDedupRecord::read,
                )
                .optional(),
            None => connection
                .prepare_cached(SELECT_FIRST_UNKNOWN)
                .map_err(|_| DedupStoreError::Unavailable)?
                .query_row([rowid_ceiling], RawDedupRecord::read)
                .optional(),
        }
        .map_err(|_| DedupStoreError::Unavailable)?;
        record.map(RawDedupRecord::validate).transpose()
    }
}

impl DedupStore for SqlCipherDedupStore {
    fn durability(&self) -> StoreDurability {
        StoreDurability::Persistent
    }

    fn claim(
        &self,
        key: DedupKey,
        policy: DedupClaimPolicy,
        updated_at_unix_ms: u64,
    ) -> Result<DedupClaim, DedupStoreError> {
        let updated_at = encoded_time(updated_at_unix_ms)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| DedupStoreError::Unavailable)?;
        transaction
            .execute(
                "DELETE FROM webhook_dedup
                 WHERE state = 'completed' AND expires_at_ms IS NOT NULL
                     AND expires_at_ms <= ?1",
                [updated_at],
            )
            .map_err(|_| DedupStoreError::Unavailable)?;
        let existing = transaction
            .query_row(
                "SELECT state FROM webhook_dedup
                 WHERE route_id = ?1 AND verifier_namespace = ?2 AND delivery_hash = ?3",
                params![
                    key.route().as_str(),
                    key.namespace().as_str(),
                    key.delivery_hash().as_bytes().as_slice(),
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| DedupStoreError::Unavailable)?;
        if let Some(state) = existing {
            let state = decode_state(&state)?;
            transaction
                .commit()
                .map_err(|_| DedupStoreError::Unavailable)?;
            return Ok(DedupClaim::Duplicate(state));
        }
        let (records, bytes): (i64, i64) = transaction
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(charged_bytes), 0) FROM webhook_dedup",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| DedupStoreError::Unavailable)?;
        let charged_bytes = encoded_charge(&key)?;
        if records >= i64::from(self.limits.records())
            || bytes.saturating_add(charged_bytes)
                > i64::try_from(self.limits.bytes()).map_err(|_| DedupStoreError::Unavailable)?
        {
            transaction
                .commit()
                .map_err(|_| DedupStoreError::Unavailable)?;
            return Err(DedupStoreError::CapacityExhausted);
        }
        transaction
            .execute(
                "INSERT INTO webhook_dedup (
                     route_id, verifier_namespace, delivery_hash, state,
                     automatic_expiry, updated_at_ms, expires_at_ms, charged_bytes
                 ) VALUES (?1, ?2, ?3, 'in_flight', ?4, ?5, NULL, ?6)",
                params![
                    key.route().as_str(),
                    key.namespace().as_str(),
                    key.delivery_hash().as_bytes().as_slice(),
                    i64::from(policy == DedupClaimPolicy::ExpireCompleted),
                    updated_at,
                    charged_bytes,
                ],
            )
            .map_err(|_| DedupStoreError::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| DedupStoreError::Unavailable)?;
        Ok(DedupClaim::Claimed)
    }

    fn complete(&self, key: &DedupKey, updated_at_unix_ms: u64) -> Result<(), DedupStoreError> {
        let updated_at = encoded_time(updated_at_unix_ms)?;
        let expires_at = expiration(updated_at, self.limits)?;
        self.transition(key, |transaction| {
            transaction.execute(
                "UPDATE webhook_dedup
                 SET state = 'completed', updated_at_ms = ?4,
                     expires_at_ms = CASE automatic_expiry WHEN 1 THEN ?5 ELSE NULL END
                 WHERE route_id = ?1 AND verifier_namespace = ?2 AND delivery_hash = ?3
                     AND state = 'in_flight'",
                params![
                    key.route().as_str(),
                    key.namespace().as_str(),
                    key.delivery_hash().as_bytes().as_slice(),
                    updated_at,
                    expires_at,
                ],
            )
        })
    }

    fn mark_unknown(&self, key: &DedupKey, updated_at_unix_ms: u64) -> Result<(), DedupStoreError> {
        let updated_at = encoded_time(updated_at_unix_ms)?;
        self.transition(key, |transaction| {
            transaction.execute(
                "UPDATE webhook_dedup
                 SET state = 'unknown', updated_at_ms = ?4, expires_at_ms = NULL
                 WHERE route_id = ?1 AND verifier_namespace = ?2 AND delivery_hash = ?3
                     AND state = 'in_flight'",
                params![
                    key.route().as_str(),
                    key.namespace().as_str(),
                    key.delivery_hash().as_bytes().as_slice(),
                    updated_at,
                ],
            )
        })
    }

    fn release_claim(&self, key: &DedupKey) -> Result<(), DedupStoreError> {
        self.transition(key, |transaction| {
            transaction.execute(
                "DELETE FROM webhook_dedup
                 WHERE route_id = ?1 AND verifier_namespace = ?2 AND delivery_hash = ?3
                     AND state = 'in_flight'",
                params![
                    key.route().as_str(),
                    key.namespace().as_str(),
                    key.delivery_hash().as_bytes().as_slice(),
                ],
            )
        })
    }

    fn record(&self, key: &DedupKey) -> Result<Option<DedupRecord>, DedupStoreError> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT route_id, verifier_namespace, delivery_hash, state, updated_at_ms
                 FROM webhook_dedup
                 WHERE route_id = ?1 AND verifier_namespace = ?2 AND delivery_hash = ?3",
                params![
                    key.route().as_str(),
                    key.namespace().as_str(),
                    key.delivery_hash().as_bytes().as_slice(),
                ],
                RawDedupRecord::read,
            )
            .optional()
            .map_err(|_| DedupStoreError::Unavailable)?
            .map(RawDedupRecord::validate)
            .transpose()
    }

    fn recover_in_flight(&self, updated_at_unix_ms: u64) -> Result<u64, DedupStoreError> {
        let updated_at = encoded_time(updated_at_unix_ms)?;
        let connection = self.connection()?;
        connection
            .execute(
                "UPDATE webhook_dedup
                 SET state = 'unknown', updated_at_ms = ?1, expires_at_ms = NULL
                 WHERE state = 'in_flight'",
                [updated_at],
            )
            .map(|changed| changed as u64)
            .map_err(|_| DedupStoreError::Unavailable)
    }

    fn resolve_unknown(
        &self,
        key: &DedupKey,
        resolution: DedupResolution,
        updated_at_unix_ms: u64,
    ) -> Result<(), DedupStoreError> {
        let updated_at = encoded_time(updated_at_unix_ms)?;
        let expires_at = expiration(updated_at, self.limits)?;
        self.transition(key, |transaction| match resolution {
            DedupResolution::Completed => transaction.execute(
                "UPDATE webhook_dedup
                 SET state = 'completed', updated_at_ms = ?4,
                     expires_at_ms = CASE automatic_expiry WHEN 1 THEN ?5 ELSE NULL END
                 WHERE route_id = ?1 AND verifier_namespace = ?2 AND delivery_hash = ?3
                     AND state = 'unknown'",
                params![
                    key.route().as_str(),
                    key.namespace().as_str(),
                    key.delivery_hash().as_bytes().as_slice(),
                    updated_at,
                    expires_at,
                ],
            ),
            DedupResolution::RetryAllowed => transaction.execute(
                "DELETE FROM webhook_dedup
                 WHERE route_id = ?1 AND verifier_namespace = ?2 AND delivery_hash = ?3
                     AND state = 'unknown'",
                params![
                    key.route().as_str(),
                    key.namespace().as_str(),
                    key.delivery_hash().as_bytes().as_slice(),
                ],
            ),
        })
    }

    fn visit_unknown(
        &self,
        visitor: &mut dyn FnMut(&DedupRecord) -> bool,
    ) -> Result<(), DedupStoreError> {
        let (rowid_ceiling, record_count) = self.unknown_scan_bounds()?;
        let mut cursor = None;
        for _ in 0..record_count {
            let Some(record) = self.next_unknown(cursor.as_ref(), rowid_ceiling)? else {
                return Ok(());
            };
            cursor = Some(record.key().clone());
            if !visitor(&record) {
                return Ok(());
            }
        }
        Ok(())
    }

    fn clear_completed_before(&self, updated_before_unix_ms: u64) -> Result<u64, DedupStoreError> {
        let cutoff = encoded_time(updated_before_unix_ms)?;
        let connection = self.connection()?;
        connection
            .execute(
                "DELETE FROM webhook_dedup
                 WHERE state = 'completed' AND updated_at_ms < ?1",
                [cutoff],
            )
            .map(|changed| changed as u64)
            .map_err(|_| DedupStoreError::Unavailable)
    }
}

fn record_exists(transaction: &Transaction<'_>, key: &DedupKey) -> Result<bool, DedupStoreError> {
    transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM webhook_dedup
                 WHERE route_id = ?1 AND verifier_namespace = ?2 AND delivery_hash = ?3
             )",
            params![
                key.route().as_str(),
                key.namespace().as_str(),
                key.delivery_hash().as_bytes().as_slice(),
            ],
            |row| row.get(0),
        )
        .map_err(|_| DedupStoreError::Unavailable)
}

fn encoded_time(value: u64) -> Result<i64, DedupStoreError> {
    i64::try_from(value).map_err(|_| DedupStoreError::InvalidTransition)
}

fn expiration(updated_at: i64, limits: DedupStoreLimits) -> Result<i64, DedupStoreError> {
    let retention = i64::try_from(limits.retention().as_millis())
        .map_err(|_| DedupStoreError::InvalidTransition)?;
    Ok(updated_at.saturating_add(retention))
}

fn encoded_charge(key: &DedupKey) -> Result<i64, DedupStoreError> {
    let charge = DEDUP_RECORD_BASE_CHARGE_BYTES
        .checked_add(key.route().as_str().len() as u64)
        .and_then(|charge| charge.checked_add(key.namespace().as_str().len() as u64))
        .ok_or(DedupStoreError::Unavailable)?;
    i64::try_from(charge).map_err(|_| DedupStoreError::Unavailable)
}

fn decode_state(value: &str) -> Result<DedupState, DedupStoreError> {
    match value {
        "in_flight" => Ok(DedupState::InFlight),
        "completed" => Ok(DedupState::Completed),
        "unknown" => Ok(DedupState::Unknown),
        _ => Err(DedupStoreError::Unavailable),
    }
}

struct RawDedupRecord {
    route: String,
    namespace: String,
    delivery_hash: Vec<u8>,
    state: String,
    updated_at_ms: i64,
}

impl RawDedupRecord {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            route: row.get(0)?,
            namespace: row.get(1)?,
            delivery_hash: row.get(2)?,
            state: row.get(3)?,
            updated_at_ms: row.get(4)?,
        })
    }

    fn validate(self) -> Result<DedupRecord, DedupStoreError> {
        let route = RouteId::new(self.route).map_err(|_| DedupStoreError::Unavailable)?;
        let namespace =
            VerifierNamespace::new(self.namespace).map_err(|_| DedupStoreError::Unavailable)?;
        let delivery_hash: [u8; 32] = self
            .delivery_hash
            .try_into()
            .map_err(|_| DedupStoreError::Unavailable)?;
        let updated_at_ms =
            u64::try_from(self.updated_at_ms).map_err(|_| DedupStoreError::Unavailable)?;
        Ok(DedupRecord::from_stored_parts(
            DedupKey::new(
                route,
                namespace,
                TrustedDeliveryIdHash::from_bytes(delivery_hash),
            ),
            decode_state(&self.state)?,
            updated_at_ms,
        ))
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::StatementStatus;

    use super::{SELECT_FIRST_UNKNOWN, SELECT_NEXT_UNKNOWN, SqlCipherDedupStore};
    use crate::{DatabaseKey, SqlCipherStore};
    use bondry_delivery_store::{DedupStore, DedupStoreLimits};
    use std::sync::Arc;

    #[test]
    fn unknown_traversal_uses_bounded_index_seeks() -> Result<(), Box<dyn std::error::Error>> {
        const RECORDS: u32 = 2_000;
        let store = Arc::new(SqlCipherStore::open_in_memory(&DatabaseKey::from_bytes(
            [38; 32],
        ))?);
        {
            let mut connection = store.connection()?;
            let transaction = connection.transaction()?;
            for index in 0..RECORDS {
                let mut hash = [0_u8; 32];
                hash[..4].copy_from_slice(&index.to_be_bytes());
                transaction.execute(
                    "INSERT INTO webhook_dedup (
                         route_id, verifier_namespace, delivery_hash, state,
                         automatic_expiry, updated_at_ms, charged_bytes
                     ) VALUES ('route', 'namespace', ?1, 'unknown', 0, 0, 128)",
                    [hash.as_slice()],
                )?;
            }
            transaction.commit()?;
        }
        let dedup = SqlCipherDedupStore::new(store.clone(), DedupStoreLimits::default());
        let mut visited = 0;
        dedup.visit_unknown(&mut |_| {
            visited += 1;
            true
        })?;
        assert_eq!(visited, RECORDS);

        let connection = store.connection()?;
        for query in [SELECT_FIRST_UNKNOWN, SELECT_NEXT_UNKNOWN] {
            let statement = connection.prepare_cached(query)?;
            assert_eq!(statement.get_status(StatementStatus::Sort), 0);
            let steps = statement.get_status(StatementStatus::VmStep);
            assert!(
                steps > 0 && steps < (RECORDS * 100) as i32,
                "{steps} VM steps"
            );
        }
        Ok(())
    }
}
