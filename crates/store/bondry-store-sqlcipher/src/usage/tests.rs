use std::{
    cell::Cell,
    sync::{Arc, Barrier},
    time::Duration,
};

use bondry_delivery_store::{
    DedupClaim, DedupClaimPolicy, DedupKey, DedupResolution, DedupState, DedupStore,
    DedupStoreError, DedupStoreLimits, DeliveryId, DeliveryIntent, DeliveryLog, DeliveryLogError,
    DeliveryOutcome, PersistentDeliveryLogLimits, RouteId, TrustedDeliveryIdHash,
    VerifierNamespace,
};
use rusqlite::{
    Connection, StatementStatus, params,
    trace::{TraceEvent, TraceEventCodes},
};
use tempfile::TempDir;

use crate::{DatabaseKey, SqlCipherDedupStore, SqlCipherDeliveryLog, SqlCipherStore};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const RETENTION_MS: u64 = 7 * 86_400 * 1_000;

fn store() -> TestResult<Arc<SqlCipherStore>> {
    Ok(Arc::new(SqlCipherStore::open_in_memory(
        &DatabaseKey::from_bytes([41; 32]),
    )?))
}

fn key(index: u32) -> TestResult<DedupKey> {
    let mut hash = [0; 32];
    hash[..4].copy_from_slice(&index.to_be_bytes());
    Ok(DedupKey::new(
        RouteId::new("route")?,
        VerifierNamespace::new("namespace")?,
        TrustedDeliveryIdHash::from_bytes(hash),
    ))
}

fn intent(index: u32, time: u64) -> TestResult<DeliveryIntent> {
    Ok(DeliveryIntent::new(
        RouteId::new("route")?,
        DeliveryId::new(format!("delivery_{index}"))?,
        time,
    ))
}

fn dedup(store: &Arc<SqlCipherStore>) -> SqlCipherDedupStore {
    SqlCipherDedupStore::new(store.clone(), DedupStoreLimits::default())
}

fn delivery(store: &Arc<SqlCipherStore>) -> SqlCipherDeliveryLog {
    SqlCipherDeliveryLog::new(store.clone(), PersistentDeliveryLogLimits::default())
}

fn seed_history(store: &SqlCipherStore, records: u32) -> TestResult {
    let mut connection = store.connection()?;
    let transaction = connection.transaction()?;
    {
        let mut delivery = transaction.prepare(
            "INSERT INTO delivery_log (delivery_id, route_id, accepted_at_ms, attempts,
                 state, updated_at_ms, charged_bytes)
             VALUES (?1, 'route', 100, 1, 'delivered', 100, 512)",
        )?;
        let mut dedup = transaction.prepare(
            "INSERT INTO webhook_dedup (route_id, verifier_namespace, delivery_hash, state,
                 automatic_expiry, updated_at_ms, expires_at_ms, charged_bytes)
             VALUES ('route', 'namespace', ?1, 'completed', 1, 100, ?2, 110)",
        )?;
        for index in 0..records {
            delivery.execute([format!("delivery_{index}")])?;
            dedup.execute(params![
                key(index)?.delivery_hash().as_bytes().as_slice(),
                (RETENTION_MS + 100) as i64
            ])?;
        }
    }
    transaction.commit()?;
    Ok(())
}

fn assert_usage(store: &SqlCipherStore) -> TestResult {
    let connection = store.connection()?;
    for table in ["delivery_log", "webhook_dedup"] {
        let actual: (i64, i64) = connection.query_row(
            &format!("SELECT COUNT(*), COALESCE(SUM(charged_bytes), 0) FROM {table}"),
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(super::read(&connection, table)?, actual, "{table}");
    }
    Ok(())
}

pub(crate) fn remove_schema(store: &SqlCipherStore) -> rusqlite::Result<()> {
    let connection = store
        .connection()
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    for table in ["delivery_log", "webhook_dedup"] {
        for operation in ["insert", "delete", "update"] {
            connection.execute_batch(&format!("DROP TRIGGER {table}_usage_{operation}"))?;
        }
    }
    connection.execute_batch(
        "DROP TABLE storage_usage;
         DROP INDEX delivery_log_terminal_expiry;
         DROP INDEX webhook_dedup_by_expiry;
         CREATE INDEX webhook_dedup_by_expiry ON webhook_dedup(expires_at_ms)
             WHERE expires_at_ms IS NOT NULL;",
    )
}

#[test]
fn usage_tracks_dedup_lifecycle_and_variable_charges() -> TestResult {
    let store = store()?;
    let dedup = dedup(&store);
    for (index, policy) in [
        (1, DedupClaimPolicy::RetainCompleted),
        (2, DedupClaimPolicy::ExpireCompleted),
        (3, DedupClaimPolicy::RetainCompleted),
        (4, DedupClaimPolicy::RetainCompleted),
    ] {
        dedup.claim(key(index)?, policy, 100)?;
        assert_usage(&store)?;
    }
    dedup.complete(&key(1)?, 101)?;
    dedup.complete(&key(2)?, 101)?;
    dedup.mark_unknown(&key(3)?, 101)?;
    assert_eq!(
        dedup.claim(key(1)?, DedupClaimPolicy::RetainCompleted, 102)?,
        DedupClaim::Duplicate(DedupState::Completed)
    );
    assert_usage(&store)?;
    dedup.release_claim(&key(4)?)?;
    assert_usage(&store)?;
    dedup.resolve_unknown(&key(3)?, DedupResolution::RetryAllowed, 102)?;
    assert_usage(&store)?;
    dedup.claim(
        key(5)?,
        DedupClaimPolicy::RetainCompleted,
        RETENTION_MS + 102,
    )?;
    assert!(dedup.record(&key(2)?)?.is_none());
    assert_usage(&store)?;
    assert_eq!(dedup.clear_completed_before(102)?, 1);
    store
        .connection()?
        .execute("UPDATE webhook_dedup SET charged_bytes = 120", [])?;
    assert_eq!(
        super::read(&*store.connection()?, "webhook_dedup")?,
        (1, 120)
    );
    assert_usage(&store)?;
    assert_eq!(dedup.recover_in_flight(RETENTION_MS + 103)?, 1);
    dedup.resolve_unknown(&key(5)?, DedupResolution::Completed, RETENTION_MS + 104)?;
    assert_usage(&store)?;
    dedup.clear_completed_before(RETENTION_MS + 105)?;
    assert_usage(&store)?;
    assert_eq!(super::read(&*store.connection()?, "webhook_dedup")?, (0, 0));
    Ok(())
}

#[test]
fn usage_tracks_delivery_outcomes_recovery_and_retention() -> TestResult {
    let store = store()?;
    let delivery = delivery(&store);
    delivery.insert_intent(intent(1, 100)?)?;
    delivery.record_attempt(intent(1, 0)?.delivery(), 1, 101)?;
    delivery.record_outcome(
        intent(1, 0)?.delivery(),
        DeliveryOutcome::Delivered,
        102,
        None,
    )?;
    assert_usage(&store)?;
    delivery.insert_intent(intent(2, RETENTION_MS + 103)?)?;
    assert!(delivery.delivery(intent(1, 0)?.delivery())?.is_none());
    assert_usage(&store)?;
    assert_eq!(delivery.recover_unfinished(RETENTION_MS + 104)?, 1);
    assert_usage(&store)?;
    delivery.insert_intent(intent(3, 2 * RETENTION_MS + 105)?)?;
    assert!(delivery.delivery(intent(2, 0)?.delivery())?.is_none());
    assert_usage(&store)?;
    assert_eq!(
        super::read(&*store.connection()?, "delivery_log")?,
        (1, 512)
    );
    Ok(())
}

#[test]
fn failed_admission_rolls_back_cleanup_and_usage() -> TestResult {
    for table in ["delivery_log", "webhook_dedup"] {
        let store = store()?;
        seed_history(&store, 1)?;
        store.connection()?.execute_batch(&format!(
            "CREATE TRIGGER reject_admission BEFORE INSERT ON {table} BEGIN
                 SELECT RAISE(ABORT, 'fixture rejection'); END;"
        ))?;
        if table == "delivery_log" {
            assert_eq!(
                delivery(&store).insert_intent(intent(1, RETENTION_MS + 101)?),
                Err(DeliveryLogError::Unavailable)
            );
        } else {
            assert_eq!(
                dedup(&store).claim(
                    key(1)?,
                    DedupClaimPolicy::RetainCompleted,
                    RETENTION_MS + 101
                ),
                Err(DedupStoreError::Unavailable)
            );
        }
        assert_eq!(super::read(&*store.connection()?, table)?.0, 1);
        assert_usage(&store)?;
    }
    Ok(())
}

#[test]
fn ignored_admission_commits_completed_retention_cleanup() -> TestResult {
    let store = store()?;
    seed_history(&store, 1)?;
    store.connection()?.execute_batch(
        "CREATE TRIGGER ignore_admission BEFORE INSERT ON delivery_log BEGIN
             SELECT RAISE(IGNORE); END;",
    )?;
    assert_eq!(
        delivery(&store).insert_intent(intent(1, RETENTION_MS + 101)?),
        Err(DeliveryLogError::Conflict)
    );
    assert_eq!(super::read(&*store.connection()?, "delivery_log")?, (0, 0));
    assert_usage(&store)?;
    Ok(())
}

#[test]
fn duplicate_admissions_commit_completed_retention_cleanup() -> TestResult {
    let store = store()?;
    seed_history(&store, 2)?;
    store.connection()?.execute(
        "UPDATE delivery_log SET updated_at_ms = ?1 WHERE delivery_id = 'delivery_1'",
        [(RETENTION_MS + 100) as i64],
    )?;
    store.connection()?.execute(
        "UPDATE webhook_dedup SET expires_at_ms = ?1 WHERE delivery_hash = ?2",
        params![
            (2 * RETENTION_MS) as i64,
            key(1)?.delivery_hash().as_bytes().as_slice()
        ],
    )?;
    assert_eq!(
        delivery(&store).insert_intent(intent(1, RETENTION_MS + 101)?),
        Err(DeliveryLogError::Conflict)
    );
    assert_eq!(super::read(&*store.connection()?, "delivery_log")?.0, 1);
    assert_eq!(
        dedup(&store).claim(
            key(1)?,
            DedupClaimPolicy::RetainCompleted,
            RETENTION_MS + 101
        )?,
        DedupClaim::Duplicate(DedupState::Completed)
    );
    assert_eq!(super::read(&*store.connection()?, "webhook_dedup")?.0, 1);
    assert_usage(&store)?;
    Ok(())
}

#[test]
fn capacity_rejection_commits_completed_retention_cleanup() -> TestResult {
    let store = store()?;
    seed_history(&store, 1_001)?;
    store.connection()?.execute(
        "UPDATE delivery_log SET updated_at_ms = ?1 WHERE delivery_id != 'delivery_0'",
        [(RETENTION_MS + 100) as i64],
    )?;
    store.connection()?.execute(
        "UPDATE webhook_dedup SET expires_at_ms = ?1 WHERE delivery_hash != ?2",
        params![
            (2 * RETENTION_MS) as i64,
            key(0)?.delivery_hash().as_bytes().as_slice()
        ],
    )?;
    let delivery = SqlCipherDeliveryLog::new(
        store.clone(),
        PersistentDeliveryLogLimits::new(
            1_000,
            64 * 1024 * 1024,
            Duration::from_millis(RETENTION_MS),
        )?,
    );
    let dedup = SqlCipherDedupStore::new(
        store.clone(),
        DedupStoreLimits::new(1_000, 16 * 1024 * 1024, Duration::from_millis(RETENTION_MS))?,
    );
    assert_eq!(
        delivery.insert_intent(intent(2_000, RETENTION_MS + 101)?),
        Err(DeliveryLogError::CapacityExhausted)
    );
    assert_eq!(super::read(&*store.connection()?, "delivery_log")?.0, 1_000);
    assert_eq!(
        dedup.claim(
            key(2_000)?,
            DedupClaimPolicy::RetainCompleted,
            RETENTION_MS + 101
        ),
        Err(DedupStoreError::CapacityExhausted)
    );
    assert_eq!(
        super::read(&*store.connection()?, "webhook_dedup")?.0,
        1_000
    );
    assert_usage(&store)?;
    Ok(())
}

#[test]
fn byte_limits_use_persisted_usage_independently_of_record_limits() -> TestResult {
    let store = store()?;
    let records = 1024 * 1024 / 110;
    seed_history(&store, records)?;
    let dedup = SqlCipherDedupStore::new(
        store.clone(),
        DedupStoreLimits::new(100_000, 1024 * 1024, Duration::from_millis(RETENTION_MS))?,
    );
    assert_eq!(
        dedup.claim(key(records)?, DedupClaimPolicy::RetainCompleted, 1_000),
        Err(DedupStoreError::CapacityExhausted)
    );
    let delivery = SqlCipherDeliveryLog::new(
        store.clone(),
        PersistentDeliveryLogLimits::new(
            100_000,
            1024 * 1024,
            Duration::from_millis(RETENTION_MS),
        )?,
    );
    assert_eq!(
        delivery.insert_intent(intent(records, 1_000)?),
        Err(DeliveryLogError::CapacityExhausted)
    );
    assert_usage(&store)?;
    dedup.clear_completed_before(101)?;
    dedup.claim(key(records)?, DedupClaimPolicy::RetainCompleted, 1_000)?;
    assert_usage(&store)?;
    Ok(())
}

#[test]
fn missing_or_malformed_usage_fails_closed() -> TestResult {
    for table in ["delivery_log", "webhook_dedup"] {
        for damage in [
            "records = -1",
            "records = 'invalid'",
            "records = 1.5",
            "records = 0, charged_bytes = 1",
            "records = 1, charged_bytes = 0",
            "records = 9223372036854775807",
        ] {
            let store = store()?;
            store.connection()?.execute_batch(&format!(
                "PRAGMA ignore_check_constraints = ON;
                 UPDATE storage_usage SET {damage} WHERE table_name = '{table}';
                 PRAGMA ignore_check_constraints = OFF;"
            ))?;
            assert_admission_unavailable(&store, table)?;
        }
        let store = store()?;
        store
            .connection()?
            .execute("DELETE FROM storage_usage WHERE table_name = ?1", [table])?;
        assert_admission_unavailable(&store, table)?;
        let insert = if table == "delivery_log" {
            "INSERT OR IGNORE INTO delivery_log(delivery_id,route_id,accepted_at_ms,state,updated_at_ms,charged_bytes) VALUES ('direct','route',0,'pending',0,512)"
        } else {
            "INSERT OR IGNORE INTO webhook_dedup(route_id,verifier_namespace,delivery_hash,state,automatic_expiry,updated_at_ms,charged_bytes) VALUES ('route','namespace',zeroblob(32),'in_flight',0,0,110)"
        };
        assert!(store.connection()?.execute(insert, []).is_err());
        assert_eq!(
            store
                .connection()?
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))?,
            0
        );
    }
    Ok(())
}

fn assert_admission_unavailable(store: &Arc<SqlCipherStore>, table: &str) -> TestResult {
    if table == "delivery_log" {
        assert_eq!(
            delivery(store).insert_intent(intent(0, 1_000)?),
            Err(DeliveryLogError::Unavailable)
        );
    } else {
        assert_eq!(
            dedup(store).claim(key(0)?, DedupClaimPolicy::RetainCompleted, 1_000),
            Err(DedupStoreError::Unavailable)
        );
    }
    Ok(())
}

#[test]
fn counter_overflow_aborts_even_when_insert_conflicts_are_ignored() -> TestResult {
    let store = store()?;
    let dedup = dedup(&store);
    dedup.claim(key(0)?, DedupClaimPolicy::RetainCompleted, 100)?;
    store.connection()?.execute(
        "UPDATE storage_usage SET charged_bytes = ?1 WHERE table_name = 'webhook_dedup'",
        [i64::MAX],
    )?;
    assert!(store.connection()?.execute(
        "INSERT OR IGNORE INTO webhook_dedup(route_id,verifier_namespace,delivery_hash,state,automatic_expiry,updated_at_ms,charged_bytes)
         VALUES ('route','namespace',?1,'in_flight',0,0,110)",
        [key(1)?.delivery_hash().as_bytes().as_slice()],
    ).is_err());
    assert!(dedup.record(&key(1)?)?.is_none());
    assert_eq!(
        super::read(&*store.connection()?, "webhook_dedup")?,
        (1, i64::MAX)
    );
    Ok(())
}

#[test]
fn independent_connections_compete_for_the_last_quota_slot() -> TestResult {
    for is_dedup in [false, true] {
        let directory = TempDir::new()?;
        let path = directory.path().join("quota.db");
        let database_key = DatabaseKey::from_bytes([42; 32]);
        let first = Arc::new(SqlCipherStore::open(&path, &database_key)?);
        seed_history(&first, 999)?;
        let second = Arc::new(SqlCipherStore::open(&path, &database_key)?);
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for (index, store) in [(1_000, first.clone()), (1_001, second)] {
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || -> TestResult<bool> {
                barrier.wait();
                if is_dedup {
                    let dedup = SqlCipherDedupStore::new(
                        store,
                        DedupStoreLimits::new(
                            1_000,
                            16 * 1024 * 1024,
                            Duration::from_millis(RETENTION_MS),
                        )?,
                    );
                    match dedup.claim(key(index)?, DedupClaimPolicy::RetainCompleted, 1_000) {
                        Ok(DedupClaim::Claimed) => Ok(true),
                        Err(DedupStoreError::CapacityExhausted) => Ok(false),
                        result => Err(format!("unexpected quota result: {result:?}").into()),
                    }
                } else {
                    let delivery = SqlCipherDeliveryLog::new(
                        store,
                        PersistentDeliveryLogLimits::new(
                            1_000,
                            64 * 1024 * 1024,
                            Duration::from_millis(RETENTION_MS),
                        )?,
                    );
                    match delivery.insert_intent(intent(index, 1_000)?) {
                        Ok(()) => Ok(true),
                        Err(DeliveryLogError::CapacityExhausted) => Ok(false),
                        result => Err(format!("unexpected quota result: {result:?}").into()),
                    }
                }
            }));
        }
        barrier.wait();
        let accepted = threads
            .into_iter()
            .map(|thread| thread.join().map_err(|_| "quota thread panicked")?)
            .collect::<TestResult<Vec<_>>>()?;
        assert_eq!(accepted.into_iter().filter(|accepted| *accepted).count(), 1);
        assert_usage(&first)?;
        drop(first);
        assert_usage(&SqlCipherStore::open(&path, &database_key)?)?;
    }
    Ok(())
}

#[test]
fn version_six_migration_initializes_exact_usage_and_preserves_records() -> TestResult {
    let directory = TempDir::new()?;
    let path = directory.path().join("migration.db");
    let database_key = DatabaseKey::from_bytes([43; 32]);
    let store = Arc::new(SqlCipherStore::open(&path, &database_key)?);
    seed_history(&store, 3)?;
    dedup(&store).claim(key(3)?, DedupClaimPolicy::RetainCompleted, 1_000)?;
    dedup(&store).mark_unknown(&key(3)?, 1_001)?;
    delivery(&store).insert_intent(intent(3, 1_000)?)?;
    remove_schema(&store)?;
    store.connection()?.pragma_update(None, "user_version", 6)?;
    drop(store);

    let store = Arc::new(SqlCipherStore::open(&path, &database_key)?);
    assert_usage(&store)?;
    assert_eq!(
        super::read(&*store.connection()?, "delivery_log")?,
        (4, 4 * 512)
    );
    assert_eq!(
        super::read(&*store.connection()?, "webhook_dedup")?,
        (4, 4 * 110)
    );
    assert_eq!(
        dedup(&store).record(&key(3)?)?.map(|record| record.state()),
        Some(DedupState::Unknown)
    );
    dedup(&store).resolve_unknown(&key(3)?, DedupResolution::RetryAllowed, 1_002)?;
    delivery(&store).insert_intent(intent(4, 1_003)?)?;
    assert_usage(&store)?;
    drop(store);
    assert_usage(&SqlCipherStore::open(&path, &database_key)?)?;
    Ok(())
}

#[test]
fn invalid_legacy_charges_roll_back_the_entire_migration() -> TestResult {
    let directory = TempDir::new()?;
    let path = directory.path().join("invalid-migration.db");
    let database_key = DatabaseKey::from_bytes([44; 32]);
    let store = SqlCipherStore::open(&path, &database_key)?;
    seed_history(&store, 1)?;
    remove_schema(&store)?;
    store.connection()?.execute_batch(
        "UPDATE webhook_dedup SET charged_bytes = 110.5;
         PRAGMA user_version = 6;",
    )?;
    drop(store);

    assert!(SqlCipherStore::open(&path, &database_key).is_err());
    let connection = Connection::open(&path)?;
    let passphrase = database_key.sqlcipher_passphrase();
    connection.pragma_update(None, "key", passphrase.as_str())?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(version, 6);
    let usage_tables: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'storage_usage'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(usage_tables, 0);
    let charge: f64 =
        connection.query_row("SELECT charged_bytes FROM webhook_dedup", [], |row| {
            row.get(0)
        })?;
    assert_eq!(charge, 110.5);
    let delivery_records: i64 =
        connection.query_row("SELECT COUNT(*) FROM delivery_log", [], |row| row.get(0))?;
    assert_eq!(delivery_records, 1);
    Ok(())
}

thread_local! { static VM_STEPS: Cell<u64> = const { Cell::new(0) }; }

fn record_steps(event: TraceEvent<'_>) {
    if let TraceEvent::Profile(statement, _) = event {
        VM_STEPS.set(VM_STEPS.get() + statement.get_status(StatementStatus::VmStep) as u64);
    }
}

fn measure_steps(
    store: &SqlCipherStore,
    operation: impl FnOnce() -> TestResult,
) -> TestResult<u64> {
    {
        let connection = store.connection()?;
        connection.flush_prepared_statement_cache();
        VM_STEPS.set(0);
        connection.trace_v2(TraceEventCodes::SQLITE_TRACE_PROFILE, Some(record_steps));
    }
    let result = operation();
    store.connection()?.trace_v2(TraceEventCodes::empty(), None);
    result?;
    Ok(VM_STEPS.get())
}

#[test]
fn admission_work_stays_bounded_as_retained_history_grows() -> TestResult {
    let mut measured = Vec::new();
    for records in [2_000, 20_000] {
        let store = store()?;
        seed_history(&store, records)?;
        let delivery_steps = measure_steps(&store, || {
            delivery(&store).insert_intent(intent(records, 1_000)?)?;
            Ok(())
        })?;
        let dedup_steps = measure_steps(&store, || {
            dedup(&store).claim(key(records)?, DedupClaimPolicy::RetainCompleted, 1_000)?;
            Ok(())
        })?;
        assert_usage(&store)?;
        assert!(
            (1..1_000).contains(&delivery_steps),
            "{delivery_steps} delivery VM steps"
        );
        assert!(
            (1..1_000).contains(&dedup_steps),
            "{dedup_steps} dedup VM steps"
        );
        eprintln!(
            "{records} retained rows: delivery={delivery_steps}, dedup={dedup_steps} VM steps"
        );
        measured.push((delivery_steps, dedup_steps));
    }
    assert!(measured[1].0 <= measured[0].0 + 100);
    assert!(measured[1].1 <= measured[0].1 + 100);
    Ok(())
}

#[test]
fn repeated_delivery_rejections_do_not_repeat_expired_history_cleanup() -> TestResult {
    for conflict in [false, true] {
        for expired in [2_000_u32, 20_000] {
            let store = store()?;
            seed_history(&store, expired + 1_000)?;
            store.connection()?.execute(
                "UPDATE delivery_log SET state = 'pending' WHERE sequence > ?1",
                [expired + 1],
            )?;
            store.connection()?.execute(
                "UPDATE delivery_log SET updated_at_ms = 101 WHERE sequence = ?1",
                [expired + 1],
            )?;
            let delivery = SqlCipherDeliveryLog::new(
                store.clone(),
                PersistentDeliveryLogLimits::new(
                    1_000,
                    64 * 1024 * 1024,
                    Duration::from_millis(RETENTION_MS),
                )?,
            );
            let (rejected_id, error) = if conflict {
                (expired, DeliveryLogError::Conflict)
            } else {
                (expired + 1_000, DeliveryLogError::CapacityExhausted)
            };
            let mut measurements = Vec::new();
            for _ in 0..2 {
                measurements.push(measure_steps(&store, || {
                    assert_eq!(
                        delivery.insert_intent(intent(rejected_id, RETENTION_MS + 101)?),
                        Err(error)
                    );
                    Ok(())
                })?);
                assert_eq!(
                    super::read(&*store.connection()?, "delivery_log")?,
                    (1_000, 1_000 * 512)
                );
                assert_usage(&store)?;
            }
            assert!(measurements[0] > u64::from(expired), "{measurements:?}");
            assert!((1..1_000).contains(&measurements[1]), "{measurements:?}");
            assert!(delivery.delivery(intent(expired, 0)?.delivery())?.is_some());
            assert_eq!(
                delivery
                    .delivery(intent(expired + 999, 0)?.delivery())?
                    .map(|record| record.state()),
                Some(bondry_delivery_store::DeliveryState::Pending)
            );
            eprintln!("{expired} expired rows, {error:?}: {measurements:?} VM steps");
        }
    }
    Ok(())
}
