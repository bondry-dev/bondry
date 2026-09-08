use std::{
    cell::{Cell, RefCell},
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use bondry_delivery_store::{
    DedupClaimPolicy, DedupKey, DedupResolution, DedupState, DedupStore, DedupStoreError,
    DedupStoreLimits, DeliveryId, DeliveryIntent, DeliveryLog, PersistentDeliveryLogLimits,
    RouteId, TrustedDeliveryIdHash, VerifierNamespace,
};
use rusqlite::{
    Connection, StatementStatus,
    trace::{TraceEvent, TraceEventCodes},
};
use tempfile::TempDir;

use crate::{DatabaseKey, SqlCipherDedupStore, SqlCipherDeliveryLog, SqlCipherStore};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type StoredRow = (String, String, Vec<u8>, String, i64, i64, Option<i64>, i64);

fn key(route: &str) -> TestResult<DedupKey> {
    Ok(DedupKey::new(
        RouteId::new(route)?,
        VerifierNamespace::new("namespace")?,
        TrustedDeliveryIdHash::from_bytes([0; 32]),
    ))
}

fn dedup(store: &Arc<SqlCipherStore>) -> SqlCipherDedupStore {
    SqlCipherDedupStore::new(store.clone(), DedupStoreLimits::default())
}

fn claim_unknown(store: &SqlCipherDedupStore, key: DedupKey) -> Result<(), DedupStoreError> {
    store.claim(key.clone(), DedupClaimPolicy::RetainCompleted, 100)?;
    store.mark_unknown(&key, 101)
}

#[test]
fn callback_insertions_do_not_displace_initial_unknown_records() -> TestResult {
    let store = Arc::new(SqlCipherStore::open_in_memory(&DatabaseKey::from_bytes(
        [45; 32],
    ))?);
    let dedup = dedup(&store);
    let (a, ab, b) = (key("a")?, key("ab")?, key("b")?);
    claim_unknown(&dedup, b.clone())?;
    claim_unknown(&dedup, a.clone())?;
    let mut visited = Vec::new();
    let mut callback_result = Ok(());

    dedup.visit_unknown(&mut |record| {
        visited.push(record.key().clone());
        if record.key() == &a {
            callback_result = (|| {
                dedup.resolve_unknown(&a, DedupResolution::RetryAllowed, 102)?;
                claim_unknown(&dedup, ab.clone())
            })();
        }
        callback_result.is_ok()
    })?;

    callback_result?;
    assert_eq!(visited, [a, b]);
    assert_eq!(
        dedup.record(&ab)?.map(|record| record.state()),
        Some(DedupState::Unknown)
    );
    Ok(())
}

#[test]
fn traversal_excludes_reinserted_keys_after_emptying_and_reopening_the_store() -> TestResult {
    let directory = TempDir::new()?;
    let path = directory.path().join("reinsert.db");
    let database_key = DatabaseKey::from_bytes([46; 32]);
    let store = Arc::new(SqlCipherStore::open(&path, &database_key)?);
    let reader = dedup(&store);
    let (a, b) = (key("a")?, key("b")?);
    claim_unknown(&reader, b.clone())?;
    claim_unknown(&reader, a.clone())?;
    let mut visited = Vec::new();
    let mut callback_result: TestResult = Ok(());

    reader.visit_unknown(&mut |record| {
        visited.push(record.key().clone());
        if record.key() == &a {
            callback_result = (|| {
                reader.resolve_unknown(&a, DedupResolution::RetryAllowed, 102)?;
                reader.resolve_unknown(&b, DedupResolution::RetryAllowed, 102)?;
                let writer = Arc::new(SqlCipherStore::open(&path, &database_key)?);
                claim_unknown(&dedup(&writer), b.clone())?;
                Ok(())
            })();
        }
        callback_result.is_ok()
    })?;

    callback_result?;
    assert_eq!(visited, [a]);
    let mut next_pass = Vec::new();
    reader.visit_unknown(&mut |record| {
        next_pass.push(record.key().clone());
        true
    })?;
    assert_eq!(next_pass, [b]);
    assert_usage(&store)?;
    Ok(())
}

struct MigrationGate {
    waiting: mpsc::SyncSender<()>,
    resume: mpsc::Receiver<()>,
}

thread_local! {
    static MIGRATION_GATE: RefCell<Option<MigrationGate>> = const { RefCell::new(None) };
}

fn wait_for_migration(attempt: i32) -> bool {
    attempt == 0
        && MIGRATION_GATE.with_borrow(|gate| {
            gate.as_ref().is_some_and(|gate| {
                gate.waiting.send(()).is_ok()
                    && gate.resume.recv_timeout(Duration::from_secs(5)).is_ok()
            })
        })
}

#[test]
fn competing_migration_preserves_sequences_captured_by_active_traversal() -> TestResult {
    let directory = TempDir::new()?;
    let path = directory.path().join("competing.db");
    let database_key = DatabaseKey::from_bytes([51; 32]);
    let store = Arc::new(SqlCipherStore::open(&path, &database_key)?);
    let reader = dedup(&store);
    let (a, ab, b) = (key("a")?, key("ab")?, key("b")?);
    claim_unknown(&reader, b.clone())?;
    claim_unknown(&reader, a.clone())?;
    make_legacy_schema(&store, 7)?;
    let mut connection = store.connection()?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let (waiting_tx, waiting_rx) = mpsc::sync_channel(1);
    let (resume_tx, resume_rx) = mpsc::sync_channel(1);
    let worker = thread::spawn(move || -> TestResult {
        let mut connection = Connection::open(path)?;
        connection.pragma_update(None, "key", database_key.sqlcipher_passphrase().as_str())?;
        MIGRATION_GATE.set(Some(MigrationGate {
            waiting: waiting_tx,
            resume: resume_rx,
        }));
        connection.busy_handler(Some(wait_for_migration))?;
        super::migrate(&mut connection)?;
        Ok(())
    });
    waiting_rx.recv_timeout(Duration::from_secs(5))?;
    super::migrate_from_version_seven(&transaction)?;
    transaction.pragma_update(None, "user_version", super::SCHEMA_VERSION)?;
    transaction.commit()?;
    drop(connection);
    let mut worker = Some(worker);
    let mut visited = Vec::new();
    let mut callback_result: TestResult = Ok(());

    reader.visit_unknown(&mut |record| {
        visited.push(record.key().clone());
        if record.key() == &a {
            callback_result = (|| {
                reader.resolve_unknown(&a, DedupResolution::RetryAllowed, 102)?;
                claim_unknown(&reader, ab.clone())?;
                resume_tx.send(())?;
                if let Some(worker) = worker.take() {
                    worker
                        .join()
                        .map_err(|_| std::io::Error::other("migration worker panicked"))??;
                }
                Ok(())
            })();
        }
        callback_result.is_ok()
    })?;

    callback_result?;
    assert!(worker.is_none());
    assert_eq!(visited, [a, b]);
    assert_eq!(sequence_ceiling(&store)?, 3);
    assert_usage(&store)?;
    Ok(())
}

thread_local! { static STARTUP_VM_STEPS: Cell<u64> = const { Cell::new(0) }; }

fn record_steps(event: TraceEvent<'_>) {
    if let TraceEvent::Profile(statement, _) = event {
        STARTUP_VM_STEPS
            .set(STARTUP_VM_STEPS.get() + statement.get_status(StatementStatus::VmStep) as u64);
    }
}

#[test]
fn early_stop_cost_includes_constant_work_before_the_first_callback() -> TestResult {
    let mut measurements = Vec::new();
    for records in [2_000_u32, 20_000] {
        let store = Arc::new(SqlCipherStore::open_in_memory(&DatabaseKey::from_bytes(
            [47; 32],
        ))?);
        {
            let mut connection = store.connection()?;
            let transaction = connection.transaction()?;
            {
                let mut insert = transaction.prepare(
                    "INSERT INTO webhook_dedup (route_id, verifier_namespace, delivery_hash,
                         state, automatic_expiry, updated_at_ms, charged_bytes)
                     VALUES ('route', 'namespace', ?1, 'unknown', 0, 100, 110)",
                )?;
                for index in 0..records {
                    let mut hash = [0; 32];
                    hash[..4].copy_from_slice(&index.to_be_bytes());
                    insert.execute([hash.as_slice()])?;
                }
            }
            transaction.commit()?;
            connection.flush_prepared_statement_cache();
            STARTUP_VM_STEPS.set(0);
            connection.trace_v2(TraceEventCodes::SQLITE_TRACE_PROFILE, Some(record_steps));
        }
        let mut visited = 0;
        let result = dedup(&store).visit_unknown(&mut |_| {
            visited += 1;
            false
        });
        store.connection()?.trace_v2(TraceEventCodes::empty(), None);
        result?;
        let steps = STARTUP_VM_STEPS.get();
        assert_eq!(visited, 1);
        assert!(steps > 0 && steps < 200, "{steps} startup VM steps");
        println!("{records} unknown rows: traversal startup={steps} VM steps");
        measurements.push(steps);
    }
    assert!(measurements[1] <= measurements[0] + 16, "{measurements:?}");
    Ok(())
}

#[test]
fn legacy_migrations_preserve_replay_records_accounting_and_atomicity() -> TestResult {
    for (version, malformed) in [(5, false), (6, false), (7, false), (7, true)] {
        let directory = TempDir::new()?;
        let path = directory.path().join("legacy.db");
        let database_key = DatabaseKey::from_bytes([48; 32]);
        let store = Arc::new(SqlCipherStore::open(&path, &database_key)?);
        seed_migration_records(&store)?;
        make_legacy_schema(&store, version)?;
        if malformed {
            store.connection()?.execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 UPDATE webhook_dedup SET state = 'invalid' WHERE route_id = 'unknown';
                 PRAGMA ignore_check_constraints = OFF;",
            )?;
        }
        let expected = stored_rows(&*store.connection()?)?;
        drop(store);

        if malformed {
            assert!(SqlCipherStore::open(&path, &database_key).is_err());
            let connection = Connection::open(&path)?;
            connection.pragma_update(None, "key", database_key.sqlcipher_passphrase().as_str())?;
            assert_eq!(stored_rows(&connection)?, expected);
            assert_eq!(schema_version(&connection)?, version);
            let replacement_exists: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'webhook_dedup_next')",
                [],
                |row| row.get(0),
            )?;
            assert!(!replacement_exists);
            assert_eq!(crate::usage::read(&connection, "webhook_dedup")?.0, 4);
            continue;
        }

        let store = Arc::new(SqlCipherStore::open(&path, &database_key)?);
        {
            let connection = store.connection()?;
            assert_eq!(schema_version(&connection)?, 8);
            assert_eq!(stored_rows(&connection)?, expected);
            for (index, predicate) in [
                ("webhook_dedup_by_expiry", "state = 'completed'"),
                ("webhook_dedup_by_state_key", "state = 'unknown'"),
            ] {
                let sql: String = connection.query_row(
                    "SELECT sql FROM sqlite_master WHERE name = ?1",
                    [index],
                    |row| row.get(0),
                )?;
                assert!(sql.contains(predicate));
            }
            assert_eq!(crate::usage::read(&connection, "delivery_log")?, (1, 512));
        }
        assert_usage(&store)?;
        claim_unknown(&dedup(&store), key("after")?)?;
        assert_usage(&store)?;
        drop(store);
        let reopened = Arc::new(SqlCipherStore::open(&path, &database_key)?);
        assert_usage(&reopened)?;
        let mut unknown = Vec::new();
        dedup(&reopened).visit_unknown(&mut |record| {
            unknown.push(record.key().route().as_str().to_owned());
            true
        })?;
        assert_eq!(unknown, ["after", "unknown"]);
    }
    Ok(())
}

#[test]
fn failed_insertions_preserve_sequence_accounting_and_existing_records() -> TestResult {
    let store = Arc::new(SqlCipherStore::open_in_memory(&DatabaseKey::from_bytes(
        [49; 32],
    ))?);
    let dedup = dedup(&store);
    let existing = key("existing")?;
    claim_unknown(&dedup, existing.clone())?;
    let ceiling = sequence_ceiling(&store)?;
    {
        let mut connection = store.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO webhook_dedup (route_id, verifier_namespace, delivery_hash, state,
                 automatic_expiry, updated_at_ms, charged_bytes)
             VALUES ('rolled_back', 'namespace', ?1, 'unknown', 0, 100, 128)",
            [[0_u8; 32].as_slice()],
        )?;
        transaction.rollback()?;
    }
    assert_eq!(sequence_ceiling(&store)?, ceiling);
    assert!(dedup.record(&key("rolled_back")?)?.is_none());
    assert_usage(&store)?;
    store.connection()?.execute(
        "UPDATE sqlite_sequence SET seq = ?1 WHERE name = 'webhook_dedup'",
        [i64::MAX],
    )?;
    assert_eq!(
        dedup.claim(key("exhausted")?, DedupClaimPolicy::RetainCompleted, 102),
        Err(DedupStoreError::Unavailable)
    );
    assert_eq!(sequence_ceiling(&store)?, ceiling);
    assert!(dedup.record(&key("exhausted")?)?.is_none());
    assert_eq!(
        dedup.record(&existing)?.map(|record| record.state()),
        Some(DedupState::Unknown)
    );
    assert_usage(&store)?;
    Ok(())
}

#[test]
fn sequence_aliases_cannot_change_during_ordinary_record_transitions() -> TestResult {
    let store = Arc::new(SqlCipherStore::open_in_memory(&DatabaseKey::from_bytes(
        [50; 32],
    ))?);
    let dedup = dedup(&store);
    let key = key("record")?;
    claim_unknown(&dedup, key.clone())?;
    let ceiling = sequence_ceiling(&store)?;
    for alias in ["sequence", "rowid", "_rowid_", "oid"] {
        assert!(
            store
                .connection()?
                .execute(
                    &format!("UPDATE webhook_dedup SET {alias} = 100 WHERE route_id = 'record'"),
                    [],
                )
                .is_err()
        );
    }
    dedup.resolve_unknown(&key, DedupResolution::Completed, 102)?;
    assert_eq!(sequence_ceiling(&store)?, ceiling);
    assert_eq!(
        dedup.record(&key)?.map(|record| record.state()),
        Some(DedupState::Completed)
    );
    assert_usage(&store)?;
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
        assert_eq!(crate::usage::read(&connection, table)?, actual);
    }
    Ok(())
}

fn schema_version(connection: &Connection) -> rusqlite::Result<i64> {
    connection.pragma_query_value(None, "user_version", |row| row.get(0))
}

fn stored_rows(connection: &Connection) -> rusqlite::Result<Vec<StoredRow>> {
    connection
        .prepare(
            "SELECT route_id, verifier_namespace, delivery_hash, state, automatic_expiry,
             updated_at_ms, expires_at_ms, charged_bytes FROM webhook_dedup ORDER BY route_id",
        )?
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ))
        })?
        .collect()
}

fn seed_migration_records(store: &Arc<SqlCipherStore>) -> TestResult {
    let dedup = dedup(store);
    for (route, policy) in [
        ("in_flight", DedupClaimPolicy::RetainCompleted),
        ("unknown", DedupClaimPolicy::RetainCompleted),
        ("retained", DedupClaimPolicy::RetainCompleted),
        ("expiring", DedupClaimPolicy::ExpireCompleted),
    ] {
        dedup.claim(key(route)?, policy, 100)?;
    }
    dedup.mark_unknown(&key("unknown")?, 101)?;
    dedup.complete(&key("retained")?, 102)?;
    dedup.complete(&key("expiring")?, 103)?;
    SqlCipherDeliveryLog::new(store.clone(), PersistentDeliveryLogLimits::default())
        .insert_intent(DeliveryIntent::new(
            RouteId::new("route")?,
            DeliveryId::new("delivery")?,
            100,
        ))?;
    Ok(())
}

fn make_legacy_schema(store: &SqlCipherStore, version: i64) -> TestResult {
    if version < 7 {
        crate::usage::tests::remove_schema(store)?;
    }
    let mut connection = store.connection()?;
    let transaction = connection.transaction()?;
    transaction.execute_batch(
        "CREATE TABLE webhook_dedup_legacy (
             route_id TEXT NOT NULL, verifier_namespace TEXT NOT NULL,
             delivery_hash BLOB NOT NULL CHECK (length(delivery_hash) = 32),
             state TEXT NOT NULL CHECK (state IN ('in_flight', 'completed', 'unknown')),
             automatic_expiry INTEGER NOT NULL CHECK (automatic_expiry IN (0, 1)),
             updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0), expires_at_ms INTEGER,
             charged_bytes INTEGER NOT NULL CHECK (charged_bytes >= 96),
             PRIMARY KEY (route_id, verifier_namespace, delivery_hash),
             CHECK ((state = 'completed' AND automatic_expiry = 1 AND expires_at_ms IS NOT NULL)
                 OR (state = 'completed' AND automatic_expiry = 0 AND expires_at_ms IS NULL)
                 OR (state != 'completed' AND expires_at_ms IS NULL))
         );
         INSERT INTO webhook_dedup_legacy
         SELECT route_id, verifier_namespace, delivery_hash, state, automatic_expiry,
             updated_at_ms, expires_at_ms, charged_bytes FROM webhook_dedup ORDER BY sequence;
         DROP TABLE webhook_dedup;
         ALTER TABLE webhook_dedup_legacy RENAME TO webhook_dedup;
         CREATE INDEX webhook_dedup_by_state ON webhook_dedup(state, updated_at_ms);",
    )?;
    if version == 7 {
        transaction.execute_batch(
            "CREATE INDEX webhook_dedup_by_expiry ON webhook_dedup(state, expires_at_ms)
                 WHERE state = 'completed' AND expires_at_ms IS NOT NULL;",
        )?;
        crate::usage::create_triggers(&transaction, "webhook_dedup")?;
    } else {
        transaction.execute_batch(
            "CREATE INDEX webhook_dedup_by_expiry ON webhook_dedup(expires_at_ms)
                 WHERE expires_at_ms IS NOT NULL;",
        )?;
    }
    if version >= 6 {
        transaction.execute_batch(
            "CREATE INDEX webhook_dedup_by_state_key
                 ON webhook_dedup(state, route_id, verifier_namespace, delivery_hash)
                 WHERE state = 'unknown';",
        )?;
    }
    transaction.pragma_update(None, "user_version", version)?;
    transaction.commit()?;
    Ok(())
}

fn sequence_ceiling(store: &SqlCipherStore) -> TestResult<i64> {
    Ok(store.connection()?.query_row(
        "SELECT COALESCE(MAX(sequence), 0) FROM webhook_dedup",
        [],
        |row| row.get(0),
    )?)
}
