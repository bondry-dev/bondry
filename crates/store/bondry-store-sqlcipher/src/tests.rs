use std::{
    fs,
    sync::{Arc, Barrier},
    time::SystemTime,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bondry_auth::{
    AuthManager, AuthStore, Client, ClientName, RotationOutcome, StoreError, TokenDigest, TokenId,
    TokenLabel, TokenLifecycleError, TokenRecord, TokenReplacement,
};
use bondry_core::{
    AdapterId, AuditEvent, AuditOutcome, AuditSink, CapabilityDescriptor, CapabilityEffect,
    CapabilityGrant, CapabilityId, CapabilityRegistry, Dispatcher, GrantStore, Invocation,
    InvocationId, Principal, PrincipalId, PrincipalKind, StoredGrantPolicy,
};
use bondry_delivery_store::{
    DedupClaim, DedupClaimPolicy, DedupKey, DedupResolution, DedupState, DedupStore,
    DedupStoreError, DedupStoreLimits, DeliveryId, DeliveryIntent, DeliveryLog, DeliveryLogError,
    DeliveryOutcome, DeliveryResultCategory, DeliveryResultMetadata, DeliveryState,
    MIN_DEDUP_STORE_BYTES, MIN_DEDUP_STORE_RECORDS, MIN_DEDUP_STORE_RETENTION,
    MIN_PERSISTENT_DELIVERY_LOG_BYTES, MIN_PERSISTENT_DELIVERY_LOG_RECORDS,
    MIN_PERSISTENT_DELIVERY_LOG_RETENTION, PersistentDeliveryLogLimits, RouteId, StoreDurability,
    TrustedDeliveryIdHash, VerifierNamespace,
};
use futures::executor::block_on;
use serde_json::json;
use tempfile::TempDir;

use crate::{
    AuditQueryLimit, DatabaseKey, DatabaseKeyError, SqlCipherDedupStore, SqlCipherDeliveryLog,
    SqlCipherStore, SqlCipherStoreError,
};

fn database_path(directory: &TempDir) -> std::path::PathBuf {
    directory.path().join("bondry.db")
}

fn fixed_key(value: u8) -> DatabaseKey {
    DatabaseKey::from_bytes([value; 32])
}

fn delivery_intent(id: impl Into<String>, timestamp: u64) -> DeliveryIntent {
    let id = id.into();
    DeliveryIntent::new(
        RouteId::new("watchdog.power")
            .unwrap_or_else(|error| unreachable!("valid route ID: {error}")),
        DeliveryId::new(id).unwrap_or_else(|error| unreachable!("valid delivery ID: {error}")),
        timestamp,
    )
}

fn dedup_key(index: u32) -> Result<DedupKey, Box<dyn std::error::Error>> {
    let mut hash = [0_u8; 32];
    hash[..4].copy_from_slice(&index.to_be_bytes());
    Ok(DedupKey::new(
        RouteId::new("webhook.route")?,
        VerifierNamespace::new("provider:hmac:v1")?,
        TrustedDeliveryIdHash::from_bytes(hash),
    ))
}

#[test]
fn encrypts_the_database_and_rejects_the_wrong_key() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = database_path(&directory);
    let key = fixed_key(7);
    let store = Arc::new(SqlCipherStore::open(&path, &key)?);
    let manager = AuthManager::from_shared(store.clone());
    let client = manager.create_client(ClientName::new("Private Client Marker")?)?;
    let issued = manager.issue_token(
        client.id(),
        Some(TokenLabel::new("Private Token Marker")?),
        None,
    )?;
    assert!(store.add_grant(CapabilityGrant::new(
        client.id().clone(),
        AdapterId::new("private_adapter")?,
        CapabilityId::new("private.capability")?,
    ))?);
    let delivery_log =
        SqlCipherDeliveryLog::new(store.clone(), PersistentDeliveryLogLimits::default());
    delivery_log.insert_intent(DeliveryIntent::new(
        RouteId::new("private.route.marker")?,
        DeliveryId::new("private.delivery.marker")?,
        1,
    ))?;
    let dedup = SqlCipherDedupStore::new(store.clone(), DedupStoreLimits::default());
    let dedup_marker = DedupKey::new(
        RouteId::new("private.dedup.route.marker")?,
        VerifierNamespace::new("private.dedup.namespace.marker")?,
        TrustedDeliveryIdHash::from_bytes([0x5a; 32]),
    );
    assert_eq!(
        dedup.claim(dedup_marker.clone(), DedupClaimPolicy::RetainCompleted, 1,)?,
        DedupClaim::Claimed
    );
    dedup.complete(&dedup_marker, 2)?;
    assert!(manager.authenticate(issued.secret().expose()).is_ok());
    drop(delivery_log);
    drop(dedup);
    drop(manager);
    drop(store);

    let mut persisted = Vec::new();
    for candidate in [
        path.clone(),
        path.with_extension("db-wal"),
        path.with_extension("db-shm"),
    ] {
        if candidate.exists() {
            persisted.extend(fs::read(candidate)?);
        }
    }
    for marker in [
        b"SQLite format 3".as_slice(),
        b"CREATE TABLE clients".as_slice(),
        b"Private Client Marker".as_slice(),
        b"Private Token Marker".as_slice(),
        b"private_adapter".as_slice(),
        b"private.capability".as_slice(),
        b"private.route.marker".as_slice(),
        b"private.delivery.marker".as_slice(),
        b"private.dedup.route.marker".as_slice(),
        b"private.dedup.namespace.marker".as_slice(),
        issued.secret().expose().as_bytes(),
    ] {
        assert!(!contains_bytes(&persisted, marker));
    }

    assert!(matches!(
        SqlCipherStore::open(&path, &fixed_key(8)),
        Err(SqlCipherStoreError::InvalidKey)
    ));
    let reopened = Arc::new(SqlCipherStore::open(&path, &key)?);
    let manager = AuthManager::from_shared(reopened);
    assert!(manager.authenticate(issued.secret().expose()).is_ok());
    Ok(())
}

#[cfg(unix)]
#[test]
fn restricts_database_file_permissions() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let directory = TempDir::new()?;
    let path = database_path(&directory);
    let store = SqlCipherStore::open(&path, &fixed_key(9))?;
    let manager = AuthManager::new(store);
    let _client = manager.create_client(ClientName::new("Client")?)?;
    drop(manager);

    assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    Ok(())
}

#[test]
fn reports_a_real_sqlcipher_runtime() -> Result<(), Box<dyn std::error::Error>> {
    let store = SqlCipherStore::open_in_memory(&fixed_key(10))?;
    let version: String = store
        .connection()?
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
    assert!(!version.is_empty());
    Ok(())
}

#[test]
fn keeps_rotation_atomic_when_replacement_conflicts() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(SqlCipherStore::open_in_memory(&fixed_key(11))?);
    let manager = AuthManager::from_shared(store.clone());
    let client = manager.create_client(ClientName::new("Client")?)?;
    let current = manager.issue_token(client.id(), None, None)?;
    let blocker = manager.issue_token(client.id(), None, None)?;
    let blocker_record = store
        .tokens_for_client(client.id())?
        .into_iter()
        .find(|token| token.id() == blocker.metadata().id())
        .ok_or(std::io::Error::other("blocker token missing"))?;
    let replacement = TokenReplacement::new(
        token_id(200)?,
        None,
        blocker_record.digest().clone(),
        2_000,
        None,
    );

    assert_eq!(
        store.rotate_token(current.metadata().id(), replacement, 2_000),
        Err(StoreError::Conflict)
    );
    assert!(manager.authenticate(current.secret().expose()).is_ok());
    assert_eq!(store.tokens_for_client(client.id())?.len(), 2);
    Ok(())
}

#[test]
fn lists_clients_in_stable_identifier_order() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(SqlCipherStore::open_in_memory(&fixed_key(21))?);
    let manager = AuthManager::from_shared(store.clone());
    let first = manager.create_client(ClientName::new("First")?)?;
    let second = manager.create_client(ClientName::new("Second")?)?;
    let mut expected = vec![first, second];
    expected.sort_unstable_by(|left, right| left.id().cmp(right.id()));

    assert_eq!(manager.clients()?, expected);
    assert_eq!(store.clients()?, expected);
    Ok(())
}

#[test]
fn allows_only_one_rotation_across_independent_connections()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = database_path(&directory);
    let key = fixed_key(12);
    let first_store = Arc::new(SqlCipherStore::open(&path, &key)?);
    let first = Arc::new(AuthManager::from_shared(first_store));
    let client = first.create_client(ClientName::new("Client")?)?;
    let current = first.issue_token(client.id(), None, None)?;
    let second_store = Arc::new(SqlCipherStore::open(&path, &key)?);
    let second = Arc::new(AuthManager::from_shared(second_store));
    let barrier = Arc::new(Barrier::new(3));

    let mut handles = Vec::new();
    for manager in [first, second] {
        let current = current.metadata().id().clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            manager.rotate_token(&current, None, None).map(|_| ())
        }));
    }
    barrier.wait();

    let mut results = Vec::new();
    for handle in handles {
        results.push(
            handle
                .join()
                .map_err(|_| std::io::Error::other("rotation thread panicked"))?,
        );
    }
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(TokenLifecycleError::Inactive))
            .count(),
        1
    );
    Ok(())
}

#[test]
fn persists_and_filters_protocol_neutral_audit_events() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = database_path(&directory);
    let key = fixed_key(13);
    let store = Arc::new(SqlCipherStore::open(&path, &key)?);
    let manager = AuthManager::from_shared(store.clone());
    let client = manager.create_client(ClientName::new("Client")?)?;
    let capability = CapabilityId::new("battery.snapshot")?;
    let adapter = AdapterId::new("mcp")?;
    let mut registry = CapabilityRegistry::new();
    registry.register(
        CapabilityDescriptor::new(
            capability.clone(),
            "Read battery snapshot",
            CapabilityEffect::ReadOnly,
        )?,
        |_, _| async { Ok(json!({ "level": 80 })) },
    )?;
    let grant = CapabilityGrant::new(client.id().clone(), adapter.clone(), capability.clone());
    assert!(store.add_grant(grant)?);
    let policy_store: Arc<dyn GrantStore> = store.clone();
    let policy = StoredGrantPolicy::from_shared(policy_store);
    let audit: Arc<dyn AuditSink> = store.clone();
    let dispatcher = Dispatcher::from_shared(registry, Arc::new(policy), audit);

    let output = block_on(dispatcher.dispatch(Invocation::new(
        InvocationId::new("request-1")?,
        adapter,
        Principal::new(client.id().clone(), PrincipalKind::Application),
        capability,
        json!({ "private": "payload-marker" }),
    )))?;
    assert_eq!(output, json!({ "level": 80 }));

    store.record(AuditEvent::from_parts(
        SystemTime::now(),
        InvocationId::new("request-other")?,
        PrincipalId::new("client_other")?,
        AdapterId::new("rest")?,
        CapabilityId::new("other.read")?,
        AuditOutcome::Succeeded,
    ))?;
    drop(dispatcher);
    drop(manager);
    drop(store);

    let store = SqlCipherStore::open(&path, &key)?;
    let persisted_grant = CapabilityGrant::new(
        client.id().clone(),
        AdapterId::new("mcp")?,
        CapabilityId::new("battery.snapshot")?,
    );
    assert!(store.contains_grant(
        persisted_grant.principal(),
        persisted_grant.adapter(),
        persisted_grant.capability(),
    )?);
    let events = store.audit_events_for_principal(client.id(), AuditQueryLimit::new(10)?)?;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event().outcome(), &AuditOutcome::Succeeded);
    assert_eq!(events[1].event().outcome(), &AuditOutcome::Started);
    assert_eq!(
        store.recent_audit_events(AuditQueryLimit::new(10)?)?.len(),
        3
    );
    assert_eq!(
        store.recent_audit_events(AuditQueryLimit::new(1)?)?.len(),
        1
    );
    let persisted = fs::read(path)?;
    assert!(!contains_bytes(&persisted, b"payload-marker"));
    Ok(())
}

#[test]
fn schema_contains_no_credential_or_payload_columns() -> Result<(), Box<dyn std::error::Error>> {
    let store = SqlCipherStore::open_in_memory(&fixed_key(14))?;
    let connection = store.connection()?;
    for table in [
        "clients",
        "tokens",
        "audit_events",
        "grants",
        "delivery_log",
        "webhook_dedup",
    ] {
        let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
        let names = statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for forbidden in [
            "secret",
            "credential",
            "payload",
            "input",
            "output",
            "token",
        ] {
            assert!(!names.iter().any(|name| name == forbidden));
        }
    }
    Ok(())
}

#[test]
fn persists_lists_and_removes_exact_grants() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = database_path(&directory);
    let key = fixed_key(22);
    let store = SqlCipherStore::open(&path, &key)?;
    let principal = PrincipalId::new("client_policy")?;
    let first = CapabilityGrant::new(
        principal.clone(),
        AdapterId::new("rest")?,
        CapabilityId::new("battery.status")?,
    );
    let second = CapabilityGrant::new(
        principal.clone(),
        AdapterId::new("mcp")?,
        CapabilityId::new("battery.health")?,
    );

    assert!(store.add_grant(first.clone())?);
    assert!(!store.add_grant(first.clone())?);
    assert!(store.add_grant(second.clone())?);
    assert_eq!(
        store.grants_for_principal(&principal)?,
        vec![second.clone(), first.clone()]
    );
    drop(store);

    let store = SqlCipherStore::open(&path, &key)?;
    assert!(store.contains_grant(first.principal(), first.adapter(), first.capability())?);
    assert!(store.remove_grant(&first)?);
    assert!(!store.remove_grant(&first)?);
    assert!(!store.contains_grant(first.principal(), first.adapter(), first.capability())?);
    assert_eq!(store.grants_for_principal(&principal)?, vec![second]);
    Ok(())
}

#[test]
fn migrates_version_one_without_losing_authentication_state()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = database_path(&directory);
    let key = fixed_key(23);
    let store = Arc::new(SqlCipherStore::open(&path, &key)?);
    let manager = AuthManager::from_shared(store.clone());
    let client = manager.create_client(ClientName::new("Migrated Client")?)?;
    let issued = manager.issue_token(client.id(), None, None)?;
    store.connection()?.execute_batch(
        "DROP TABLE grants;
         DROP TABLE delivery_log;
         DROP TABLE webhook_dedup;
         PRAGMA user_version = 1;",
    )?;
    drop(manager);
    drop(store);

    let store = Arc::new(SqlCipherStore::open(&path, &key)?);
    let manager = AuthManager::from_shared(store.clone());
    assert!(manager.authenticate(issued.secret().expose()).is_ok());
    let grant = CapabilityGrant::new(
        client.id().clone(),
        AdapterId::new("rest")?,
        CapabilityId::new("battery.read")?,
    );
    assert!(store.add_grant(grant.clone())?);
    assert!(store.contains_grant(grant.principal(), grant.adapter(), grant.capability())?);
    Ok(())
}

#[test]
fn migrates_version_two_without_losing_audit_events() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = database_path(&directory);
    let key = fixed_key(24);
    let store = SqlCipherStore::open(&path, &key)?;
    store.record(AuditEvent::from_parts(
        SystemTime::now(),
        InvocationId::new("request_migrated")?,
        PrincipalId::new("client_migrated")?,
        AdapterId::new("rest")?,
        CapabilityId::new("battery.read")?,
        AuditOutcome::Succeeded,
    ))?;
    store.connection()?.pragma_update(None, "user_version", 2)?;
    store.connection()?.execute_batch(
        "DROP TABLE delivery_log;
         DROP TABLE webhook_dedup;",
    )?;
    drop(store);

    let store = SqlCipherStore::open(&path, &key)?;
    let events = store.recent_audit_events(AuditQueryLimit::new(10)?)?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event().outcome(), &AuditOutcome::Succeeded);
    store.record(AuditEvent::from_parts(
        SystemTime::now(),
        InvocationId::new("request_invalid")?,
        PrincipalId::new("client_migrated")?,
        AdapterId::new("rest")?,
        CapabilityId::new("battery.read")?,
        AuditOutcome::InvalidInput,
    ))?;
    assert_eq!(
        store.recent_audit_events(AuditQueryLimit::new(1)?)?[0]
            .event()
            .outcome(),
        &AuditOutcome::InvalidInput
    );
    Ok(())
}

#[test]
fn migrates_version_three_and_adds_delivery_persistence() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = TempDir::new()?;
    let path = database_path(&directory);
    let key = fixed_key(25);
    let store = SqlCipherStore::open(&path, &key)?;
    store.connection()?.execute_batch(
        "DROP TABLE delivery_log;
         DROP TABLE webhook_dedup;
         PRAGMA user_version = 3;",
    )?;
    drop(store);

    let store = Arc::new(SqlCipherStore::open(&path, &key)?);
    let log = SqlCipherDeliveryLog::new(store, PersistentDeliveryLogLimits::default());
    let intent = delivery_intent("delivery_migrated", 100);
    let id = intent.delivery().clone();
    log.insert_intent(intent)?;
    assert_eq!(
        log.delivery(&id)?.map(|record| record.state()),
        Some(DeliveryState::Pending)
    );
    Ok(())
}

#[test]
fn migrates_version_four_and_adds_webhook_replay_persistence()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = database_path(&directory);
    let key = fixed_key(30);
    let store = SqlCipherStore::open(&path, &key)?;
    store.connection()?.execute_batch(
        "DROP TABLE webhook_dedup;
         PRAGMA user_version = 4;",
    )?;
    drop(store);

    let store = Arc::new(SqlCipherStore::open(&path, &key)?);
    let dedup = SqlCipherDedupStore::new(store, DedupStoreLimits::default());
    assert_eq!(
        dedup.claim(dedup_key(1)?, DedupClaimPolicy::RetainCompleted, 100,)?,
        DedupClaim::Claimed
    );
    Ok(())
}

#[test]
fn persists_delivery_transitions_without_sensitive_fields() -> Result<(), Box<dyn std::error::Error>>
{
    let store = Arc::new(SqlCipherStore::open_in_memory(&fixed_key(26))?);
    let log = SqlCipherDeliveryLog::new(store, PersistentDeliveryLogLimits::default());
    assert_eq!(log.durability(), StoreDurability::Persistent);
    let intent = delivery_intent("delivery_status", 100);
    let id = intent.delivery().clone();
    log.insert_intent(intent)?;
    log.record_attempt(&id, 1, 110)?;
    log.record_outcome(
        &id,
        DeliveryOutcome::Delivered,
        120,
        Some(DeliveryResultMetadata::new(
            DeliveryResultCategory::Succeeded,
            24,
        )),
    )?;

    let record = log
        .delivery(&id)?
        .ok_or(std::io::Error::other("record missing"))?;
    assert_eq!(record.attempts(), 1);
    assert_eq!(
        record.state(),
        DeliveryState::Terminal(DeliveryOutcome::Delivered)
    );
    assert_eq!(record.result().map(DeliveryResultMetadata::bytes), Some(24));
    let rendered = format!("{record:?}");
    assert!(!rendered.contains("payload"));
    assert!(!rendered.contains("endpoint"));
    assert_eq!(
        log.record_outcome(&id, DeliveryOutcome::Delivered, 130, None),
        Err(DeliveryLogError::InvalidTransition)
    );
    assert_eq!(
        log.record_attempt(&id, 2, 130),
        Err(DeliveryLogError::InvalidTransition)
    );
    Ok(())
}

#[test]
fn restart_marks_only_unfinished_delivery_intents_unknown() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = TempDir::new()?;
    let path = database_path(&directory);
    let key = fixed_key(27);
    let store = Arc::new(SqlCipherStore::open(&path, &key)?);
    let log = SqlCipherDeliveryLog::new(store, PersistentDeliveryLogLimits::default());
    let pending = delivery_intent("delivery_pending", 100);
    let pending_id = pending.delivery().clone();
    let delivered = delivery_intent("delivery_delivered", 100);
    let delivered_id = delivered.delivery().clone();
    log.insert_intent(pending)?;
    log.insert_intent(delivered)?;
    log.record_outcome(&delivered_id, DeliveryOutcome::Delivered, 110, None)?;
    drop(log);

    let store = Arc::new(SqlCipherStore::open(&path, &key)?);
    let log = SqlCipherDeliveryLog::new(store, PersistentDeliveryLogLimits::default());
    assert_eq!(log.recover_unfinished(200)?, 1);
    assert_eq!(
        log.delivery(&pending_id)?.map(|record| record.state()),
        Some(DeliveryState::Terminal(DeliveryOutcome::UnknownAfterCrash))
    );
    assert_eq!(
        log.delivery(&delivered_id)?.map(|record| record.state()),
        Some(DeliveryState::Terminal(DeliveryOutcome::Delivered))
    );
    assert_eq!(log.recover_unfinished(300)?, 0);
    Ok(())
}

#[test]
fn delivery_log_capacity_is_bounded_and_expired_terminal_records_are_reclaimed()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = PersistentDeliveryLogLimits::new(
        MIN_PERSISTENT_DELIVERY_LOG_RECORDS,
        MIN_PERSISTENT_DELIVERY_LOG_BYTES,
        MIN_PERSISTENT_DELIVERY_LOG_RETENTION,
    )?;
    let store = Arc::new(SqlCipherStore::open_in_memory(&fixed_key(28))?);
    let log = SqlCipherDeliveryLog::new(store, limits);
    let expired = delivery_intent("delivery_expired", 0);
    let expired_id = expired.delivery().clone();
    log.insert_intent(expired)?;
    log.record_outcome(&expired_id, DeliveryOutcome::Delivered, 0, None)?;
    for index in 1..MIN_PERSISTENT_DELIVERY_LOG_RECORDS {
        log.insert_intent(delivery_intent(format!("delivery_{index}"), 1))?;
    }
    assert_eq!(
        log.insert_intent(delivery_intent("delivery_over_capacity", 1)),
        Err(DeliveryLogError::CapacityExhausted)
    );

    let after_retention = MIN_PERSISTENT_DELIVERY_LOG_RETENTION.as_millis() as u64 + 1;
    log.insert_intent(delivery_intent("delivery_after_retention", after_retention))?;
    assert!(log.delivery(&expired_id)?.is_none());
    Ok(())
}

#[test]
fn independent_connections_admit_one_delivery_intent() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = database_path(&directory);
    let key = fixed_key(29);
    let first = SqlCipherDeliveryLog::new(
        Arc::new(SqlCipherStore::open(&path, &key)?),
        PersistentDeliveryLogLimits::default(),
    );
    let second = SqlCipherDeliveryLog::new(
        Arc::new(SqlCipherStore::open(&path, &key)?),
        PersistentDeliveryLogLimits::default(),
    );
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for log in [first, second] {
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            log.insert_intent(delivery_intent("delivery_race", 100))
        }));
    }
    barrier.wait();
    let mut results = Vec::new();
    for handle in handles {
        results.push(
            handle
                .join()
                .map_err(|_| std::io::Error::other("delivery thread panicked"))?,
        );
    }
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(DeliveryLogError::Conflict))
            .count(),
        1
    );
    Ok(())
}

#[test]
fn persists_deduplication_transitions_and_allows_reentrant_administration()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(SqlCipherStore::open_in_memory(&fixed_key(31))?);
    let dedup = SqlCipherDedupStore::new(store, DedupStoreLimits::default());
    let key = dedup_key(1)?;

    assert_eq!(dedup.durability(), StoreDurability::Persistent);
    assert_eq!(
        dedup.claim(key.clone(), DedupClaimPolicy::RetainCompleted, 100,)?,
        DedupClaim::Claimed
    );
    assert_eq!(
        dedup.claim(key.clone(), DedupClaimPolicy::ExpireCompleted, 101,)?,
        DedupClaim::Duplicate(DedupState::InFlight)
    );
    dedup.mark_unknown(&key, 102)?;
    let mut resolution = None;
    dedup.visit_unknown(&mut |record| {
        resolution = Some(dedup.resolve_unknown(record.key(), DedupResolution::RetryAllowed, 103));
        false
    })?;
    assert_eq!(resolution, Some(Ok(())));
    assert!(dedup.record(&key)?.is_none());

    assert_eq!(
        dedup.claim(key.clone(), DedupClaimPolicy::RetainCompleted, 104,)?,
        DedupClaim::Claimed
    );
    dedup.complete(&key, 105)?;
    assert_eq!(
        dedup.claim(key.clone(), DedupClaimPolicy::ExpireCompleted, 106,)?,
        DedupClaim::Duplicate(DedupState::Completed)
    );
    assert_eq!(dedup.clear_completed_before(106)?, 1);
    assert!(dedup.record(&key)?.is_none());
    Ok(())
}

#[test]
fn expires_only_eligible_completed_tombstones_and_never_unknown_records()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = DedupStoreLimits::new(
        MIN_DEDUP_STORE_RECORDS,
        MIN_DEDUP_STORE_BYTES,
        MIN_DEDUP_STORE_RETENTION,
    )?;
    let store = Arc::new(SqlCipherStore::open_in_memory(&fixed_key(32))?);
    let dedup = SqlCipherDedupStore::new(store, limits);
    let retained = dedup_key(1)?;
    let expiring = dedup_key(2)?;
    let unknown = dedup_key(3)?;
    for (key, policy) in [
        (retained.clone(), DedupClaimPolicy::RetainCompleted),
        (expiring.clone(), DedupClaimPolicy::ExpireCompleted),
        (unknown.clone(), DedupClaimPolicy::ExpireCompleted),
    ] {
        assert_eq!(dedup.claim(key, policy, 0)?, DedupClaim::Claimed);
    }
    dedup.complete(&retained, 0)?;
    dedup.complete(&expiring, 0)?;
    dedup.mark_unknown(&unknown, 0)?;
    let after_retention = MIN_DEDUP_STORE_RETENTION.as_millis() as u64 + 1;
    assert_eq!(
        dedup.claim(
            dedup_key(4)?,
            DedupClaimPolicy::ExpireCompleted,
            after_retention,
        )?,
        DedupClaim::Claimed
    );

    assert_eq!(
        dedup.record(&retained)?.map(|record| record.state()),
        Some(DedupState::Completed)
    );
    assert!(dedup.record(&expiring)?.is_none());
    assert_eq!(
        dedup.record(&unknown)?.map(|record| record.state()),
        Some(DedupState::Unknown)
    );
    Ok(())
}

#[test]
fn recovers_in_flight_deduplication_as_unknown_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = database_path(&directory);
    let key = fixed_key(33);
    let delivery = dedup_key(1)?;
    let store = Arc::new(SqlCipherStore::open(&path, &key)?);
    let dedup = SqlCipherDedupStore::new(store, DedupStoreLimits::default());
    dedup.claim(delivery.clone(), DedupClaimPolicy::RetainCompleted, 100)?;
    drop(dedup);

    let store = Arc::new(SqlCipherStore::open(&path, &key)?);
    let dedup = SqlCipherDedupStore::new(store, DedupStoreLimits::default());
    assert_eq!(dedup.recover_in_flight(200)?, 1);
    assert_eq!(
        dedup.record(&delivery)?.map(|record| record.state()),
        Some(DedupState::Unknown)
    );
    assert_eq!(dedup.recover_in_flight(300)?, 0);
    Ok(())
}

#[test]
fn deduplication_capacity_exhaustion_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let limits = DedupStoreLimits::new(
        MIN_DEDUP_STORE_RECORDS,
        MIN_DEDUP_STORE_BYTES,
        MIN_DEDUP_STORE_RETENTION,
    )?;
    let store = Arc::new(SqlCipherStore::open_in_memory(&fixed_key(34))?);
    let dedup = SqlCipherDedupStore::new(store, limits);
    for index in 0..MIN_DEDUP_STORE_RECORDS {
        assert_eq!(
            dedup.claim(dedup_key(index)?, DedupClaimPolicy::RetainCompleted, 0,)?,
            DedupClaim::Claimed
        );
    }
    assert_eq!(
        dedup.claim(
            dedup_key(MIN_DEDUP_STORE_RECORDS)?,
            DedupClaimPolicy::RetainCompleted,
            0,
        ),
        Err(DedupStoreError::CapacityExhausted)
    );
    Ok(())
}

#[test]
fn independent_connections_admit_one_deduplication_claim() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = TempDir::new()?;
    let path = database_path(&directory);
    let key = fixed_key(35);
    let first = SqlCipherDedupStore::new(
        Arc::new(SqlCipherStore::open(&path, &key)?),
        DedupStoreLimits::default(),
    );
    let second = SqlCipherDedupStore::new(
        Arc::new(SqlCipherStore::open(&path, &key)?),
        DedupStoreLimits::default(),
    );
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for dedup in [first, second] {
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            dedup.claim(
                dedup_key(1).map_err(|_| DedupStoreError::Unavailable)?,
                DedupClaimPolicy::RetainCompleted,
                100,
            )
        }));
    }
    barrier.wait();
    let mut results = Vec::new();
    for handle in handles {
        results.push(
            handle
                .join()
                .map_err(|_| std::io::Error::other("deduplication thread panicked"))?,
        );
    }
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Ok(DedupClaim::Claimed))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Ok(DedupClaim::Duplicate(DedupState::InFlight)))
            .count(),
        1
    );
    Ok(())
}

#[test]
fn rejects_unsupported_schema_versions() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = database_path(&directory);
    let key = fixed_key(15);
    let store = SqlCipherStore::open(&path, &key)?;
    store
        .connection()?
        .pragma_update(None, "user_version", 99)?;
    drop(store);

    assert!(matches!(
        SqlCipherStore::open(&path, &key),
        Err(SqlCipherStoreError::UnsupportedSchema(99))
    ));
    Ok(())
}

#[test]
fn validates_audit_query_limits() {
    assert!(AuditQueryLimit::new(0).is_err());
    assert!(AuditQueryLimit::new(1).is_ok());
    assert!(AuditQueryLimit::new(1_000).is_ok());
    assert!(AuditQueryLimit::new(1_001).is_err());
}

#[test]
fn redacts_database_keys() {
    let key = fixed_key(16);
    assert_eq!(format!("{key:?}"), "DatabaseKey([REDACTED])");
    assert_eq!(key.expose_bytes(), &[16_u8; 32]);
}

#[test]
fn reconstructs_database_keys_only_from_exact_slices() -> Result<(), DatabaseKeyError> {
    let bytes = [0x17_u8; 32];
    let key = DatabaseKey::from_slice(&bytes)?;

    assert_eq!(key.expose_bytes(), &bytes);
    assert_eq!(
        DatabaseKey::from_slice(&bytes[..31]).err(),
        Some(DatabaseKeyError::InvalidLength)
    );
    assert_eq!(
        DatabaseKey::from_slice(&[0_u8; 33]).err(),
        Some(DatabaseKeyError::InvalidLength)
    );
    Ok(())
}

fn token_id(value: u8) -> Result<TokenId, Box<dyn std::error::Error>> {
    Ok(TokenId::new(format!(
        "token_{}",
        URL_SAFE_NO_PAD.encode([value; 16])
    ))?)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[test]
fn rejects_invalid_digest_lengths_at_storage_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let store = SqlCipherStore::open_in_memory(&fixed_key(17))?;
    let client = Client::from_stored_parts(
        PrincipalId::new("client_test")?,
        ClientName::new("Client")?,
        true,
        1,
    );
    store.insert_client(client.clone())?;
    let result = store.connection()?.execute(
        "INSERT INTO tokens (id, client_id, digest, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![token_id(4)?.as_str(), client.id().as_str(), [0_u8; 31], 1],
    );

    assert!(result.is_err());
    Ok(())
}

#[test]
fn does_not_revoke_already_expired_tokens() -> Result<(), Box<dyn std::error::Error>> {
    let store = SqlCipherStore::open_in_memory(&fixed_key(20))?;
    let client = Client::from_stored_parts(
        PrincipalId::new("client_expired")?,
        ClientName::new("Expired Client")?,
        true,
        1,
    );
    store.insert_client(client.clone())?;
    let token = TokenRecord::from_stored_parts(
        token_id(5)?,
        client.id().clone(),
        None,
        TokenDigest::from_bytes([6_u8; 32]),
        1,
        Some(10),
        None,
    );
    let id = token.id().clone();
    store.insert_token(token)?;

    assert!(!store.revoke_token(&id, 10)?);
    assert!(
        store
            .authentication_record(&id)?
            .ok_or(std::io::Error::other("expired token missing"))?
            .token()
            .revoked_at_unix_seconds()
            .is_none()
    );
    Ok(())
}

#[test]
fn reports_missing_tokens_during_direct_rotation() -> Result<(), Box<dyn std::error::Error>> {
    let store = SqlCipherStore::open_in_memory(&fixed_key(18))?;
    let outcome = store.rotate_token(
        &token_id(1)?,
        TokenReplacement::new(
            token_id(2)?,
            None,
            TokenDigest::from_bytes([3; 32]),
            1,
            None,
        ),
        1,
    )?;
    assert_eq!(outcome, RotationOutcome::NotFound);
    Ok(())
}
