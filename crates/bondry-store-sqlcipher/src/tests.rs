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
use futures::executor::block_on;
use serde_json::json;
use tempfile::TempDir;

use crate::{AuditQueryLimit, DatabaseKey, DatabaseKeyError, SqlCipherStore, SqlCipherStoreError};

fn database_path(directory: &TempDir) -> std::path::PathBuf {
    directory.path().join("bondry.db")
}

fn fixed_key(value: u8) -> DatabaseKey {
    DatabaseKey::from_bytes([value; 32])
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
    assert!(manager.authenticate(issued.secret().expose()).is_ok());
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
    assert!(store.contains_grant(&CapabilityGrant::new(
        client.id().clone(),
        AdapterId::new("mcp")?,
        CapabilityId::new("battery.snapshot")?,
    ))?);
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
    for table in ["clients", "tokens", "audit_events", "grants"] {
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
    assert!(store.contains_grant(&first)?);
    assert!(store.remove_grant(&first)?);
    assert!(!store.remove_grant(&first)?);
    assert!(!store.contains_grant(&first)?);
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
    assert!(store.contains_grant(&grant)?);
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
