use std::{
    fs::OpenOptions,
    path::Path,
    sync::{Mutex, MutexGuard},
    time::Duration,
};

use rusqlite::{Connection, TransactionBehavior};
use thiserror::Error;

use crate::DatabaseKey;

const SCHEMA_VERSION: i64 = 4;

/// SQLCipher-backed authentication and audit persistence.
pub struct SqlCipherStore {
    pub(crate) connection: Mutex<Connection>,
}

impl SqlCipherStore {
    /// Opens or creates an encrypted database at the supplied path.
    pub fn open(path: impl AsRef<Path>, key: &DatabaseKey) -> Result<Self, SqlCipherStoreError> {
        let path = path.as_ref();
        protect_database_file(path)?;
        Self::initialize(Connection::open(path)?, key)
    }

    /// Opens an isolated encrypted in-memory database.
    pub fn open_in_memory(key: &DatabaseKey) -> Result<Self, SqlCipherStoreError> {
        Self::initialize(Connection::open_in_memory()?, key)
    }

    /// Verifies that the encrypted connection is available and responsive.
    pub fn check_health(&self) -> Result<(), SqlCipherStoreError> {
        let connection = self.connection()?;
        let value: i64 = connection.query_row("SELECT 1", [], |row| row.get(0))?;
        if value == 1 {
            Ok(())
        } else {
            Err(SqlCipherStoreError::InvalidData)
        }
    }

    fn initialize(
        mut connection: Connection,
        key: &DatabaseKey,
    ) -> Result<Self, SqlCipherStoreError> {
        let passphrase = key.sqlcipher_passphrase();
        connection.pragma_update(None, "key", passphrase.as_str())?;
        connection.pragma_update(None, "cipher_memory_security", true)?;
        connection
            .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(|_| SqlCipherStoreError::InvalidKey)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;",
        )?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub(crate) fn connection(&self) -> Result<MutexGuard<'_, Connection>, SqlCipherStoreError> {
        self.connection
            .lock()
            .map_err(|_| SqlCipherStoreError::Unavailable)
    }
}

fn protect_database_file(path: &Path) -> Result<(), SqlCipherStoreError> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn migrate(connection: &mut Connection) -> Result<(), SqlCipherStoreError> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    match version {
        SCHEMA_VERSION => Ok(()),
        3 => migrate_from_version_three(connection),
        2 => migrate_from_version_two(connection),
        1 => migrate_from_version_one(connection),
        0 => migrate_from_empty(connection),
        unsupported => Err(SqlCipherStoreError::UnsupportedSchema(unsupported)),
    }
}

fn migrate_from_empty(connection: &mut Connection) -> Result<(), SqlCipherStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "CREATE TABLE clients (
             id TEXT PRIMARY KEY NOT NULL,
             name TEXT NOT NULL,
             enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
             created_at INTEGER NOT NULL
         );

         CREATE TABLE tokens (
             id TEXT PRIMARY KEY NOT NULL,
             client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
             label TEXT,
             digest BLOB NOT NULL UNIQUE CHECK (length(digest) = 32),
             created_at INTEGER NOT NULL,
             expires_at INTEGER,
             revoked_at INTEGER,
             CHECK (expires_at IS NULL OR expires_at > created_at)
         );
         CREATE INDEX tokens_by_client ON tokens(client_id, created_at DESC);

         CREATE TABLE audit_events (
             sequence INTEGER PRIMARY KEY AUTOINCREMENT,
             occurred_at_ms INTEGER NOT NULL,
             invocation_id TEXT NOT NULL,
             principal_id TEXT NOT NULL,
             adapter_id TEXT NOT NULL,
             capability_id TEXT NOT NULL,
             outcome_kind TEXT NOT NULL CHECK (
                 outcome_kind IN (
                     'capability_not_found',
                     'denied',
                     'started',
                     'invalid_input',
                     'succeeded',
                     'handler_failed'
                 )
             ),
             detail_code TEXT,
             CHECK (
                 (outcome_kind IN ('denied', 'handler_failed') AND detail_code IS NOT NULL)
                 OR
                 (outcome_kind NOT IN ('denied', 'handler_failed') AND detail_code IS NULL)
             )
         );
         CREATE INDEX audit_by_principal ON audit_events(principal_id, sequence DESC);
         CREATE INDEX audit_by_invocation ON audit_events(invocation_id, sequence);

         CREATE TABLE grants (
             principal_id TEXT NOT NULL,
             adapter_id TEXT NOT NULL,
             capability_id TEXT NOT NULL,
             PRIMARY KEY (principal_id, adapter_id, capability_id)
         );",
    )?;
    create_delivery_log_table(&transaction)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_from_version_one(connection: &mut Connection) -> Result<(), SqlCipherStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "CREATE TABLE grants (
             principal_id TEXT NOT NULL,
             adapter_id TEXT NOT NULL,
             capability_id TEXT NOT NULL,
             PRIMARY KEY (principal_id, adapter_id, capability_id)
         );",
    )?;
    rebuild_audit_table(&transaction)?;
    create_delivery_log_table(&transaction)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_from_version_two(connection: &mut Connection) -> Result<(), SqlCipherStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    rebuild_audit_table(&transaction)?;
    create_delivery_log_table(&transaction)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_from_version_three(connection: &mut Connection) -> Result<(), SqlCipherStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    create_delivery_log_table(&transaction)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn create_delivery_log_table(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    transaction.execute_batch(
        "CREATE TABLE delivery_log (
             sequence INTEGER PRIMARY KEY AUTOINCREMENT,
             delivery_id TEXT NOT NULL UNIQUE,
             route_id TEXT NOT NULL,
             accepted_at_ms INTEGER NOT NULL CHECK (accepted_at_ms >= 0),
             attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 65535),
             state TEXT NOT NULL CHECK (
                 state IN (
                     'pending',
                     'delivered',
                     'failed',
                     'lost_on_shutdown',
                     'unknown_after_crash'
                 )
             ),
             failure_kind TEXT,
             updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms >= 0),
             result_category TEXT,
             result_bytes INTEGER,
             charged_bytes INTEGER NOT NULL CHECK (charged_bytes = 512),
             CHECK (
                 (state = 'failed' AND failure_kind IS NOT NULL)
                 OR (state != 'failed' AND failure_kind IS NULL)
             ),
             CHECK (
                 (result_category IS NULL AND result_bytes IS NULL)
                 OR (state != 'pending' AND result_category IS NOT NULL
                     AND result_bytes IS NOT NULL AND result_bytes >= 0)
             )
         );
         CREATE INDEX delivery_log_by_state ON delivery_log(state, updated_at_ms);
         CREATE INDEX delivery_log_by_route ON delivery_log(route_id, sequence DESC);",
    )
}

fn rebuild_audit_table(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    transaction.execute_batch(
        "ALTER TABLE audit_events RENAME TO audit_events_previous;
         CREATE TABLE audit_events (
             sequence INTEGER PRIMARY KEY AUTOINCREMENT,
             occurred_at_ms INTEGER NOT NULL,
             invocation_id TEXT NOT NULL,
             principal_id TEXT NOT NULL,
             adapter_id TEXT NOT NULL,
             capability_id TEXT NOT NULL,
             outcome_kind TEXT NOT NULL CHECK (
                 outcome_kind IN (
                     'capability_not_found',
                     'denied',
                     'started',
                     'invalid_input',
                     'succeeded',
                     'handler_failed'
                 )
             ),
             detail_code TEXT,
             CHECK (
                 (outcome_kind IN ('denied', 'handler_failed') AND detail_code IS NOT NULL)
                 OR
                 (outcome_kind NOT IN ('denied', 'handler_failed') AND detail_code IS NULL)
             )
         );
         INSERT INTO audit_events (
             sequence, occurred_at_ms, invocation_id, principal_id, adapter_id,
             capability_id, outcome_kind, detail_code
         )
         SELECT
             sequence, occurred_at_ms, invocation_id, principal_id, adapter_id,
             capability_id, outcome_kind, detail_code
         FROM audit_events_previous;
         DROP TABLE audit_events_previous;
         CREATE INDEX audit_by_principal ON audit_events(principal_id, sequence DESC);
         CREATE INDEX audit_by_invocation ON audit_events(invocation_id, sequence);",
    )
}

/// An encrypted SQLCipher persistence failure.
#[derive(Debug, Error)]
pub enum SqlCipherStoreError {
    /// The database cannot be created or protected on the file system.
    #[error("SQLCipher database file operation failed")]
    FileSystem(#[from] std::io::Error),
    /// SQLCipher rejected or could not complete an operation.
    #[error("SQLCipher storage operation failed")]
    Database(#[from] rusqlite::Error),
    /// The database contains a schema newer than this library understands.
    #[error("unsupported SQLite schema version {0}")]
    UnsupportedSchema(i64),
    /// The supplied key cannot decrypt the database.
    #[error("SQLCipher database key is invalid")]
    InvalidKey,
    /// Persisted data violates Bondry's validated data model.
    #[error("SQLCipher storage contains invalid Bondry data")]
    InvalidData,
    /// The database connection cannot be accessed safely.
    #[error("SQLCipher storage is unavailable")]
    Unavailable,
}
