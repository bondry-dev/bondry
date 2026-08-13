use bondry_auth::{
    AuthStore, AuthenticationRecord, Client, ClientName, RotationOutcome, StoreError, TokenDigest,
    TokenId, TokenLabel, TokenRecord, TokenReplacement,
};
use bondry_core::PrincipalId;
use rusqlite::{ErrorCode, OptionalExtension, Row, TransactionBehavior, params};

use crate::{SqlCipherStore, SqlCipherStoreError};

impl AuthStore for SqlCipherStore {
    fn insert_client(&self, client: Client) -> Result<(), StoreError> {
        self.connection()
            .map_err(map_store_error)?
            .execute(
                "INSERT INTO clients (id, name, enabled, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![
                    client.id().as_str(),
                    client.name().as_str(),
                    i64::from(client.is_enabled()),
                    client.created_at_unix_seconds(),
                ],
            )
            .map(|_| ())
            .map_err(map_database_error)
    }

    fn client(&self, id: &PrincipalId) -> Result<Option<Client>, StoreError> {
        let raw = self
            .connection()
            .map_err(map_store_error)?
            .query_row(
                "SELECT id, name, enabled, created_at FROM clients WHERE id = ?1",
                [id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(map_database_error)?;
        raw.map(|(id, name, enabled, created_at)| {
            Ok(Client::from_stored_parts(
                PrincipalId::new(id).map_err(|_| StoreError::Unavailable)?,
                ClientName::new(name).map_err(|_| StoreError::Unavailable)?,
                enabled != 0,
                created_at,
            ))
        })
        .transpose()
    }

    fn set_client_enabled(&self, id: &PrincipalId, enabled: bool) -> Result<bool, StoreError> {
        self.connection()
            .map_err(map_store_error)?
            .execute(
                "UPDATE clients SET enabled = ?1 WHERE id = ?2",
                params![i64::from(enabled), id.as_str()],
            )
            .map(|changed| changed == 1)
            .map_err(map_database_error)
    }

    fn insert_token(&self, token: TokenRecord) -> Result<(), StoreError> {
        let connection = self.connection().map_err(map_store_error)?;
        insert_token(&connection, &token)
            .map(|_| ())
            .map_err(map_database_error)
    }

    fn authentication_record(
        &self,
        id: &TokenId,
    ) -> Result<Option<AuthenticationRecord>, StoreError> {
        let raw = self
            .connection()
            .map_err(map_store_error)?
            .query_row(
                "SELECT
                     t.id, t.client_id, t.label, t.digest, t.created_at, t.expires_at, t.revoked_at,
                     c.enabled
                 FROM tokens t
                 JOIN clients c ON c.id = t.client_id
                 WHERE t.id = ?1",
                [id.as_str()],
                |row| Ok((RawToken::read(row)?, row.get::<_, i64>(7)?)),
            )
            .optional()
            .map_err(map_database_error)?;
        raw.map(|(token, enabled)| {
            Ok(AuthenticationRecord::from_stored_parts(
                token.validate()?,
                enabled != 0,
            ))
        })
        .transpose()
    }

    fn revoke_token(&self, id: &TokenId, revoked_at_unix_seconds: i64) -> Result<bool, StoreError> {
        self.connection()
            .map_err(map_store_error)?
            .execute(
                "UPDATE tokens
                 SET revoked_at = ?1
                 WHERE id = ?2
                   AND revoked_at IS NULL
                   AND (expires_at IS NULL OR ?1 < expires_at)",
                params![revoked_at_unix_seconds, id.as_str()],
            )
            .map(|changed| changed == 1)
            .map_err(map_database_error)
    }

    fn rotate_token(
        &self,
        current: &TokenId,
        replacement: TokenReplacement,
        revoked_at_unix_seconds: i64,
    ) -> Result<RotationOutcome, StoreError> {
        let mut connection = self.connection().map_err(map_store_error)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_database_error)?;
        let raw = transaction
            .query_row(
                "SELECT
                     t.id, t.client_id, t.label, t.digest, t.created_at, t.expires_at, t.revoked_at,
                     c.enabled
                 FROM tokens t
                 JOIN clients c ON c.id = t.client_id
                 WHERE t.id = ?1",
                [current.as_str()],
                |row| Ok((RawToken::read(row)?, row.get::<_, i64>(7)?)),
            )
            .optional()
            .map_err(map_database_error)?;
        let Some((current_token, enabled)) = raw else {
            return Ok(RotationOutcome::NotFound);
        };
        let current_token = current_token.validate()?;
        if enabled == 0 {
            return Ok(RotationOutcome::ClientDisabled);
        }
        if !current_token.is_active_at(revoked_at_unix_seconds) {
            return Ok(RotationOutcome::Inactive);
        }

        let replacement = replacement.into_record(current_token.client().clone());
        insert_token(&transaction, &replacement).map_err(map_database_error)?;
        let changed = transaction
            .execute(
                "UPDATE tokens SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
                params![revoked_at_unix_seconds, current.as_str()],
            )
            .map_err(map_database_error)?;
        if changed != 1 {
            return Err(StoreError::Unavailable);
        }
        transaction.commit().map_err(map_database_error)?;
        Ok(RotationOutcome::Rotated(current_token.client().clone()))
    }

    fn tokens_for_client(&self, id: &PrincipalId) -> Result<Vec<TokenRecord>, StoreError> {
        let connection = self.connection().map_err(map_store_error)?;
        let mut statement = connection
            .prepare(
                "SELECT id, client_id, label, digest, created_at, expires_at, revoked_at
                 FROM tokens
                 WHERE client_id = ?1
                 ORDER BY created_at DESC, id ASC",
            )
            .map_err(map_database_error)?;
        let rows = statement
            .query_map([id.as_str()], RawToken::read)
            .map_err(map_database_error)?;
        let mut tokens = Vec::new();
        for row in rows {
            tokens.push(row.map_err(map_database_error)?.validate()?);
        }
        Ok(tokens)
    }
}

fn insert_token(connection: &rusqlite::Connection, token: &TokenRecord) -> rusqlite::Result<usize> {
    connection.execute(
        "INSERT INTO tokens (
             id, client_id, label, digest, created_at, expires_at, revoked_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            token.id().as_str(),
            token.client().as_str(),
            token.label().map(TokenLabel::as_str),
            token.digest().as_bytes().as_slice(),
            token.created_at_unix_seconds(),
            token.expires_at_unix_seconds(),
            token.revoked_at_unix_seconds(),
        ],
    )
}

struct RawToken {
    id: String,
    client: String,
    label: Option<String>,
    digest: Vec<u8>,
    created_at: i64,
    expires_at: Option<i64>,
    revoked_at: Option<i64>,
}

impl RawToken {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            client: row.get(1)?,
            label: row.get(2)?,
            digest: row.get(3)?,
            created_at: row.get(4)?,
            expires_at: row.get(5)?,
            revoked_at: row.get(6)?,
        })
    }

    fn validate(self) -> Result<TokenRecord, StoreError> {
        let digest: [u8; 32] = self
            .digest
            .try_into()
            .map_err(|_| StoreError::Unavailable)?;
        Ok(TokenRecord::from_stored_parts(
            TokenId::new(self.id).map_err(|_| StoreError::Unavailable)?,
            PrincipalId::new(self.client).map_err(|_| StoreError::Unavailable)?,
            self.label
                .map(TokenLabel::new)
                .transpose()
                .map_err(|_| StoreError::Unavailable)?,
            TokenDigest::from_bytes(digest),
            self.created_at,
            self.expires_at,
            self.revoked_at,
        ))
    }
}

fn map_store_error(error: SqlCipherStoreError) -> StoreError {
    match error {
        SqlCipherStoreError::Database(error) => map_database_error(error),
        SqlCipherStoreError::FileSystem(_)
        | SqlCipherStoreError::UnsupportedSchema(_)
        | SqlCipherStoreError::InvalidKey
        | SqlCipherStoreError::InvalidData
        | SqlCipherStoreError::Unavailable => StoreError::Unavailable,
    }
}

fn map_database_error(error: rusqlite::Error) -> StoreError {
    if matches!(
        error,
        rusqlite::Error::SqliteFailure(details, _)
            if details.code == ErrorCode::ConstraintViolation
    ) {
        StoreError::Conflict
    } else {
        StoreError::Unavailable
    }
}
