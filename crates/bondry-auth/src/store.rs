use bondry_core::PrincipalId;
use thiserror::Error;

use crate::{Client, TokenDigest, TokenId, TokenLabel, TokenRecord};

/// A token and its current client state loaded atomically for authentication.
pub struct AuthenticationRecord {
    token: TokenRecord,
    client_enabled: bool,
}

impl AuthenticationRecord {
    /// Reconstructs an authentication record from trusted persistent state.
    #[must_use]
    pub const fn from_stored_parts(token: TokenRecord, client_enabled: bool) -> Self {
        Self {
            token,
            client_enabled,
        }
    }

    /// Returns the stored token.
    #[must_use]
    pub const fn token(&self) -> &TokenRecord {
        &self.token
    }

    /// Returns whether the owning client is enabled.
    #[must_use]
    pub const fn client_enabled(&self) -> bool {
        self.client_enabled
    }
}

/// New token state used during an atomic rotation.
pub struct TokenReplacement {
    id: TokenId,
    label: Option<TokenLabel>,
    digest: TokenDigest,
    created_at_unix_seconds: i64,
    expires_at_unix_seconds: Option<i64>,
}

impl TokenReplacement {
    /// Creates replacement state that inherits the previous token's client.
    #[must_use]
    pub const fn new(
        id: TokenId,
        label: Option<TokenLabel>,
        digest: TokenDigest,
        created_at_unix_seconds: i64,
        expires_at_unix_seconds: Option<i64>,
    ) -> Self {
        Self {
            id,
            label,
            digest,
            created_at_unix_seconds,
            expires_at_unix_seconds,
        }
    }

    /// Returns the replacement token identifier.
    #[must_use]
    pub const fn id(&self) -> &TokenId {
        &self.id
    }

    /// Returns the optional administrative label.
    #[must_use]
    pub const fn label(&self) -> Option<&TokenLabel> {
        self.label.as_ref()
    }

    /// Returns the replacement token digest.
    #[must_use]
    pub const fn digest(&self) -> &TokenDigest {
        &self.digest
    }

    /// Returns the creation time as Unix seconds.
    #[must_use]
    pub const fn created_at_unix_seconds(&self) -> i64 {
        self.created_at_unix_seconds
    }

    /// Returns the optional expiration time as Unix seconds.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> Option<i64> {
        self.expires_at_unix_seconds
    }

    /// Converts replacement state into a stored token for its inherited client.
    #[must_use]
    pub fn into_record(self, client: PrincipalId) -> TokenRecord {
        TokenRecord::from_stored_parts(
            self.id,
            client,
            self.label,
            self.digest,
            self.created_at_unix_seconds,
            self.expires_at_unix_seconds,
            None,
        )
    }
}

/// The result of an atomic token rotation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RotationOutcome {
    /// Rotation succeeded for the returned client principal.
    Rotated(PrincipalId),
    /// The current token does not exist.
    NotFound,
    /// The current token is revoked or expired.
    Inactive,
    /// The owning client is disabled.
    ClientDisabled,
}

/// Persistent operations required by the authentication manager.
pub trait AuthStore: Send + Sync {
    /// Inserts a new client.
    fn insert_client(&self, client: Client) -> Result<(), StoreError>;

    /// Loads a client by principal identifier.
    fn client(&self, id: &PrincipalId) -> Result<Option<Client>, StoreError>;

    /// Changes client authentication state and reports whether it exists.
    fn set_client_enabled(&self, id: &PrincipalId, enabled: bool) -> Result<bool, StoreError>;

    /// Inserts a newly issued token.
    fn insert_token(&self, token: TokenRecord) -> Result<(), StoreError>;

    /// Loads token and client state in one consistent operation.
    fn authentication_record(
        &self,
        id: &TokenId,
    ) -> Result<Option<AuthenticationRecord>, StoreError>;

    /// Revokes an active token and reports whether state changed.
    fn revoke_token(&self, id: &TokenId, revoked_at_unix_seconds: i64) -> Result<bool, StoreError>;

    /// Atomically revokes one active token and inserts its replacement.
    fn rotate_token(
        &self,
        current: &TokenId,
        replacement: TokenReplacement,
        revoked_at_unix_seconds: i64,
    ) -> Result<RotationOutcome, StoreError>;

    /// Lists the non-secret token metadata associated with a client.
    fn tokens_for_client(&self, id: &PrincipalId) -> Result<Vec<TokenRecord>, StoreError>;
}

/// A safe authentication-storage failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StoreError {
    /// A generated identifier or digest conflicts with existing state.
    #[error("authentication state conflicts with an existing record")]
    Conflict,
    /// Authentication state cannot be read or changed safely.
    #[error("authentication storage is unavailable")]
    Unavailable,
}
