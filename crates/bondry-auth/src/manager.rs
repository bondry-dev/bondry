use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bondry_core::{Principal, PrincipalId, PrincipalKind};
use thiserror::Error;

use crate::{
    AuthStore, Client, ClientName, RotationOutcome, StoreError, TokenLabel, TokenMetadata,
    TokenRecord, TokenReplacement,
    token::{GeneratedToken, PresentedToken, RandomError, RandomSource, SystemRandom},
};

const CLIENT_ID_RANDOM_BYTES: usize = 16;
const GENERATION_ATTEMPTS: usize = 8;

trait Clock: Send + Sync {
    fn now_unix_seconds(&self) -> Result<i64, TimeError>;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_seconds(&self) -> Result<i64, TimeError> {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TimeError)?
            .as_secs();
        i64::try_from(seconds).map_err(|_| TimeError)
    }
}

struct TimeError;

/// Coordinates client registration and local access-token lifecycle.
pub struct AuthManager {
    store: Arc<dyn AuthStore>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
}

impl AuthManager {
    /// Creates an authentication manager with operating-system entropy and time.
    #[must_use]
    pub fn new<S>(store: S) -> Self
    where
        S: AuthStore + 'static,
    {
        Self::from_shared(Arc::new(store))
    }

    /// Creates an authentication manager from shared persistent state.
    #[must_use]
    pub fn from_shared(store: Arc<dyn AuthStore>) -> Self {
        Self {
            store,
            random: Arc::new(SystemRandom),
            clock: Arc::new(SystemClock),
        }
    }

    #[cfg(test)]
    fn with_sources(
        store: Arc<dyn AuthStore>,
        random: Arc<dyn RandomSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            random,
            clock,
        }
    }

    /// Registers a client with a random principal identifier.
    pub fn create_client(&self, name: ClientName) -> Result<Client, ClientManagementError> {
        let created_at = self
            .clock
            .now_unix_seconds()
            .map_err(|_| ClientManagementError::TimeUnavailable)?;
        for _ in 0..GENERATION_ATTEMPTS {
            let id = self
                .generate_client_id()
                .map_err(|_| ClientManagementError::EntropyUnavailable)?;
            let client = Client::from_stored_parts(id, name.clone(), true, created_at);
            match self.store.insert_client(client.clone()) {
                Ok(()) => return Ok(client),
                Err(StoreError::Conflict) => {}
                Err(StoreError::Unavailable) => {
                    return Err(ClientManagementError::StorageUnavailable);
                }
            }
        }
        Err(ClientManagementError::GenerationExhausted)
    }

    /// Enables or disables an existing client.
    pub fn set_client_enabled(
        &self,
        id: &PrincipalId,
        enabled: bool,
    ) -> Result<(), ClientManagementError> {
        match self.store.set_client_enabled(id, enabled) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ClientManagementError::NotFound),
            Err(_) => Err(ClientManagementError::StorageUnavailable),
        }
    }

    /// Issues a random token for an enabled client.
    pub fn issue_token(
        &self,
        client: &PrincipalId,
        label: Option<TokenLabel>,
        expires_in: Option<Duration>,
    ) -> Result<crate::IssuedToken, TokenLifecycleError> {
        let owner = self.load_enabled_client(client)?;
        let created_at = self.now_for_token()?;
        let expires_at = expiration(created_at, expires_in)?;
        for _ in 0..GENERATION_ATTEMPTS {
            let generated = GeneratedToken::generate(self.random.as_ref())
                .map_err(|_| TokenLifecycleError::EntropyUnavailable)?;
            let record = TokenRecord::from_stored_parts(
                generated.id,
                owner.id().clone(),
                label.clone(),
                generated.digest,
                created_at,
                expires_at,
                None,
            );
            let metadata = record.metadata();
            match self.store.insert_token(record) {
                Ok(()) => {
                    return Ok(crate::IssuedToken::new(metadata, generated.secret));
                }
                Err(StoreError::Conflict) => {}
                Err(StoreError::Unavailable) => {
                    return Err(TokenLifecycleError::StorageUnavailable);
                }
            }
        }
        Err(TokenLifecycleError::GenerationExhausted)
    }

    /// Authenticates a presented token without disclosing rejection details.
    pub fn authenticate(&self, presented: &str) -> Result<Principal, AuthenticationError> {
        let presented =
            PresentedToken::parse(presented).map_err(|()| AuthenticationError::Rejected)?;
        let record = self
            .store
            .authentication_record(&presented.id)
            .map_err(|_| AuthenticationError::StorageUnavailable)?
            .ok_or(AuthenticationError::Rejected)?;
        let now = self
            .clock
            .now_unix_seconds()
            .map_err(|_| AuthenticationError::StorageUnavailable)?;
        let valid = presented.matches(record.token().digest())
            & record.token().is_active_at(now)
            & record.client_enabled();
        if !valid {
            return Err(AuthenticationError::Rejected);
        }
        Ok(Principal::new(
            record.token().client().clone(),
            PrincipalKind::Application,
        ))
    }

    /// Revokes an active token and reports whether state changed.
    pub fn revoke_token(&self, id: &crate::TokenId) -> Result<bool, TokenLifecycleError> {
        let revoked_at = self.now_for_token()?;
        self.store
            .revoke_token(id, revoked_at)
            .map_err(|_| TokenLifecycleError::StorageUnavailable)
    }

    /// Atomically replaces an active token and returns its new secret once.
    pub fn rotate_token(
        &self,
        current: &crate::TokenId,
        label: Option<TokenLabel>,
        expires_in: Option<Duration>,
    ) -> Result<crate::IssuedToken, TokenLifecycleError> {
        let created_at = self.now_for_token()?;
        let expires_at = expiration(created_at, expires_in)?;
        for _ in 0..GENERATION_ATTEMPTS {
            let generated = GeneratedToken::generate(self.random.as_ref())
                .map_err(|_| TokenLifecycleError::EntropyUnavailable)?;
            let replacement = TokenReplacement::new(
                generated.id.clone(),
                label.clone(),
                generated.digest,
                created_at,
                expires_at,
            );
            match self.store.rotate_token(current, replacement, created_at) {
                Ok(RotationOutcome::Rotated(client)) => {
                    let metadata = TokenMetadata::from_stored_parts(
                        generated.id,
                        client,
                        label,
                        created_at,
                        expires_at,
                        None,
                    );
                    return Ok(crate::IssuedToken::new(metadata, generated.secret));
                }
                Ok(RotationOutcome::NotFound) => return Err(TokenLifecycleError::NotFound),
                Ok(RotationOutcome::Inactive) => return Err(TokenLifecycleError::Inactive),
                Ok(RotationOutcome::ClientDisabled) => {
                    return Err(TokenLifecycleError::ClientDisabled);
                }
                Err(StoreError::Conflict) => {}
                Err(StoreError::Unavailable) => {
                    return Err(TokenLifecycleError::StorageUnavailable);
                }
            }
        }
        Err(TokenLifecycleError::GenerationExhausted)
    }

    /// Lists administrative token metadata for a client.
    pub fn tokens_for_client(
        &self,
        client: &PrincipalId,
    ) -> Result<Vec<TokenMetadata>, TokenLifecycleError> {
        self.store
            .tokens_for_client(client)
            .map(|tokens| tokens.iter().map(TokenRecord::metadata).collect())
            .map_err(|_| TokenLifecycleError::StorageUnavailable)
    }

    fn load_enabled_client(&self, id: &PrincipalId) -> Result<Client, TokenLifecycleError> {
        let client = self
            .store
            .client(id)
            .map_err(|_| TokenLifecycleError::StorageUnavailable)?
            .ok_or(TokenLifecycleError::ClientNotFound)?;
        if !client.is_enabled() {
            return Err(TokenLifecycleError::ClientDisabled);
        }
        Ok(client)
    }

    fn generate_client_id(&self) -> Result<PrincipalId, RandomError> {
        let mut bytes = [0_u8; CLIENT_ID_RANDOM_BYTES];
        self.random.fill(&mut bytes)?;
        PrincipalId::new(format!("client_{}", URL_SAFE_NO_PAD.encode(bytes)))
            .map_err(|_| RandomError)
    }

    fn now_for_token(&self) -> Result<i64, TokenLifecycleError> {
        self.clock
            .now_unix_seconds()
            .map_err(|_| TokenLifecycleError::TimeUnavailable)
    }
}

fn expiration(now: i64, lifetime: Option<Duration>) -> Result<Option<i64>, TokenLifecycleError> {
    let Some(lifetime) = lifetime else {
        return Ok(None);
    };
    let seconds =
        i64::try_from(lifetime.as_secs()).map_err(|_| TokenLifecycleError::InvalidLifetime)?;
    if seconds == 0 {
        return Err(TokenLifecycleError::InvalidLifetime);
    }
    now.checked_add(seconds)
        .map(Some)
        .ok_or(TokenLifecycleError::InvalidLifetime)
}

/// A client-administration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ClientManagementError {
    /// The client does not exist.
    #[error("client was not found")]
    NotFound,
    /// Secure random generation failed.
    #[error("secure random generation is unavailable")]
    EntropyUnavailable,
    /// Repeated random identifiers conflicted with existing state.
    #[error("unable to generate a unique client identifier")]
    GenerationExhausted,
    /// System time is unavailable.
    #[error("system time is unavailable")]
    TimeUnavailable,
    /// Client state cannot be read or changed safely.
    #[error("authentication storage is unavailable")]
    StorageUnavailable,
}

/// A token lifecycle failure visible to an administrative interface.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TokenLifecycleError {
    /// The owning client does not exist.
    #[error("client was not found")]
    ClientNotFound,
    /// The owning client is disabled.
    #[error("client is disabled")]
    ClientDisabled,
    /// The requested token does not exist.
    #[error("token was not found")]
    NotFound,
    /// The requested token is already revoked or expired.
    #[error("token is inactive")]
    Inactive,
    /// The requested expiration cannot be represented safely.
    #[error("invalid token lifetime")]
    InvalidLifetime,
    /// Secure random generation failed.
    #[error("secure random generation is unavailable")]
    EntropyUnavailable,
    /// Repeated random tokens conflicted with existing state.
    #[error("unable to generate a unique token")]
    GenerationExhausted,
    /// System time is unavailable.
    #[error("system time is unavailable")]
    TimeUnavailable,
    /// Token state cannot be read or changed safely.
    #[error("authentication storage is unavailable")]
    StorageUnavailable,
}

/// A deliberately non-specific token authentication failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthenticationError {
    /// The token is malformed, unknown, mismatched, expired, revoked, or disabled.
    #[error("authentication rejected")]
    Rejected,
    /// Authentication state cannot be checked safely.
    #[error("authentication storage is unavailable")]
    StorageUnavailable,
}

#[cfg(test)]
mod tests;
