use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicI64, AtomicU8, Ordering},
    },
    time::Duration,
};

use bondry_core::{PrincipalId, PrincipalKind};

use super::{AuthManager, Clock, RandomError, RandomSource, TimeError};
use crate::{
    AuthStore, AuthenticationError, AuthenticationRecord, Client, ClientManagementError,
    ClientName, RotationOutcome, StoreError, TokenId, TokenLabel, TokenLifecycleError, TokenRecord,
    TokenReplacement,
};

#[derive(Default)]
struct MemoryState {
    clients: HashMap<PrincipalId, Client>,
    tokens: HashMap<TokenId, TokenRecord>,
}

#[derive(Default)]
struct MemoryStore {
    state: Mutex<MemoryState>,
    unavailable: AtomicBool,
}

impl MemoryStore {
    fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.store(unavailable, Ordering::SeqCst);
    }

    fn state(&self) -> Result<MutexGuard<'_, MemoryState>, StoreError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable);
        }
        self.state.lock().map_err(|_| StoreError::Unavailable)
    }
}

impl AuthStore for MemoryStore {
    fn insert_client(&self, client: Client) -> Result<(), StoreError> {
        let mut state = self.state()?;
        if state.clients.contains_key(client.id()) {
            return Err(StoreError::Conflict);
        }
        state.clients.insert(client.id().clone(), client);
        Ok(())
    }

    fn client(&self, id: &PrincipalId) -> Result<Option<Client>, StoreError> {
        Ok(self.state()?.clients.get(id).cloned())
    }

    fn set_client_enabled(&self, id: &PrincipalId, enabled: bool) -> Result<bool, StoreError> {
        let mut state = self.state()?;
        let Some(client) = state.clients.get_mut(id) else {
            return Ok(false);
        };
        *client = Client::from_stored_parts(
            client.id().clone(),
            client.name().clone(),
            enabled,
            client.created_at_unix_seconds(),
        );
        Ok(true)
    }

    fn insert_token(&self, token: TokenRecord) -> Result<(), StoreError> {
        let mut state = self.state()?;
        if !state.clients.contains_key(token.client()) {
            return Err(StoreError::Unavailable);
        }
        if state.tokens.contains_key(token.id())
            || state
                .tokens
                .values()
                .any(|existing| existing.digest() == token.digest())
        {
            return Err(StoreError::Conflict);
        }
        state.tokens.insert(token.id().clone(), token);
        Ok(())
    }

    fn authentication_record(
        &self,
        id: &TokenId,
    ) -> Result<Option<AuthenticationRecord>, StoreError> {
        let state = self.state()?;
        let Some(token) = state.tokens.get(id) else {
            return Ok(None);
        };
        let client_enabled = state
            .clients
            .get(token.client())
            .ok_or(StoreError::Unavailable)?
            .is_enabled();
        Ok(Some(AuthenticationRecord::from_stored_parts(
            token.clone(),
            client_enabled,
        )))
    }

    fn revoke_token(&self, id: &TokenId, revoked_at_unix_seconds: i64) -> Result<bool, StoreError> {
        let mut state = self.state()?;
        let Some(token) = state.tokens.get_mut(id) else {
            return Ok(false);
        };
        if token.revoked_at_unix_seconds().is_some() {
            return Ok(false);
        }
        token.mark_revoked(revoked_at_unix_seconds);
        Ok(true)
    }

    fn rotate_token(
        &self,
        current: &TokenId,
        replacement: TokenReplacement,
        revoked_at_unix_seconds: i64,
    ) -> Result<RotationOutcome, StoreError> {
        let mut state = self.state()?;
        let Some(current_token) = state.tokens.get(current).cloned() else {
            return Ok(RotationOutcome::NotFound);
        };
        let enabled = state
            .clients
            .get(current_token.client())
            .ok_or(StoreError::Unavailable)?
            .is_enabled();
        if !enabled {
            return Ok(RotationOutcome::ClientDisabled);
        }
        if !current_token.is_active_at(revoked_at_unix_seconds) {
            return Ok(RotationOutcome::Inactive);
        }
        let replacement = replacement.into_record(current_token.client().clone());
        if state.tokens.contains_key(replacement.id())
            || state
                .tokens
                .values()
                .any(|existing| existing.digest() == replacement.digest())
        {
            return Err(StoreError::Conflict);
        }
        state
            .tokens
            .get_mut(current)
            .ok_or(StoreError::Unavailable)?
            .mark_revoked(revoked_at_unix_seconds);
        state.tokens.insert(replacement.id().clone(), replacement);
        Ok(RotationOutcome::Rotated(current_token.client().clone()))
    }

    fn tokens_for_client(&self, id: &PrincipalId) -> Result<Vec<TokenRecord>, StoreError> {
        Ok(self
            .state()?
            .tokens
            .values()
            .filter(|token| token.client() == id)
            .cloned()
            .collect())
    }
}

struct DeterministicRandom {
    next: AtomicU8,
}

impl DeterministicRandom {
    fn new(seed: u8) -> Self {
        Self {
            next: AtomicU8::new(seed),
        }
    }
}

impl RandomSource for DeterministicRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError> {
        let value = self.next.fetch_add(1, Ordering::SeqCst);
        destination.fill(value);
        Ok(())
    }
}

struct FixedRandom(u8);

impl RandomSource for FixedRandom {
    fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError> {
        destination.fill(self.0);
        Ok(())
    }
}

struct FailingRandom;

impl RandomSource for FailingRandom {
    fn fill(&self, _destination: &mut [u8]) -> Result<(), RandomError> {
        Err(RandomError)
    }
}

struct FakeClock(AtomicI64);

impl FakeClock {
    fn new(now: i64) -> Self {
        Self(AtomicI64::new(now))
    }

    fn set(&self, now: i64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_unix_seconds(&self) -> Result<i64, TimeError> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

fn manager_with(
    store: Arc<MemoryStore>,
    random: Arc<dyn RandomSource>,
    clock: Arc<FakeClock>,
) -> AuthManager {
    AuthManager::with_sources(store, random, clock)
}

fn setup(seed: u8) -> (AuthManager, Arc<MemoryStore>, Arc<FakeClock>) {
    let store = Arc::new(MemoryStore::default());
    let clock = Arc::new(FakeClock::new(1_000));
    let manager = manager_with(
        Arc::clone(&store),
        Arc::new(DeterministicRandom::new(seed)),
        Arc::clone(&clock),
    );
    (manager, store, clock)
}

#[test]
fn issues_and_authenticates_a_redacted_token() -> Result<(), Box<dyn std::error::Error>> {
    let (manager, _, _) = setup(1);
    let client = manager.create_client(ClientName::new("  Test Client  ")?)?;
    let issued = manager.issue_token(client.id(), Some(TokenLabel::new("Primary token")?), None)?;

    assert_eq!(client.name().as_str(), "Test Client");
    assert!(issued.secret().expose().starts_with("bondry_v1.token_"));
    assert!(!format!("{:?}", issued.secret()).contains(issued.secret().expose()));
    let principal = manager.authenticate(issued.secret().expose())?;
    assert_eq!(principal.id(), client.id());
    assert_eq!(principal.kind(), PrincipalKind::Application);
    assert_eq!(manager.tokens_for_client(client.id())?.len(), 1);
    Ok(())
}

#[test]
fn collapses_all_invalid_presentations_into_one_error() -> Result<(), Box<dyn std::error::Error>> {
    let (manager, _, _) = setup(10);
    let client = manager.create_client(ClientName::new("Client")?)?;
    let issued = manager.issue_token(client.id(), None, None)?;
    let mut tampered = issued.secret().expose().as_bytes().to_vec();
    let last = tampered
        .last_mut()
        .ok_or(std::io::Error::other("empty token"))?;
    *last = if *last == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered)?;

    let (other_manager, _, _) = setup(100);
    let other_client = other_manager.create_client(ClientName::new("Other")?)?;
    let unknown = other_manager.issue_token(other_client.id(), None, None)?;

    for presented in ["malformed", tampered.as_str(), unknown.secret().expose()] {
        assert_eq!(
            manager.authenticate(presented),
            Err(AuthenticationError::Rejected)
        );
    }
    Ok(())
}

#[test]
fn client_disable_takes_effect_immediately() -> Result<(), Box<dyn std::error::Error>> {
    let (manager, _, _) = setup(20);
    let client = manager.create_client(ClientName::new("Client")?)?;
    let issued = manager.issue_token(client.id(), None, None)?;

    manager.set_client_enabled(client.id(), false)?;
    assert_eq!(
        manager.authenticate(issued.secret().expose()),
        Err(AuthenticationError::Rejected)
    );
    assert_eq!(
        manager.issue_token(client.id(), None, None).map(|_| ()),
        Err(TokenLifecycleError::ClientDisabled)
    );
    manager.set_client_enabled(client.id(), true)?;
    assert!(manager.authenticate(issued.secret().expose()).is_ok());
    Ok(())
}

#[test]
fn revocation_is_immediate_and_idempotent() -> Result<(), Box<dyn std::error::Error>> {
    let (manager, _, _) = setup(30);
    let client = manager.create_client(ClientName::new("Client")?)?;
    let issued = manager.issue_token(client.id(), None, None)?;

    assert!(manager.revoke_token(issued.metadata().id())?);
    assert!(!manager.revoke_token(issued.metadata().id())?);
    assert_eq!(
        manager.authenticate(issued.secret().expose()),
        Err(AuthenticationError::Rejected)
    );
    Ok(())
}

#[test]
fn expiration_rejects_at_the_exact_boundary() -> Result<(), Box<dyn std::error::Error>> {
    let (manager, _, clock) = setup(40);
    let client = manager.create_client(ClientName::new("Client")?)?;
    let issued = manager.issue_token(client.id(), None, Some(Duration::from_secs(10)))?;

    clock.set(1_009);
    assert!(manager.authenticate(issued.secret().expose()).is_ok());
    clock.set(1_010);
    assert_eq!(
        manager.authenticate(issued.secret().expose()),
        Err(AuthenticationError::Rejected)
    );
    Ok(())
}

#[test]
fn rotation_is_atomic_and_invalidates_the_previous_secret() -> Result<(), Box<dyn std::error::Error>>
{
    let (manager, _, _) = setup(50);
    let client = manager.create_client(ClientName::new("Client")?)?;
    let original = manager.issue_token(client.id(), None, None)?;
    let replacement = manager.rotate_token(
        original.metadata().id(),
        Some(TokenLabel::new("Rotated")?),
        None,
    )?;

    assert_eq!(
        manager.authenticate(original.secret().expose()),
        Err(AuthenticationError::Rejected)
    );
    assert!(manager.authenticate(replacement.secret().expose()).is_ok());
    let tokens = manager.tokens_for_client(client.id())?;
    assert_eq!(tokens.len(), 2);
    assert_eq!(
        tokens
            .iter()
            .filter(|token| token.revoked_at_unix_seconds().is_some())
            .count(),
        1
    );
    Ok(())
}

#[test]
fn rejects_rotation_of_inactive_tokens() -> Result<(), Box<dyn std::error::Error>> {
    let (manager, _, _) = setup(60);
    let client = manager.create_client(ClientName::new("Client")?)?;
    let issued = manager.issue_token(client.id(), None, None)?;
    assert!(manager.revoke_token(issued.metadata().id())?);

    assert_eq!(
        manager
            .rotate_token(issued.metadata().id(), None, None)
            .map(|_| ()),
        Err(TokenLifecycleError::Inactive)
    );
    Ok(())
}

#[test]
fn rejects_subsecond_and_overflowing_lifetimes() -> Result<(), Box<dyn std::error::Error>> {
    let (manager, _, clock) = setup(70);
    let client = manager.create_client(ClientName::new("Client")?)?;
    assert_eq!(
        manager
            .issue_token(client.id(), None, Some(Duration::from_millis(999)))
            .map(|_| ()),
        Err(TokenLifecycleError::InvalidLifetime)
    );

    clock.set(i64::MAX);
    assert_eq!(
        manager
            .issue_token(client.id(), None, Some(Duration::from_secs(1)))
            .map(|_| ()),
        Err(TokenLifecycleError::InvalidLifetime)
    );
    Ok(())
}

#[test]
fn maps_entropy_and_storage_failures_without_partial_state()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let clock = Arc::new(FakeClock::new(1_000));
    let failing = manager_with(
        Arc::clone(&store),
        Arc::new(FailingRandom),
        Arc::clone(&clock),
    );
    assert_eq!(
        failing.create_client(ClientName::new("Client")?),
        Err(ClientManagementError::EntropyUnavailable)
    );

    let working = manager_with(
        Arc::clone(&store),
        Arc::new(DeterministicRandom::new(80)),
        Arc::clone(&clock),
    );
    let client = working.create_client(ClientName::new("Client")?)?;
    let issued = working.issue_token(client.id(), None, None)?;
    store.set_unavailable(true);
    assert_eq!(
        working.authenticate(issued.secret().expose()),
        Err(AuthenticationError::StorageUnavailable)
    );
    assert_eq!(
        working.issue_token(client.id(), None, None).map(|_| ()),
        Err(TokenLifecycleError::StorageUnavailable)
    );
    Ok(())
}

#[test]
fn bounds_identifier_collision_retries() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let clock = Arc::new(FakeClock::new(1_000));
    let manager = manager_with(
        Arc::clone(&store),
        Arc::new(FixedRandom(0)),
        Arc::clone(&clock),
    );
    let client = manager.create_client(ClientName::new("First")?)?;
    assert_eq!(
        manager.create_client(ClientName::new("Second")?),
        Err(ClientManagementError::GenerationExhausted)
    );
    let issued = manager.issue_token(client.id(), None, None)?;
    assert_eq!(
        manager.issue_token(client.id(), None, None).map(|_| ()),
        Err(TokenLifecycleError::GenerationExhausted)
    );
    assert!(manager.authenticate(issued.secret().expose()).is_ok());
    Ok(())
}

#[test]
fn issues_unique_tokens_concurrently() -> Result<(), Box<dyn std::error::Error>> {
    let (manager, _, _) = setup(90);
    let manager = Arc::new(manager);
    let client = manager.create_client(ClientName::new("Client")?)?;
    let mut handles = Vec::new();
    for _ in 0..32 {
        let manager = Arc::clone(&manager);
        let client = client.id().clone();
        handles.push(std::thread::spawn(move || {
            manager.issue_token(&client, None, None)
        }));
    }

    let mut ids = Vec::new();
    for handle in handles {
        let token = handle
            .join()
            .map_err(|_| std::io::Error::other("token thread panicked"))??;
        ids.push(token.metadata().id().clone());
    }
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 32);
    assert_eq!(manager.tokens_for_client(client.id())?.len(), 32);
    Ok(())
}
