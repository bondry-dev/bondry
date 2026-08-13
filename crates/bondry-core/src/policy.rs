use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

use thiserror::Error;

use crate::{AdapterId, CapabilityDescriptor, CapabilityId, Principal, PrincipalId};

/// The result of authorization policy evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    /// The invocation is allowed to continue.
    Allow,
    /// The invocation is rejected.
    Deny(DenialReason),
}

/// A stable reason for denying an invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenialReason {
    /// No explicit grant matched the invocation.
    NotGranted,
    /// Policy state could not be read safely.
    PolicyUnavailable,
}

/// The trusted metadata available to an authorization policy.
#[derive(Clone, Copy, Debug)]
pub struct AuthorizationRequest<'a> {
    principal: &'a Principal,
    adapter: &'a AdapterId,
    capability: &'a CapabilityDescriptor,
}

impl<'a> AuthorizationRequest<'a> {
    pub(crate) const fn new(
        principal: &'a Principal,
        adapter: &'a AdapterId,
        capability: &'a CapabilityDescriptor,
    ) -> Self {
        Self {
            principal,
            adapter,
            capability,
        }
    }

    /// Returns the authenticated principal.
    #[must_use]
    pub const fn principal(self) -> &'a Principal {
        self.principal
    }

    /// Returns the adapter identifier.
    #[must_use]
    pub const fn adapter(self) -> &'a AdapterId {
        self.adapter
    }

    /// Returns the capability metadata.
    #[must_use]
    pub const fn capability(self) -> &'a CapabilityDescriptor {
        self.capability
    }
}

/// Evaluates whether an authenticated principal may invoke a capability.
pub trait AuthorizationPolicy: Send + Sync {
    /// Returns an explicit authorization decision.
    fn evaluate(&self, request: AuthorizationRequest<'_>) -> AuthorizationDecision;
}

/// One exact principal, adapter, and capability authorization grant.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CapabilityGrant {
    principal: PrincipalId,
    adapter: AdapterId,
    capability: CapabilityId,
}

impl CapabilityGrant {
    /// Creates an exact authorization grant.
    #[must_use]
    pub const fn new(principal: PrincipalId, adapter: AdapterId, capability: CapabilityId) -> Self {
        Self {
            principal,
            adapter,
            capability,
        }
    }

    /// Returns the granted principal identifier.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns the granted adapter identifier.
    #[must_use]
    pub const fn adapter(&self) -> &AdapterId {
        &self.adapter
    }

    /// Returns the granted capability identifier.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityId {
        &self.capability
    }
}

/// Persistent operations required by a stored authorization policy.
pub trait GrantStore: Send + Sync {
    /// Adds an exact grant and reports whether state changed.
    fn add_grant(&self, grant: CapabilityGrant) -> Result<bool, GrantStoreError>;

    /// Removes an exact grant and reports whether state changed.
    fn remove_grant(&self, grant: &CapabilityGrant) -> Result<bool, GrantStoreError>;

    /// Checks whether an exact grant exists.
    fn contains_grant(&self, grant: &CapabilityGrant) -> Result<bool, GrantStoreError>;

    /// Lists grants for one principal in stable adapter and capability order.
    fn grants_for_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<CapabilityGrant>, GrantStoreError>;
}

/// A safe authorization-storage failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GrantStoreError {
    /// Authorization state cannot be read or changed safely.
    #[error("authorization storage is unavailable")]
    Unavailable,
}

/// A deny-by-default policy backed directly by durable grant state.
pub struct StoredGrantPolicy {
    store: Arc<dyn GrantStore>,
}

impl StoredGrantPolicy {
    /// Creates a policy from owned grant storage.
    #[must_use]
    pub fn new<S>(store: S) -> Self
    where
        S: GrantStore + 'static,
    {
        Self::from_shared(Arc::new(store))
    }

    /// Creates a policy from shared grant storage.
    #[must_use]
    pub const fn from_shared(store: Arc<dyn GrantStore>) -> Self {
        Self { store }
    }
}

impl AuthorizationPolicy for StoredGrantPolicy {
    fn evaluate(&self, request: AuthorizationRequest<'_>) -> AuthorizationDecision {
        let grant = CapabilityGrant::new(
            request.principal().id().clone(),
            request.adapter().clone(),
            request.capability().id().clone(),
        );
        match self.store.contains_grant(&grant) {
            Ok(true) => AuthorizationDecision::Allow,
            Ok(false) => AuthorizationDecision::Deny(DenialReason::NotGranted),
            Err(GrantStoreError::Unavailable) => {
                AuthorizationDecision::Deny(DenialReason::PolicyUnavailable)
            }
        }
    }
}

/// A policy that rejects every invocation.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllPolicy;

impl AuthorizationPolicy for DenyAllPolicy {
    fn evaluate(&self, _request: AuthorizationRequest<'_>) -> AuthorizationDecision {
        AuthorizationDecision::Deny(DenialReason::NotGranted)
    }
}

type Grants = HashMap<PrincipalId, HashMap<AdapterId, HashSet<CapabilityId>>>;

/// A deny-by-default policy containing exact principal, adapter, and capability grants.
#[derive(Debug, Default)]
pub struct GrantPolicy {
    grants: RwLock<Grants>,
}

impl GrantPolicy {
    /// Creates an empty policy that denies every invocation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an exact grant and returns whether policy state changed.
    pub fn grant(
        &self,
        principal: PrincipalId,
        adapter: AdapterId,
        capability: CapabilityId,
    ) -> Result<bool, PolicyUpdateError> {
        let mut grants = self
            .grants
            .write()
            .map_err(|_| PolicyUpdateError::Unavailable)?;
        Ok(grants
            .entry(principal)
            .or_default()
            .entry(adapter)
            .or_default()
            .insert(capability))
    }

    /// Removes an exact grant and returns whether policy state changed.
    pub fn revoke(
        &self,
        principal: &PrincipalId,
        adapter: &AdapterId,
        capability: &CapabilityId,
    ) -> Result<bool, PolicyUpdateError> {
        let mut grants = self
            .grants
            .write()
            .map_err(|_| PolicyUpdateError::Unavailable)?;
        let Some(adapters) = grants.get_mut(principal) else {
            return Ok(false);
        };
        let Some(capabilities) = adapters.get_mut(adapter) else {
            return Ok(false);
        };
        let removed = capabilities.remove(capability);
        if capabilities.is_empty() {
            adapters.remove(adapter);
        }
        if adapters.is_empty() {
            grants.remove(principal);
        }
        Ok(removed)
    }
}

impl AuthorizationPolicy for GrantPolicy {
    fn evaluate(&self, request: AuthorizationRequest<'_>) -> AuthorizationDecision {
        let Ok(grants) = self.grants.read() else {
            return AuthorizationDecision::Deny(DenialReason::PolicyUnavailable);
        };
        let allowed = grants
            .get(request.principal().id())
            .and_then(|adapters| adapters.get(request.adapter()))
            .is_some_and(|capabilities| capabilities.contains(request.capability().id()));
        if allowed {
            AuthorizationDecision::Allow
        } else {
            AuthorizationDecision::Deny(DenialReason::NotGranted)
        }
    }
}

/// An error produced while changing built-in policy state.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PolicyUpdateError {
    /// Policy state could not be changed safely.
    #[error("authorization policy is unavailable")]
    Unavailable,
}
