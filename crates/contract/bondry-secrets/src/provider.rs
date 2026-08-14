use thiserror::Error;

use crate::{SecretRef, SecretValue};

/// The active secret and optional previous value accepted during rotation.
#[derive(Debug)]
pub struct ResolvedSecret {
    current: SecretValue,
    previous: Option<SecretValue>,
}

impl ResolvedSecret {
    /// Creates resolved material with no rotation overlap.
    #[must_use]
    pub const fn current(current: SecretValue) -> Self {
        Self {
            current,
            previous: None,
        }
    }

    /// Creates resolved material that also accepts the previous value.
    #[must_use]
    pub const fn rotating(current: SecretValue, previous: SecretValue) -> Self {
        Self {
            current,
            previous: Some(previous),
        }
    }

    /// Returns the value used for new signatures and credentials.
    #[must_use]
    pub const fn current_value(&self) -> &SecretValue {
        &self.current
    }

    /// Returns the value accepted only during a rotation overlap.
    #[must_use]
    pub const fn previous_value(&self) -> Option<&SecretValue> {
        self.previous.as_ref()
    }
}

/// Host-owned secret resolution used by ingress and egress.
pub trait SecretProvider: Send + Sync {
    /// Resolves current and rotation-overlap material without persisting it in Bondry.
    fn resolve(&self, reference: &SecretRef) -> Result<ResolvedSecret, SecretProviderError>;
}

/// A stable, non-sensitive secret-resolution failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretProviderError {
    /// The host has no secret for the reference.
    #[error("secret not found")]
    NotFound,
    /// The host secret service is temporarily unavailable.
    #[error("secret provider unavailable")]
    Unavailable,
    /// Stored material violates the Bondry secret contract.
    #[error("secret provider returned invalid material")]
    InvalidMaterial,
}
