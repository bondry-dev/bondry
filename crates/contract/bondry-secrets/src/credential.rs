use std::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

/// Maximum UTF-8 encoded credential identifier size.
pub const MAX_CREDENTIAL_ID_BYTES: usize = 255;
/// Maximum credential value size accepted by the storage contract.
pub const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

/// A bounded host-defined identifier for persisted credential material.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CredentialId(String);

impl CredentialId {
    /// Creates an identifier safe for flat platform credential namespaces.
    pub fn new(value: impl Into<String>) -> Result<Self, CredentialIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(CredentialIdError::Empty);
        }
        if value.len() > MAX_CREDENTIAL_ID_BYTES {
            return Err(CredentialIdError::TooLong);
        }
        if matches!(value.as_str(), "." | "..")
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(CredentialIdError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the non-secret storage identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CredentialId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CredentialId")
            .field(&self.0)
            .finish()
    }
}

/// An invalid credential identifier.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialIdError {
    /// The identifier is empty.
    #[error("a credential identifier cannot be empty")]
    Empty,
    /// The identifier exceeds the storage contract limit.
    #[error("a credential identifier cannot exceed {MAX_CREDENTIAL_ID_BYTES} bytes")]
    TooLong,
    /// The identifier is not a portable flat-namespace name.
    #[error("a credential identifier contains an unsupported character")]
    InvalidCharacter,
}

/// Persisted credential bytes that are cleared when dropped.
pub struct CredentialValue(Zeroizing<Vec<u8>>);

impl CredentialValue {
    /// Wraps non-empty credential material within the storage contract limit.
    pub fn new(bytes: Vec<u8>) -> Result<Self, CredentialValueError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() {
            return Err(CredentialValueError::Empty);
        }
        if bytes.len() > MAX_CREDENTIAL_BYTES {
            return Err(CredentialValueError::TooLong);
        }
        Ok(Self(bytes))
    }

    /// Exposes credential bytes to the operation that consumes them.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for CredentialValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialValue([REDACTED])")
    }
}

/// Invalid persisted credential material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialValueError {
    /// The credential is empty.
    #[error("a credential cannot be empty")]
    Empty,
    /// The credential exceeds the storage contract limit.
    #[error("a credential cannot exceed {MAX_CREDENTIAL_BYTES} bytes")]
    TooLong,
}

/// The security boundary protecting credential material at rest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialProtection {
    /// Access is controlled by the operating system's filesystem permissions.
    AccessControlled,
    /// Material is cryptographically bound to one operating-system installation.
    HostBound,
    /// Material is cryptographically bound to local security hardware.
    HardwareBound,
    /// Material is owned by an external credential service.
    External,
}

/// Whether a credential backend can modify persisted material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialStoreAccess {
    /// The backend can only resolve pre-provisioned material.
    ReadOnly,
    /// The backend can atomically create, replace, and delete material.
    ReadWrite,
}

/// Stable properties a host can use when selecting a credential backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialStoreCapabilities {
    /// The backend's at-rest protection boundary.
    pub protection: CredentialProtection,
    /// Whether the backend can modify persisted material.
    pub access: CredentialStoreAccess,
    /// Whether credentials can be resolved without interactive user presence.
    pub supports_unattended_access: bool,
}

/// Host-owned persistent credential storage.
pub trait CredentialStore: Send + Sync {
    /// Reports stable backend capabilities without resolving credential material.
    fn capabilities(&self) -> CredentialStoreCapabilities;

    /// Loads one credential, returning `None` when it has not been provisioned.
    fn load(&self, id: &CredentialId) -> Result<Option<CredentialValue>, CredentialStoreError>;

    /// Atomically creates or replaces one credential.
    fn store(&self, id: &CredentialId, value: &CredentialValue)
    -> Result<(), CredentialStoreError>;

    /// Deletes one credential and reports whether it existed.
    fn delete(&self, id: &CredentialId) -> Result<bool, CredentialStoreError>;
}

/// A stable, non-sensitive credential storage failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CredentialStoreError {
    /// The configured backend is temporarily unavailable.
    #[error("credential store unavailable")]
    Unavailable,
    /// The caller cannot access the configured backend.
    #[error("credential store access denied")]
    AccessDenied,
    /// Filesystem or platform metadata violates the backend's safety policy.
    #[error("credential store is unsafe")]
    UnsafeStorage,
    /// Persisted material violates the credential storage contract.
    #[error("stored credential is invalid")]
    InvalidMaterial,
    /// The backend was provisioned for read-only access.
    #[error("credential store is read-only")]
    ReadOnly,
}

#[cfg(test)]
mod tests {
    use super::{
        CredentialId, CredentialIdError, CredentialValue, CredentialValueError,
        MAX_CREDENTIAL_BYTES, MAX_CREDENTIAL_ID_BYTES,
    };

    #[test]
    fn accepts_portable_flat_identifiers() {
        let id = CredentialId::new("remote-client_01.tls-root")
            .unwrap_or_else(|error| unreachable!("valid credential identifier: {error}"));
        assert_eq!(id.as_str(), "remote-client_01.tls-root");
    }

    #[test]
    fn rejects_empty_oversized_and_path_identifiers() {
        assert_eq!(CredentialId::new(""), Err(CredentialIdError::Empty));
        assert_eq!(
            CredentialId::new("a".repeat(MAX_CREDENTIAL_ID_BYTES + 1)),
            Err(CredentialIdError::TooLong)
        );
        for value in [
            ".",
            "..",
            "../secret",
            "nested/secret",
            "secret\\name",
            "secret:name",
        ] {
            assert_eq!(
                CredentialId::new(value),
                Err(CredentialIdError::InvalidCharacter)
            );
        }
    }

    #[test]
    fn redacts_credential_debug_output() {
        let value = CredentialValue::new(b"private material".to_vec())
            .unwrap_or_else(|error| unreachable!("valid credential value: {error}"));
        assert_eq!(format!("{value:?}"), "CredentialValue([REDACTED])");
    }

    #[test]
    fn enforces_credential_value_bounds() {
        assert!(matches!(
            CredentialValue::new(Vec::new()),
            Err(CredentialValueError::Empty)
        ));
        assert!(matches!(
            CredentialValue::new(vec![0; MAX_CREDENTIAL_BYTES + 1]),
            Err(CredentialValueError::TooLong)
        ));
    }
}
