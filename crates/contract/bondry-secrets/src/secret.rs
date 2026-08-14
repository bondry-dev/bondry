use std::{fmt, hash::Hash};

use thiserror::Error;
use zeroize::Zeroizing;

/// Maximum resolved secret size from the limits contract.
pub const MAX_SECRET_BYTES: usize = 1024;
/// Maximum UTF-8 encoded secret reference size from the limits contract.
pub const MAX_SECRET_REF_BYTES: usize = 1024;

/// A non-secret, host-defined locator for secret material.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretRef(String);

impl SecretRef {
    /// Creates a bounded, non-empty secret reference.
    pub fn new(value: impl Into<String>) -> Result<Self, SecretRefError> {
        let value = value.into();
        if value.is_empty() {
            return Err(SecretRefError::Empty);
        }
        if value.len() > MAX_SECRET_REF_BYTES {
            return Err(SecretRefError::TooLong);
        }
        Ok(Self(value))
    }

    /// Returns the host-defined locator.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("SecretRef").field(&self.0).finish()
    }
}

/// An invalid secret reference.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretRefError {
    /// The reference is empty.
    #[error("a secret reference cannot be empty")]
    Empty,
    /// The UTF-8 encoded reference exceeds 1 KiB.
    #[error("a secret reference cannot exceed {MAX_SECRET_REF_BYTES} bytes")]
    TooLong,
}

/// Resolved secret bytes that are cleared when dropped.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Wraps non-empty secret material within the limits contract.
    pub fn new(bytes: Vec<u8>) -> Result<Self, SecretValueError> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() {
            return Err(SecretValueError::Empty);
        }
        if bytes.len() > MAX_SECRET_BYTES {
            return Err(SecretValueError::TooLong);
        }
        Ok(Self(bytes))
    }

    /// Exposes the secret to the cryptographic operation that consumes it.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

/// Invalid resolved secret material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretValueError {
    /// The provider returned an empty secret.
    #[error("a secret cannot be empty")]
    Empty,
    /// The provider returned more than 1 KiB.
    #[error("a secret cannot exceed {MAX_SECRET_BYTES} bytes")]
    TooLong,
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_SECRET_BYTES, MAX_SECRET_REF_BYTES, SecretRef, SecretRefError, SecretValue,
        SecretValueError,
    };

    #[test]
    fn rejects_empty_reference() {
        assert_eq!(SecretRef::new(""), Err(SecretRefError::Empty));
    }

    #[test]
    fn enforces_reference_byte_bound() {
        assert!(SecretRef::new("a".repeat(MAX_SECRET_REF_BYTES)).is_ok());
        assert_eq!(
            SecretRef::new("a".repeat(MAX_SECRET_REF_BYTES + 1)),
            Err(SecretRefError::TooLong)
        );
        assert_eq!(
            SecretRef::new("é".repeat(MAX_SECRET_REF_BYTES / 2 + 1)),
            Err(SecretRefError::TooLong)
        );
    }

    #[test]
    fn redacts_secret_debug_output() {
        let secret = SecretValue::new(b"private".to_vec())
            .unwrap_or_else(|error| unreachable!("valid fixture secret: {error}"));
        assert_eq!(format!("{secret:?}"), "SecretValue([REDACTED])");
    }

    #[test]
    fn enforces_secret_bounds() {
        assert!(matches!(
            SecretValue::new(Vec::new()),
            Err(SecretValueError::Empty)
        ));
        assert!(matches!(
            SecretValue::new(vec![0; MAX_SECRET_BYTES + 1]),
            Err(SecretValueError::TooLong)
        ));
    }
}
