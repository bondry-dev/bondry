use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use thiserror::Error;
use zeroize::Zeroizing;

const DATABASE_KEY_BYTES: usize = 32;

/// A 256-bit SQLCipher database key intended for platform-secure storage.
pub struct DatabaseKey {
    bytes: Zeroizing<[u8; DATABASE_KEY_BYTES]>,
}

impl DatabaseKey {
    /// Generates a key from the operating system's cryptographically secure random source.
    pub fn generate() -> Result<Self, DatabaseKeyError> {
        let mut bytes = Zeroizing::new([0_u8; DATABASE_KEY_BYTES]);
        getrandom::fill(bytes.as_mut()).map_err(|_| DatabaseKeyError::EntropyUnavailable)?;
        Ok(Self { bytes })
    }

    /// Reconstructs a key loaded from a platform-secure secret store.
    #[must_use]
    pub fn from_bytes(bytes: [u8; DATABASE_KEY_BYTES]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Exposes the bytes for deliberate persistence in a platform-secure secret store.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8; DATABASE_KEY_BYTES] {
        &self.bytes
    }

    pub(crate) fn sqlcipher_passphrase(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD_NO_PAD.encode(self.bytes.as_ref()))
    }
}

impl fmt::Debug for DatabaseKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DatabaseKey([REDACTED])")
    }
}

/// A database-key generation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DatabaseKeyError {
    /// The operating system could not provide secure random bytes.
    #[error("secure random generation is unavailable")]
    EntropyUnavailable,
}
