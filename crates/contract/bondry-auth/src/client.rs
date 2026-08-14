use bondry_core::PrincipalId;
use thiserror::Error;

const MAX_CLIENT_NAME_LENGTH: usize = 128;

/// A validated display name for an automation client.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ClientName(String);

impl ClientName {
    /// Creates a trimmed, non-empty client display name.
    pub fn new(value: impl Into<String>) -> Result<Self, ClientNameError> {
        let value = value.into();
        let value = value.trim();
        if value.is_empty() {
            return Err(ClientNameError::Empty);
        }
        if value.len() > MAX_CLIENT_NAME_LENGTH {
            return Err(ClientNameError::TooLong);
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the display name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An invalid client display name.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ClientNameError {
    /// The name is empty after trimming.
    #[error("a client name cannot be empty")]
    Empty,
    /// The name exceeds the supported encoded length.
    #[error("a client name cannot exceed {MAX_CLIENT_NAME_LENGTH} bytes")]
    TooLong,
}

/// A registered automation client represented as an application principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Client {
    id: PrincipalId,
    name: ClientName,
    enabled: bool,
    created_at_unix_seconds: i64,
}

impl Client {
    /// Reconstructs a client from trusted persistent state.
    #[must_use]
    pub const fn from_stored_parts(
        id: PrincipalId,
        name: ClientName,
        enabled: bool,
        created_at_unix_seconds: i64,
    ) -> Self {
        Self {
            id,
            name,
            enabled,
            created_at_unix_seconds,
        }
    }

    /// Returns the principal identifier assigned to the client.
    #[must_use]
    pub const fn id(&self) -> &PrincipalId {
        &self.id
    }

    /// Returns the client display name.
    #[must_use]
    pub const fn name(&self) -> &ClientName {
        &self.name
    }

    /// Returns whether the client may authenticate.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the creation time as Unix seconds.
    #[must_use]
    pub const fn created_at_unix_seconds(&self) -> i64 {
        self.created_at_unix_seconds
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientName, ClientNameError};

    #[test]
    fn trims_and_validates_client_names() -> Result<(), ClientNameError> {
        assert_eq!(ClientName::new("  Client  ")?.as_str(), "Client");
        assert_eq!(ClientName::new(" \n\t "), Err(ClientNameError::Empty));
        assert_eq!(
            ClientName::new("é".repeat(65)),
            Err(ClientNameError::TooLong)
        );
        Ok(())
    }
}
