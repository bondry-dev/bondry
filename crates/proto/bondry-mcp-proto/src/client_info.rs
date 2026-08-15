use serde_json::{Value, json};
use thiserror::Error;

use crate::server_info::{MAX_NAME_LENGTH, MAX_VERSION_LENGTH, McpServerInfoError, validate};

/// Validated MCP client implementation metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpClientInfo {
    name: String,
    version: String,
}

impl McpClientInfo {
    /// Creates protocol-safe client implementation metadata.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, McpClientInfoError> {
        Ok(Self {
            name: validate(name.into(), MAX_NAME_LENGTH).map_err(McpClientInfoError::from)?,
            version: validate(version.into(), MAX_VERSION_LENGTH)
                .map_err(McpClientInfoError::from)?,
        })
    }

    pub(crate) fn as_json(&self) -> Value {
        json!({ "name": self.name, "version": self.version })
    }
}

/// Invalid MCP client implementation metadata.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpClientInfoError {
    /// A required value is empty or contains only whitespace.
    #[error("MCP client metadata cannot be empty")]
    Empty,
    /// A value exceeds its protocol-safe length limit.
    #[error("MCP client metadata is too long")]
    TooLong,
    /// A value contains a control character.
    #[error("MCP client metadata cannot contain control characters")]
    ControlCharacter,
}

impl From<McpServerInfoError> for McpClientInfoError {
    fn from(error: McpServerInfoError) -> Self {
        match error {
            McpServerInfoError::Empty => Self::Empty,
            McpServerInfoError::TooLong => Self::TooLong,
            McpServerInfoError::ControlCharacter => Self::ControlCharacter,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{McpClientInfo, McpClientInfoError};

    #[test]
    fn validates_client_metadata() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            McpClientInfo::new("bondry-egress", "0.2.0")?.as_json()["name"],
            "bondry-egress"
        );
        assert_eq!(
            McpClientInfo::new("", "1").err(),
            Some(McpClientInfoError::Empty)
        );
        Ok(())
    }
}
