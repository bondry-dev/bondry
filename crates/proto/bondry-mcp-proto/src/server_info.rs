use serde_json::{Value, json};
use thiserror::Error;

pub(crate) const MAX_NAME_LENGTH: usize = 128;
const MAX_TITLE_LENGTH: usize = 256;
pub(crate) const MAX_VERSION_LENGTH: usize = 64;

/// Validated host-application metadata returned during MCP initialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpServerInfo {
    name: String,
    title: Option<String>,
    version: String,
}

impl McpServerInfo {
    /// Creates server metadata with a protocol-facing name and application version.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, McpServerInfoError> {
        let name = validate(name.into(), MAX_NAME_LENGTH)?;
        let version = validate(version.into(), MAX_VERSION_LENGTH)?;
        Ok(Self {
            name,
            title: None,
            version,
        })
    }

    /// Adds a user-facing application title.
    pub fn with_title(mut self, title: impl Into<String>) -> Result<Self, McpServerInfoError> {
        self.title = Some(validate(title.into(), MAX_TITLE_LENGTH)?);
        Ok(self)
    }

    pub(crate) fn as_json(&self) -> Value {
        let mut value = json!({ "name": self.name, "version": self.version });
        if let Some(title) = &self.title {
            value["title"] = Value::String(title.clone());
        }
        value
    }
}

/// Invalid MCP server implementation metadata.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpServerInfoError {
    /// A required value is empty or contains only whitespace.
    #[error("MCP server metadata cannot be empty")]
    Empty,
    /// A value exceeds its protocol-safe length limit.
    #[error("MCP server metadata is too long")]
    TooLong,
    /// A value contains a control character.
    #[error("MCP server metadata cannot contain control characters")]
    ControlCharacter,
}

pub(crate) fn validate(value: String, max_length: usize) -> Result<String, McpServerInfoError> {
    if value.trim().is_empty() {
        return Err(McpServerInfoError::Empty);
    }
    if value.len() > max_length {
        return Err(McpServerInfoError::TooLong);
    }
    if value.chars().any(char::is_control) {
        return Err(McpServerInfoError::ControlCharacter);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{McpServerInfo, McpServerInfoError};

    #[test]
    fn validates_required_and_optional_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let info = McpServerInfo::new("battery-app", "2.3.1")?.with_title("Battery App")?;
        assert_eq!(info.as_json()["title"], "Battery App");
        assert_eq!(
            McpServerInfo::new("", "1").err(),
            Some(McpServerInfoError::Empty)
        );
        assert_eq!(
            McpServerInfo::new("app", "\n").err(),
            Some(McpServerInfoError::Empty)
        );
        assert_eq!(
            McpServerInfo::new("app", "x".repeat(65)).err(),
            Some(McpServerInfoError::TooLong)
        );
        Ok(())
    }
}
