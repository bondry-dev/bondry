use bondry_transport::HttpLimits;
use thiserror::Error;

/// Default maximum encoded MCP tool input schema.
pub const DEFAULT_MCP_SCHEMA_BYTES: usize = 16 * 1024;
const MIN_MCP_SCHEMA_BYTES: usize = 1;
/// Maximum encoded MCP tool input schema.
pub const MAX_MCP_SCHEMA_BYTES: usize = 64 * 1024;
/// Default maximum raw JSON result returned by host `call`.
pub const DEFAULT_MCP_RESULT_BYTES: usize = 256 * 1024;
/// Minimum configurable raw JSON result bound.
pub const MIN_MCP_RESULT_BYTES: usize = 4 * 1024;
/// Maximum raw JSON result returned by host `call`.
pub const MAX_MCP_RESULT_BYTES: usize = 1024 * 1024;

/// Validated MCP schema and result bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McpLimits {
    schema_bytes: usize,
    result_bytes: usize,
    response: HttpLimits,
}

impl McpLimits {
    /// Creates bounds inside the accepted limits contract.
    pub const fn new(schema_bytes: usize, result_bytes: usize) -> Result<Self, McpLimitError> {
        if schema_bytes < MIN_MCP_SCHEMA_BYTES || schema_bytes > MAX_MCP_SCHEMA_BYTES {
            return Err(McpLimitError::Schema);
        }
        if result_bytes < MIN_MCP_RESULT_BYTES || result_bytes > MAX_MCP_RESULT_BYTES {
            return Err(McpLimitError::Result);
        }
        let response = match HttpLimits::new(result_bytes) {
            Ok(response) => response,
            Err(_) => return Err(McpLimitError::Result),
        };
        Ok(Self {
            schema_bytes,
            result_bytes,
            response,
        })
    }

    /// Returns the configured schema byte cap.
    #[must_use]
    pub const fn schema_bytes(self) -> usize {
        self.schema_bytes
    }

    /// Returns the configured raw result byte cap.
    #[must_use]
    pub const fn result_bytes(self) -> usize {
        self.result_bytes
    }

    pub(crate) const fn response(self) -> HttpLimits {
        self.response
    }
}

impl Default for McpLimits {
    fn default() -> Self {
        Self {
            schema_bytes: DEFAULT_MCP_SCHEMA_BYTES,
            result_bytes: DEFAULT_MCP_RESULT_BYTES,
            response: HttpLimits::new(DEFAULT_MCP_RESULT_BYTES).unwrap_or_default(),
        }
    }
}

/// MCP bound outside the accepted limits contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpLimitError {
    /// Input schema bytes are outside 1 byte through 64 KiB.
    #[error("MCP input schema limit is outside the allowed range")]
    Schema,
    /// Raw result bytes are outside 4 KiB through 1 MiB.
    #[error("MCP result limit is outside the allowed range")]
    Result,
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_MCP_RESULT_BYTES, MAX_MCP_SCHEMA_BYTES, MIN_MCP_RESULT_BYTES, McpLimitError, McpLimits,
    };

    #[test]
    fn validates_schema_and_result_boundaries() {
        assert!(McpLimits::new(MAX_MCP_SCHEMA_BYTES, MAX_MCP_RESULT_BYTES).is_ok());
        assert_eq!(
            McpLimits::new(0, MIN_MCP_RESULT_BYTES),
            Err(McpLimitError::Schema)
        );
        assert_eq!(
            McpLimits::new(MAX_MCP_SCHEMA_BYTES, MIN_MCP_RESULT_BYTES - 1),
            Err(McpLimitError::Result)
        );
    }
}
