use bondry_transport::HttpLimits;
use thiserror::Error;

/// Default maximum encoded MCP tool input schema.
pub const DEFAULT_MCP_SCHEMA_BYTES: usize = 16 * 1024;
const MIN_MCP_SCHEMA_BYTES: usize = 1;
/// Maximum encoded MCP tool input schema.
pub const MAX_MCP_SCHEMA_BYTES: usize = 64 * 1024;
/// Default maximum tools accepted from configuration-time discovery.
pub const DEFAULT_MCP_DISCOVERY_TOOLS: usize = 128;
const MIN_MCP_DISCOVERY_TOOLS: usize = 1;
/// Maximum tools accepted from configuration-time discovery.
pub const MAX_MCP_DISCOVERY_TOOLS: usize = 256;
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

/// Validated bounds for one explicit MCP discovery operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct McpDiscoveryLimits {
    tools: usize,
    schema_bytes: usize,
    response: HttpLimits,
}

impl McpDiscoveryLimits {
    /// Creates discovery bounds inside the accepted limits contract.
    pub const fn new(
        tools: usize,
        schema_bytes: usize,
        response_bytes: usize,
    ) -> Result<Self, McpDiscoveryLimitError> {
        if tools < MIN_MCP_DISCOVERY_TOOLS || tools > MAX_MCP_DISCOVERY_TOOLS {
            return Err(McpDiscoveryLimitError::Tools);
        }
        if schema_bytes < MIN_MCP_SCHEMA_BYTES || schema_bytes > MAX_MCP_SCHEMA_BYTES {
            return Err(McpDiscoveryLimitError::Schema);
        }
        let response = match HttpLimits::new(response_bytes) {
            Ok(response) => response,
            Err(_) => return Err(McpDiscoveryLimitError::Response),
        };
        Ok(Self {
            tools,
            schema_bytes,
            response,
        })
    }

    /// Returns the maximum number of accepted tools.
    #[must_use]
    pub const fn tools(self) -> usize {
        self.tools
    }

    /// Returns the maximum encoded input schema size for each tool.
    #[must_use]
    pub const fn schema_bytes(self) -> usize {
        self.schema_bytes
    }

    /// Returns the aggregate discovery response body bound.
    #[must_use]
    pub const fn response_bytes(self) -> usize {
        self.response.max_response_body_bytes()
    }

    pub(crate) const fn response(self) -> HttpLimits {
        self.response
    }
}

impl Default for McpDiscoveryLimits {
    fn default() -> Self {
        Self {
            tools: DEFAULT_MCP_DISCOVERY_TOOLS,
            schema_bytes: DEFAULT_MCP_SCHEMA_BYTES,
            response: HttpLimits::default(),
        }
    }
}

/// MCP discovery bound outside the accepted limits contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpDiscoveryLimitError {
    /// Tool count is outside 1 through 256.
    #[error("MCP discovery tool limit is outside the allowed range")]
    Tools,
    /// Input schema bytes are outside 1 byte through 64 KiB.
    #[error("MCP discovery schema limit is outside the allowed range")]
    Schema,
    /// Aggregate response bytes are outside the HTTP response range.
    #[error("MCP discovery response limit is outside the allowed range")]
    Response,
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_MCP_DISCOVERY_TOOLS, MAX_MCP_RESULT_BYTES, MAX_MCP_SCHEMA_BYTES, MIN_MCP_RESULT_BYTES,
        McpDiscoveryLimitError, McpDiscoveryLimits, McpLimitError, McpLimits,
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

    #[test]
    fn validates_discovery_boundaries() {
        assert!(
            McpDiscoveryLimits::new(MAX_MCP_DISCOVERY_TOOLS, MAX_MCP_SCHEMA_BYTES, 1024 * 1024)
                .is_ok()
        );
        assert_eq!(
            McpDiscoveryLimits::new(0, MAX_MCP_SCHEMA_BYTES, 64 * 1024),
            Err(McpDiscoveryLimitError::Tools)
        );
        assert_eq!(
            McpDiscoveryLimits::new(MAX_MCP_DISCOVERY_TOOLS, 0, 64 * 1024),
            Err(McpDiscoveryLimitError::Schema)
        );
        assert_eq!(
            McpDiscoveryLimits::new(MAX_MCP_DISCOVERY_TOOLS, MAX_MCP_SCHEMA_BYTES, 1),
            Err(McpDiscoveryLimitError::Response)
        );
    }
}
