#![doc = "Sans-I/O MCP tool composition and response classification for Bondry egress."]

mod limits;
mod mcp;

pub use limits::{
    DEFAULT_MCP_RESULT_BYTES, DEFAULT_MCP_SCHEMA_BYTES, MAX_MCP_RESULT_BYTES, MAX_MCP_SCHEMA_BYTES,
    MIN_MCP_RESULT_BYTES, McpLimitError, McpLimits,
};
pub use mcp::{
    McpAuthentication, McpConfigurationError, McpDeliveryKind, McpInputError, McpToolBinding,
    McpToolBindingError,
};
