#![doc = "Sans-I/O MCP tool composition and response classification for Bondry egress."]

mod discovery;
mod limits;
mod mcp;

pub use discovery::{
    McpDiscoveredTool, McpDiscoveryError, McpDiscoveryOperation, McpDiscoveryResult,
    McpDiscoveryTransition,
};
pub use limits::{
    DEFAULT_MCP_DISCOVERY_TOOLS, DEFAULT_MCP_RESULT_BYTES, DEFAULT_MCP_SCHEMA_BYTES,
    MAX_MCP_DISCOVERY_TOOLS, MAX_MCP_RESULT_BYTES, MAX_MCP_SCHEMA_BYTES, MIN_MCP_RESULT_BYTES,
    McpDiscoveryLimitError, McpDiscoveryLimits, McpLimitError, McpLimits,
};
pub use mcp::{
    McpAuthentication, McpConfigurationError, McpDeliveryKind, McpInputError, McpToolBinding,
    McpToolBindingError,
};
