/// The latest formal MCP protocol revision implemented by this adapter.
pub const LATEST_PROTOCOL_VERSION: &str = "2026-07-28";

/// MCP protocol revisions accepted by this adapter.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[LATEST_PROTOCOL_VERSION, "2025-11-25"];

/// One MCP protocol revision implemented by Bondry's client and server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpProtocolVersion {
    /// Revision dated 2026-07-28.
    V2026_07_28,
    /// Revision dated 2025-11-25.
    V2025_11_25,
}

impl McpProtocolVersion {
    /// Parses a protocol revision supported by this build.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            LATEST_PROTOCOL_VERSION => Some(Self::V2026_07_28),
            "2025-11-25" => Some(Self::V2025_11_25),
            _ => None,
        }
    }

    pub(crate) const fn negotiate_legacy(_requested: &str) -> Self {
        Self::V2025_11_25
    }

    /// Returns the wire representation of this protocol revision.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2026_07_28 => LATEST_PROTOCOL_VERSION,
            Self::V2025_11_25 => "2025-11-25",
        }
    }

    /// Returns whether this revision uses routed request headers and metadata.
    #[must_use]
    pub const fn is_modern(self) -> bool {
        matches!(self, Self::V2026_07_28)
    }
}

#[cfg(test)]
mod tests {
    use super::{LATEST_PROTOCOL_VERSION, McpProtocolVersion};

    #[test]
    fn recognizes_both_protocol_eras() {
        assert_eq!(
            McpProtocolVersion::parse(LATEST_PROTOCOL_VERSION).map(McpProtocolVersion::as_str),
            Some(LATEST_PROTOCOL_VERSION)
        );
        assert_eq!(
            McpProtocolVersion::negotiate_legacy("unsupported").as_str(),
            "2025-11-25"
        );
    }
}
