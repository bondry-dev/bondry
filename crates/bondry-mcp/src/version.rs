/// The latest formal MCP protocol revision implemented by this adapter.
pub const LATEST_PROTOCOL_VERSION: &str = "2026-07-28";

/// MCP protocol revisions accepted by this adapter.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[LATEST_PROTOCOL_VERSION, "2025-11-25"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtocolVersion {
    V2026_07_28,
    V2025_11_25,
}

impl ProtocolVersion {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            LATEST_PROTOCOL_VERSION => Some(Self::V2026_07_28),
            "2025-11-25" => Some(Self::V2025_11_25),
            _ => None,
        }
    }

    pub(crate) const fn negotiate_legacy(_requested: &str) -> Self {
        Self::V2025_11_25
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::V2026_07_28 => LATEST_PROTOCOL_VERSION,
            Self::V2025_11_25 => "2025-11-25",
        }
    }

    pub(crate) const fn is_modern(self) -> bool {
        matches!(self, Self::V2026_07_28)
    }
}

#[cfg(test)]
mod tests {
    use super::{LATEST_PROTOCOL_VERSION, ProtocolVersion};

    #[test]
    fn recognizes_both_protocol_eras() {
        assert_eq!(
            ProtocolVersion::parse(LATEST_PROTOCOL_VERSION).map(ProtocolVersion::as_str),
            Some(LATEST_PROTOCOL_VERSION)
        );
        assert_eq!(
            ProtocolVersion::negotiate_legacy("unsupported").as_str(),
            "2025-11-25"
        );
    }
}
