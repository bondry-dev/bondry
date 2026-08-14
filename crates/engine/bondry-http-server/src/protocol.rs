use bondry_core::Principal;
use bondry_mcp_proto::McpAdapter;
use bondry_rest_proto::RestAdapter;
use bytes::Bytes;
use http::{Request, Response};

/// A protocol handler mounted on the shared local HTTP server.
pub enum MountedProtocol {
    /// The Bondry REST protocol.
    Rest(RestAdapter),
    /// The Model Context Protocol.
    Mcp(McpAdapter),
}

impl MountedProtocol {
    pub(crate) fn accepts_path(&self, path: &str) -> bool {
        match self {
            Self::Rest(protocol) => protocol.accepts_path(path),
            Self::Mcp(protocol) => protocol.accepts_path(path),
        }
    }

    pub(crate) async fn handle(
        &self,
        request: Request<Bytes>,
        principal: Principal,
    ) -> Response<Bytes> {
        match self {
            Self::Rest(protocol) => protocol.handle(request, principal).await,
            Self::Mcp(protocol) => protocol.handle(request, principal).await,
        }
    }
}
