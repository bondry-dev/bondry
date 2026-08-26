use std::{future::Future, pin::Pin};

use bondry_core::Principal;
#[cfg(feature = "mcp")]
use bondry_mcp_proto::McpAdapter;
#[cfg(feature = "rest")]
use bondry_rest_proto::RestAdapter;
use bytes::Bytes;
use http::{Request, Response};

/// The response future returned by an HTTP protocol handler.
pub type HttpProtocolFuture<'a> = Pin<Box<dyn Future<Output = Response<Bytes>> + Send + 'a>>;

/// A bounded HTTP protocol mounted on the shared server runtime.
pub trait HttpProtocol: Send + Sync {
    /// Returns whether this protocol owns the request path.
    fn accepts_path(&self, path: &str) -> bool;

    /// Handles one authenticated request.
    fn handle<'a>(
        &'a self,
        request: Request<Bytes>,
        principal: Principal,
    ) -> HttpProtocolFuture<'a>;
}

/// A protocol handler mounted on the shared local HTTP server.
#[cfg(any(feature = "mcp", feature = "rest"))]
pub enum MountedProtocol {
    /// The Bondry REST protocol.
    #[cfg(feature = "rest")]
    Rest(RestAdapter),
    /// The Model Context Protocol.
    #[cfg(feature = "mcp")]
    Mcp(McpAdapter),
}

#[cfg(any(feature = "mcp", feature = "rest"))]
impl HttpProtocol for MountedProtocol {
    fn accepts_path(&self, path: &str) -> bool {
        match self {
            #[cfg(feature = "rest")]
            Self::Rest(protocol) => protocol.accepts_path(path),
            #[cfg(feature = "mcp")]
            Self::Mcp(protocol) => protocol.accepts_path(path),
        }
    }

    fn handle<'a>(
        &'a self,
        request: Request<Bytes>,
        principal: Principal,
    ) -> HttpProtocolFuture<'a> {
        match self {
            #[cfg(feature = "rest")]
            Self::Rest(protocol) => Box::pin(protocol.handle(request, principal)),
            #[cfg(feature = "mcp")]
            Self::Mcp(protocol) => Box::pin(protocol.handle(request, principal)),
        }
    }
}

#[cfg(feature = "rest")]
impl HttpProtocol for RestAdapter {
    fn accepts_path(&self, path: &str) -> bool {
        RestAdapter::accepts_path(self, path)
    }

    fn handle<'a>(
        &'a self,
        request: Request<Bytes>,
        principal: Principal,
    ) -> HttpProtocolFuture<'a> {
        Box::pin(RestAdapter::handle(self, request, principal))
    }
}

#[cfg(feature = "mcp")]
impl HttpProtocol for McpAdapter {
    fn accepts_path(&self, path: &str) -> bool {
        McpAdapter::accepts_path(self, path)
    }

    fn handle<'a>(
        &'a self,
        request: Request<Bytes>,
        principal: Principal,
    ) -> HttpProtocolFuture<'a> {
        Box::pin(McpAdapter::handle(self, request, principal))
    }
}
