use std::{future::Future, net::SocketAddr, pin::Pin};

use bondry_core::Principal;
use bytes::Bytes;
use http::{Request, Response};

/// A future returned by an HTTP protocol adapter.
pub type AdapterFuture<'a> = Pin<Box<dyn Future<Output = Response<Bytes>> + Send + 'a>>;

/// An authenticated HTTP request with credential headers removed.
pub struct AdapterRequest {
    request: Request<Bytes>,
    principal: Principal,
    peer: SocketAddr,
}

impl AdapterRequest {
    pub(crate) const fn new(
        request: Request<Bytes>,
        principal: Principal,
        peer: SocketAddr,
    ) -> Self {
        Self {
            request,
            principal,
            peer,
        }
    }

    /// Returns the HTTP request.
    #[must_use]
    pub const fn request(&self) -> &Request<Bytes> {
        &self.request
    }

    /// Returns the authenticated principal.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Returns the connected peer address.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Splits the request into its trusted metadata and HTTP value.
    #[must_use]
    pub fn into_parts(self) -> (Request<Bytes>, Principal, SocketAddr) {
        (self.request, self.principal, self.peer)
    }
}

/// Maps one HTTP route family into a protocol-specific response.
pub trait HttpAdapter: Send + Sync {
    /// Returns whether this adapter owns the request path.
    fn accepts_path(&self, path: &str) -> bool;

    /// Handles one authenticated request.
    fn handle(&self, request: AdapterRequest) -> AdapterFuture<'_>;
}
