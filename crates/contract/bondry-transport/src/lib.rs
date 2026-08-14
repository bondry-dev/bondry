#![doc = "Runtime-neutral transport contracts and endpoint security policy for Bondry."]

mod endpoint;
mod http_transport;
mod local;
mod policy;
mod websocket;

use std::{future::Future, pin::Pin, time::Instant};

pub use endpoint::{EndpointError, MAX_NETWORK_ENDPOINT_BYTES, NetworkEndpoint, NetworkScheme};
pub use http_transport::{
    HttpLimits, HttpRequest, HttpRequestParts, HttpResponse, HttpTransport,
    MAX_HTTP_REQUEST_BODY_BYTES, MAX_HTTP_RESPONSE_BODY_BYTES, MAX_HTTP_RESPONSE_HEADER_BYTES,
    MAX_HTTP_RESPONSE_HEADERS, MIN_HTTP_RESPONSE_BODY_BYTES, TransportError,
};
pub use local::{
    LocalByteStream, LocalByteStreamTransport, LocalConnection, LocalEndpoint, LocalEndpointPolicy,
    LocalPeerEvidence, LocalTransportError, UnixSocketPolicy, VerifiedLocalConnection,
};
pub use policy::{
    AdditionalTrustAnchor, ConnectionEvidence, EndpointPolicy, IpAddress, IpAddressClass,
    PeerAddress, PolicyError, RedirectPolicy, TlsConnectionEvidence, VerifiedConnection,
    classify_ip,
};
pub use websocket::{
    WebSocketClose, WebSocketConnection, WebSocketEvent, WebSocketMessage, WebSocketRequest,
    WebSocketTransport,
};

/// A transport future tied to the transport or stream that created it.
pub type TransportFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// An absolute monotonic deadline supplied by the caller.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Deadline(Instant);

impl Deadline {
    /// Wraps an absolute monotonic instant without reading the clock.
    #[must_use]
    pub const fn at(instant: Instant) -> Self {
        Self(instant)
    }

    /// Returns the absolute monotonic instant.
    #[must_use]
    pub const fn instant(self) -> Instant {
        self.0
    }
}
