use bytes::Bytes;
use http::HeaderMap;

use crate::{
    Deadline, EndpointPolicy, NetworkEndpoint, NetworkScheme, TransportError, TransportFuture,
    VerifiedConnection, http_transport::validate_headers,
};

/// A bounded WebSocket handshake request.
pub struct WebSocketRequest {
    endpoint: NetworkEndpoint,
    headers: HeaderMap,
    deadline: Deadline,
    policy: EndpointPolicy,
    max_message_bytes: usize,
}

impl WebSocketRequest {
    /// Validates WebSocket scheme, headers, and the caller-supplied message bound.
    pub fn new(
        endpoint: NetworkEndpoint,
        headers: HeaderMap,
        deadline: Deadline,
        policy: EndpointPolicy,
        max_message_bytes: usize,
    ) -> Result<Self, TransportError> {
        if !matches!(
            endpoint.scheme(),
            NetworkScheme::WebSocket | NetworkScheme::WebSocketSecure
        ) {
            return Err(TransportError::UnsupportedEndpoint);
        }
        if max_message_bytes == 0 {
            return Err(TransportError::InvalidLimits);
        }
        validate_headers(&headers)?;
        Ok(Self {
            endpoint,
            headers,
            deadline,
            policy,
            max_message_bytes,
        })
    }

    /// Returns the endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &NetworkEndpoint {
        &self.endpoint
    }

    /// Returns bounded handshake headers.
    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the absolute handshake deadline.
    #[must_use]
    pub const fn deadline(&self) -> Deadline {
        self.deadline
    }

    /// Returns endpoint policy for connection-time enforcement.
    #[must_use]
    pub const fn policy(&self) -> &EndpointPolicy {
        &self.policy
    }

    /// Returns the caller-supplied message cap.
    #[must_use]
    pub const fn max_message_bytes(&self) -> usize {
        self.max_message_bytes
    }
}

/// An application message sent over WebSocket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WebSocketMessage {
    /// UTF-8 text bytes.
    Text(Bytes),
    /// Arbitrary binary bytes.
    Binary(Bytes),
}

/// A WebSocket close frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebSocketClose {
    /// RFC 6455 close status.
    pub code: u16,
    /// Bounded UTF-8 reason bytes.
    pub reason: Bytes,
}

/// One bounded event received from the peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WebSocketEvent {
    /// Application text or binary message.
    Message(WebSocketMessage),
    /// Ping control payload.
    Ping(Bytes),
    /// Pong control payload.
    Pong(Bytes),
    /// Peer close or end-of-stream.
    Close(Option<WebSocketClose>),
}

/// An established WebSocket with explicit control-frame lifecycle.
pub trait WebSocketConnection: Send + Sync {
    /// Returns the connection evidence accepted by endpoint policy.
    fn verified_connection(&self) -> &VerifiedConnection;

    /// Sends one bounded application message.
    fn send(
        &self,
        message: WebSocketMessage,
        deadline: Deadline,
    ) -> TransportFuture<'_, Result<(), TransportError>>;

    /// Receives one bounded application or control event.
    fn receive(
        &self,
        deadline: Deadline,
    ) -> TransportFuture<'_, Result<WebSocketEvent, TransportError>>;

    /// Sends a bounded ping control payload.
    fn ping(
        &self,
        payload: Bytes,
        deadline: Deadline,
    ) -> TransportFuture<'_, Result<(), TransportError>>;

    /// Performs an explicit close handshake.
    fn close(
        &self,
        close: Option<WebSocketClose>,
        deadline: Deadline,
    ) -> TransportFuture<'_, Result<(), TransportError>>;
}

/// WebSocket transport independent from HTTP and local byte streams.
pub trait WebSocketTransport: Send + Sync {
    /// Establishes and verifies one WebSocket connection.
    fn connect(
        &self,
        request: WebSocketRequest,
    ) -> TransportFuture<'_, Result<Box<dyn WebSocketConnection>, TransportError>>;
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use http::HeaderMap;

    use super::WebSocketRequest;
    use crate::{Deadline, EndpointPolicy, NetworkEndpoint, TransportError};

    fn endpoint(value: &str) -> NetworkEndpoint {
        NetworkEndpoint::new(
            value
                .parse()
                .unwrap_or_else(|error| unreachable!("valid URI: {error}")),
        )
        .unwrap_or_else(|error| unreachable!("valid endpoint: {error}"))
    }

    #[test]
    fn reserves_only_bounded_websocket_contract() {
        assert!(
            WebSocketRequest::new(
                endpoint("wss://example.com/socket"),
                HeaderMap::new(),
                Deadline::at(Instant::now()),
                EndpointPolicy::default(),
                16 * 1024,
            )
            .is_ok()
        );
        assert!(matches!(
            WebSocketRequest::new(
                endpoint("https://example.com/socket"),
                HeaderMap::new(),
                Deadline::at(Instant::now()),
                EndpointPolicy::default(),
                16 * 1024,
            ),
            Err(TransportError::UnsupportedEndpoint)
        ));
    }
}
