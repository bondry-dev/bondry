use bytes::Bytes;
use http::HeaderMap;

use crate::{
    Deadline, EndpointPolicy, NetworkEndpoint, NetworkScheme, TransportError, TransportFuture,
    VerifiedConnection, http_transport::validate_headers,
};

const MAX_CONTROL_PAYLOAD_BYTES: usize = 125;
const MAX_CLOSE_REASON_BYTES: usize = MAX_CONTROL_PAYLOAD_BYTES - size_of::<u16>();

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
        validate_headers(&headers, TransportError::RequestTooLarge)?;
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

/// WebSocket application-message type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebSocketMessageKind {
    /// UTF-8 text.
    Text,
    /// Arbitrary binary data.
    Binary,
}

/// An application message sent over WebSocket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebSocketMessage {
    kind: WebSocketMessageKind,
    payload: Bytes,
}

impl WebSocketMessage {
    /// Creates a text message after validating UTF-8.
    pub fn text(payload: Bytes) -> Result<Self, TransportError> {
        std::str::from_utf8(&payload).map_err(|_| TransportError::InvalidMessage)?;
        Ok(Self {
            kind: WebSocketMessageKind::Text,
            payload,
        })
    }

    /// Creates a binary message.
    #[must_use]
    pub const fn binary(payload: Bytes) -> Self {
        Self {
            kind: WebSocketMessageKind::Binary,
            payload,
        }
    }

    /// Returns the message type.
    #[must_use]
    pub const fn kind(&self) -> WebSocketMessageKind {
        self.kind
    }

    /// Returns the caller-bounded payload.
    #[must_use]
    pub const fn payload(&self) -> &Bytes {
        &self.payload
    }
}

/// A protocol-bounded WebSocket control-frame payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebSocketControlPayload(Bytes);

impl WebSocketControlPayload {
    /// Creates a control payload within the RFC 6455 limit.
    pub fn new(payload: Bytes) -> Result<Self, TransportError> {
        if payload.len() > MAX_CONTROL_PAYLOAD_BYTES {
            return Err(TransportError::InvalidMessage);
        }
        Ok(Self(payload))
    }

    /// Returns the validated payload.
    #[must_use]
    pub const fn as_bytes(&self) -> &Bytes {
        &self.0
    }
}

/// A WebSocket close frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebSocketClose {
    code: u16,
    reason: Bytes,
}

impl WebSocketClose {
    /// Creates a close frame with a sendable status and bounded UTF-8 reason.
    pub fn new(code: u16, reason: Bytes) -> Result<Self, TransportError> {
        if !valid_close_code(code)
            || reason.len() > MAX_CLOSE_REASON_BYTES
            || std::str::from_utf8(&reason).is_err()
        {
            return Err(TransportError::InvalidMessage);
        }
        Ok(Self { code, reason })
    }

    /// Returns the close status.
    #[must_use]
    pub const fn code(&self) -> u16 {
        self.code
    }

    /// Returns the bounded UTF-8 reason.
    #[must_use]
    pub const fn reason(&self) -> &Bytes {
        &self.reason
    }
}

/// One bounded event received from the peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WebSocketEvent {
    /// Application text or binary message.
    Message(WebSocketMessage),
    /// Ping control payload.
    Ping(WebSocketControlPayload),
    /// Pong control payload.
    Pong(WebSocketControlPayload),
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
        payload: WebSocketControlPayload,
        deadline: Deadline,
    ) -> TransportFuture<'_, Result<(), TransportError>>;

    /// Performs an explicit close handshake.
    fn close(
        &self,
        close: Option<WebSocketClose>,
        deadline: Deadline,
    ) -> TransportFuture<'_, Result<(), TransportError>>;
}

fn valid_close_code(code: u16) -> bool {
    (1000..=4999).contains(&code) && !matches!(code, 1004..=1006 | 1015)
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

    use bytes::Bytes;

    use super::{WebSocketClose, WebSocketControlPayload, WebSocketMessage, WebSocketRequest};
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

    #[test]
    fn rejects_invalid_message_and_control_payloads() {
        assert!(WebSocketMessage::text(Bytes::from_static(b"valid")).is_ok());
        assert!(WebSocketMessage::text(Bytes::from_static(&[0xff])).is_err());
        assert!(WebSocketControlPayload::new(Bytes::from(vec![0; 125])).is_ok());
        assert!(WebSocketControlPayload::new(Bytes::from(vec![0; 126])).is_err());
        assert!(WebSocketClose::new(1000, Bytes::from(vec![b'a'; 123])).is_ok());
        assert!(WebSocketClose::new(1005, Bytes::new()).is_err());
        assert!(WebSocketClose::new(1000, Bytes::from(vec![b'a'; 124])).is_err());
        assert!(WebSocketClose::new(1000, Bytes::from_static(&[0xff])).is_err());
    }
}
