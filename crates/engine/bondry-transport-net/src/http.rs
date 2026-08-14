use std::net::SocketAddr;

#[cfg(feature = "tls")]
use std::sync::Arc;

use bondry_transport::{
    ConnectionEvidence, HttpLimits, HttpRequest, HttpRequestParts, HttpResponse, HttpTransport,
    IpAddress, NetworkEndpoint, NetworkScheme, PeerAddress, TransportError, TransportFuture,
    VerifiedConnection,
};
use bytes::{Bytes, BytesMut};
use http::{Request, header};
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    time::{Instant, timeout_at},
};

#[cfg(feature = "tls")]
use {
    bondry_transport::{EndpointPolicy, TlsConnectionEvidence},
    rustls::{ClientConfig, pki_types::CertificateDer},
    rustls_platform_verifier::ConfigVerifierExt as _,
    tokio_rustls::TlsConnector,
};

/// Default one-shot HTTP transport using the caller's Tokio executor.
pub struct NetHttpTransport {
    #[cfg(feature = "tls")]
    default_tls: Arc<ClientConfig>,
}

impl NetHttpTransport {
    /// Creates a transport with platform TLS verification when enabled.
    pub fn new() -> Result<Self, TransportConfigurationError> {
        #[cfg(feature = "tls")]
        let default_tls = Arc::new(
            ClientConfig::with_platform_verifier()
                .map_err(|_| TransportConfigurationError::TlsUnavailable)?,
        );
        Ok(Self {
            #[cfg(feature = "tls")]
            default_tls,
        })
    }

    async fn send_request(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let deadline = Instant::from_std(request.deadline().instant());
        timeout_at(deadline, self.send_before_deadline(request))
            .await
            .map_err(|_| TransportError::DeadlineExceeded)?
    }

    async fn send_before_deadline(
        &self,
        request: HttpRequest,
    ) -> Result<HttpResponse, TransportError> {
        let parts = request.into_parts();
        let stream = connect(&parts.endpoint).await?;
        match parts.endpoint.scheme() {
            NetworkScheme::Http => {
                let evidence = cleartext_evidence(&stream)?;
                let verified = parts.policy.verify_connection(&parts.endpoint, evidence)?;
                send_over_io(stream, parts, verified).await
            }
            NetworkScheme::Https => self.send_tls(stream, parts).await,
            NetworkScheme::WebSocket | NetworkScheme::WebSocketSecure => {
                Err(TransportError::UnsupportedEndpoint)
            }
        }
    }

    #[cfg(feature = "tls")]
    async fn send_tls(
        &self,
        stream: TcpStream,
        parts: HttpRequestParts,
    ) -> Result<HttpResponse, TransportError> {
        let server_name = rustls::pki_types::ServerName::try_from(parts.endpoint.host().to_owned())
            .map_err(|_| TransportError::TlsFailed)?;
        let config = self.tls_config(&parts.policy)?;
        let stream = TlsConnector::from(config)
            .connect(server_name, stream)
            .await
            .map_err(|_| TransportError::TlsFailed)?;
        let verified = parts.policy.verify_connection(
            &parts.endpoint,
            ConnectionEvidence::Tls(TlsConnectionEvidence::verified(parts.endpoint.host())),
        )?;
        send_over_io(stream, parts, verified).await
    }

    #[cfg(not(feature = "tls"))]
    async fn send_tls(
        &self,
        _stream: TcpStream,
        _parts: HttpRequestParts,
    ) -> Result<HttpResponse, TransportError> {
        Err(TransportError::TlsFailed)
    }

    #[cfg(feature = "tls")]
    fn tls_config(&self, policy: &EndpointPolicy) -> Result<Arc<ClientConfig>, TransportError> {
        if policy.additional_trust_anchors().is_empty() {
            return Ok(Arc::clone(&self.default_tls));
        }

        let roots = policy
            .additional_trust_anchors()
            .iter()
            .map(|anchor| CertificateDer::from(anchor.as_der().to_vec()));
        let builder = ClientConfig::builder();
        let verifier = rustls_platform_verifier::Verifier::new_with_extra_roots(
            roots,
            Arc::clone(builder.crypto_provider()),
        )
        .map_err(|_| TransportError::TlsFailed)?;
        Ok(Arc::new(
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth(),
        ))
    }
}

impl HttpTransport for NetHttpTransport {
    fn send(
        &self,
        request: HttpRequest,
    ) -> TransportFuture<'_, Result<HttpResponse, TransportError>> {
        Box::pin(self.send_request(request))
    }
}

/// Failure to initialize selected transport features safely.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TransportConfigurationError {
    /// A verified platform TLS configuration could not be created.
    #[error("platform TLS verification is unavailable")]
    TlsUnavailable,
}

async fn connect(endpoint: &NetworkEndpoint) -> Result<TcpStream, TransportError> {
    let addresses = tokio::net::lookup_host((endpoint.host(), endpoint.port()))
        .await
        .map_err(|_| TransportError::ConnectionFailed)?;
    for address in addresses {
        if let Ok(stream) = TcpStream::connect(address).await {
            return Ok(stream);
        }
    }
    Err(TransportError::ConnectionFailed)
}

fn cleartext_evidence(stream: &TcpStream) -> Result<ConnectionEvidence, TransportError> {
    let peer = stream
        .peer_addr()
        .map_err(|_| TransportError::ConnectionFailed)?;
    Ok(ConnectionEvidence::Cleartext(peer_address(peer)))
}

fn peer_address(address: SocketAddr) -> PeerAddress {
    match address {
        SocketAddr::V4(address) => {
            PeerAddress::new(IpAddress::V4(address.ip().octets()), address.port())
        }
        SocketAddr::V6(address) => {
            PeerAddress::new(IpAddress::V6(address.ip().octets()), address.port())
                .with_interface_scope(address.scope_id())
        }
    }
}

async fn send_over_io<IO>(
    io: IO,
    parts: HttpRequestParts,
    verified: VerifiedConnection,
) -> Result<HttpResponse, TransportError>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let HttpRequestParts {
        method,
        endpoint,
        mut headers,
        body,
        limits,
        ..
    } = parts;
    headers.remove(header::HOST);
    headers.remove(header::CONNECTION);
    headers.remove(header::CONTENT_LENGTH);
    headers.remove(header::TRANSFER_ENCODING);
    headers.insert(
        header::HOST,
        endpoint
            .uri()
            .authority()
            .ok_or(TransportError::UnsupportedEndpoint)?
            .as_str()
            .parse()
            .map_err(|_| TransportError::UnsupportedEndpoint)?,
    );
    headers.insert(header::CONNECTION, http::HeaderValue::from_static("close"));

    let mut request = Request::new(Full::new(body));
    *request.method_mut() = method;
    *request.uri_mut() = endpoint
        .path_and_query()
        .parse()
        .map_err(|_| TransportError::UnsupportedEndpoint)?;
    *request.headers_mut() = headers;

    let mut builder = http1::Builder::new();
    builder.max_headers(bondry_transport::MAX_HTTP_RESPONSE_HEADERS);
    builder.max_buf_size(bondry_transport::MAX_HTTP_RESPONSE_HEADER_BYTES);
    let (mut sender, connection) = builder
        .handshake(TokioIo::new(io))
        .await
        .map_err(|_| TransportError::ConnectionFailed)?;
    let exchange = async move {
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| TransportError::InvalidResponse)?;
        if response.status().is_redirection() {
            return Err(TransportError::Policy(
                bondry_transport::PolicyError::RedirectDenied,
            ));
        }
        let (response_parts, body) = response.into_parts();
        let body = read_body(body, limits).await?;
        HttpResponse::new(
            response_parts.status,
            response_parts.headers,
            body,
            verified,
            limits,
        )
    };
    tokio::pin!(exchange);
    tokio::pin!(connection);
    tokio::select! {
        response = &mut exchange => response,
        connection_result = &mut connection => {
            connection_result.map_err(|_| TransportError::InvalidResponse)?;
            exchange.await
        }
    }
}

async fn read_body(
    mut body: hyper::body::Incoming,
    limits: HttpLimits,
) -> Result<Bytes, TransportError> {
    let mut bytes = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| TransportError::InvalidResponse)?;
        if let Ok(data) = frame.into_data() {
            if bytes.len().saturating_add(data.len()) > limits.max_response_body_bytes() {
                return Err(TransportError::ResponseTooLarge);
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes.freeze())
}
