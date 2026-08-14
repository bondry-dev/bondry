use std::{
    collections::VecDeque,
    error::Error as _,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
};

#[cfg(feature = "tls")]
use std::sync::Arc;

use bondry_transport::{
    ConnectionEvidence, EndpointPolicy, HttpLimits, HttpRequest, HttpRequestParts, HttpResponse,
    HttpTransport, IpAddress, NetworkEndpoint, NetworkScheme, PeerAddress, TransportError,
    TransportFuture, VerifiedConnection,
};
use bytes::{Bytes, BytesMut};
use http::{Request, Uri, header};
use http_body_util::{BodyExt as _, Full};
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connected, Connection as HyperConnection, HttpConnector},
    },
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::{Instant, timeout_at},
};
use tower_service::Service;

#[cfg(feature = "tls")]
use {
    bondry_transport::TlsConnectionEvidence,
    rustls::{ClientConfig, pki_types::CertificateDer},
    rustls_platform_verifier::ConfigVerifierExt as _,
    tokio_rustls::{TlsConnector, client::TlsStream},
};

/// Maximum retained origin-policy connection pool partitions.
pub const MAX_HTTP_POOL_PARTITIONS: usize = 256;
const MAX_IDLE_CONNECTIONS_PER_PARTITION: usize = 2;

type PooledClient = Client<PolicyConnector, Full<Bytes>>;

/// Default pooled HTTP transport using the caller's Tokio executor.
pub struct NetHttpTransport {
    clients: Mutex<ClientCache>,
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
            clients: Mutex::new(ClientCache::default()),
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
        let client = self.client_for(&parts.endpoint, &parts.policy)?;
        send_with_client(client, parts).await
    }

    fn client_for(
        &self,
        endpoint: &NetworkEndpoint,
        policy: &EndpointPolicy,
    ) -> Result<PooledClient, TransportError> {
        let key = PoolKey::new(endpoint, policy);
        if let Some(client) = self
            .clients
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?
            .get(&key)
        {
            return Ok(client);
        }

        let client = self.build_client(endpoint.clone(), policy.clone())?;
        let mut clients = self
            .clients
            .lock()
            .map_err(|_| TransportError::ConnectionFailed)?;
        Ok(clients.insert(key, client))
    }

    fn build_client(
        &self,
        endpoint: NetworkEndpoint,
        policy: EndpointPolicy,
    ) -> Result<PooledClient, TransportError> {
        #[cfg(feature = "tls")]
        let tls_config = match endpoint.scheme() {
            NetworkScheme::Https => Some(self.tls_config(&policy)?),
            NetworkScheme::Http => None,
            NetworkScheme::WebSocket | NetworkScheme::WebSocketSecure => {
                return Err(TransportError::UnsupportedEndpoint);
            }
        };
        #[cfg(not(feature = "tls"))]
        if endpoint.scheme() == NetworkScheme::Https {
            return Err(TransportError::TlsFailed);
        }

        let connector = PolicyConnector::new(
            endpoint,
            policy,
            #[cfg(feature = "tls")]
            tls_config,
        );
        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_timer(TokioTimer::new())
            .pool_max_idle_per_host(MAX_IDLE_CONNECTIONS_PER_PARTITION)
            .http1_max_headers(bondry_transport::MAX_HTTP_HEADERS)
            .http1_max_buf_size(bondry_transport::MAX_HTTP_HEADER_BYTES);
        Ok(builder.build(connector))
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

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PoolKey {
    scheme: NetworkScheme,
    host: String,
    port: u16,
    policy: EndpointPolicy,
}

impl PoolKey {
    fn new(endpoint: &NetworkEndpoint, policy: &EndpointPolicy) -> Self {
        Self {
            scheme: endpoint.scheme(),
            host: endpoint.host().to_ascii_lowercase(),
            port: endpoint.port(),
            policy: policy.clone(),
        }
    }
}

#[derive(Default)]
struct ClientCache {
    entries: VecDeque<(PoolKey, PooledClient)>,
}

impl ClientCache {
    fn get(&mut self, key: &PoolKey) -> Option<PooledClient> {
        let index = self
            .entries
            .iter()
            .position(|(candidate, _)| candidate == key)?;
        let entry = self.entries.remove(index)?;
        let client = entry.1.clone();
        self.entries.push_back(entry);
        Some(client)
    }

    fn insert(&mut self, key: PoolKey, client: PooledClient) -> PooledClient {
        if let Some(existing) = self.get(&key) {
            return existing;
        }
        if self.entries.len() == MAX_HTTP_POOL_PARTITIONS {
            self.entries.pop_front();
        }
        self.entries.push_back((key, client.clone()));
        client
    }
}

#[derive(Clone)]
struct PolicyConnector {
    endpoint: NetworkEndpoint,
    policy: EndpointPolicy,
    http: HttpConnector,
    #[cfg(feature = "tls")]
    tls_config: Option<Arc<ClientConfig>>,
}

impl PolicyConnector {
    fn new(
        endpoint: NetworkEndpoint,
        policy: EndpointPolicy,
        #[cfg(feature = "tls")] tls_config: Option<Arc<ClientConfig>>,
    ) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);
        Self {
            endpoint,
            policy,
            http,
            #[cfg(feature = "tls")]
            tls_config,
        }
    }

    async fn connect(self, uri: Uri) -> Result<TokioIo<PolicyConnection>, TransportError> {
        if !same_origin(&uri, &self.endpoint) {
            return Err(TransportError::UnsupportedEndpoint);
        }
        let mut http = self.http.clone();
        let stream = http
            .call(uri)
            .await
            .map_err(|_| TransportError::ConnectionFailed)?
            .into_inner();
        match self.endpoint.scheme() {
            NetworkScheme::Http => {
                let evidence = cleartext_evidence(&stream)?;
                let verified = self.policy.verify_connection(&self.endpoint, evidence)?;
                Ok(TokioIo::new(PolicyConnection {
                    io: PolicyIo::Cleartext(stream),
                    verified,
                }))
            }
            NetworkScheme::Https => self.connect_tls(stream).await,
            NetworkScheme::WebSocket | NetworkScheme::WebSocketSecure => {
                Err(TransportError::UnsupportedEndpoint)
            }
        }
    }

    #[cfg(feature = "tls")]
    async fn connect_tls(
        self,
        stream: TcpStream,
    ) -> Result<TokioIo<PolicyConnection>, TransportError> {
        let server_name = rustls::pki_types::ServerName::try_from(self.endpoint.host().to_owned())
            .map_err(|_| TransportError::TlsFailed)?;
        let config = self.tls_config.ok_or(TransportError::TlsFailed)?;
        let stream = TlsConnector::from(config)
            .connect(server_name, stream)
            .await
            .map_err(|_| TransportError::TlsFailed)?;
        let verified = self.policy.verify_connection(
            &self.endpoint,
            ConnectionEvidence::Tls(TlsConnectionEvidence::verified(self.endpoint.host())),
        )?;
        Ok(TokioIo::new(PolicyConnection {
            io: PolicyIo::Tls(Box::new(stream)),
            verified,
        }))
    }

    #[cfg(not(feature = "tls"))]
    async fn connect_tls(
        self,
        _stream: TcpStream,
    ) -> Result<TokioIo<PolicyConnection>, TransportError> {
        Err(TransportError::TlsFailed)
    }
}

impl Service<Uri> for PolicyConnector {
    type Response = TokioIo<PolicyConnection>;
    type Error = TransportError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http
            .poll_ready(context)
            .map_err(|_| TransportError::ConnectionFailed)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        Box::pin(self.clone().connect(uri))
    }
}

struct PolicyConnection {
    io: PolicyIo,
    verified: VerifiedConnection,
}

enum PolicyIo {
    Cleartext(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for PolicyConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.io {
            PolicyIo::Cleartext(stream) => Pin::new(stream).poll_read(context, buffer),
            #[cfg(feature = "tls")]
            PolicyIo::Tls(stream) => Pin::new(stream.as_mut()).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for PolicyConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut self.io {
            PolicyIo::Cleartext(stream) => Pin::new(stream).poll_write(context, buffer),
            #[cfg(feature = "tls")]
            PolicyIo::Tls(stream) => Pin::new(stream.as_mut()).poll_write(context, buffer),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.io {
            PolicyIo::Cleartext(stream) => Pin::new(stream).poll_flush(context),
            #[cfg(feature = "tls")]
            PolicyIo::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(context),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.io {
            PolicyIo::Cleartext(stream) => Pin::new(stream).poll_shutdown(context),
            #[cfg(feature = "tls")]
            PolicyIo::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(context),
        }
    }
}

impl HyperConnection for PolicyConnection {
    fn connected(&self) -> Connected {
        Connected::new().extra(self.verified.clone())
    }
}

fn same_origin(uri: &Uri, endpoint: &NetworkEndpoint) -> bool {
    uri.scheme_str() == Some(endpoint.scheme().as_str())
        && uri
            .host()
            .is_some_and(|host| host.eq_ignore_ascii_case(endpoint.host()))
        && uri.port_u16().unwrap_or(endpoint.scheme().default_port()) == endpoint.port()
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

async fn send_with_client(
    client: PooledClient,
    parts: HttpRequestParts,
) -> Result<HttpResponse, TransportError> {
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

    let mut request = Request::new(Full::new(body));
    *request.method_mut() = method;
    *request.uri_mut() = endpoint.uri().clone();
    *request.headers_mut() = headers;

    let response = client.request(request).await.map_err(|error| {
        error_source(&error).unwrap_or_else(|| {
            if error.is_connect() {
                TransportError::ConnectionFailed
            } else {
                TransportError::InvalidResponse
            }
        })
    })?;
    let verified = response
        .extensions()
        .get::<VerifiedConnection>()
        .cloned()
        .ok_or(TransportError::Policy(
            bondry_transport::PolicyError::MissingEvidence,
        ))?;
    if response.headers().contains_key(header::TRANSFER_ENCODING)
        && response.headers().contains_key(header::CONTENT_LENGTH)
    {
        return Err(TransportError::InvalidResponse);
    }
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
}

fn error_source(error: &hyper_util::client::legacy::Error) -> Option<TransportError> {
    let mut source = error.source();
    while let Some(current) = source {
        if let Some(transport) = current.downcast_ref::<TransportError>() {
            return Some(*transport);
        }
        source = current.source();
    }
    None
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

#[cfg(test)]
mod tests {
    use super::{MAX_HTTP_POOL_PARTITIONS, NetHttpTransport, PoolKey};
    use bondry_transport::{EndpointPolicy, NetworkEndpoint};

    #[tokio::test(flavor = "current_thread")]
    async fn pool_partition_cache_evicts_least_recently_used_origin() {
        let transport = NetHttpTransport::new()
            .unwrap_or_else(|error| unreachable!("platform transport available: {error}"));
        for index in 0..=MAX_HTTP_POOL_PARTITIONS {
            let endpoint = NetworkEndpoint::new(
                format!("http://host-{index}.example/")
                    .parse()
                    .unwrap_or_else(|error| unreachable!("valid fixture endpoint: {error}")),
            )
            .unwrap_or_else(|error| unreachable!("valid fixture endpoint: {error}"));
            transport
                .client_for(&endpoint, &EndpointPolicy::default())
                .unwrap_or_else(|error| unreachable!("valid fixture policy: {error}"));
        }

        let clients = transport
            .clients
            .lock()
            .unwrap_or_else(|_| unreachable!("test cache lock is not poisoned"));
        assert_eq!(clients.entries.len(), MAX_HTTP_POOL_PARTITIONS);
        assert_eq!(
            clients.entries.front().map(|entry| &entry.0),
            Some(&PoolKey {
                scheme: bondry_transport::NetworkScheme::Http,
                host: "host-1.example".to_owned(),
                port: 80,
                policy: EndpointPolicy::default(),
            })
        );
    }
}
