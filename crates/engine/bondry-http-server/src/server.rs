use std::{
    convert::Infallible,
    io,
    net::{IpAddr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

#[cfg(feature = "unix-socket")]
use std::path::Path;

use bondry_core::PrincipalId;
use bytes::{Bytes, BytesMut};
use http::{HeaderMap, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde_json::json;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    task::JoinSet,
};

#[cfg(feature = "tls")]
use crate::TlsServerConfiguration;

#[cfg(any(feature = "mcp", feature = "rest"))]
use crate::MountedProtocol;
use crate::{
    AuthenticationError, AuthenticationRequest, HttpProtocol, RawBodyHandler, RawBodyRegistration,
    RawBodyRegistrationError, RawBodyRoute, ServerConfiguration, ServerConfigurationError,
    rate_limit::{RateLimitDecision, SlidingWindow},
    raw_body::{
        AcceptedRawBodyRequest, MAX_SELECTED_HEADERS, RawBodyHeader, RawBodyMatch, RawBodyRegistry,
        RawBodyRequest, RawBodyResponse,
    },
};
#[cfg(feature = "unix-socket")]
use crate::{
    UnixServerConfigurationError,
    unix_socket::{BoundUnixListener, UnixSocketConfiguration},
};

type ServerThread = thread::JoinHandle<Result<(), ServerRuntimeError>>;
const MAX_BODY_PREALLOCATION: usize = 64 * 1_024;

/// A running local HTTP server with deterministic shutdown ownership.
pub struct LocalHttpServer {
    local_address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<ServerThread>,
    protocols: Arc<[Arc<dyn HttpProtocol>]>,
    raw_body_registry: Arc<RawBodyRegistry>,
}

/// A running HTTP/1.1 server bound to a verified Unix-domain socket.
#[cfg(feature = "unix-socket")]
pub struct LocalUnixHttpServer {
    socket_path: Box<Path>,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<ServerThread>,
}

impl LocalHttpServer {
    /// Starts a server on its dedicated asynchronous runtime.
    #[cfg(any(feature = "mcp", feature = "rest"))]
    pub fn start(
        configuration: ServerConfiguration,
        protocols: Vec<MountedProtocol>,
    ) -> Result<Self, ServerStartError> {
        let protocols = protocols
            .into_iter()
            .map(|protocol| Arc::new(protocol) as Arc<dyn HttpProtocol>)
            .collect();
        Self::start_with_protocols(configuration, protocols)
    }

    /// Starts a server with protocol-neutral HTTP handlers.
    pub fn start_with_protocols(
        configuration: ServerConfiguration,
        protocols: Vec<Arc<dyn HttpProtocol>>,
    ) -> Result<Self, ServerStartError> {
        configuration.validate()?;
        Self::start_network(configuration, protocols, NetworkTransport::Cleartext)
    }

    /// Starts a TLS 1.3 server with protocol-neutral HTTP handlers.
    #[cfg(feature = "tls")]
    pub fn start_tls_with_protocols(
        configuration: ServerConfiguration,
        tls: TlsServerConfiguration,
        protocols: Vec<Arc<dyn HttpProtocol>>,
    ) -> Result<Self, ServerStartError> {
        configuration.validate_tls()?;
        Self::start_network(configuration, protocols, NetworkTransport::Tls(tls))
    }

    fn start_network(
        configuration: ServerConfiguration,
        protocols: Vec<Arc<dyn HttpProtocol>>,
        transport: NetworkTransport,
    ) -> Result<Self, ServerStartError> {
        let protocols: Arc<[Arc<dyn HttpProtocol>]> = protocols.into();
        let raw_body_registry = Arc::new(RawBodyRegistry::new(configuration.raw_body_limits));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(ServerStartError::Runtime)?;
        let (shutdown, shutdown_receiver) = oneshot::channel();
        let (startup_sender, startup_receiver) = mpsc::sync_channel(1);
        let server_protocols = Arc::clone(&protocols);
        let server_raw_body_registry = Arc::clone(&raw_body_registry);
        let thread = thread::Builder::new()
            .name("bondry-http".to_owned())
            .spawn(move || {
                runtime.block_on(run_server(
                    configuration,
                    transport,
                    server_protocols,
                    server_raw_body_registry,
                    shutdown_receiver,
                    startup_sender,
                ))
            })
            .map_err(ServerStartError::Thread)?;
        match startup_receiver.recv() {
            Ok(Ok(local_address)) => Ok(Self {
                local_address,
                shutdown: Some(shutdown),
                thread: Some(thread),
                protocols,
                raw_body_registry,
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(ServerStartError::Bind(error))
            }
            Err(_) => {
                let _ = thread.join();
                Err(ServerStartError::Startup)
            }
        }
    }

    /// Returns the bound address, including an automatically selected port.
    #[must_use]
    pub const fn local_address(&self) -> SocketAddr {
        self.local_address
    }

    /// Registers one exact raw-body handler generation while the server is running.
    pub fn register_raw_body_handler(
        &self,
        route: RawBodyRoute,
        handler: Arc<dyn RawBodyHandler>,
    ) -> Result<RawBodyRegistration, RawBodyRegistrationError> {
        if self
            .protocols
            .iter()
            .any(|protocol| protocol.accepts_path(route.path()))
        {
            return Err(RawBodyRegistrationError::ProtocolConflict);
        }
        self.raw_body_registry.register(route, handler)
    }

    /// Stops accepting requests and waits for bounded graceful shutdown.
    pub fn stop(&mut self) -> Result<(), ServerStopError> {
        self.raw_body_registry.begin_shutdown();
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        server_thread_result(thread)
    }
}

impl Drop for LocalHttpServer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(feature = "unix-socket")]
impl LocalUnixHttpServer {
    /// Starts a Unix-domain server with protocol-neutral HTTP handlers.
    pub fn start_with_protocols(
        configuration: ServerConfiguration,
        socket: UnixSocketConfiguration,
        protocols: Vec<Arc<dyn HttpProtocol>>,
    ) -> Result<Self, UnixServerStartError> {
        configuration.validate_unix()?;
        let socket_path = socket.path().into();
        let protocols: Arc<[Arc<dyn HttpProtocol>]> = protocols.into();
        let raw_body_registry = Arc::new(RawBodyRegistry::new(configuration.raw_body_limits));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(ServerStartError::Runtime)?;
        let (shutdown, shutdown_receiver) = oneshot::channel();
        let (startup_sender, startup_receiver) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("bondry-unix-http".to_owned())
            .spawn(move || {
                runtime.block_on(run_unix_server(
                    configuration,
                    socket,
                    protocols,
                    raw_body_registry,
                    shutdown_receiver,
                    startup_sender,
                ))
            })
            .map_err(ServerStartError::Thread)?;
        match startup_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                socket_path,
                shutdown: Some(shutdown),
                thread: Some(thread),
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(ServerStartError::Bind(error).into())
            }
            Err(_) => {
                let _ = thread.join();
                Err(ServerStartError::Startup.into())
            }
        }
    }

    /// Returns the bound socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Stops accepting requests, drains connections, and removes the owned socket path.
    pub fn stop(&mut self) -> Result<(), ServerStopError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        server_thread_result(thread)
    }
}

#[cfg(feature = "unix-socket")]
impl Drop for LocalUnixHttpServer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

async fn run_server(
    configuration: ServerConfiguration,
    transport: NetworkTransport,
    protocols: Arc<[Arc<dyn HttpProtocol>]>,
    raw_body_registry: Arc<RawBodyRegistry>,
    mut shutdown: oneshot::Receiver<()>,
    startup: mpsc::SyncSender<io::Result<SocketAddr>>,
) -> Result<(), ServerRuntimeError> {
    let listener = match TcpListener::bind((configuration.bind_address, configuration.port)).await {
        Ok(listener) => listener,
        Err(error) => {
            let _ = startup.send(Err(clone_io_error(&error)));
            return Err(ServerRuntimeError::Io(error));
        }
    };
    let local_address = listener.local_addr().map_err(ServerRuntimeError::Io)?;
    if startup.send(Ok(local_address)).is_err() {
        return Ok(());
    }

    let state = Arc::new(ServerState {
        configuration: configuration.clone(),
        protocols,
        raw_body_registry: Arc::clone(&raw_body_registry),
        request_limits: SlidingWindow::new(),
        authentication_failure_limits: SlidingWindow::new(),
    });
    let connection_slots = Arc::new(Semaphore::new(configuration.max_connections));
    let mut connections = JoinSet::new();
    let runtime_result = loop {
        tokio::select! {
            _ = &mut shutdown => break Ok(()),
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => break Err(error),
                };
                let Ok(slot) = Arc::clone(&connection_slots).try_acquire_owned() else {
                    continue;
                };
                let state = Arc::clone(&state);
                let transport = transport.clone();
                connections.spawn(async move {
                    let _slot = slot;
                    let _ = stream.set_nodelay(true);
                    serve_network_connection(stream, peer, state, transport).await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    };

    drain_connections(&configuration, &raw_body_registry, &mut connections).await?;
    runtime_result.map_err(ServerRuntimeError::Io)
}

#[derive(Clone)]
enum NetworkTransport {
    Cleartext,
    #[cfg(feature = "tls")]
    Tls(TlsServerConfiguration),
}

async fn serve_network_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    state: Arc<ServerState>,
    transport: NetworkTransport,
) {
    match transport {
        NetworkTransport::Cleartext => {
            serve_connection(stream, ConnectionPeer::Network(peer), state).await;
        }
        #[cfg(feature = "tls")]
        NetworkTransport::Tls(tls) => {
            let accepted =
                tokio::time::timeout(tls.handshake_timeout, tls.acceptor.accept(stream)).await;
            if let Ok(Ok(stream)) = accepted {
                serve_connection(stream, ConnectionPeer::Network(peer), state).await;
            }
        }
    }
}

#[cfg(feature = "unix-socket")]
async fn run_unix_server(
    configuration: ServerConfiguration,
    socket: UnixSocketConfiguration,
    protocols: Arc<[Arc<dyn HttpProtocol>]>,
    raw_body_registry: Arc<RawBodyRegistry>,
    mut shutdown: oneshot::Receiver<()>,
    startup: mpsc::SyncSender<io::Result<()>>,
) -> Result<(), ServerRuntimeError> {
    let mut listener = match BoundUnixListener::bind(&socket).await {
        Ok(listener) => listener,
        Err(error) => {
            let _ = startup.send(Err(clone_io_error(&error)));
            return Err(ServerRuntimeError::Io(error));
        }
    };
    if startup.send(Ok(())).is_err() {
        return Ok(());
    }

    let state = Arc::new(ServerState {
        configuration: configuration.clone(),
        protocols,
        raw_body_registry: Arc::clone(&raw_body_registry),
        request_limits: SlidingWindow::new(),
        authentication_failure_limits: SlidingWindow::new(),
    });
    let connection_slots = Arc::new(Semaphore::new(configuration.max_connections));
    let mut connections = JoinSet::new();
    let runtime_result = loop {
        tokio::select! {
            _ = &mut shutdown => break Ok(()),
            accepted = listener.accept() => {
                let stream = match accepted {
                    Ok(Some(stream)) => stream,
                    Ok(None) => continue,
                    Err(error) => break Err(error),
                };
                let Ok(slot) = Arc::clone(&connection_slots).try_acquire_owned() else {
                    continue;
                };
                let state = Arc::clone(&state);
                connections.spawn(async move {
                    let _slot = slot;
                    serve_connection(stream, ConnectionPeer::Unix, state).await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    };

    let drain_result =
        drain_connections(&configuration, &raw_body_registry, &mut connections).await;
    let cleanup_result = listener.cleanup().map_err(ServerRuntimeError::Io);
    drain_result?;
    cleanup_result?;
    runtime_result.map_err(ServerRuntimeError::Io)
}

async fn drain_connections(
    configuration: &ServerConfiguration,
    raw_body_registry: &RawBodyRegistry,
    connections: &mut JoinSet<()>,
) -> Result<(), ServerRuntimeError> {
    raw_body_registry.begin_shutdown();
    if tokio::time::timeout(configuration.shutdown_grace_period, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
    if !raw_body_registry.wait_for_shutdown().await {
        return Err(ServerRuntimeError::HandlerDrainTimedOut);
    }
    Ok(())
}

async fn serve_connection<Stream>(stream: Stream, peer: ConnectionPeer, state: Arc<ServerState>)
where
    Stream: AsyncRead + AsyncWrite + Unpin,
{
    let header_read_timeout = state.configuration.header_read_timeout;
    let request_timeout = state.configuration.request_timeout;
    let service = service_fn(move |request| {
        let state = Arc::clone(&state);
        async move {
            let response = match tokio::time::timeout(
                state.configuration.request_timeout,
                state.handle(request, peer),
            )
            .await
            {
                Ok(response) => response,
                Err(_) => error_response(StatusCode::GATEWAY_TIMEOUT, "request_timeout"),
            };
            Ok::<_, Infallible>(response.map(Full::new))
        }
    });
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(true)
        .max_headers(64)
        .max_buf_size(32 * 1_024)
        .timer(TokioTimer::default())
        .header_read_timeout(header_read_timeout);
    let connection_timeout = header_read_timeout
        .saturating_add(request_timeout)
        .saturating_add(Duration::from_secs(5));
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    let _ = tokio::time::timeout(connection_timeout, connection).await;
}

struct ServerState {
    configuration: ServerConfiguration,
    protocols: Arc<[Arc<dyn HttpProtocol>]>,
    raw_body_registry: Arc<RawBodyRegistry>,
    request_limits: SlidingWindow<PrincipalId>,
    authentication_failure_limits: SlidingWindow<IpAddr>,
}

#[derive(Clone, Copy)]
enum ConnectionPeer {
    Network(SocketAddr),
    #[cfg(feature = "unix-socket")]
    Unix,
}

impl ConnectionPeer {
    const fn network_address(self) -> Option<SocketAddr> {
        match self {
            Self::Network(address) => Some(address),
            #[cfg(feature = "unix-socket")]
            Self::Unix => None,
        }
    }
}

impl ServerState {
    async fn handle(
        &self,
        mut request: Request<Incoming>,
        peer: ConnectionPeer,
    ) -> Response<Bytes> {
        if let Some(address) = peer.network_address() {
            match self
                .raw_body_registry
                .match_request(request.method(), request.uri().path())
            {
                RawBodyMatch::Accepted(accepted) => {
                    return self.handle_raw_body(request, address, accepted).await;
                }
                RawBodyMatch::Closed => {
                    return retryable_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "raw_body_handler_draining",
                        1,
                    );
                }
                RawBodyMatch::NotRegistered => {}
            }
        }
        let Some(protocol) = self
            .protocols
            .iter()
            .find(|protocol| protocol.accepts_path(request.uri().path()))
        else {
            return error_response(StatusCode::NOT_FOUND, "not_found");
        };
        if !self.configuration.origins.permits(request.headers()) {
            return error_response(StatusCode::FORBIDDEN, "origin_rejected");
        }

        let now = Instant::now();
        let principal = match peer {
            ConnectionPeer::Network(address) => {
                match self.authenticate_network(&request, address, now) {
                    NetworkAuthentication::Authenticated(principal) => principal,
                    NetworkAuthentication::Rejected(response) => return response,
                }
            }
            #[cfg(feature = "unix-socket")]
            ConnectionPeer::Unix => {
                let Some(principal) = self.configuration.authentication.local_principal() else {
                    return error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "authentication_unavailable",
                    );
                };
                principal
            }
        };

        if let RateLimitDecision::Limited { retry_after } = self.request_limits.consume(
            principal.id().clone(),
            self.configuration.rate_limits.requests_per_minute(),
            now,
        ) {
            return rate_limited_response(retry_after);
        }
        self.configuration
            .authentication
            .redact_credentials(request.headers_mut());

        let (parts, body) = request.into_parts();
        let body = match read_body(body, self.configuration.max_body_bytes).await {
            Ok(body) => body,
            Err(BodyReadError::TooLarge) => {
                return error_response(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
            }
            Err(BodyReadError::Invalid) => {
                return error_response(StatusCode::BAD_REQUEST, "invalid_request_body");
            }
            Err(BodyReadError::Capacity) => {
                return error_response(StatusCode::SERVICE_UNAVAILABLE, "body_capacity");
            }
        };
        let request = Request::from_parts(parts, body);
        secure_response(protocol.handle(request, principal).await)
    }

    fn authenticate_network(
        &self,
        request: &Request<Incoming>,
        peer: SocketAddr,
        now: Instant,
    ) -> NetworkAuthentication {
        let peer_ip = peer.ip();
        let failure_limit = self
            .configuration
            .rate_limits
            .authentication_failures_per_minute();
        if let RateLimitDecision::Limited { retry_after } = self
            .authentication_failure_limits
            .check(&peer_ip, failure_limit, now)
        {
            return NetworkAuthentication::Rejected(rate_limited_response(retry_after));
        }
        let authentication_request =
            AuthenticationRequest::new(request.method(), request.uri(), request.headers(), peer);
        match self
            .configuration
            .authentication
            .authenticate(authentication_request)
        {
            Ok(principal) => NetworkAuthentication::Authenticated(principal),
            Err(AuthenticationError::Rejected) => {
                let _ = self
                    .authentication_failure_limits
                    .consume(peer_ip, failure_limit, now);
                NetworkAuthentication::Rejected(unauthorized_response(
                    self.configuration.authentication.challenge(),
                ))
            }
            Err(AuthenticationError::Unavailable) => {
                NetworkAuthentication::Rejected(error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authentication_unavailable",
                ))
            }
        }
    }

    async fn handle_raw_body(
        &self,
        request: Request<Incoming>,
        peer: SocketAddr,
        accepted: AcceptedRawBodyRequest,
    ) -> Response<Bytes> {
        if !self.configuration.origins.permits(request.headers()) {
            return error_response(StatusCode::FORBIDDEN, "origin_rejected");
        }
        if let RateLimitDecision::Limited { retry_after } =
            self.raw_body_registry
                .admit(&accepted, peer.ip(), Instant::now())
        {
            return rate_limited_response(retry_after);
        }
        let (parts, body) = request.into_parts();
        let selected_headers = match select_raw_body_headers(&accepted, &parts.headers) {
            Ok(headers) => headers,
            Err(()) => {
                return error_response(StatusCode::BAD_REQUEST, "invalid_selected_headers");
            }
        };
        let retained = match read_raw_body(
            body,
            accepted.route().limits().body_bytes(),
            accepted.route().limits().retained_bytes(),
            self.raw_body_registry.retained_bytes(),
        )
        .await
        {
            Ok(body) => body,
            Err(BodyReadError::TooLarge) => {
                return error_response(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
            }
            Err(BodyReadError::Invalid) => {
                return error_response(StatusCode::BAD_REQUEST, "invalid_request_body");
            }
            Err(BodyReadError::Capacity) => {
                return retryable_response(StatusCode::SERVICE_UNAVAILABLE, "raw_body_capacity", 1);
            }
        };
        let target = parts
            .uri
            .path_and_query()
            .map_or(parts.uri.path(), |target| target.as_str());
        let RetainedRawBody { body, permits } = retained;
        let (invocation, completion, receiver) = accepted.invocation(permits);
        let raw_request = RawBodyRequest::new(target, &selected_headers, &body, peer);
        let invoked = catch_unwind(AssertUnwindSafe(|| {
            invocation.invoke(raw_request, completion);
        }));
        drop(invocation);
        drop(selected_headers);
        drop(parts);
        drop(body);
        if invoked.is_err() {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "raw_body_handler_failed");
        }
        let response = match receiver.await {
            Ok(response) => response,
            Err(_) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "raw_body_handler_failed",
                );
            }
        };
        raw_body_response(response)
    }
}

enum NetworkAuthentication {
    Authenticated(bondry_core::Principal),
    Rejected(Response<Bytes>),
}

fn select_raw_body_headers<'a>(
    accepted: &AcceptedRawBodyRequest,
    headers: &'a HeaderMap,
) -> Result<Vec<RawBodyHeader<'a>>, ()> {
    let route = accepted.route();
    let limits = route.limits();
    let mut selected = Vec::with_capacity(route.selected_headers().len());
    let mut aggregate_bytes = 0_usize;
    for name in route.selected_headers() {
        for value in headers.get_all(name).iter() {
            if selected.len() >= MAX_SELECTED_HEADERS
                || value.as_bytes().len() > limits.selected_header_bytes()
            {
                return Err(());
            }
            aggregate_bytes = aggregate_bytes
                .checked_add(name.as_str().len())
                .and_then(|length| length.checked_add(value.as_bytes().len()))
                .ok_or(())?;
            if aggregate_bytes > limits.selected_headers_bytes() {
                return Err(());
            }
            selected.push(RawBodyHeader::new(name, value.as_bytes()));
        }
    }
    Ok(selected)
}

async fn read_body(mut body: Incoming, limit: usize) -> Result<Bytes, BodyReadError> {
    let expected_length = body
        .size_hint()
        .exact()
        .and_then(|length| usize::try_from(length).ok());
    if expected_length.is_some_and(|length| length > limit) {
        return Err(BodyReadError::TooLarge);
    }
    let mut first: Option<Bytes> = None;
    let mut output: Option<BytesMut> = None;
    let mut length = 0_usize;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| BodyReadError::Invalid)?;
        let data = frame.into_data().map_err(|_| BodyReadError::Invalid)?;
        length = length
            .checked_add(data.len())
            .ok_or(BodyReadError::TooLarge)?;
        if length > limit {
            return Err(BodyReadError::TooLarge);
        }
        if let Some(output) = &mut output {
            output.extend_from_slice(&data);
        } else if let Some(initial) = first.take() {
            let capacity = expected_length
                .map_or(length, |expected| expected.min(MAX_BODY_PREALLOCATION))
                .max(length);
            let mut combined = BytesMut::with_capacity(capacity);
            combined.extend_from_slice(&initial);
            combined.extend_from_slice(&data);
            output = Some(combined);
        } else {
            first = Some(data);
        }
    }
    Ok(output.map_or_else(|| first.unwrap_or_default(), BytesMut::freeze))
}

async fn read_raw_body(
    mut body: Incoming,
    limit: usize,
    lifecycle_retained_bytes: usize,
    retained_bytes: Arc<Semaphore>,
) -> Result<RetainedRawBody, BodyReadError> {
    let expected_length = body
        .size_hint()
        .exact()
        .and_then(|length| usize::try_from(length).ok());
    if expected_length.is_some_and(|length| length > limit) {
        return Err(BodyReadError::TooLarge);
    }
    let permit = reserve_retained_bytes(retained_bytes, lifecycle_retained_bytes)?;
    let mut first: Option<Bytes> = None;
    let mut output: Option<BytesMut> = None;
    let mut length = 0_usize;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| BodyReadError::Invalid)?;
        let data = frame.into_data().map_err(|_| BodyReadError::Invalid)?;
        length = length
            .checked_add(data.len())
            .ok_or(BodyReadError::TooLarge)?;
        if length > limit {
            return Err(BodyReadError::TooLarge);
        }
        if let Some(output) = &mut output {
            output.extend_from_slice(&data);
        } else if let Some(initial) = first.take() {
            let capacity = expected_length
                .map_or(length, |expected| expected.min(MAX_BODY_PREALLOCATION))
                .max(length);
            let mut combined = BytesMut::with_capacity(capacity);
            combined.extend_from_slice(&initial);
            combined.extend_from_slice(&data);
            output = Some(combined);
        } else {
            first = Some(data);
        }
    }
    Ok(RetainedRawBody {
        body: output.map_or_else(|| first.unwrap_or_default(), BytesMut::freeze),
        permits: vec![permit],
    })
}

fn reserve_retained_bytes(
    retained_bytes: Arc<Semaphore>,
    bytes: usize,
) -> Result<OwnedSemaphorePermit, BodyReadError> {
    let bytes = u32::try_from(bytes).map_err(|_| BodyReadError::TooLarge)?;
    retained_bytes
        .try_acquire_many_owned(bytes)
        .map_err(|_| BodyReadError::Capacity)
}

struct RetainedRawBody {
    body: Bytes,
    permits: Vec<OwnedSemaphorePermit>,
}

enum BodyReadError {
    TooLarge,
    Invalid,
    Capacity,
}

fn secure_response(mut response: Response<Bytes>) -> Response<Bytes> {
    response
        .headers_mut()
        .entry(header::CACHE_CONTROL)
        .or_insert_with(|| http::HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .entry(header::X_CONTENT_TYPE_OPTIONS)
        .or_insert_with(|| http::HeaderValue::from_static("nosniff"));
    response
}

fn error_response(status: StatusCode, code: &str) -> Response<Bytes> {
    let body = serde_json::to_vec(&json!({ "error": code })).unwrap_or_default();
    let mut response = Response::new(Bytes::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json; charset=utf-8"),
    );
    secure_response(response)
}

fn unauthorized_response(challenge: Option<&'static str>) -> Response<Bytes> {
    let mut response = error_response(StatusCode::UNAUTHORIZED, "unauthorized");
    if let Some(challenge) = challenge {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            http::HeaderValue::from_static(challenge),
        );
    }
    response
}

fn rate_limited_response(retry_after: u64) -> Response<Bytes> {
    let mut response = error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    if let Ok(value) = http::HeaderValue::from_str(&retry_after.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

fn retryable_response(status: StatusCode, code: &'static str, retry_after: u64) -> Response<Bytes> {
    let mut response = error_response(status, code);
    if let Ok(value) = http::HeaderValue::from_str(&retry_after.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

fn raw_body_response(response: RawBodyResponse) -> Response<Bytes> {
    let mut output = response.error_code().map_or_else(
        || {
            let mut output = Response::new(Bytes::new());
            *output.status_mut() = response.status();
            secure_response(output)
        },
        |code| error_response(response.status(), code),
    );
    if let Some(retry_after) = response.retry_after_seconds() {
        if let Ok(value) = http::HeaderValue::from_str(&retry_after.to_string()) {
            output.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    output
}

fn clone_io_error(error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), error.to_string())
}

fn server_thread_result(thread: ServerThread) -> Result<(), ServerStopError> {
    match thread.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(ServerRuntimeError::Io(error))) => Err(ServerStopError::Runtime(error)),
        Ok(Err(ServerRuntimeError::HandlerDrainTimedOut)) => {
            Err(ServerStopError::HandlerDrainTimedOut)
        }
        Err(_) => Err(ServerStopError::ThreadPanicked),
    }
}

/// A local HTTP server startup failure.
#[derive(Debug, Error)]
pub enum ServerStartError {
    /// Server configuration was rejected.
    #[error(transparent)]
    Configuration(#[from] ServerConfigurationError),
    /// Legacy empty-adapter error retained for source compatibility and no longer emitted.
    #[error("at least one HTTP adapter is required")]
    NoAdapters,
    /// The asynchronous runtime could not be created.
    #[error("HTTP runtime creation failed")]
    Runtime(#[source] io::Error),
    /// The server thread could not be created.
    #[error("HTTP server thread creation failed")]
    Thread(#[source] io::Error),
    /// The requested address could not be bound.
    #[error("HTTP listen address could not be bound")]
    Bind(#[source] io::Error),
    /// The server stopped before reporting its listening address.
    #[error("HTTP server stopped during startup")]
    Startup,
}

/// A Unix HTTP server startup failure.
#[cfg(feature = "unix-socket")]
#[derive(Debug, Error)]
pub enum UnixServerStartError {
    /// Unix-specific server policy was rejected.
    #[error(transparent)]
    Configuration(#[from] UnixServerConfigurationError),
    /// Shared server startup failed.
    #[error(transparent)]
    Server(#[from] ServerStartError),
}

/// A local HTTP server shutdown failure.
#[derive(Debug, Error)]
pub enum ServerStopError {
    /// The accept loop ended with an operating-system error.
    #[error("HTTP server stopped after an I/O failure")]
    Runtime(#[source] io::Error),
    /// One or more raw-body callbacks remained active past the shutdown deadline.
    #[error("raw-body handler drain timed out")]
    HandlerDrainTimedOut,
    /// The server thread panicked.
    #[error("HTTP server thread panicked")]
    ThreadPanicked,
}

enum ServerRuntimeError {
    Io(io::Error),
    HandlerDrainTimedOut,
}
