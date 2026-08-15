use std::{
    convert::Infallible,
    io,
    net::{IpAddr, SocketAddr},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

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
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    task::JoinSet,
};

use crate::{
    AuthenticationError, AuthenticationRequest, MountedProtocol, RawBodyHandler,
    RawBodyRegistration, RawBodyRegistrationError, RawBodyRoute, ServerConfiguration,
    ServerConfigurationError,
    rate_limit::{RateLimitDecision, SlidingWindow},
    raw_body::{
        AcceptedRawBodyRequest, MAX_SELECTED_HEADERS, RawBodyHeader, RawBodyMatch, RawBodyRegistry,
        RawBodyRequest, RawBodyResponse,
    },
};

type ServerThread = thread::JoinHandle<Result<(), ServerRuntimeError>>;
const MAX_BODY_PREALLOCATION: usize = 64 * 1_024;

/// A running local HTTP server with deterministic shutdown ownership.
pub struct LocalHttpServer {
    local_address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<ServerThread>,
    protocols: Arc<[MountedProtocol]>,
    raw_body_registry: Arc<RawBodyRegistry>,
}

impl LocalHttpServer {
    /// Starts a server on its dedicated asynchronous runtime.
    pub fn start(
        configuration: ServerConfiguration,
        protocols: Vec<MountedProtocol>,
    ) -> Result<Self, ServerStartError> {
        configuration.validate()?;
        if protocols.is_empty() {
            return Err(ServerStartError::NoAdapters);
        }
        let protocols: Arc<[MountedProtocol]> = protocols.into();
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
        match thread.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(ServerRuntimeError::Io(error))) => Err(ServerStopError::Runtime(error)),
            Ok(Err(ServerRuntimeError::HandlerDrainTimedOut)) => {
                Err(ServerStopError::HandlerDrainTimedOut)
            }
            Err(_) => Err(ServerStopError::ThreadPanicked),
        }
    }
}

impl Drop for LocalHttpServer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

async fn run_server(
    configuration: ServerConfiguration,
    protocols: Arc<[MountedProtocol]>,
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
                connections.spawn(async move {
                    let _slot = slot;
                    serve_connection(stream, peer, state).await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    };

    raw_body_registry.begin_shutdown();
    let grace_period = configuration.shutdown_grace_period;
    if tokio::time::timeout(grace_period, async {
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
    runtime_result.map_err(ServerRuntimeError::Io)
}

async fn serve_connection(stream: TcpStream, peer: SocketAddr, state: Arc<ServerState>) {
    let _ = stream.set_nodelay(true);
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
    protocols: Arc<[MountedProtocol]>,
    raw_body_registry: Arc<RawBodyRegistry>,
    request_limits: SlidingWindow<PrincipalId>,
    authentication_failure_limits: SlidingWindow<IpAddr>,
}

impl ServerState {
    async fn handle(&self, mut request: Request<Incoming>, peer: SocketAddr) -> Response<Bytes> {
        match self
            .raw_body_registry
            .match_request(request.method(), request.uri().path())
        {
            RawBodyMatch::Accepted(accepted) => {
                return self.handle_raw_body(request, peer, accepted).await;
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
        let peer_ip = peer.ip();
        let failure_limit = self
            .configuration
            .rate_limits
            .authentication_failures_per_minute();
        if let RateLimitDecision::Limited { retry_after } = self
            .authentication_failure_limits
            .check(&peer_ip, failure_limit, now)
        {
            return rate_limited_response(retry_after);
        }
        let authentication_request =
            AuthenticationRequest::new(request.method(), request.uri(), request.headers(), peer);
        let principal = match self
            .configuration
            .authentication
            .authenticate(authentication_request)
        {
            Ok(principal) => principal,
            Err(AuthenticationError::Rejected) => {
                let _ = self
                    .authentication_failure_limits
                    .consume(peer_ip, failure_limit, now);
                return unauthorized_response(self.configuration.authentication.challenge());
            }
            Err(AuthenticationError::Unavailable) => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authentication_unavailable",
                );
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

/// A local HTTP server startup failure.
#[derive(Debug, Error)]
pub enum ServerStartError {
    /// Server configuration was rejected.
    #[error(transparent)]
    Configuration(#[from] ServerConfigurationError),
    /// At least one protocol adapter is required.
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
