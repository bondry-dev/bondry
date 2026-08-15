#![allow(missing_docs)]

use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use bondry_core::{
    AdapterId, AutomationService, CapabilityDescriptor, CapabilityDiscoveryError, CapabilityEffect,
    CapabilityId, DispatchFuture, Invocation, Principal, PrincipalId, PrincipalKind,
};
use bondry_http_server::{
    Authentication, AuthenticationError, BearerAuthenticator, BearerTokenVerifier, LocalHttpServer,
    MountedProtocol, OriginPolicy, RateLimits, RawBodyCompletion, RawBodyHandler,
    RawBodyHandlerLimits, RawBodyLifecycle, RawBodyRegistrationError, RawBodyRequest,
    RawBodyResponse, RawBodyRoute, RawBodyServerLimits, ServerConfiguration,
    ServerConfigurationError, ServerStartError,
};
use bondry_rest_proto::RestAdapter;
use http::{HeaderName, StatusCode};
use serde_json::json;

struct TestVerifier;

impl BearerTokenVerifier for TestVerifier {
    fn verify(&self, token: &str) -> Result<Principal, AuthenticationError> {
        match token {
            "unavailable" => Err(AuthenticationError::Unavailable),
            "alpha" | "beta" => Ok(Principal::new(
                PrincipalId::new(format!("client_{token}"))
                    .map_err(|_| AuthenticationError::Unavailable)?,
                PrincipalKind::Application,
            )),
            _ => Err(AuthenticationError::Rejected),
        }
    }
}

struct EchoService {
    capabilities: Vec<CapabilityDescriptor>,
}

#[derive(Debug, Eq, PartialEq)]
struct CapturedRawBody {
    target: String,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    peer: SocketAddr,
}

struct CapturingRawBodyHandler {
    captured: mpsc::SyncSender<CapturedRawBody>,
}

impl RawBodyHandler for CapturingRawBodyHandler {
    fn handle(&self, request: RawBodyRequest<'_>, completion: RawBodyCompletion) {
        let captured = CapturedRawBody {
            target: request.target().to_owned(),
            headers: request
                .headers()
                .iter()
                .map(|header| (header.name().as_str().to_owned(), header.value().to_vec()))
                .collect(),
            body: request.body().to_vec(),
            peer: request.peer(),
        };
        let _ = self.captured.send(captured);
        completion.complete(RawBodyResponse::no_content());
    }
}

struct CountingRawBodyHandler {
    calls: Arc<AtomicUsize>,
}

struct RespondingRawBodyHandler {
    response: RawBodyResponse,
}

impl RawBodyHandler for RespondingRawBodyHandler {
    fn handle(&self, _request: RawBodyRequest<'_>, completion: RawBodyCompletion) {
        completion.complete(self.response.clone());
    }
}

impl RawBodyHandler for CountingRawBodyHandler {
    fn handle(&self, _request: RawBodyRequest<'_>, completion: RawBodyCompletion) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        completion.complete(RawBodyResponse::no_content());
    }
}

struct DeferredRawBodyHandler {
    entered: mpsc::SyncSender<()>,
    completion: Arc<Mutex<Option<RawBodyCompletion>>>,
    releases: Arc<AtomicUsize>,
}

impl RawBodyHandler for DeferredRawBodyHandler {
    fn handle(&self, _request: RawBodyRequest<'_>, completion: RawBodyCompletion) {
        if let Ok(mut retained) = self.completion.lock() {
            *retained = Some(completion);
        }
        let _ = self.entered.send(());
    }
}

impl Drop for DeferredRawBodyHandler {
    fn drop(&mut self) {
        self.releases.fetch_add(1, Ordering::SeqCst);
    }
}

impl AutomationService for EchoService {
    fn capabilities(
        &self,
        _principal: &Principal,
        _adapter: &AdapterId,
    ) -> Result<Vec<CapabilityDescriptor>, CapabilityDiscoveryError> {
        Ok(self.capabilities.clone())
    }

    fn dispatch(&self, invocation: Invocation) -> DispatchFuture<'_> {
        Box::pin(async move {
            if invocation.capability().as_str() == "slow" {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Ok(json!({
                "principal": invocation.principal().id().as_str(),
                "body": invocation.input(),
            }))
        })
    }
}

fn authenticated_configuration() -> ServerConfiguration {
    let verifier: Arc<dyn BearerTokenVerifier> = Arc::new(TestVerifier);
    ServerConfiguration::new(Authentication::required(Arc::new(
        BearerAuthenticator::new(verifier),
    )))
}

fn protocols() -> Result<Vec<MountedProtocol>, Box<dyn std::error::Error>> {
    let service: Arc<dyn AutomationService> = Arc::new(EchoService {
        capabilities: ["echo", "slow"]
            .into_iter()
            .map(|name| {
                Ok(CapabilityDescriptor::new(
                    CapabilityId::new(name)?,
                    format!("Test {name} capability"),
                    CapabilityEffect::ReadOnly,
                )?)
            })
            .collect::<Result<_, Box<dyn std::error::Error>>>()?,
    });
    Ok(vec![MountedProtocol::Rest(RestAdapter::new(service)?)])
}

fn start(
    configuration: ServerConfiguration,
) -> Result<LocalHttpServer, Box<dyn std::error::Error>> {
    Ok(LocalHttpServer::start(configuration, protocols()?)?)
}

fn request(address: SocketAddr, request: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn get(address: SocketAddr, path: &str, authorization: &str) -> std::io::Result<String> {
    request(
        address,
        &format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {authorization}\r\nConnection: close\r\n\r\n"
        ),
    )
}

fn post(
    address: SocketAddr,
    path: &str,
    authorization: &str,
    body: &str,
) -> std::io::Result<String> {
    request(
        address,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {authorization}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

fn status(response: &str) -> Option<u16> {
    response
        .lines()
        .next()?
        .split_ascii_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn body(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

fn wait_for_lifecycle(
    registration: &bondry_http_server::RawBodyRegistration,
    lifecycle: RawBodyLifecycle,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if registration.lifecycle() == lifecycle {
            return true;
        }
        thread::sleep(Duration::from_millis(1));
    }
    false
}

#[test]
fn starts_on_an_automatic_port_and_releases_it() -> Result<(), Box<dyn std::error::Error>> {
    let mut server = start(authenticated_configuration())?;
    let address = server.local_address();
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);

    let unknown = get(address, "/unknown", "Bearer alpha")?;
    assert_eq!(status(&unknown), Some(404));

    server.stop()?;
    server.stop()?;
    let replacement = std::net::TcpListener::bind(address)?;
    drop(replacement);
    Ok(())
}

#[test]
fn keeps_http_11_connections_alive_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let server = start(authenticated_configuration())?;
    let mut stream = TcpStream::connect(server.local_address())?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(
        b"POST /api/v1/capabilities/echo HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer alpha\r\nContent-Length: 0\r\n\r\n\
          POST /api/v1/capabilities/echo HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer beta\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )?;
    let mut responses = String::new();
    stream.read_to_string(&mut responses)?;

    assert_eq!(responses.matches("HTTP/1.1 200 OK").count(), 2);
    assert!(responses.contains("client_alpha"));
    assert!(responses.contains("client_beta"));
    Ok(())
}

#[test]
fn requires_one_well_formed_bearer_header() -> Result<(), Box<dyn std::error::Error>> {
    let server = start(authenticated_configuration())?;
    let address = server.local_address();

    let missing = request(
        address,
        "GET /api/v1/capabilities/echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )?;
    assert_eq!(status(&missing), Some(401));
    assert!(missing.contains("www-authenticate: Bearer"));

    let duplicate = request(
        address,
        "GET /api/v1/capabilities/echo HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer alpha\r\nAuthorization: Bearer beta\r\nConnection: close\r\n\r\n",
    )?;
    assert_eq!(status(&duplicate), Some(401));

    let accepted = post(address, "/api/v1/capabilities/echo", "bEaReR alpha", "{}")?;
    assert_eq!(status(&accepted), Some(200));
    assert!(body(&accepted).contains("client_alpha"));
    Ok(())
}

#[test]
fn dispatches_valid_json_after_authentication() -> Result<(), Box<dyn std::error::Error>> {
    let server = start(authenticated_configuration())?;
    let response = request(
        server.local_address(),
        "POST /api/v1/capabilities/echo HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer alpha\r\nCookie: secret=value\r\nContent-Type: application/json\r\nContent-Length: 6\r\nConnection: close\r\n\r\n\"test\"",
    )?;

    assert_eq!(status(&response), Some(200));
    assert!(body(&response).contains("\"body\":\"test\""));
    Ok(())
}

#[test]
fn enforces_exact_origin_policy() -> Result<(), Box<dyn std::error::Error>> {
    let denied_server = start(authenticated_configuration())?;
    let denied = request(
        denied_server.local_address(),
        "GET /api/v1/capabilities/echo HTTP/1.1\r\nHost: localhost\r\nOrigin: http://example.test\r\nAuthorization: Bearer alpha\r\nConnection: close\r\n\r\n",
    )?;
    assert_eq!(status(&denied), Some(403));

    let policy = OriginPolicy::default().allowing("http://example.test")?;
    let allowed_server = start(authenticated_configuration().with_origin_policy(policy))?;
    let allowed = request(
        allowed_server.local_address(),
        "GET /api/v1/capabilities/echo HTTP/1.1\r\nHost: localhost\r\nOrigin: http://example.test\r\nAuthorization: Bearer alpha\r\nConnection: close\r\n\r\n",
    )?;
    assert_eq!(status(&allowed), Some(200));
    Ok(())
}

#[test]
fn bounds_request_bodies() -> Result<(), Box<dyn std::error::Error>> {
    let server = start(authenticated_configuration().with_max_body_bytes(4)?)?;
    let response = request(
        server.local_address(),
        "POST /api/v1/capabilities/echo HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer alpha\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345",
    )?;

    assert_eq!(status(&response), Some(413));
    Ok(())
}

#[test]
fn delivers_exact_bounded_raw_body_without_weakening_rest_authentication()
-> Result<(), Box<dyn std::error::Error>> {
    let server = start(authenticated_configuration())?;
    let (captured_sender, captured_receiver) = mpsc::sync_channel(1);
    let route = RawBodyRoute::post(
        "/hooks/provider",
        [
            HeaderName::from_static("x-signature"),
            HeaderName::from_static("x-event"),
        ],
        RawBodyHandlerLimits::default(),
    )?;
    let _registration = server.register_raw_body_handler(
        route,
        Arc::new(CapturingRawBodyHandler {
            captured: captured_sender,
        }),
    )?;

    let response = request(
        server.local_address(),
        "POST /hooks/provider?delivery=%2Fone HTTP/1.1\r\nHost: localhost\r\nX-Signature: first\r\nX-Signature: second\r\nX-Event: created\r\nX-Ignored: secret\r\nContent-Length: 5\r\nConnection: close\r\n\r\n\x00raw!",
    )?;
    assert_eq!(status(&response), Some(204));
    let captured = captured_receiver.recv_timeout(Duration::from_secs(1))?;
    assert_eq!(captured.target, "/hooks/provider?delivery=%2Fone");
    assert_eq!(
        captured.headers,
        [
            ("x-signature".to_owned(), b"first".to_vec()),
            ("x-signature".to_owned(), b"second".to_vec()),
            ("x-event".to_owned(), b"created".to_vec()),
        ]
    );
    assert_eq!(captured.body, b"\x00raw!");
    assert!(captured.peer.ip().is_loopback());

    let rest_without_bearer = request(
        server.local_address(),
        "GET /api/v1/capabilities/echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )?;
    assert_eq!(status(&rest_without_bearer), Some(401));
    Ok(())
}

#[test]
fn rejects_oversized_raw_bodies_and_rate_limits_before_reading_them()
-> Result<(), Box<dyn std::error::Error>> {
    let server = start(authenticated_configuration())?;
    let calls = Arc::new(AtomicUsize::new(0));
    let limits = RawBodyHandlerLimits::new(1_024, 3 * 1_048_576, 2_048, 32 * 1_024, 1, 1)?;
    let _registration = server.register_raw_body_handler(
        RawBodyRoute::post("/hooks/bounded", [], limits)?,
        Arc::new(CountingRawBodyHandler {
            calls: Arc::clone(&calls),
        }),
    )?;
    let oversized_headers = "POST /hooks/bounded HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1025\r\nConnection: close\r\n\r\n";

    let oversized = request(server.local_address(), oversized_headers)?;
    assert_eq!(status(&oversized), Some(413));
    let limited = request(server.local_address(), oversized_headers)?;
    assert_eq!(status(&limited), Some(429));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn serializes_only_bounded_raw_body_error_codes() -> Result<(), Box<dyn std::error::Error>> {
    let server = start(authenticated_configuration())?;
    let response = RawBodyResponse::new(StatusCode::UNPROCESSABLE_ENTITY, Some(2))?
        .with_error_code("invalid_payload")?;
    let _registration = server.register_raw_body_handler(
        RawBodyRoute::post("/hooks/error", [], RawBodyHandlerLimits::default())?,
        Arc::new(RespondingRawBodyHandler { response }),
    )?;

    let response = request(
        server.local_address(),
        "POST /hooks/error HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )?;
    assert_eq!(status(&response), Some(422));
    assert_eq!(body(&response), r#"{"error":"invalid_payload"}"#);
    assert!(response.contains("retry-after: 2"));
    assert!(
        RawBodyResponse::new(StatusCode::BAD_REQUEST, None)?
            .with_error_code("Not Safe")
            .is_err()
    );
    Ok(())
}

#[test]
fn enforces_the_aggregate_raw_body_budget_before_copying_another_body()
-> Result<(), Box<dyn std::error::Error>> {
    let configuration = authenticated_configuration()
        .with_raw_body_limits(RawBodyServerLimits::new(1_048_576, Duration::from_secs(1))?);
    let server = start(configuration)?;
    let completion = Arc::new(Mutex::new(None));
    let releases = Arc::new(AtomicUsize::new(0));
    let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
    let handler = Arc::new(DeferredRawBodyHandler {
        entered: entered_sender,
        completion: Arc::clone(&completion),
        releases,
    });
    let _registration = server.register_raw_body_handler(
        RawBodyRoute::post(
            "/hooks/memory",
            [],
            RawBodyHandlerLimits::new(1_048_576, 1_048_576, 2_048, 32 * 1_024, 60, 120)?,
        )?,
        handler,
    )?;
    let address = server.local_address();
    let request_thread = thread::spawn(move || {
        let body = "x".repeat(700 * 1_024);
        request(
            address,
            &format!(
                "POST /hooks/memory HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ),
        )
    });
    entered_receiver.recv_timeout(Duration::from_secs(1))?;

    let capacity = request(
        server.local_address(),
        "POST /hooks/memory HTTP/1.1\r\nHost: localhost\r\nContent-Length: 716800\r\nConnection: close\r\n\r\n",
    )?;
    assert_eq!(status(&capacity), Some(503));
    assert!(capacity.contains("raw_body_capacity"));

    let retained_completion = completion
        .lock()
        .map_err(|_| std::io::Error::other("completion lock poisoned"))?
        .take()
        .ok_or_else(|| std::io::Error::other("completion was not retained"))?;
    retained_completion.complete(RawBodyResponse::no_content());
    let first_response = request_thread
        .join()
        .map_err(|_| std::io::Error::other("request thread panicked"))??;
    assert_eq!(status(&first_response), Some(204));
    Ok(())
}

#[test]
fn drains_raw_body_generations_without_fallback_or_early_release()
-> Result<(), Box<dyn std::error::Error>> {
    let server = start(authenticated_configuration())?;
    let address = server.local_address();
    let completion = Arc::new(Mutex::new(None));
    let releases = Arc::new(AtomicUsize::new(0));
    let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
    let handler = Arc::new(DeferredRawBodyHandler {
        entered: entered_sender,
        completion: Arc::clone(&completion),
        releases: Arc::clone(&releases),
    });
    let registration = Arc::new(server.register_raw_body_handler(
        RawBodyRoute::post("/hooks/drain", [], RawBodyHandlerLimits::default())?,
        handler.clone(),
    )?);
    drop(handler);

    let request_thread = thread::spawn(move || {
        request(
            address,
            "POST /hooks/drain HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        )
    });
    entered_receiver.recv_timeout(Duration::from_secs(1))?;

    let disable_registration = Arc::clone(&registration);
    let disable_thread =
        thread::spawn(move || disable_registration.disable(Duration::from_secs(2)));
    assert!(wait_for_lifecycle(
        &registration,
        RawBodyLifecycle::Draining
    ));
    assert_eq!(releases.load(Ordering::SeqCst), 0);

    let draining = request(
        server.local_address(),
        "POST /hooks/drain HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )?;
    assert_eq!(status(&draining), Some(503));
    assert!(draining.contains("raw_body_handler_draining"));

    let retained_completion = completion
        .lock()
        .map_err(|_| std::io::Error::other("completion lock poisoned"))?
        .take()
        .ok_or_else(|| std::io::Error::other("completion was not retained"))?;
    retained_completion.complete(RawBodyResponse::no_content());
    let first_response = request_thread
        .join()
        .map_err(|_| std::io::Error::other("request thread panicked"))??;
    assert_eq!(status(&first_response), Some(204));
    disable_thread
        .join()
        .map_err(|_| std::io::Error::other("disable thread panicked"))??;
    assert_eq!(registration.lifecycle(), RawBodyLifecycle::Detached);
    assert_eq!(releases.load(Ordering::SeqCst), 1);

    let (captured_sender, captured_receiver) = mpsc::sync_channel(1);
    let _replacement = server.register_raw_body_handler(
        RawBodyRoute::post("/hooks/drain", [], RawBodyHandlerLimits::default())?,
        Arc::new(CapturingRawBodyHandler {
            captured: captured_sender,
        }),
    )?;
    let replacement_response = request(
        server.local_address(),
        "POST /hooks/drain HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )?;
    assert_eq!(status(&replacement_response), Some(204));
    let _ = captured_receiver.recv_timeout(Duration::from_secs(1))?;
    Ok(())
}

#[test]
fn rejects_raw_body_route_conflicts_and_duplicate_generations()
-> Result<(), Box<dyn std::error::Error>> {
    let server = start(authenticated_configuration())?;
    let calls = Arc::new(AtomicUsize::new(0));
    let handler: Arc<dyn RawBodyHandler> = Arc::new(CountingRawBodyHandler { calls });
    let conflict = server.register_raw_body_handler(
        RawBodyRoute::post(
            "/api/v1/capabilities/echo",
            [],
            RawBodyHandlerLimits::default(),
        )?,
        Arc::clone(&handler),
    );
    assert!(matches!(
        conflict,
        Err(RawBodyRegistrationError::ProtocolConflict)
    ));

    let _registration = server.register_raw_body_handler(
        RawBodyRoute::post("/hooks/unique", [], RawBodyHandlerLimits::default())?,
        Arc::clone(&handler),
    )?;
    let duplicate = server.register_raw_body_handler(
        RawBodyRoute::post("/hooks/unique", [], RawBodyHandlerLimits::default())?,
        handler,
    );
    assert!(matches!(
        duplicate,
        Err(RawBodyRegistrationError::AlreadyRegistered)
    ));
    Ok(())
}

#[test]
fn rate_limits_principals_and_rejected_peers_separately() -> Result<(), Box<dyn std::error::Error>>
{
    let limits = RateLimits::new(1, 1)?;
    let server = start(authenticated_configuration().with_rate_limits(limits))?;
    let address = server.local_address();

    let path = "/api/v1/capabilities/echo";
    assert_eq!(status(&get(address, path, "Bearer alpha")?), Some(200));
    assert_eq!(status(&get(address, path, "Bearer alpha")?), Some(429));
    assert_eq!(status(&get(address, path, "Bearer beta")?), Some(200));

    assert_eq!(status(&get(address, path, "Bearer invalid")?), Some(401));
    assert_eq!(status(&get(address, path, "Bearer invalid")?), Some(429));
    Ok(())
}

#[test]
fn maps_authentication_unavailability_and_request_timeouts()
-> Result<(), Box<dyn std::error::Error>> {
    let unavailable_server = start(authenticated_configuration())?;
    assert_eq!(
        status(&get(
            unavailable_server.local_address(),
            "/api/v1/capabilities/echo",
            "Bearer unavailable"
        )?),
        Some(503)
    );

    let configuration = authenticated_configuration().with_timeouts(
        Duration::from_secs(1),
        Duration::from_millis(10),
        Duration::from_secs(1),
    )?;
    let timeout_server = start(configuration)?;
    assert_eq!(
        status(&post(
            timeout_server.local_address(),
            "/api/v1/capabilities/slow",
            "Bearer alpha",
            "{}"
        )?),
        Some(504)
    );
    Ok(())
}

#[test]
fn unauthenticated_network_binding_requires_acknowledgement()
-> Result<(), Box<dyn std::error::Error>> {
    let principal = Principal::new(
        PrincipalId::new("local_anonymous")?,
        PrincipalKind::Application,
    );
    let configuration = ServerConfiguration::new(Authentication::disabled(principal))
        .with_bind_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .allowing_cleartext_network();
    assert!(matches!(
        LocalHttpServer::start(configuration, protocols()?),
        Err(ServerStartError::Configuration(
            ServerConfigurationError::UnauthenticatedNetworkExposure
        ))
    ));
    Ok(())
}

#[test]
fn disabled_authentication_uses_an_explicit_local_principal()
-> Result<(), Box<dyn std::error::Error>> {
    let principal = Principal::new(
        PrincipalId::new("local_anonymous")?,
        PrincipalKind::Application,
    );
    let server = start(ServerConfiguration::new(Authentication::disabled(
        principal,
    )))?;
    let response = post(
        server.local_address(),
        "/api/v1/capabilities/echo",
        "Bearer ignored",
        "{}",
    )?;

    assert_eq!(status(&response), Some(200));
    assert!(body(&response).contains("local_anonymous"));
    Ok(())
}

#[test]
fn validates_configuration_bounds_and_allows_raw_body_only_startup()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(RateLimits::new(0, 1).is_err());
    assert!(RateLimits::new(1, 60_001).is_err());
    assert!(OriginPolicy::default().allowing("not-an-origin").is_err());
    assert!(
        OriginPolicy::default()
            .allowing("https://example.test/path")
            .is_err()
    );

    let configuration = authenticated_configuration();
    assert!(configuration.clone().with_max_body_bytes(0).is_err());
    assert!(configuration.clone().with_max_connections(0).is_err());
    assert!(
        configuration
            .clone()
            .with_timeouts(
                Duration::ZERO,
                Duration::from_secs(1),
                Duration::from_secs(1),
            )
            .is_err()
    );
    let mut raw_body_only = LocalHttpServer::start(configuration, Vec::new())?;
    raw_body_only.stop()?;
    let network_configuration =
        authenticated_configuration().with_bind_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert!(matches!(
        LocalHttpServer::start(network_configuration, protocols()?),
        Err(ServerStartError::Configuration(
            ServerConfigurationError::CleartextNetworkExposure
        ))
    ));
    Ok(())
}
