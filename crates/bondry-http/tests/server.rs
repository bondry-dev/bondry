#![allow(missing_docs)]

use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

use bondry_core::{Principal, PrincipalId, PrincipalKind};
use bondry_http::{
    AdapterFuture, AdapterRequest, Authentication, AuthenticationError, BearerAuthenticator,
    BearerTokenVerifier, HttpAdapter, LocalHttpServer, OriginPolicy, RateLimits,
    ServerConfiguration, ServerConfigurationError, ServerStartError,
};
use bytes::Bytes;
use http::{Response, StatusCode, header};
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

struct EchoAdapter;

impl HttpAdapter for EchoAdapter {
    fn accepts_path(&self, path: &str) -> bool {
        path == "/echo" || path == "/slow"
    }

    fn handle(&self, request: AdapterRequest) -> AdapterFuture<'_> {
        Box::pin(async move {
            if request.request().uri().path() == "/slow" {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let body = json!({
                "authorization": request.request().headers().contains_key(header::AUTHORIZATION),
                "cookie": request.request().headers().contains_key(header::COOKIE),
                "principal": request.principal().id().as_str(),
                "body": String::from_utf8_lossy(request.request().body()),
            });
            let mut response =
                Response::new(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()));
            *response.status_mut() = StatusCode::OK;
            response
        })
    }
}

fn authenticated_configuration() -> ServerConfiguration {
    let verifier: Arc<dyn BearerTokenVerifier> = Arc::new(TestVerifier);
    ServerConfiguration::new(Authentication::required(Arc::new(
        BearerAuthenticator::new(verifier),
    )))
}

fn start(configuration: ServerConfiguration) -> Result<LocalHttpServer, ServerStartError> {
    LocalHttpServer::start(configuration, vec![Arc::new(EchoAdapter)])
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
fn serves_multiple_requests_over_one_connection() -> Result<(), Box<dyn std::error::Error>> {
    let server = start(authenticated_configuration())?;
    let mut stream = TcpStream::connect(server.local_address())?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(
        b"GET /echo HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer alpha\r\n\r\n\
          GET /echo HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer beta\r\nConnection: close\r\n\r\n",
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
        "GET /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )?;
    assert_eq!(status(&missing), Some(401));
    assert!(missing.contains("www-authenticate: Bearer"));

    let duplicate = request(
        address,
        "GET /echo HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer alpha\r\nAuthorization: Bearer beta\r\nConnection: close\r\n\r\n",
    )?;
    assert_eq!(status(&duplicate), Some(401));

    let accepted = get(address, "/echo", "bEaReR alpha")?;
    assert_eq!(status(&accepted), Some(200));
    assert!(body(&accepted).contains("client_alpha"));
    Ok(())
}

#[test]
fn removes_credentials_before_adapter_dispatch() -> Result<(), Box<dyn std::error::Error>> {
    let server = start(authenticated_configuration())?;
    let response = request(
        server.local_address(),
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer alpha\r\nCookie: secret=value\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntest",
    )?;

    assert_eq!(status(&response), Some(200));
    assert!(body(&response).contains("\"authorization\":false"));
    assert!(body(&response).contains("\"cookie\":false"));
    assert!(body(&response).contains("\"body\":\"test\""));
    Ok(())
}

#[test]
fn enforces_exact_origin_policy() -> Result<(), Box<dyn std::error::Error>> {
    let denied_server = start(authenticated_configuration())?;
    let denied = request(
        denied_server.local_address(),
        "GET /echo HTTP/1.1\r\nHost: localhost\r\nOrigin: http://example.test\r\nAuthorization: Bearer alpha\r\nConnection: close\r\n\r\n",
    )?;
    assert_eq!(status(&denied), Some(403));

    let policy = OriginPolicy::default().allowing("http://example.test")?;
    let allowed_server = start(authenticated_configuration().with_origin_policy(policy))?;
    let allowed = request(
        allowed_server.local_address(),
        "GET /echo HTTP/1.1\r\nHost: localhost\r\nOrigin: http://example.test\r\nAuthorization: Bearer alpha\r\nConnection: close\r\n\r\n",
    )?;
    assert_eq!(status(&allowed), Some(200));
    Ok(())
}

#[test]
fn bounds_request_bodies() -> Result<(), Box<dyn std::error::Error>> {
    let server = start(authenticated_configuration().with_max_body_bytes(4)?)?;
    let response = request(
        server.local_address(),
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer alpha\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345",
    )?;

    assert_eq!(status(&response), Some(413));
    Ok(())
}

#[test]
fn rate_limits_principals_and_rejected_peers_separately() -> Result<(), Box<dyn std::error::Error>>
{
    let limits = RateLimits::new(1, 1)?;
    let server = start(authenticated_configuration().with_rate_limits(limits))?;
    let address = server.local_address();

    assert_eq!(status(&get(address, "/echo", "Bearer alpha")?), Some(200));
    assert_eq!(status(&get(address, "/echo", "Bearer alpha")?), Some(429));
    assert_eq!(status(&get(address, "/echo", "Bearer beta")?), Some(200));

    assert_eq!(status(&get(address, "/echo", "Bearer invalid")?), Some(401));
    assert_eq!(status(&get(address, "/echo", "Bearer invalid")?), Some(429));
    Ok(())
}

#[test]
fn maps_authentication_unavailability_and_request_timeouts()
-> Result<(), Box<dyn std::error::Error>> {
    let unavailable_server = start(authenticated_configuration())?;
    assert_eq!(
        status(&get(
            unavailable_server.local_address(),
            "/echo",
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
        status(&get(
            timeout_server.local_address(),
            "/slow",
            "Bearer alpha"
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
        start(configuration),
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
    let response = get(server.local_address(), "/echo", "Bearer ignored")?;

    assert_eq!(status(&response), Some(200));
    assert!(body(&response).contains("local_anonymous"));
    assert!(body(&response).contains("\"authorization\":false"));
    Ok(())
}

#[test]
fn validates_configuration_bounds_and_adapter_presence() -> Result<(), Box<dyn std::error::Error>> {
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
    assert!(matches!(
        LocalHttpServer::start(configuration, Vec::new()),
        Err(ServerStartError::NoAdapters)
    ));
    let network_configuration =
        authenticated_configuration().with_bind_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert!(matches!(
        LocalHttpServer::start(network_configuration, vec![Arc::new(EchoAdapter)]),
        Err(ServerStartError::Configuration(
            ServerConfigurationError::CleartextNetworkExposure
        ))
    ));
    Ok(())
}
