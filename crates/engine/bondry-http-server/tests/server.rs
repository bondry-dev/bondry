#![allow(missing_docs)]

use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

use bondry_core::{
    AdapterId, AutomationService, CapabilityDescriptor, CapabilityDiscoveryError, CapabilityEffect,
    CapabilityId, DispatchFuture, Invocation, Principal, PrincipalId, PrincipalKind,
};
use bondry_http_server::{
    Authentication, AuthenticationError, BearerAuthenticator, BearerTokenVerifier, LocalHttpServer,
    MountedProtocol, OriginPolicy, RateLimits, ServerConfiguration, ServerConfigurationError,
    ServerStartError,
};
use bondry_rest_proto::RestAdapter;
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
        LocalHttpServer::start(network_configuration, protocols()?),
        Err(ServerStartError::Configuration(
            ServerConfigurationError::CleartextNetworkExposure
        ))
    ));
    Ok(())
}
