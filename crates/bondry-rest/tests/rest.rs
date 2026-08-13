#![allow(missing_docs)]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bondry_core::{
    AdapterId, AuditError, AuditEvent, AuditOutcome, AuditSink, AutomationService,
    CapabilityDescriptor, CapabilityDiscoveryError, CapabilityEffect, CapabilityId,
    CapabilityRegistry, DenialReason, DispatchError, DispatchFuture, Dispatcher, GrantPolicy,
    HandlerError, HandlerErrorCode, Invocation, InvocationId, Principal, PrincipalId,
    PrincipalKind,
};
use bondry_http::{
    Authentication, InvocationIdGenerationError, InvocationIdGenerator, LocalHttpServer,
    ServerConfiguration,
};
use bondry_rest::RestAdapter;
use serde_json::{Value, json};

const STATUS_CAPABILITY: &str = "battery.status";
const FAILURE_CAPABILITY: &str = "battery.failure";
const HIDDEN_CAPABILITY: &str = "battery.hidden";

#[derive(Default)]
struct RecordingAudit {
    events: Mutex<Vec<AuditEvent>>,
}

impl RecordingAudit {
    fn outcomes(&self) -> Vec<AuditOutcome> {
        self.events.lock().map_or_else(
            |_| Vec::new(),
            |events| events.iter().map(|event| event.outcome().clone()).collect(),
        )
    }
}

impl AuditSink for RecordingAudit {
    fn record(&self, event: AuditEvent) -> Result<(), AuditError> {
        self.events
            .lock()
            .map_err(|_| AuditError::Unavailable)?
            .push(event);
        Ok(())
    }
}

#[derive(Default)]
struct SequentialIds(AtomicUsize);

impl InvocationIdGenerator for SequentialIds {
    fn generate(&self) -> Result<InvocationId, InvocationIdGenerationError> {
        let sequence = self.0.fetch_add(1, Ordering::Relaxed) + 1;
        InvocationId::new(format!("request_{sequence}")).map_err(|_| InvocationIdGenerationError)
    }
}

struct FailingIds;

impl InvocationIdGenerator for FailingIds {
    fn generate(&self) -> Result<InvocationId, InvocationIdGenerationError> {
        Err(InvocationIdGenerationError)
    }
}

struct UnavailableService;

impl AutomationService for UnavailableService {
    fn capabilities(
        &self,
        _principal: &Principal,
        _adapter: &AdapterId,
    ) -> Result<Vec<CapabilityDescriptor>, CapabilityDiscoveryError> {
        Err(CapabilityDiscoveryError::PolicyUnavailable)
    }

    fn dispatch(&self, _invocation: Invocation) -> DispatchFuture<'_> {
        Box::pin(async { Err(DispatchError::AccessDenied(DenialReason::PolicyUnavailable)) })
    }
}

struct Fixture {
    server: LocalHttpServer,
    audit: Arc<RecordingAudit>,
    handler_calls: Arc<AtomicUsize>,
}

impl Fixture {
    fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let principal = principal()?;
        let adapter = AdapterId::new("rest")?;
        let status = CapabilityId::new(STATUS_CAPABILITY)?;
        let failure = CapabilityId::new(FAILURE_CAPABILITY)?;
        let hidden = CapabilityId::new(HIDDEN_CAPABILITY)?;
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let mut registry = CapabilityRegistry::new();

        let status_calls = Arc::clone(&handler_calls);
        registry.register(
            CapabilityDescriptor::new(
                status.clone(),
                "Read the current battery status",
                CapabilityEffect::ReadOnly,
            )?
            .with_input_schema(json!({
                "type": "object",
                "properties": { "detail": { "type": "boolean" } },
                "required": ["detail"],
                "additionalProperties": false,
            }))?,
            move |_context, input: Value| {
                status_calls.fetch_add(1, Ordering::Relaxed);
                async move { Ok(json!({ "charging": true, "detail": input["detail"] })) }
            },
        )?;
        let failure_code = HandlerErrorCode::new("battery.unavailable")?;
        registry.register(
            CapabilityDescriptor::new(
                failure.clone(),
                "Return a stable failure",
                CapabilityEffect::ReadOnly,
            )?,
            move |_context, _input| {
                let failure_code = failure_code.clone();
                async move { Err(HandlerError::new(failure_code)) }
            },
        )?;
        registry.register(
            CapabilityDescriptor::new(
                hidden,
                "A capability without a REST grant",
                CapabilityEffect::Mutating,
            )?,
            |_context, _input| async { Ok(json!({ "hidden": true })) },
        )?;

        let policy = Arc::new(GrantPolicy::new());
        policy.grant(principal.id().clone(), adapter.clone(), status)?;
        policy.grant(principal.id().clone(), adapter, failure)?;
        let audit = Arc::new(RecordingAudit::default());
        let dispatcher = Dispatcher::from_shared(registry, policy, audit.clone());
        let service: Arc<dyn AutomationService> = Arc::new(dispatcher);
        let rest = RestAdapter::with_dependencies(
            service,
            AdapterId::new("rest")?,
            Arc::new(SequentialIds::default()),
        );
        let server = start_server(principal, rest)?;
        Ok(Self {
            server,
            audit,
            handler_calls,
        })
    }

    fn address(&self) -> SocketAddr {
        self.server.local_address()
    }
}

fn principal() -> Result<Principal, bondry_core::IdentifierError> {
    Ok(Principal::new(
        PrincipalId::new("client_test")?,
        PrincipalKind::Application,
    ))
}

fn start_server(
    principal: Principal,
    adapter: RestAdapter,
) -> Result<LocalHttpServer, Box<dyn std::error::Error>> {
    Ok(LocalHttpServer::start(
        ServerConfiguration::new(Authentication::disabled(principal)),
        vec![Arc::new(adapter)],
    )?)
}

fn request(address: SocketAddr, request: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn get(address: SocketAddr, path: &str) -> std::io::Result<String> {
    request(
        address,
        &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    )
}

fn post(
    address: SocketAddr,
    path: &str,
    content_type: Option<&str>,
    body: &str,
) -> std::io::Result<String> {
    let content_type =
        content_type.map_or_else(String::new, |value| format!("Content-Type: {value}\r\n"));
    request(
        address,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\n{content_type}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

fn header_value<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    response.lines().find_map(|line| {
        let (header, value) = line.split_once(':')?;
        header.eq_ignore_ascii_case(name).then_some(value.trim())
    })
}

fn body(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

fn json_body(response: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str(body(response))
}

#[test]
fn exposes_only_authorized_capability_metadata() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::start()?;

    let root = get(fixture.address(), "/api/v1")?;
    assert_eq!(status(&root), Some(200));
    assert_eq!(
        json_body(&root)?["resources"]["capabilities"],
        "/api/v1/capabilities"
    );

    let list = get(fixture.address(), "/api/v1/capabilities")?;
    assert_eq!(status(&list), Some(200));
    let list = json_body(&list)?;
    let capabilities = list["capabilities"].as_array().ok_or("missing array")?;
    assert_eq!(capabilities.len(), 2);
    assert_eq!(capabilities[0]["id"], FAILURE_CAPABILITY);
    assert_eq!(capabilities[1]["id"], STATUS_CAPABILITY);
    assert_eq!(capabilities[1]["effect"], "read_only");
    assert_eq!(capabilities[1]["inputSchema"]["required"][0], "detail");

    let one = get(fixture.address(), "/api/v1/capabilities/battery.status")?;
    assert_eq!(status(&one), Some(200));
    assert_eq!(json_body(&one)?["id"], STATUS_CAPABILITY);

    let hidden = get(fixture.address(), "/api/v1/capabilities/battery.hidden")?;
    assert_eq!(status(&hidden), Some(404));
    assert_eq!(json_body(&hidden)?["error"], "not_found");
    Ok(())
}

#[test]
fn invokes_an_authorized_capability() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::start()?;
    let response = post(
        fixture.address(),
        "/api/v1/capabilities/battery.status",
        Some("application/json; charset=utf-8"),
        r#"{"detail":true}"#,
    )?;

    assert_eq!(status(&response), Some(200));
    let response = json_body(&response)?;
    assert_eq!(response["invocationId"], "request_1");
    assert_eq!(
        response["result"],
        json!({ "charging": true, "detail": true })
    );
    assert_eq!(fixture.handler_calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        fixture.audit.outcomes(),
        vec![AuditOutcome::Started, AuditOutcome::Succeeded]
    );
    Ok(())
}

#[test]
fn validates_media_type_json_and_input_before_execution() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = Fixture::start()?;
    let path = "/api/v1/capabilities/battery.status";

    let missing_type = post(fixture.address(), path, None, r#"{"detail":true}"#)?;
    assert_eq!(status(&missing_type), Some(415));
    assert_eq!(json_body(&missing_type)?["error"], "unsupported_media_type");

    let malformed = post(fixture.address(), path, Some("application/json"), "{")?;
    assert_eq!(status(&malformed), Some(400));
    assert_eq!(json_body(&malformed)?["error"], "invalid_json");

    let invalid = post(fixture.address(), path, Some("application/json"), "{}")?;
    assert_eq!(status(&invalid), Some(422));
    let invalid = json_body(&invalid)?;
    assert_eq!(invalid["error"], "invalid_input");
    assert_eq!(invalid["invocationId"], "request_1");
    assert_eq!(fixture.handler_calls.load(Ordering::Relaxed), 0);
    assert_eq!(fixture.audit.outcomes(), vec![AuditOutcome::InvalidInput]);
    Ok(())
}

#[test]
fn conceals_denied_and_missing_capabilities() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::start()?;
    for path in [
        "/api/v1/capabilities/battery.hidden",
        "/api/v1/capabilities/battery.missing",
    ] {
        let response = post(fixture.address(), path, Some("application/json"), "{}")?;
        assert_eq!(status(&response), Some(404));
        assert_eq!(json_body(&response)?["error"], "not_found");
    }
    Ok(())
}

#[test]
fn exposes_only_stable_handler_failure_codes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::start()?;
    let response = post(
        fixture.address(),
        "/api/v1/capabilities/battery.failure",
        None,
        "",
    )?;

    assert_eq!(status(&response), Some(422));
    let response = json_body(&response)?;
    assert_eq!(response["error"], "capability_failed");
    assert_eq!(response["code"], "battery.unavailable");
    assert_eq!(response["invocationId"], "request_1");
    Ok(())
}

#[test]
fn maps_policy_and_identifier_outages_to_service_unavailable()
-> Result<(), Box<dyn std::error::Error>> {
    let principal = principal()?;
    let unavailable = RestAdapter::with_dependencies(
        Arc::new(UnavailableService),
        AdapterId::new("rest")?,
        Arc::new(SequentialIds::default()),
    );
    let unavailable_server = start_server(principal.clone(), unavailable)?;

    let list = get(unavailable_server.local_address(), "/api/v1/capabilities")?;
    assert_eq!(status(&list), Some(503));
    assert_eq!(json_body(&list)?["error"], "policy_unavailable");

    let invoke = post(
        unavailable_server.local_address(),
        "/api/v1/capabilities/battery.status",
        None,
        "",
    )?;
    assert_eq!(status(&invoke), Some(503));
    assert_eq!(json_body(&invoke)?["error"], "policy_unavailable");

    let failing = RestAdapter::with_dependencies(
        Arc::new(UnavailableService),
        AdapterId::new("rest")?,
        Arc::new(FailingIds),
    );
    let failing_server = start_server(principal, failing)?;
    let response = post(
        failing_server.local_address(),
        "/api/v1/capabilities/battery.status",
        None,
        "",
    )?;
    assert_eq!(status(&response), Some(503));
    assert_eq!(
        json_body(&response)?["error"],
        "identifier_generation_unavailable"
    );
    Ok(())
}

#[test]
fn rejects_unsupported_methods_and_paths() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::start()?;
    let method = request(
        fixture.address(),
        "DELETE /api/v1/capabilities/battery.status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )?;
    assert_eq!(status(&method), Some(405));
    assert_eq!(header_value(&method, "allow"), Some("GET, POST"));

    let nested = get(
        fixture.address(),
        "/api/v1/capabilities/battery.status/nested",
    )?;
    assert_eq!(status(&nested), Some(404));
    Ok(())
}
