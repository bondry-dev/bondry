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
use bondry_mcp::{LATEST_PROTOCOL_VERSION, MCP_PATH, McpAdapter, McpServerInfo};
use serde_json::{Value, json};

const STATUS_CAPABILITY: &str = "battery.status";
const FAILURE_CAPABILITY: &str = "battery.failure";
const HIDDEN_CAPABILITY: &str = "battery.hidden";
const INCOMPATIBLE_CAPABILITY: &str = "battery:legacy";

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
        let adapter = AdapterId::new("mcp")?;
        let status = CapabilityId::new(STATUS_CAPABILITY)?;
        let failure = CapabilityId::new(FAILURE_CAPABILITY)?;
        let hidden = CapabilityId::new(HIDDEN_CAPABILITY)?;
        let incompatible = CapabilityId::new(INCOMPATIBLE_CAPABILITY)?;
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
                "properties": {
                    "detail": { "type": "boolean", "x-mcp-header": "Detail" }
                },
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
                "A capability without an MCP grant",
                CapabilityEffect::Mutating,
            )?,
            |_context, _input| async { Ok(json!({ "hidden": true })) },
        )?;
        registry.register(
            CapabilityDescriptor::new(
                incompatible.clone(),
                "A capability whose identifier is not an MCP tool name",
                CapabilityEffect::ReadOnly,
            )?,
            |_context, _input| async { Ok(json!({ "legacy": true })) },
        )?;

        let policy = Arc::new(GrantPolicy::new());
        for capability in [status, failure, incompatible] {
            policy.grant(principal.id().clone(), adapter.clone(), capability)?;
        }
        let audit = Arc::new(RecordingAudit::default());
        let dispatcher = Dispatcher::from_shared(registry, policy, audit.clone());
        let service: Arc<dyn AutomationService> = Arc::new(dispatcher);
        let mcp = McpAdapter::with_dependencies(
            service,
            adapter,
            Arc::new(SequentialIds::default()),
            server_info()?,
        );
        let server = start_server(principal, mcp)?;
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

fn server_info() -> Result<McpServerInfo, bondry_mcp::McpServerInfoError> {
    McpServerInfo::new("battery-app", "2.3.1")?.with_title("Battery App")
}

fn start_server(
    principal: Principal,
    adapter: McpAdapter,
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

fn post(
    address: SocketAddr,
    body: &str,
    content_type: Option<&str>,
    accept: Option<&str>,
    version: Option<&str>,
) -> std::io::Result<String> {
    post_routed(address, body, content_type, accept, version, None, None)
}

#[allow(clippy::too_many_arguments)]
fn post_routed(
    address: SocketAddr,
    body: &str,
    content_type: Option<&str>,
    accept: Option<&str>,
    version: Option<&str>,
    method: Option<&str>,
    name: Option<&str>,
) -> std::io::Result<String> {
    let content_type =
        content_type.map_or_else(String::new, |value| format!("Content-Type: {value}\r\n"));
    let accept = accept.map_or_else(String::new, |value| format!("Accept: {value}\r\n"));
    let version = version.map_or_else(String::new, |value| {
        format!("MCP-Protocol-Version: {value}\r\n")
    });
    let method = method.map_or_else(String::new, |value| format!("Mcp-Method: {value}\r\n"));
    let name = name.map_or_else(String::new, |value| format!("Mcp-Name: {value}\r\n"));
    request(
        address,
        &format!(
            "POST {MCP_PATH} HTTP/1.1\r\nHost: localhost\r\n{content_type}{accept}{version}{method}{name}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
}

fn mcp_post(address: SocketAddr, mut body: Value) -> std::io::Result<String> {
    let method = body
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let name = if method.is_some() {
        if body.get("params").is_none() {
            body["params"] = json!({});
        }
        let Some(params) = body.get_mut("params").and_then(Value::as_object_mut) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "modern MCP params must be an object",
            ));
        };
        params.insert(
            "_meta".to_owned(),
            json!({
                "io.modelcontextprotocol/protocolVersion": LATEST_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientInfo": {
                    "name": "test-client",
                    "version": "1.0",
                },
                "io.modelcontextprotocol/clientCapabilities": {},
            }),
        );
        params
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned)
    } else {
        None
    };
    post_routed(
        address,
        &serde_json::to_string(&body).unwrap_or_default(),
        Some("application/json"),
        Some("application/json, text/event-stream"),
        Some(LATEST_PROTOCOL_VERSION),
        method.as_deref(),
        name.as_deref(),
    )
}

fn initialize(address: SocketAddr, version: &str) -> std::io::Result<String> {
    post(
        address,
        &serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": version,
                "capabilities": {},
                "clientInfo": { "name": "test-client", "version": "1.0" },
            },
        }))
        .unwrap_or_default(),
        Some("application/json"),
        Some("application/json, text/event-stream"),
        None,
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
fn enforces_streamable_http_transport_requirements() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::start()?;
    let ping = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;

    let media_type = post(
        fixture.address(),
        ping,
        Some("application/json, text/plain"),
        Some("application/json, text/event-stream"),
        Some(LATEST_PROTOCOL_VERSION),
    )?;
    assert_eq!(status(&media_type), Some(415));

    let accept = post(
        fixture.address(),
        ping,
        Some("application/json"),
        Some("application/json"),
        Some(LATEST_PROTOCOL_VERSION),
    )?;
    assert_eq!(status(&accept), Some(406));

    let missing_version = post(
        fixture.address(),
        ping,
        Some("application/json"),
        Some("application/json, text/event-stream"),
        None,
    )?;
    assert_eq!(status(&missing_version), Some(400));
    assert_eq!(json_body(&missing_version)?["error"]["code"], -32_020);

    let old_version = post(
        fixture.address(),
        ping,
        Some("application/json"),
        Some("application/json, text/event-stream"),
        Some("2025-03-26"),
    )?;
    assert_eq!(status(&old_version), Some(400));
    let old_version = json_body(&old_version)?;
    assert_eq!(old_version["error"]["code"], -32_022);
    assert_eq!(old_version["error"]["data"]["requested"], "2025-03-26");

    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": LATEST_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }))?;
    let missing_routing = post(
        fixture.address(),
        &body,
        Some("application/json"),
        Some("application/json, text/event-stream"),
        Some(LATEST_PROTOCOL_VERSION),
    )?;
    assert_eq!(status(&missing_routing), Some(400));
    assert_eq!(json_body(&missing_routing)?["error"]["code"], -32_020);

    let mismatched_body = body.replace(LATEST_PROTOCOL_VERSION, "2025-11-25");
    let mismatched_version = post_routed(
        fixture.address(),
        &mismatched_body,
        Some("application/json"),
        Some("application/json, text/event-stream"),
        Some(LATEST_PROTOCOL_VERSION),
        Some("tools/list"),
        None,
    )?;
    assert_eq!(status(&mismatched_version), Some(400));
    assert_eq!(json_body(&mismatched_version)?["error"]["code"], -32_020);

    let missing_metadata = post_routed(
        fixture.address(),
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
        Some("application/json"),
        Some("application/json, text/event-stream"),
        Some(LATEST_PROTOCOL_VERSION),
        Some("tools/list"),
        None,
    )?;
    assert_eq!(status(&missing_metadata), Some(400));
    assert_eq!(json_body(&missing_metadata)?["error"]["code"], -32_602);

    for method in ["GET", "DELETE"] {
        let response = request(
            fixture.address(),
            &format!(
                "{method} {MCP_PATH} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            ),
        )?;
        assert_eq!(status(&response), Some(405));
        assert_eq!(header_value(&response, "allow"), Some("POST"));
    }
    Ok(())
}

#[test]
fn supports_modern_discovery_and_legacy_initialization() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::start()?;

    let discovery = mcp_post(
        fixture.address(),
        json!({ "jsonrpc": "2.0", "id": "discover", "method": "server/discover" }),
    )?;
    assert_eq!(status(&discovery), Some(200));
    let discovery = json_body(&discovery)?;
    assert_eq!(discovery["result"]["resultType"], "complete");
    assert_eq!(
        discovery["result"]["supportedVersions"][0],
        LATEST_PROTOCOL_VERSION
    );
    assert_eq!(
        discovery["result"]["capabilities"]["tools"]["listChanged"],
        false
    );
    assert_eq!(discovery["result"]["ttlMs"], 0);
    assert_eq!(discovery["result"]["cacheScope"], "private");
    assert_eq!(
        discovery["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "battery-app"
    );

    let legacy = initialize(fixture.address(), "2025-11-25")?;
    assert_eq!(status(&legacy), Some(200));
    let legacy = json_body(&legacy)?;
    assert_eq!(legacy["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(legacy["result"]["serverInfo"]["title"], "Battery App");
    assert!(legacy["result"].get("resultType").is_none());
    Ok(())
}

#[test]
fn handles_messages_according_to_the_selected_protocol_era()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::start()?;
    let modern_notification = mcp_post(
        fixture.address(),
        json!({ "jsonrpc": "2.0", "method": "notifications/example" }),
    )?;
    assert_eq!(status(&modern_notification), Some(202));

    let legacy_notification = post(
        fixture.address(),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        Some("application/json"),
        Some("application/json, text/event-stream"),
        Some("2025-11-25"),
    )?;
    assert_eq!(status(&legacy_notification), Some(202));

    let modern_response = mcp_post(
        fixture.address(),
        json!({ "jsonrpc": "2.0", "id": "server-request", "result": {} }),
    )?;
    assert_eq!(status(&modern_response), Some(400));
    assert_eq!(json_body(&modern_response)?["error"]["code"], -32_600);
    Ok(())
}

#[test]
fn rejects_malformed_json_rpc_messages() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::start()?;
    let malformed = post(
        fixture.address(),
        "{",
        Some("application/json"),
        Some("application/json, text/event-stream"),
        Some(LATEST_PROTOCOL_VERSION),
    )?;
    assert_eq!(status(&malformed), Some(400));
    assert_eq!(json_body(&malformed)?["error"]["code"], -32_700);

    for message in [
        json!([]),
        json!({ "jsonrpc": "2.0", "id": null, "method": "ping" }),
    ] {
        let response = mcp_post(fixture.address(), message)?;
        assert_eq!(status(&response), Some(400));
        assert_eq!(json_body(&response)?["error"]["code"], -32_600);
    }
    let invalid_notification = post(
        fixture.address(),
        r#"{"jsonrpc":"2.0","method":"notification","params":[]}"#,
        Some("application/json"),
        Some("application/json, text/event-stream"),
        Some(LATEST_PROTOCOL_VERSION),
    )?;
    assert_eq!(json_body(&invalid_notification)?["error"]["code"], -32_600);
    Ok(())
}

#[test]
fn lists_authorized_tools_in_stable_order() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::start()?;
    let response = mcp_post(
        fixture.address(),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
    )?;

    assert_eq!(status(&response), Some(200));
    let response = json_body(&response)?;
    let tools = response["result"]["tools"]
        .as_array()
        .ok_or("missing tools")?;
    assert_eq!(tools.len(), 3);
    assert_eq!(tools[0]["name"], FAILURE_CAPABILITY);
    assert_eq!(tools[1]["name"], STATUS_CAPABILITY);
    assert_eq!(tools[2]["name"], INCOMPATIBLE_CAPABILITY);
    assert_eq!(tools[1]["annotations"]["readOnlyHint"], true);
    assert_eq!(tools[1]["inputSchema"]["required"][0], "detail");
    assert!(
        tools[1]["inputSchema"]["properties"]["detail"]
            .get("x-mcp-header")
            .is_none()
    );
    assert_eq!(response["result"]["resultType"], "complete");
    assert_eq!(response["result"]["ttlMs"], 0);
    assert_eq!(response["result"]["cacheScope"], "private");
    Ok(())
}

#[test]
fn invokes_tools_with_structured_and_text_results() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::start()?;
    let response = mcp_post(
        fixture.address(),
        json!({
            "jsonrpc": "2.0",
            "id": "call-one",
            "method": "tools/call",
            "params": { "name": STATUS_CAPABILITY, "arguments": { "detail": true } },
        }),
    )?;

    assert_eq!(status(&response), Some(200));
    let response = json_body(&response)?;
    assert_eq!(response["id"], "call-one");
    assert_eq!(response["result"]["resultType"], "complete");
    assert_eq!(
        response["result"]["structuredContent"],
        json!({ "charging": true, "detail": true })
    );
    assert_eq!(
        response["result"]["content"][0]["text"],
        r#"{"charging":true,"detail":true}"#
    );
    assert_eq!(
        response["result"]["_meta"]["dev.bondry/invocationId"],
        "request_1"
    );
    assert_eq!(fixture.handler_calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        fixture.audit.outcomes(),
        vec![AuditOutcome::Started, AuditOutcome::Succeeded]
    );

    let encoded_name_body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": "encoded-name",
        "method": "tools/call",
        "params": {
            "name": INCOMPATIBLE_CAPABILITY,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": LATEST_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }))?;
    let encoded_name = post_routed(
        fixture.address(),
        &encoded_name_body,
        Some("application/json"),
        Some("application/json, text/event-stream"),
        Some(LATEST_PROTOCOL_VERSION),
        Some("tools/call"),
        Some("=?base64?YmF0dGVyeTpsZWdhY3k=?="),
    )?;
    assert_eq!(status(&encoded_name), Some(200));
    assert_eq!(
        json_body(&encoded_name)?["result"]["structuredContent"]["legacy"],
        true
    );
    Ok(())
}

#[test]
fn preserves_the_2025_11_25_tool_flow() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::start()?;
    let list = post(
        fixture.address(),
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        Some("application/json"),
        Some("application/json, text/event-stream"),
        Some("2025-11-25"),
    )?;
    assert_eq!(status(&list), Some(200));
    let list = json_body(&list)?;
    assert!(list["result"].get("resultType").is_none());
    assert!(list["result"].get("ttlMs").is_none());

    let call_body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": { "name": STATUS_CAPABILITY, "arguments": { "detail": false } },
    }))?;
    let call = post(
        fixture.address(),
        &call_body,
        Some("application/json"),
        Some("application/json, text/event-stream"),
        Some("2025-11-25"),
    )?;
    assert_eq!(status(&call), Some(200));
    let call = json_body(&call)?;
    assert!(call["result"].get("resultType").is_none());
    assert_eq!(call["result"]["structuredContent"]["detail"], false);
    Ok(())
}

#[test]
fn returns_tool_execution_errors_for_input_and_handler_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::start()?;
    let invalid = mcp_post(
        fixture.address(),
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": STATUS_CAPABILITY, "arguments": {} },
        }),
    )?;
    let invalid = json_body(&invalid)?;
    assert_eq!(invalid["result"]["isError"], true);
    assert_eq!(
        invalid["result"]["content"][0]["text"],
        "Capability input is invalid"
    );
    assert_eq!(fixture.handler_calls.load(Ordering::Relaxed), 0);

    let failure = mcp_post(
        fixture.address(),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": FAILURE_CAPABILITY },
        }),
    )?;
    let failure = json_body(&failure)?;
    assert_eq!(failure["result"]["isError"], true);
    assert_eq!(
        failure["result"]["content"][0]["text"],
        "Capability execution failed"
    );
    assert_eq!(
        failure["result"]["_meta"]["dev.bondry/errorCode"],
        "battery.unavailable"
    );
    assert_eq!(
        fixture.audit.outcomes(),
        vec![
            AuditOutcome::InvalidInput,
            AuditOutcome::Started,
            AuditOutcome::HandlerFailed(HandlerErrorCode::new("battery.unavailable")?),
        ]
    );
    Ok(())
}

#[test]
fn conceals_denied_and_missing_capabilities() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::start()?;
    for name in [HIDDEN_CAPABILITY, "battery.missing"] {
        let response = mcp_post(
            fixture.address(),
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": name },
            }),
        )?;
        let response = json_body(&response)?;
        assert_eq!(response["error"]["code"], -32_602);
        assert_eq!(response["error"]["message"], "Unknown tool");
    }
    Ok(())
}

#[test]
fn maps_protocol_and_service_failures_without_private_details()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::start()?;
    let method = mcp_post(
        fixture.address(),
        json!({ "jsonrpc": "2.0", "id": 1, "method": "unknown" }),
    )?;
    assert_eq!(status(&method), Some(404));
    assert_eq!(json_body(&method)?["error"]["code"], -32_601);

    let params = mcp_post(
        fixture.address(),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": { "cursor": "unknown" },
        }),
    )?;
    assert_eq!(json_body(&params)?["error"]["code"], -32_602);

    let principal = principal()?;
    let unavailable = McpAdapter::with_dependencies(
        Arc::new(UnavailableService),
        AdapterId::new("mcp")?,
        Arc::new(SequentialIds::default()),
        server_info()?,
    );
    let unavailable_server = start_server(principal.clone(), unavailable)?;
    let list = mcp_post(
        unavailable_server.local_address(),
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
    )?;
    assert_eq!(json_body(&list)?["error"]["code"], -32_603);

    let call = mcp_post(
        unavailable_server.local_address(),
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": STATUS_CAPABILITY },
        }),
    )?;
    assert_eq!(json_body(&call)?["error"]["code"], -32_603);

    let failing_ids = McpAdapter::with_dependencies(
        Arc::new(UnavailableService),
        AdapterId::new("mcp")?,
        Arc::new(FailingIds),
        server_info()?,
    );
    let failing_server = start_server(principal, failing_ids)?;
    let call = mcp_post(
        failing_server.local_address(),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": STATUS_CAPABILITY },
        }),
    )?;
    assert_eq!(json_body(&call)?["error"]["code"], -32_603);
    Ok(())
}
