#![allow(missing_docs)]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};

use bondry_core::{
    AdapterId, AutomationService, CapabilityDescriptor, CapabilityDiscoveryError, DenialReason,
    DispatchError, DispatchFuture, Invocation, Principal, PrincipalId, PrincipalKind,
};
use bondry_http::{Authentication, HttpAdapter, LocalHttpServer, ServerConfiguration};
use bondry_mcp::{McpAdapter, McpServerInfo};
use bondry_rest::RestAdapter;
use serde_json::Value;

const REST_REQUEST: &str = include_str!("../../../fixtures/protocol-v1/rest/root.request.http");
const REST_RESPONSE: &str = include_str!("../../../fixtures/protocol-v1/rest/root.response.json");
const MCP_REQUEST: &str = include_str!("../../../fixtures/protocol-v1/mcp/initialize.request.json");
const MCP_RESPONSE: &str =
    include_str!("../../../fixtures/protocol-v1/mcp/initialize.response.json");

struct EmptyService;

impl AutomationService for EmptyService {
    fn capabilities(
        &self,
        _principal: &Principal,
        _adapter: &AdapterId,
    ) -> Result<Vec<CapabilityDescriptor>, CapabilityDiscoveryError> {
        Ok(Vec::new())
    }

    fn dispatch(&self, _invocation: Invocation) -> DispatchFuture<'_> {
        Box::pin(async { Err(DispatchError::AccessDenied(DenialReason::NotGranted)) })
    }
}

#[test]
fn serves_rest_and_mcp_through_one_runtime() -> Result<(), Box<dyn std::error::Error>> {
    let principal = Principal::new(
        PrincipalId::new("phase_zero_test")?,
        PrincipalKind::Application,
    );
    let service: Arc<dyn AutomationService> = Arc::new(EmptyService);
    let rest = RestAdapter::new(Arc::clone(&service))?;
    let mcp = McpAdapter::new(
        service,
        McpServerInfo::new("phase-zero", "0.1.2")?.with_title("Phase Zero")?,
    )?;
    let adapters: Vec<Arc<dyn HttpAdapter>> = vec![Arc::new(rest), Arc::new(mcp)];
    let server = LocalHttpServer::start(
        ServerConfiguration::new(Authentication::disabled(principal)),
        adapters,
    )?;

    let rest_request = REST_REQUEST.replace('\n', "\r\n");
    let rest_response = request(server.local_address(), &rest_request)?;
    assert_response(&rest_response, 200, REST_RESPONSE)?;

    let mcp_body = compact_json(MCP_REQUEST)?;
    let mcp_request = format!(
        "POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        mcp_body.len(),
        mcp_body
    );
    let mcp_response = request(server.local_address(), &mcp_request)?;
    assert_response(&mcp_response, 200, MCP_RESPONSE)?;
    Ok(())
}

fn request(address: SocketAddr, request: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn assert_response(
    response: &str,
    expected_status: u16,
    expected_body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(status(response), Some(expected_status));
    assert_eq!(
        header(response, "content-type"),
        Some("application/json; charset=utf-8")
    );
    assert_eq!(header(response, "cache-control"), Some("no-store"));
    assert_eq!(header(response, "x-content-type-options"), Some("nosniff"));
    let expected: Value = serde_json::from_str(expected_body)?;
    assert_eq!(json_body(response)?, expected);
    Ok(())
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

fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    response.lines().find_map(|line| {
        let (header, value) = line.split_once(':')?;
        header.eq_ignore_ascii_case(name).then_some(value.trim())
    })
}

fn json_body(response: &str) -> Result<Value, serde_json::Error> {
    serde_json::from_str(response.split_once("\r\n\r\n").map_or("", |(_, body)| body))
}

fn compact_json(value: &str) -> Result<String, serde_json::Error> {
    serde_json::from_str::<Value>(value).and_then(|value| serde_json::to_string(&value))
}
