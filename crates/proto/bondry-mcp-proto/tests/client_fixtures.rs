#![doc = "MCP client protocol conformance fixtures."]

use bondry_mcp_proto::{
    McpClient, McpClientError, McpClientInfo, McpClientResponse, McpProtocolVersion,
    McpToolCallOutcome,
};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde_json::{Value, json};

const DISCOVER_REQUEST: &str =
    include_str!("../../../../fixtures/protocol-v1/mcp/discover.request.json");
const DISCOVER_RESPONSE: &str =
    include_str!("../../../../fixtures/protocol-v1/mcp/discover.response.json");
const LIST_REQUEST: &str =
    include_str!("../../../../fixtures/protocol-v1/mcp/tools-list.request.json");
const INITIALIZED_REQUEST: &str =
    include_str!("../../../../fixtures/protocol-v1/mcp/initialized.request.json");
const LIST_RESPONSE: &str =
    include_str!("../../../../fixtures/protocol-v1/mcp/tools-list.response.json");
const CALL_REQUEST: &str =
    include_str!("../../../../fixtures/protocol-v1/mcp/tools-call.request.json");
const CALL_RESPONSE: &str =
    include_str!("../../../../fixtures/protocol-v1/mcp/tools-call.response.json");
const UNSUPPORTED_VERSION: &str =
    include_str!("../../../../fixtures/protocol-v1/mcp/unsupported-version.response.json");

fn client() -> Result<McpClient, Box<dyn std::error::Error>> {
    Ok(McpClient::new(McpClientInfo::new(
        "bondry-egress",
        "0.2.0",
    )?))
}

fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers
}

fn request_json(
    request: bondry_mcp_proto::McpClientRequest,
) -> Result<(Value, bondry_mcp_proto::McpResponseDecoder), Box<dyn std::error::Error>> {
    let (_, body, decoder) = request.into_parts().into_values();
    Ok((serde_json::from_slice(&body)?, decoder))
}

#[test]
fn client_requests_match_protocol_fixtures() -> Result<(), Box<dyn std::error::Error>> {
    let client = client()?;
    let (discover, _) = request_json(client.discover(1)?)?;
    let (initialized, _) = request_json(client.initialized(McpProtocolVersion::V2025_11_25)?)?;
    let (list, _) = request_json(client.list_tools(2, McpProtocolVersion::V2026_07_28, 256)?)?;
    let (call, _) = request_json(client.call_tool(
        3,
        McpProtocolVersion::V2026_07_28,
        "battery:status",
        json!({ "detail": true }),
    )?)?;

    assert_eq!(discover, serde_json::from_str::<Value>(DISCOVER_REQUEST)?);
    assert_eq!(
        initialized,
        serde_json::from_str::<Value>(INITIALIZED_REQUEST)?
    );
    assert_eq!(list, serde_json::from_str::<Value>(LIST_REQUEST)?);
    assert_eq!(call, serde_json::from_str::<Value>(CALL_REQUEST)?);
    Ok(())
}

#[test]
fn client_responses_match_protocol_fixtures() -> Result<(), Box<dyn std::error::Error>> {
    let client = client()?;
    let (_, discovery) = request_json(client.discover(1)?)?;
    assert!(matches!(
        discovery.decode(StatusCode::OK, &headers(), DISCOVER_RESPONSE.as_bytes())?,
        McpClientResponse::Discovery(discovery)
            if discovery.version() == McpProtocolVersion::V2026_07_28
    ));

    let (_, list) = request_json(client.list_tools(2, McpProtocolVersion::V2026_07_28, 256)?)?;
    assert!(matches!(
        list.decode(StatusCode::OK, &headers(), LIST_RESPONSE.as_bytes())?,
        McpClientResponse::Tools(tools)
            if tools.tools().len() == 1 && tools.tools()[0].name() == "battery:status"
    ));

    let (_, call) = request_json(client.call_tool(
        3,
        McpProtocolVersion::V2026_07_28,
        "battery:status",
        json!({ "detail": true }),
    )?)?;
    assert!(matches!(
        call.decode(StatusCode::OK, &headers(), CALL_RESPONSE.as_bytes())?,
        McpClientResponse::ToolCall(result)
            if result.outcome() == McpToolCallOutcome::Succeeded
    ));
    Ok(())
}

#[test]
fn unsupported_version_fixture_is_stable() -> Result<(), Box<dyn std::error::Error>> {
    let (_, decoder) = request_json(client()?.discover(1)?)?;
    assert!(matches!(
        decoder.decode(
            StatusCode::BAD_REQUEST,
            &headers(),
            UNSUPPORTED_VERSION.as_bytes()
        ),
        Err(McpClientError::UnsupportedProtocolVersion)
    ));
    Ok(())
}
