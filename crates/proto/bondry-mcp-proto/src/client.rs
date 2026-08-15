use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode, header};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::{
    LATEST_PROTOCOL_VERSION, McpClientInfo, McpProtocolVersion, SUPPORTED_PROTOCOL_VERSIONS,
    protocol::{
        CALL_TOOL_METHOD, CLIENT_CAPABILITIES_META, CLIENT_INFO_META, DISCOVER_METHOD,
        INITIALIZE_METHOD, LIST_TOOLS_METHOD, METHOD_HEADER, Message, NAME_HEADER,
        PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION_META, RpcResponsePayload,
    },
};

/// Stateless builder for bounded MCP Streamable HTTP client messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpClient {
    info: McpClientInfo,
}

impl McpClient {
    /// Creates a client that identifies itself with validated implementation metadata.
    #[must_use]
    pub const fn new(info: McpClientInfo) -> Self {
        Self { info }
    }

    /// Creates modern server discovery for protocol negotiation.
    pub fn discover(&self, id: u64) -> Result<McpClientRequest, McpClientRequestError> {
        self.request(
            id,
            DISCOVER_METHOD,
            Some(Value::Object(Map::new())),
            Some(McpProtocolVersion::V2026_07_28),
            ResponseShape::Discovery,
        )
    }

    /// Creates legacy initialization for a server that cannot perform modern discovery.
    pub fn initialize(&self, id: u64) -> Result<McpClientRequest, McpClientRequestError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": INITIALIZE_METHOD,
            "params": {
                "protocolVersion": LATEST_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": self.info.as_json(),
            },
        });
        McpClientRequest::new(id, body, None, ResponseShape::Initialization)
    }

    /// Creates a tool-list request for a negotiated protocol revision.
    pub fn list_tools(
        &self,
        id: u64,
        version: McpProtocolVersion,
    ) -> Result<McpClientRequest, McpClientRequestError> {
        self.request(
            id,
            LIST_TOOLS_METHOD,
            version.is_modern().then(|| Value::Object(Map::new())),
            Some(version),
            ResponseShape::ToolList,
        )
    }

    /// Creates a fixed tool call using an object-shaped arguments payload.
    pub fn call_tool(
        &self,
        id: u64,
        version: McpProtocolVersion,
        name: &str,
        arguments: Value,
    ) -> Result<McpClientRequest, McpClientRequestError> {
        if name.trim().is_empty() || name.chars().any(char::is_control) {
            return Err(McpClientRequestError::InvalidToolName);
        }
        if !arguments.is_object() {
            return Err(McpClientRequestError::InvalidArguments);
        }
        self.request(
            id,
            CALL_TOOL_METHOD,
            Some(json!({ "name": name, "arguments": arguments })),
            Some(version),
            ResponseShape::ToolCall,
        )
    }

    fn request(
        &self,
        id: u64,
        method: &'static str,
        params: Option<Value>,
        version: Option<McpProtocolVersion>,
        response: ResponseShape,
    ) -> Result<McpClientRequest, McpClientRequestError> {
        let mut params = params;
        if let Some(version) = version.filter(|version| version.is_modern()) {
            let object = params
                .get_or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .ok_or(McpClientRequestError::InvalidArguments)?;
            object.insert("_meta".to_owned(), self.modern_metadata(version));
        }
        let mut body = json!({ "jsonrpc": "2.0", "id": id, "method": method });
        if let Some(params) = params {
            body["params"] = params;
        }
        let name = (method == CALL_TOOL_METHOD)
            .then(|| {
                body["params"]["name"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(McpClientRequestError::InvalidToolName)
            })
            .transpose()?;
        let routing = version.map(|version| (version, method, name.as_deref()));
        McpClientRequest::new(id, body, routing, response)
    }

    fn modern_metadata(&self, version: McpProtocolVersion) -> Value {
        let mut metadata = Map::new();
        metadata.insert(
            PROTOCOL_VERSION_META.to_owned(),
            Value::String(version.as_str().to_owned()),
        );
        metadata.insert(CLIENT_INFO_META.to_owned(), self.info.as_json());
        metadata.insert(
            CLIENT_CAPABILITIES_META.to_owned(),
            Value::Object(Map::new()),
        );
        Value::Object(metadata)
    }
}

/// One protocol request awaiting transport composition.
pub struct McpClientRequest {
    headers: HeaderMap,
    body: Bytes,
    decoder: McpResponseDecoder,
}

impl McpClientRequest {
    fn new(
        id: u64,
        body: Value,
        routing: Option<(McpProtocolVersion, &'static str, Option<&str>)>,
        response: ResponseShape,
    ) -> Result<Self, McpClientRequestError> {
        let mut headers = HeaderMap::with_capacity(5);
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        if let Some((version, method, name)) = routing {
            headers.insert(
                PROTOCOL_VERSION_HEADER,
                HeaderValue::from_static(version.as_str()),
            );
            if version.is_modern() {
                headers.insert(METHOD_HEADER, HeaderValue::from_static(method));
                if let Some(name) = name {
                    headers.insert(NAME_HEADER, encoded_name_header(name)?);
                }
            }
        }
        let body = serde_json::to_vec(&body)
            .map(Bytes::from)
            .map_err(|_| McpClientRequestError::Encoding)?;
        Ok(Self {
            headers,
            body,
            decoder: McpResponseDecoder {
                id,
                version: routing.map(|(version, _, _)| version),
                shape: response,
            },
        })
    }

    /// Moves bounded protocol fields into transport-facing parts.
    #[must_use]
    pub fn into_parts(self) -> McpClientRequestParts {
        McpClientRequestParts {
            headers: self.headers,
            body: self.body,
            decoder: self.decoder,
        }
    }
}

/// Bounded MCP request fields and the matching response decoder.
pub struct McpClientRequestParts {
    headers: HeaderMap,
    body: Bytes,
    decoder: McpResponseDecoder,
}

impl McpClientRequestParts {
    /// Returns protocol-owned request headers.
    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns exact request body bytes.
    #[must_use]
    pub const fn body(&self) -> &Bytes {
        &self.body
    }

    /// Moves all fields into their transport-facing values.
    #[must_use]
    pub fn into_values(self) -> (HeaderMap, Bytes, McpResponseDecoder) {
        (self.headers, self.body, self.decoder)
    }
}

/// Response validator bound to one request identifier and operation shape.
pub struct McpResponseDecoder {
    id: u64,
    version: Option<McpProtocolVersion>,
    shape: ResponseShape,
}

impl McpResponseDecoder {
    /// Validates HTTP response mode and JSON-RPC framing before exposing typed data.
    pub fn decode(
        self,
        status: StatusCode,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<McpClientResponse, McpClientError> {
        validate_content_type(headers)?;
        let message = crate::protocol::parse(body).map_err(|error| {
            if error.code == -32_700 {
                McpClientError::InvalidJson
            } else {
                McpClientError::InvalidEnvelope
            }
        })?;
        let Message::Response(response) = message else {
            return Err(McpClientError::InvalidEnvelope);
        };
        if response.id.as_u64() != Some(self.id) {
            return Err(McpClientError::MismatchedResponseId);
        }
        match response.payload {
            RpcResponsePayload::Error(error) => Err(classify_remote_error(error.code)),
            RpcResponsePayload::Result(result) => {
                if !status.is_success() {
                    return Err(McpClientError::UnexpectedHttpStatus);
                }
                if self.version.is_some_and(McpProtocolVersion::is_modern)
                    && result.get("resultType") != Some(&Value::String("complete".to_owned()))
                {
                    return Err(McpClientError::UnsupportedResponseMode);
                }
                self.decode_result(result)
            }
        }
    }

    fn decode_result(self, result: Value) -> Result<McpClientResponse, McpClientError> {
        match self.shape {
            ResponseShape::Discovery => parse_discovery(result).map(McpClientResponse::Discovery),
            ResponseShape::Initialization => {
                parse_initialization(result).map(McpClientResponse::Initialized)
            }
            ResponseShape::ToolList => parse_tool_list(result).map(McpClientResponse::Tools),
            ResponseShape::ToolCall => parse_tool_call(result).map(McpClientResponse::ToolCall),
        }
    }
}

#[derive(Clone, Copy)]
enum ResponseShape {
    Discovery,
    Initialization,
    ToolList,
    ToolCall,
}

/// Validated response to one MCP client request.
pub enum McpClientResponse {
    /// Modern server discovery and supported revisions.
    Discovery(McpDiscovery),
    /// Legacy initialization and selected revision.
    Initialized(McpInitialization),
    /// Bounded tool descriptors.
    Tools(McpToolList),
    /// One valid bounded tool result.
    ToolCall(McpToolCallResult),
}

/// Modern discovery data used to select a mutually supported revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpDiscovery {
    version: McpProtocolVersion,
}

impl McpDiscovery {
    /// Returns the highest mutually supported revision, independent of peer ordering.
    #[must_use]
    pub const fn version(&self) -> McpProtocolVersion {
        self.version
    }
}

/// Legacy initialization result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpInitialization {
    version: McpProtocolVersion,
}

impl McpInitialization {
    /// Returns the server-selected supported revision.
    #[must_use]
    pub const fn version(&self) -> McpProtocolVersion {
        self.version
    }
}

/// One discovered MCP tool descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpTool {
    name: String,
    description: Option<String>,
    input_schema: Value,
}

impl McpTool {
    /// Returns the protocol tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the optional user-facing tool description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the discovered JSON input schema.
    #[must_use]
    pub const fn input_schema(&self) -> &Value {
        &self.input_schema
    }
}

/// Validated tool-list response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpToolList {
    tools: Vec<McpTool>,
}

impl McpToolList {
    /// Returns tools in receiver-provided order.
    #[must_use]
    pub fn tools(&self) -> &[McpTool] {
        &self.tools
    }
}

/// Receiver-declared tool execution outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpToolCallOutcome {
    /// The receiver returned a successful tool result.
    Succeeded,
    /// The receiver returned a valid tool-level failure result.
    Failed,
}

/// Bounded JSON tool result with no application-level interpretation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpToolCallResult {
    outcome: McpToolCallOutcome,
    json: Bytes,
}

impl McpToolCallResult {
    /// Returns the receiver-declared outcome category.
    #[must_use]
    pub const fn outcome(&self) -> McpToolCallOutcome {
        self.outcome
    }

    /// Returns the validated raw JSON result object.
    #[must_use]
    pub const fn json(&self) -> &Bytes {
        &self.json
    }
}

/// Stable, non-sensitive client response failure taxonomy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpClientError {
    /// The response selects SSE or another unsupported streaming mode.
    #[error("MCP response mode is unsupported")]
    UnsupportedResponseMode,
    /// The response does not carry one JSON content type.
    #[error("MCP response content type is invalid")]
    InvalidContentType,
    /// A non-error result arrived with a non-success HTTP status.
    #[error("MCP response HTTP status is invalid")]
    UnexpectedHttpStatus,
    /// Response bytes are not valid JSON.
    #[error("MCP response is not valid JSON")]
    InvalidJson,
    /// Response JSON-RPC framing or result shape is invalid.
    #[error("MCP response framing is invalid")]
    InvalidEnvelope,
    /// The response identifier does not match its request.
    #[error("MCP response identifier does not match")]
    MismatchedResponseId,
    /// No supported protocol revision was accepted by the peer.
    #[error("MCP protocol version is unsupported")]
    UnsupportedProtocolVersion,
    /// The peer does not implement the requested method.
    #[error("MCP method is unsupported")]
    MethodNotFound,
    /// The peer rejected request framing or parameters.
    #[error("MCP request was rejected")]
    RequestRejected,
    /// The peer could not service the request.
    #[error("MCP peer is unavailable")]
    PeerUnavailable,
    /// The peer returned another protocol failure category.
    #[error("MCP peer returned an operation failure")]
    RemoteFailure,
}

/// A local request shape that cannot be encoded safely.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpClientRequestError {
    /// The fixed tool name is empty or contains control characters.
    #[error("MCP tool name is invalid")]
    InvalidToolName,
    /// Tool arguments are not a JSON object.
    #[error("MCP tool arguments must be a JSON object")]
    InvalidArguments,
    /// A validated request could not be encoded.
    #[error("MCP request encoding failed")]
    Encoding,
}

fn encoded_name_header(name: &str) -> Result<HeaderValue, McpClientRequestError> {
    let encoded = format!("=?base64?{}?=", STANDARD.encode(name));
    HeaderValue::from_str(&encoded).map_err(|_| McpClientRequestError::InvalidToolName)
}

fn validate_content_type(headers: &HeaderMap) -> Result<(), McpClientError> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let value = values.next().ok_or(McpClientError::InvalidContentType)?;
    if values.next().is_some() {
        return Err(McpClientError::InvalidContentType);
    }
    let value = value
        .to_str()
        .map_err(|_| McpClientError::InvalidContentType)?;
    let media_type = value.split(';').next().map(str::trim).unwrap_or_default();
    if media_type.eq_ignore_ascii_case("text/event-stream") {
        return Err(McpClientError::UnsupportedResponseMode);
    }
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err(McpClientError::InvalidContentType);
    }
    Ok(())
}

fn classify_remote_error(code: i64) -> McpClientError {
    match code {
        -32_022 => McpClientError::UnsupportedProtocolVersion,
        -32_601 => McpClientError::MethodNotFound,
        -32_700 | -32_600 | -32_602 | -32_020 => McpClientError::RequestRejected,
        -32_603 => McpClientError::PeerUnavailable,
        _ => McpClientError::RemoteFailure,
    }
}

fn parse_discovery(result: Value) -> Result<McpDiscovery, McpClientError> {
    let versions = result
        .get("supportedVersions")
        .and_then(Value::as_array)
        .ok_or(McpClientError::InvalidEnvelope)?;
    let selected = SUPPORTED_PROTOCOL_VERSIONS.iter().find_map(|supported| {
        versions
            .iter()
            .any(|version| version.as_str() == Some(supported))
            .then(|| McpProtocolVersion::parse(supported))
            .flatten()
    });
    selected
        .map(|version| McpDiscovery { version })
        .ok_or(McpClientError::UnsupportedProtocolVersion)
}

fn parse_initialization(result: Value) -> Result<McpInitialization, McpClientError> {
    let version = result
        .get("protocolVersion")
        .and_then(Value::as_str)
        .and_then(McpProtocolVersion::parse)
        .ok_or(McpClientError::UnsupportedProtocolVersion)?;
    Ok(McpInitialization { version })
}

fn parse_tool_list(result: Value) -> Result<McpToolList, McpClientError> {
    let tools = result
        .get("tools")
        .and_then(Value::as_array)
        .ok_or(McpClientError::InvalidEnvelope)?;
    let mut parsed = Vec::with_capacity(tools.len());
    for tool in tools {
        let tool = tool.as_object().ok_or(McpClientError::InvalidEnvelope)?;
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.trim().is_empty() && !name.chars().any(char::is_control))
            .ok_or(McpClientError::InvalidEnvelope)?;
        if parsed.iter().any(|tool: &McpTool| tool.name == name) {
            return Err(McpClientError::InvalidEnvelope);
        }
        let description = match tool.get("description") {
            Some(Value::String(description)) => Some(description.clone()),
            Some(_) => return Err(McpClientError::InvalidEnvelope),
            None => None,
        };
        let input_schema = tool
            .get("inputSchema")
            .filter(|schema| schema.is_object())
            .cloned()
            .ok_or(McpClientError::InvalidEnvelope)?;
        parsed.push(McpTool {
            name: name.to_owned(),
            description,
            input_schema,
        });
    }
    Ok(McpToolList { tools: parsed })
}

fn parse_tool_call(result: Value) -> Result<McpToolCallResult, McpClientError> {
    let object = result.as_object().ok_or(McpClientError::InvalidEnvelope)?;
    if !object.get("content").is_some_and(Value::is_array) {
        return Err(McpClientError::InvalidEnvelope);
    }
    let outcome = match object.get("isError") {
        Some(Value::Bool(true)) => McpToolCallOutcome::Failed,
        Some(Value::Bool(false)) | None => McpToolCallOutcome::Succeeded,
        Some(_) => return Err(McpClientError::InvalidEnvelope),
    };
    let json = serde_json::to_vec(&result)
        .map(Bytes::from)
        .map_err(|_| McpClientError::InvalidEnvelope)?;
    Ok(McpToolCallResult { outcome, json })
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, StatusCode, header};
    use serde_json::{Value, json};

    use super::{
        McpClient, McpClientError, McpClientRequestError, McpClientResponse, McpToolCallOutcome,
    };
    use crate::{LATEST_PROTOCOL_VERSION, McpClientInfo, McpProtocolVersion};

    fn client() -> Result<McpClient, Box<dyn std::error::Error>> {
        Ok(McpClient::new(McpClientInfo::new(
            "bondry-egress",
            "0.2.0",
        )?))
    }

    fn json_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        headers
    }

    #[test]
    fn builds_modern_routed_requests_from_one_protocol_copy()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = client()?.call_tool(
            7,
            McpProtocolVersion::V2026_07_28,
            "battery:status",
            json!({ "detail": true }),
        )?;
        let parts = request.into_parts();
        assert_eq!(parts.headers()["mcp-method"], "tools/call");
        assert_eq!(
            parts.headers()["mcp-name"],
            "=?base64?YmF0dGVyeTpzdGF0dXM=?="
        );
        let body: Value = serde_json::from_slice(parts.body())?;
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            LATEST_PROTOCOL_VERSION
        );
        Ok(())
    }

    #[test]
    fn negotiates_without_accepting_peer_ordered_downgrades()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, _, decoder) = client()?.discover(1)?.into_parts().into_values();
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "resultType": "complete",
                "supportedVersions": ["2025-11-25", LATEST_PROTOCOL_VERSION],
            },
        }))?;
        let response = decoder.decode(StatusCode::OK, &json_headers(), &body)?;
        assert!(matches!(
            response,
            McpClientResponse::Discovery(discovery)
                if discovery.version() == McpProtocolVersion::V2026_07_28
        ));
        Ok(())
    }

    #[test]
    fn validates_tool_results_and_rejects_sse() -> Result<(), Box<dyn std::error::Error>> {
        let (_, _, decoder) = client()?
            .call_tool(
                9,
                McpProtocolVersion::V2026_07_28,
                "battery:status",
                json!({}),
            )?
            .into_parts()
            .into_values();
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 9,
            "result": {
                "resultType": "complete",
                "content": [{ "type": "text", "text": "unavailable" }],
                "isError": true,
            },
        }))?;
        let response = decoder.decode(StatusCode::OK, &json_headers(), &body)?;
        assert!(matches!(
            response,
            McpClientResponse::ToolCall(result)
                if result.outcome() == McpToolCallOutcome::Failed && !result.json().is_empty()
        ));

        let (_, _, decoder) = client()?.discover(1)?.into_parts().into_values();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        assert!(matches!(
            decoder.decode(StatusCode::OK, &headers, b""),
            Err(McpClientError::UnsupportedResponseMode)
        ));
        Ok(())
    }

    #[test]
    fn rejects_invalid_arguments_and_response_ids() -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            client()?.call_tool(1, McpProtocolVersion::V2025_11_25, "tool", json!([]),),
            Err(McpClientRequestError::InvalidArguments)
        ));
        let (_, _, decoder) = client()?.initialize(1)?.into_parts().into_values();
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "result": { "protocolVersion": "2025-11-25" },
        }))?;
        assert!(matches!(
            decoder.decode(StatusCode::OK, &json_headers(), &body),
            Err(McpClientError::MismatchedResponseId)
        ));
        Ok(())
    }
}
