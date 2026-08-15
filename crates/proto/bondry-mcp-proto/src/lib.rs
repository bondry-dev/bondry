#![doc = "Pure MCP Streamable HTTP protocol handling for Bondry."]

mod client;
mod client_info;
mod protocol;
mod server_info;
mod version;

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bondry_core::{
    AdapterId, AutomationService, CapabilityDescriptor, CapabilityDiscoveryError, CapabilityEffect,
    CapabilityId, DenialReason, DispatchError, IdentifierError, Invocation, InvocationIdGenerator,
    Principal, SystemInvocationIdGenerator,
};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use serde_json::{Map, Value, json};

pub use client::{
    McpClient, McpClientError, McpClientRequest, McpClientRequestError, McpClientRequestParts,
    McpClientResponse, McpDiscovery, McpInitialization, McpResponseDecoder, McpTool,
    McpToolCallOutcome, McpToolCallResult, McpToolList,
};
pub use client_info::{McpClientInfo, McpClientInfoError};
pub use server_info::{McpServerInfo, McpServerInfoError};
pub use version::{LATEST_PROTOCOL_VERSION, McpProtocolVersion, SUPPORTED_PROTOCOL_VERSIONS};

use crate::protocol::{
    CALL_TOOL_METHOD, CLIENT_CAPABILITIES_META, CLIENT_INFO_META, DISCOVER_METHOD,
    INITIALIZE_METHOD, LIST_TOOLS_METHOD, METHOD_HEADER, Message, NAME_HEADER,
    PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION_META, RpcNotification, RpcRequest, SERVER_INFO_META,
    accepted_response, error_response, json_response, rpc_error, rpc_error_with_data, rpc_result,
};

/// The standard Streamable HTTP endpoint owned by the adapter.
pub const MCP_PATH: &str = "/mcp";

const ADAPTER_ID: &str = "mcp";

/// Exposes authorized Bondry capabilities as MCP tools over Streamable HTTP.
pub struct McpAdapter {
    service: Arc<dyn AutomationService>,
    adapter: AdapterId,
    invocation_ids: Arc<dyn InvocationIdGenerator>,
    server_info: McpServerInfo,
}

struct RequestContext {
    request: Request<Bytes>,
    principal: Principal,
}

impl RequestContext {
    const fn new(request: Request<Bytes>, principal: Principal) -> Self {
        Self { request, principal }
    }

    const fn request(&self) -> &Request<Bytes> {
        &self.request
    }

    const fn principal(&self) -> &Principal {
        &self.principal
    }
}

impl McpAdapter {
    /// Creates an MCP adapter with the stable `mcp` adapter identifier.
    pub fn new(
        service: Arc<dyn AutomationService>,
        server_info: McpServerInfo,
    ) -> Result<Self, IdentifierError> {
        Ok(Self {
            service,
            adapter: AdapterId::new(ADAPTER_ID)?,
            invocation_ids: Arc::new(SystemInvocationIdGenerator),
            server_info,
        })
    }

    /// Creates an MCP adapter with explicit service and identifier dependencies.
    #[must_use]
    pub const fn with_dependencies(
        service: Arc<dyn AutomationService>,
        adapter: AdapterId,
        invocation_ids: Arc<dyn InvocationIdGenerator>,
        server_info: McpServerInfo,
    ) -> Self {
        Self {
            service,
            adapter,
            invocation_ids,
            server_info,
        }
    }

    /// Returns the adapter identifier used for authorization and audit events.
    #[must_use]
    pub const fn adapter_id(&self) -> &AdapterId {
        &self.adapter
    }

    /// Returns whether this protocol handler owns the request path.
    #[must_use]
    pub fn accepts_path(&self, path: &str) -> bool {
        path == MCP_PATH
    }

    /// Handles one authenticated, bounded request.
    pub async fn handle(&self, request: Request<Bytes>, principal: Principal) -> Response<Bytes> {
        self.route(RequestContext::new(request, principal)).await
    }

    async fn route(&self, request: RequestContext) -> Response<Bytes> {
        match *request.request().method() {
            Method::POST => self.handle_post(request).await,
            _ => method_not_allowed(),
        }
    }

    async fn handle_post(&self, request: RequestContext) -> Response<Bytes> {
        if !has_json_content_type(request.request().headers()) {
            return transport_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type");
        }
        if !accepts_json_and_sse(request.request().headers()) {
            return transport_error(StatusCode::NOT_ACCEPTABLE, "not_acceptable");
        }
        let message = match protocol::parse(request.request().body()) {
            Ok(message) => message,
            Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
        };
        let response_id = message_id(&message);
        let version = match single_header(request.request().headers(), PROTOCOL_VERSION_HEADER) {
            Ok(Some(value)) => match McpProtocolVersion::parse(value) {
                Some(version) => version,
                None => return unsupported_version(response_id, value),
            },
            Ok(None) if is_legacy_initialize(&message) => McpProtocolVersion::V2025_11_25,
            Ok(None) | Err(()) => return header_mismatch(response_id),
        };

        match message {
            Message::Request(request_message) => {
                self.handle_rpc_request(
                    request.principal(),
                    request.request().headers(),
                    request_message,
                    version,
                )
                .await
            }
            Message::Notification(notification) => self.handle_notification(notification, version),
            Message::Response(_) if version.is_modern() => {
                rpc_error(StatusCode::BAD_REQUEST, None, -32_600, "Invalid Request")
            }
            Message::Response(_) => accepted_response(),
        }
    }

    async fn handle_rpc_request(
        &self,
        principal: &bondry_core::Principal,
        headers: &HeaderMap,
        request: RpcRequest,
        version: McpProtocolVersion,
    ) -> Response<Bytes> {
        if version.is_modern() {
            if let Err(error) = validate_modern_request(headers, &request, version) {
                return validation_error(request.id, error);
            }
            return self
                .handle_modern_request(principal, request, version)
                .await;
        }
        self.handle_legacy_request(principal, request, version)
            .await
    }

    async fn handle_modern_request(
        &self,
        principal: &bondry_core::Principal,
        request: RpcRequest,
        version: McpProtocolVersion,
    ) -> Response<Bytes> {
        let RpcRequest { id, method, params } = request;
        match method.as_str() {
            DISCOVER_METHOD => self.discover(id, params.as_ref(), version),
            LIST_TOOLS_METHOD => self.list_tools(principal, id, params.as_ref(), version),
            CALL_TOOL_METHOD => {
                self.call_tool(principal, id, params.as_ref(), version)
                    .await
            }
            _ => rpc_error(StatusCode::NOT_FOUND, Some(id), -32_601, "Method not found"),
        }
    }

    async fn handle_legacy_request(
        &self,
        principal: &bondry_core::Principal,
        request: RpcRequest,
        version: McpProtocolVersion,
    ) -> Response<Bytes> {
        let RpcRequest { id, method, params } = request;
        match method.as_str() {
            INITIALIZE_METHOD => self.initialize(id, params.as_ref()),
            "ping" => empty_result(id, params.as_ref()),
            LIST_TOOLS_METHOD => self.list_tools(principal, id, params.as_ref(), version),
            CALL_TOOL_METHOD => {
                self.call_tool(principal, id, params.as_ref(), version)
                    .await
            }
            _ => rpc_error_response(id, -32_601, "Method not found"),
        }
    }

    fn handle_notification(
        &self,
        notification: RpcNotification,
        version: McpProtocolVersion,
    ) -> Response<Bytes> {
        if version.is_modern() {
            return match validate_modern_metadata(notification.params.as_ref(), version) {
                Ok(()) => accepted_response(),
                Err(ModernValidationError::HeaderMismatch) => header_mismatch(None),
                Err(ModernValidationError::InvalidParams) => {
                    rpc_error(StatusCode::BAD_REQUEST, None, -32_602, "Invalid params")
                }
            };
        }
        accepted_response()
    }

    fn initialize(&self, id: Value, params: Option<&Value>) -> Response<Bytes> {
        let Some(params) = params.and_then(Value::as_object) else {
            return rpc_error_response(id, -32_602, "Invalid params");
        };
        let Some(requested_version) = params.get("protocolVersion").and_then(Value::as_str) else {
            return rpc_error_response(id, -32_602, "Invalid params");
        };
        if !params.get("capabilities").is_some_and(Value::is_object)
            || !valid_implementation(params.get("clientInfo"))
        {
            return rpc_error_response(id, -32_602, "Invalid params");
        }
        let version = McpProtocolVersion::negotiate_legacy(requested_version);
        rpc_result(
            id,
            json!({
                "protocolVersion": version.as_str(),
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": self.server_info.as_json(),
            }),
        )
    }

    fn discover(
        &self,
        id: Value,
        params: Option<&Value>,
        version: McpProtocolVersion,
    ) -> Response<Bytes> {
        if !valid_modern_metadata(params, version)
            || !params
                .and_then(Value::as_object)
                .is_some_and(|params| params.keys().all(|key| key == "_meta"))
        {
            return rpc_error_response(id, -32_602, "Invalid params");
        }
        self.complete_result(
            id,
            json!({
                "supportedVersions": SUPPORTED_PROTOCOL_VERSIONS,
                "capabilities": { "tools": { "listChanged": false } },
                "ttlMs": 0,
                "cacheScope": "private",
            }),
            version,
        )
    }

    fn list_tools(
        &self,
        principal: &bondry_core::Principal,
        id: Value,
        params: Option<&Value>,
        version: McpProtocolVersion,
    ) -> Response<Bytes> {
        if !valid_list_params(params) {
            return rpc_error_response(id, -32_602, "Invalid params");
        }
        match self.service.capabilities(principal, &self.adapter) {
            Ok(capabilities) => {
                let mut result = json!({
                    "tools": capabilities.iter().map(tool_json).collect::<Vec<_>>(),
                });
                if version.is_modern() {
                    result["ttlMs"] = json!(0);
                    result["cacheScope"] = json!("private");
                }
                self.complete_result(id, result, version)
            }
            Err(CapabilityDiscoveryError::PolicyUnavailable) => {
                rpc_error_response(id, -32_603, "Internal error")
            }
        }
    }

    async fn call_tool(
        &self,
        principal: &bondry_core::Principal,
        id: Value,
        params: Option<&Value>,
        version: McpProtocolVersion,
    ) -> Response<Bytes> {
        let Some((name, arguments)) = tool_call(params) else {
            return rpc_error_response(id, -32_602, "Invalid params");
        };
        let Ok(capability) = CapabilityId::new(name) else {
            return rpc_error_response(id, -32_602, "Unknown tool");
        };
        let invocation_id = match self.invocation_ids.generate() {
            Ok(invocation_id) => invocation_id,
            Err(_) => return rpc_error_response(id, -32_603, "Internal error"),
        };
        let invocation_id_value = invocation_id.as_str().to_owned();
        let invocation = Invocation::new(
            invocation_id,
            self.adapter.clone(),
            principal.clone(),
            capability,
            arguments,
        );
        match self.service.dispatch(invocation).await {
            Ok(output) => self.complete_result(
                id,
                tool_success(output, &invocation_id_value, version),
                version,
            ),
            Err(DispatchError::InvalidInput) => self.complete_result(
                id,
                tool_failure("Capability input is invalid", &invocation_id_value, None),
                version,
            ),
            Err(DispatchError::Handler(error)) => self.complete_result(
                id,
                tool_failure(
                    "Capability execution failed",
                    &invocation_id_value,
                    Some(error.code().as_str()),
                ),
                version,
            ),
            Err(DispatchError::CapabilityNotFound(_))
            | Err(DispatchError::AccessDenied(DenialReason::NotGranted)) => {
                rpc_error_response(id, -32_602, "Unknown tool")
            }
            Err(DispatchError::AccessDenied(DenialReason::PolicyUnavailable))
            | Err(DispatchError::Audit(_)) => rpc_error_response(id, -32_603, "Internal error"),
        }
    }

    fn complete_result(
        &self,
        id: Value,
        mut result: Value,
        version: McpProtocolVersion,
    ) -> Response<Bytes> {
        if version.is_modern() {
            result["resultType"] = json!("complete");
            let metadata = result
                .get_mut("_meta")
                .and_then(Value::as_object_mut)
                .map_or_else(Map::new, std::mem::take);
            let mut metadata = metadata;
            metadata.insert(SERVER_INFO_META.to_owned(), self.server_info.as_json());
            result["_meta"] = Value::Object(metadata);
        }
        rpc_result(id, result)
    }
}

#[derive(Clone, Copy)]
enum ModernValidationError {
    HeaderMismatch,
    InvalidParams,
}

fn validate_modern_request(
    headers: &HeaderMap,
    request: &RpcRequest,
    version: McpProtocolVersion,
) -> Result<(), ModernValidationError> {
    let method = single_header(headers, METHOD_HEADER)
        .map_err(|()| ModernValidationError::HeaderMismatch)?
        .ok_or(ModernValidationError::HeaderMismatch)?;
    if method != request.method {
        return Err(ModernValidationError::HeaderMismatch);
    }
    if request.method == CALL_TOOL_METHOD {
        let encoded_name = single_header(headers, NAME_HEADER)
            .map_err(|()| ModernValidationError::HeaderMismatch)?
            .ok_or(ModernValidationError::HeaderMismatch)?;
        let header_name =
            decode_header_value(encoded_name).ok_or(ModernValidationError::HeaderMismatch)?;
        let body_name = request
            .params
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|params| params.get("name"))
            .and_then(Value::as_str)
            .ok_or(ModernValidationError::InvalidParams)?;
        if header_name != body_name {
            return Err(ModernValidationError::HeaderMismatch);
        }
    }
    validate_modern_metadata(request.params.as_ref(), version)
}

fn valid_modern_metadata(params: Option<&Value>, version: McpProtocolVersion) -> bool {
    validate_modern_metadata(params, version).is_ok()
}

fn validate_modern_metadata(
    params: Option<&Value>,
    version: McpProtocolVersion,
) -> Result<(), ModernValidationError> {
    let Some(metadata) = params
        .and_then(Value::as_object)
        .and_then(|params| params.get("_meta"))
        .and_then(Value::as_object)
    else {
        return Err(ModernValidationError::InvalidParams);
    };
    let Some(body_version) = metadata.get(PROTOCOL_VERSION_META).and_then(Value::as_str) else {
        return Err(ModernValidationError::InvalidParams);
    };
    if body_version != version.as_str() {
        return Err(ModernValidationError::HeaderMismatch);
    }
    if !metadata
        .get(CLIENT_CAPABILITIES_META)
        .is_some_and(Value::is_object)
        || !metadata
            .get(CLIENT_INFO_META)
            .is_none_or(|client_info| valid_implementation(Some(client_info)))
    {
        return Err(ModernValidationError::InvalidParams);
    }
    Ok(())
}

fn valid_implementation(value: Option<&Value>) -> bool {
    value.and_then(Value::as_object).is_some_and(|info| {
        info.get("name").and_then(Value::as_str).is_some()
            && info.get("version").and_then(Value::as_str).is_some()
    })
}

fn valid_list_params(params: Option<&Value>) -> bool {
    params.is_none_or(|params| {
        params
            .as_object()
            .is_some_and(|params| !params.contains_key("cursor"))
    })
}

fn tool_call(params: Option<&Value>) -> Option<(&str, Value)> {
    let params = params?.as_object()?;
    let name = params.get("name")?.as_str()?;
    let arguments = match params.get("arguments") {
        Some(arguments) if arguments.is_object() => arguments.clone(),
        Some(_) => return None,
        None => Value::Object(Map::new()),
    };
    Some((name, arguments))
}

fn tool_json(descriptor: &CapabilityDescriptor) -> Value {
    let mut input_schema = descriptor.input_schema().clone();
    remove_custom_header_annotations(&mut input_schema);
    json!({
        "name": descriptor.id().as_str(),
        "description": descriptor.summary(),
        "inputSchema": input_schema,
        "annotations": {
            "readOnlyHint": descriptor.effect() == CapabilityEffect::ReadOnly,
        },
    })
}

fn remove_custom_header_annotations(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(remove_custom_header_annotations),
        Value::Object(object) => {
            object.remove("x-mcp-header");
            object
                .values_mut()
                .for_each(remove_custom_header_annotations);
        }
        _ => {}
    }
}

fn tool_success(output: Value, invocation_id: &str, version: McpProtocolVersion) -> Value {
    let text = serde_json::to_string(&output).unwrap_or_default();
    let mut result = json!({
        "content": [{ "type": "text", "text": text }],
        "isError": false,
        "_meta": { "dev.bondry/invocationId": invocation_id },
    });
    if version.is_modern() || output.is_object() {
        result["structuredContent"] = output;
    }
    result
}

fn tool_failure(message: &str, invocation_id: &str, code: Option<&str>) -> Value {
    let mut metadata = json!({ "dev.bondry/invocationId": invocation_id });
    if let Some(code) = code {
        metadata["dev.bondry/errorCode"] = Value::String(code.to_owned());
    }
    json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true,
        "_meta": metadata,
    })
}

fn empty_result(id: Value, params: Option<&Value>) -> Response<Bytes> {
    if params.is_none_or(Value::is_object) {
        rpc_result(id, json!({}))
    } else {
        rpc_error_response(id, -32_602, "Invalid params")
    }
}

fn validation_error(id: Value, error: ModernValidationError) -> Response<Bytes> {
    match error {
        ModernValidationError::HeaderMismatch => header_mismatch(Some(id)),
        ModernValidationError::InvalidParams => {
            rpc_error(StatusCode::BAD_REQUEST, Some(id), -32_602, "Invalid params")
        }
    }
}

fn rpc_error_response(id: Value, code: i32, message: &'static str) -> Response<Bytes> {
    rpc_error(StatusCode::OK, Some(id), code, message)
}

fn header_mismatch(id: Option<Value>) -> Response<Bytes> {
    rpc_error(StatusCode::BAD_REQUEST, id, -32_020, "Header mismatch")
}

fn unsupported_version(id: Option<Value>, requested: &str) -> Response<Bytes> {
    rpc_error_with_data(
        StatusCode::BAD_REQUEST,
        id,
        -32_022,
        "Unsupported protocol version",
        Some(json!({
            "supported": SUPPORTED_PROTOCOL_VERSIONS,
            "requested": requested,
        })),
    )
}

fn method_not_allowed() -> Response<Bytes> {
    let mut response = transport_error(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
    response
        .headers_mut()
        .insert(header::ALLOW, http::HeaderValue::from_static("POST"));
    response
}

fn transport_error(status: StatusCode, code: &'static str) -> Response<Bytes> {
    json_response(status, json!({ "error": code }))
}

fn message_id(message: &Message) -> Option<Value> {
    match message {
        Message::Request(request) => Some(request.id.clone()),
        Message::Notification(_) | Message::Response(_) => None,
    }
}

fn is_legacy_initialize(message: &Message) -> bool {
    matches!(message, Message::Request(request) if request.method == INITIALIZE_METHOD)
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    value.to_str().map(Some).map_err(|_| ())
}

fn decode_header_value(value: &str) -> Option<String> {
    let Some(encoded) = value
        .strip_prefix("=?base64?")
        .and_then(|value| value.strip_suffix("?="))
    else {
        return Some(value.to_owned());
    };
    String::from_utf8(STANDARD.decode(encoded).ok()?).ok()
}

fn has_json_content_type(headers: &HeaderMap) -> bool {
    has_media_type(headers, header::CONTENT_TYPE, "application/json", true)
}

fn accepts_json_and_sse(headers: &HeaderMap) -> bool {
    has_media_type(headers, header::ACCEPT, "application/json", false)
        && has_media_type(headers, header::ACCEPT, "text/event-stream", false)
}

fn has_media_type(
    headers: &HeaderMap,
    name: http::HeaderName,
    expected: &str,
    require_single_header: bool,
) -> bool {
    let values = headers.get_all(name).iter().collect::<Vec<_>>();
    if values.is_empty() || (require_single_header && values.len() != 1) {
        return false;
    }
    let Ok(values) = values
        .iter()
        .map(|value| value.to_str())
        .collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    if require_single_header {
        return !values[0].contains(',')
            && values[0]
                .split(';')
                .next()
                .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(expected));
    }
    values.iter().any(|value| {
        value.split(',').any(|media_range| {
            media_range
                .split(';')
                .next()
                .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(expected))
        })
    })
}
