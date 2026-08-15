use std::{fmt, slice, sync::Arc};

use bondry_mcp_proto::{
    McpClient, McpClientError, McpClientRequest, McpClientResponse, McpProtocolVersion,
    McpResponseDecoder, McpToolList,
};
use bondry_secrets::{ResolvedSecret, SecretRef};
use bondry_transport::{
    Deadline, EndpointPolicy, HttpRequest, HttpResponse, NetworkEndpoint, NetworkScheme,
    TransportError,
};
use http::{Method, header};
use thiserror::Error;

use crate::{
    McpAuthentication, McpConfigurationError, McpDiscoveryLimits, McpToolBinding,
    McpToolBindingError, mcp::bearer_header,
};

/// One user-initiated, configuration-time MCP discovery state machine.
pub struct McpDiscoveryOperation {
    endpoint: NetworkEndpoint,
    authentication: McpAuthentication,
    policy: EndpointPolicy,
    client: McpClient,
    limits: McpDiscoveryLimits,
    deadline: Option<Deadline>,
    secrets: Vec<ResolvedSecret>,
    next_request_id: u64,
    state: DiscoveryState,
}

impl McpDiscoveryOperation {
    /// Creates discovery for one explicit HTTP endpoint.
    pub fn new(
        endpoint: NetworkEndpoint,
        authentication: McpAuthentication,
        policy: EndpointPolicy,
        client: McpClient,
        limits: McpDiscoveryLimits,
    ) -> Result<Self, McpConfigurationError> {
        if !matches!(
            endpoint.scheme(),
            NetworkScheme::Http | NetworkScheme::Https
        ) {
            return Err(McpConfigurationError::UnsupportedScheme);
        }
        Ok(Self {
            endpoint,
            authentication,
            policy,
            client,
            limits,
            deadline: None,
            secrets: Vec::new(),
            next_request_id: 1,
            state: DiscoveryState::Ready,
        })
    }

    /// Returns the host-owned credentials required before starting.
    #[must_use]
    pub fn secret_references(&self) -> &[SecretRef] {
        self.authentication
            .secret_reference()
            .map_or(&[], slice::from_ref)
    }

    /// Starts modern negotiation under one absolute deadline.
    pub fn start(
        &mut self,
        deadline: Deadline,
        secrets: Vec<ResolvedSecret>,
    ) -> McpDiscoveryTransition {
        if !matches!(self.state, DiscoveryState::Ready) {
            return self.finish(Err(McpDiscoveryError::InvalidState));
        }
        let expected = usize::from(self.authentication.secret_reference().is_some());
        if secrets.len() != expected {
            return self.finish(Err(McpDiscoveryError::SecretUnavailable));
        }
        self.deadline = Some(deadline);
        self.secrets = secrets;
        self.discover()
    }

    /// Advances discovery with the exact completion of its previous HTTP action.
    pub fn resume(
        &mut self,
        completion: Result<HttpResponse, TransportError>,
    ) -> McpDiscoveryTransition {
        let state = std::mem::replace(&mut self.state, DiscoveryState::Complete);
        let response = match completion {
            Ok(response) => response,
            Err(error) => return self.finish(Err(classify_transport(error))),
        };
        match state {
            DiscoveryState::AwaitingDiscovery(decoder) => {
                match decoder.decode(response.status(), response.headers(), response.body()) {
                    Ok(McpClientResponse::Discovery(discovery)) => {
                        self.list_tools(discovery.version())
                    }
                    Err(
                        McpClientError::UnsupportedProtocolVersion | McpClientError::MethodNotFound,
                    ) => self.initialize(),
                    Ok(_) => self.finish(Err(McpDiscoveryError::InvalidResponse)),
                    Err(error) => self.finish(Err(classify_client(error))),
                }
            }
            DiscoveryState::AwaitingInitialization(decoder) => {
                match decoder.decode(response.status(), response.headers(), response.body()) {
                    Ok(McpClientResponse::Initialized(initialization)) => {
                        self.acknowledge_initialization(initialization.version())
                    }
                    Ok(_) => self.finish(Err(McpDiscoveryError::InvalidResponse)),
                    Err(error) => self.finish(Err(classify_client(error))),
                }
            }
            DiscoveryState::AwaitingAcknowledgement { version, decoder } => {
                match decoder.decode(response.status(), response.headers(), response.body()) {
                    Ok(McpClientResponse::Acknowledged) => self.list_tools(version),
                    Ok(_) => self.finish(Err(McpDiscoveryError::InvalidResponse)),
                    Err(error) => self.finish(Err(classify_client(error))),
                }
            }
            DiscoveryState::AwaitingTools { version, decoder } => {
                match decoder.decode(response.status(), response.headers(), response.body()) {
                    Ok(McpClientResponse::Tools(tools)) => {
                        self.finish(compile_result(version, tools, self.limits))
                    }
                    Ok(_) => self.finish(Err(McpDiscoveryError::InvalidResponse)),
                    Err(error) => self.finish(Err(classify_client(error))),
                }
            }
            DiscoveryState::Ready | DiscoveryState::Complete => {
                self.finish(Err(McpDiscoveryError::InvalidState))
            }
        }
    }

    fn discover(&mut self) -> McpDiscoveryTransition {
        let id = self.next_id();
        match self
            .client
            .discover(id)
            .map_err(|_| McpDiscoveryError::InvalidRequest)
            .and_then(|request| self.compose(request))
        {
            Ok((request, decoder)) => {
                self.state = DiscoveryState::AwaitingDiscovery(decoder);
                McpDiscoveryTransition::Http(Box::new(request))
            }
            Err(error) => self.finish(Err(error)),
        }
    }

    fn initialize(&mut self) -> McpDiscoveryTransition {
        let id = self.next_id();
        match self
            .client
            .initialize(id)
            .map_err(|_| McpDiscoveryError::InvalidRequest)
            .and_then(|request| self.compose(request))
        {
            Ok((request, decoder)) => {
                self.state = DiscoveryState::AwaitingInitialization(decoder);
                McpDiscoveryTransition::Http(Box::new(request))
            }
            Err(error) => self.finish(Err(error)),
        }
    }

    fn list_tools(&mut self, version: McpProtocolVersion) -> McpDiscoveryTransition {
        let id = self.next_id();
        match self
            .client
            .list_tools(id, version, self.limits.tools())
            .map_err(|_| McpDiscoveryError::InvalidRequest)
            .and_then(|request| self.compose(request))
        {
            Ok((request, decoder)) => {
                self.state = DiscoveryState::AwaitingTools { version, decoder };
                McpDiscoveryTransition::Http(Box::new(request))
            }
            Err(error) => self.finish(Err(error)),
        }
    }

    fn acknowledge_initialization(
        &mut self,
        version: McpProtocolVersion,
    ) -> McpDiscoveryTransition {
        match self
            .client
            .initialized(version)
            .map_err(|_| McpDiscoveryError::InvalidRequest)
            .and_then(|request| self.compose(request))
        {
            Ok((request, decoder)) => {
                self.state = DiscoveryState::AwaitingAcknowledgement { version, decoder };
                McpDiscoveryTransition::Http(Box::new(request))
            }
            Err(error) => self.finish(Err(error)),
        }
    }

    fn compose(
        &self,
        request: McpClientRequest,
    ) -> Result<(HttpRequest, McpResponseDecoder), McpDiscoveryError> {
        let (mut headers, body, decoder) = request.into_parts().into_values();
        if matches!(self.authentication, McpAuthentication::Bearer(_)) {
            let mut value = self
                .secrets
                .first()
                .ok_or(McpDiscoveryError::SecretUnavailable)
                .and_then(|secret| {
                    bearer_header(secret).map_err(|()| McpDiscoveryError::SecretUnavailable)
                })?;
            value.set_sensitive(true);
            headers.insert(header::AUTHORIZATION, value);
        }
        let deadline = self.deadline.ok_or(McpDiscoveryError::InvalidState)?;
        let request = HttpRequest::new(
            Method::POST,
            self.endpoint.clone(),
            headers,
            body,
            deadline,
            self.policy.clone(),
            self.limits.response(),
        )
        .map_err(|_| McpDiscoveryError::InvalidRequest)?;
        Ok((request, decoder))
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        id
    }

    fn finish(
        &mut self,
        result: Result<McpDiscoveryResult, McpDiscoveryError>,
    ) -> McpDiscoveryTransition {
        self.state = DiscoveryState::Complete;
        self.deadline = None;
        self.secrets.clear();
        McpDiscoveryTransition::Complete(result)
    }
}

impl fmt::Debug for McpDiscoveryOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpDiscoveryOperation")
            .field("endpoint", &self.endpoint)
            .field("authentication", &self.authentication)
            .field("policy", &self.policy)
            .field("limits", &self.limits)
            .field("state", &self.state.name())
            .finish()
    }
}

enum DiscoveryState {
    Ready,
    AwaitingDiscovery(McpResponseDecoder),
    AwaitingInitialization(McpResponseDecoder),
    AwaitingAcknowledgement {
        version: McpProtocolVersion,
        decoder: McpResponseDecoder,
    },
    AwaitingTools {
        version: McpProtocolVersion,
        decoder: McpResponseDecoder,
    },
    Complete,
}

impl DiscoveryState {
    const fn name(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::AwaitingDiscovery(_) => "awaiting_discovery",
            Self::AwaitingInitialization(_) => "awaiting_initialization",
            Self::AwaitingAcknowledgement { .. } => "awaiting_acknowledgement",
            Self::AwaitingTools { .. } => "awaiting_tools",
            Self::Complete => "complete",
        }
    }
}

/// The next action produced by configuration-time MCP discovery.
#[must_use]
pub enum McpDiscoveryTransition {
    /// Send one bounded request through the selected HTTP transport.
    Http(Box<HttpRequest>),
    /// Discovery completed with either validated UX data or a stable failure.
    Complete(Result<McpDiscoveryResult, McpDiscoveryError>),
}

/// Validated discovery data for one negotiated endpoint.
pub struct McpDiscoveryResult {
    version: McpProtocolVersion,
    tools: Vec<McpDiscoveredTool>,
}

impl McpDiscoveryResult {
    /// Returns the negotiated protocol revision required by route configuration.
    #[must_use]
    pub const fn version(&self) -> McpProtocolVersion {
        self.version
    }

    /// Returns tools in receiver-provided order.
    #[must_use]
    pub fn tools(&self) -> &[McpDiscoveredTool] {
        &self.tools
    }

    /// Moves all validated tools out in receiver-provided order.
    #[must_use]
    pub fn into_tools(self) -> Vec<McpDiscoveredTool> {
        self.tools
    }
}

impl fmt::Debug for McpDiscoveryResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpDiscoveryResult")
            .field("version", &self.version)
            .field("tool_count", &self.tools.len())
            .finish()
    }
}

/// One discovered tool ready for fixed route binding.
#[derive(Clone)]
pub struct McpDiscoveredTool {
    description: Option<Arc<str>>,
    binding: McpToolBinding,
}

impl McpDiscoveredTool {
    /// Returns the fixed protocol tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.binding.name()
    }

    /// Returns the optional receiver-provided description for configuration UX.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the validated JSON Schema 2020-12 input contract.
    #[must_use]
    pub fn input_schema(&self) -> &serde_json::Value {
        self.binding.input_schema()
    }

    /// Returns the compiled fixed route binding.
    #[must_use]
    pub const fn binding(&self) -> &McpToolBinding {
        &self.binding
    }

    /// Moves the compiled fixed route binding into route configuration.
    #[must_use]
    pub fn into_binding(self) -> McpToolBinding {
        self.binding
    }
}

impl fmt::Debug for McpDiscoveredTool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpDiscoveredTool")
            .field("name", &self.name())
            .field("has_description", &self.description.is_some())
            .field("schema_bytes", &encoded_len(self.input_schema()))
            .finish()
    }
}

/// Stable, non-sensitive configuration-time discovery failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpDiscoveryError {
    /// The state machine was started or resumed out of order.
    #[error("MCP discovery state is invalid")]
    InvalidState,
    /// Host-owned bearer material is absent or invalid.
    #[error("MCP discovery credential is unavailable")]
    SecretUnavailable,
    /// A locally generated request could not satisfy transport bounds.
    #[error("MCP discovery request is invalid")]
    InvalidRequest,
    /// The established connection violated endpoint or TLS policy.
    #[error("MCP discovery endpoint policy rejected the connection")]
    EndpointPolicy,
    /// Discovery did not finish before its absolute deadline.
    #[error("MCP discovery deadline was exceeded")]
    DeadlineExceeded,
    /// The endpoint could not service discovery.
    #[error("MCP discovery endpoint is unavailable")]
    Unavailable,
    /// The bounded response body limit was exceeded.
    #[error("MCP discovery response exceeds the configured bound")]
    ResponseTooLarge,
    /// The endpoint supports no mutually compatible MCP revision.
    #[error("MCP discovery protocol version is unsupported")]
    UnsupportedProtocol,
    /// The endpoint selected an unsupported streaming response mode.
    #[error("MCP discovery response mode is unsupported")]
    UnsupportedResponseMode,
    /// The endpoint rejected a valid discovery operation.
    #[error("MCP discovery request was rejected")]
    Rejected,
    /// The response did not contain valid bounded MCP framing.
    #[error("MCP discovery response is invalid")]
    InvalidResponse,
    /// The endpoint returned more tools than configured.
    #[error("MCP discovery tool list exceeds the configured bound")]
    ToolLimitExceeded,
    /// A returned tool input schema was invalid or oversized.
    #[error("MCP discovery returned an invalid tool schema")]
    InvalidToolSchema,
}

fn compile_result(
    version: McpProtocolVersion,
    tools: McpToolList,
    limits: McpDiscoveryLimits,
) -> Result<McpDiscoveryResult, McpDiscoveryError> {
    let tools = tools
        .into_tools()
        .into_iter()
        .map(|tool| {
            let (name, description, schema) = tool.into_parts();
            let binding =
                McpToolBinding::from_parts_with_schema_limit(&name, schema, limits.schema_bytes())
                    .map_err(classify_binding)?;
            Ok(McpDiscoveredTool {
                description: description.map(Arc::from),
                binding,
            })
        })
        .collect::<Result<Vec<_>, McpDiscoveryError>>()?;
    Ok(McpDiscoveryResult { version, tools })
}

fn classify_binding(error: McpToolBindingError) -> McpDiscoveryError {
    match error {
        McpToolBindingError::InvalidName => McpDiscoveryError::InvalidResponse,
        McpToolBindingError::SchemaTooLarge | McpToolBindingError::InvalidSchema => {
            McpDiscoveryError::InvalidToolSchema
        }
    }
}

fn classify_client(error: McpClientError) -> McpDiscoveryError {
    match error {
        McpClientError::UnsupportedResponseMode => McpDiscoveryError::UnsupportedResponseMode,
        McpClientError::UnsupportedProtocolVersion | McpClientError::MethodNotFound => {
            McpDiscoveryError::UnsupportedProtocol
        }
        McpClientError::PeerUnavailable => McpDiscoveryError::Unavailable,
        McpClientError::UnexpectedHttpStatus
        | McpClientError::RequestRejected
        | McpClientError::RemoteFailure => McpDiscoveryError::Rejected,
        McpClientError::ToolListTooLarge => McpDiscoveryError::ToolLimitExceeded,
        McpClientError::InvalidContentType
        | McpClientError::InvalidJson
        | McpClientError::InvalidEnvelope
        | McpClientError::MismatchedResponseId => McpDiscoveryError::InvalidResponse,
    }
}

fn classify_transport(error: TransportError) -> McpDiscoveryError {
    match error {
        TransportError::Policy(_) | TransportError::TlsFailed => McpDiscoveryError::EndpointPolicy,
        TransportError::DeadlineExceeded => McpDiscoveryError::DeadlineExceeded,
        TransportError::ConnectionFailed => McpDiscoveryError::Unavailable,
        TransportError::ResponseTooLarge => McpDiscoveryError::ResponseTooLarge,
        TransportError::InvalidResponse => McpDiscoveryError::InvalidResponse,
        TransportError::RequestTooLarge
        | TransportError::InvalidLimits
        | TransportError::UnsupportedEndpoint
        | TransportError::InvalidMessage => McpDiscoveryError::InvalidRequest,
    }
}

fn encoded_len(value: &serde_json::Value) -> usize {
    serde_json::to_vec(value).map_or(0, |encoded| encoded.len())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bondry_mcp_proto::{LATEST_PROTOCOL_VERSION, McpClient, McpClientInfo, McpProtocolVersion};
    use bondry_secrets::{ResolvedSecret, SecretRef, SecretValue};
    use bondry_transport::{
        ConnectionEvidence, Deadline, EndpointPolicy, HttpResponse, NetworkEndpoint,
        TlsConnectionEvidence,
    };
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, StatusCode, header};
    use serde_json::{Value, json};

    use super::{McpDiscoveryError, McpDiscoveryOperation, McpDiscoveryTransition};
    use crate::{McpAuthentication, McpDiscoveryLimits};

    fn endpoint() -> Result<NetworkEndpoint, Box<dyn std::error::Error>> {
        Ok(NetworkEndpoint::new(
            "https://example.com/private?opaque=value".parse()?,
        )?)
    }

    fn client() -> Result<McpClient, Box<dyn std::error::Error>> {
        Ok(McpClient::new(McpClientInfo::new(
            "bondry-egress",
            "0.2.0",
        )?))
    }

    fn operation(
        authentication: McpAuthentication,
        limits: McpDiscoveryLimits,
    ) -> Result<McpDiscoveryOperation, Box<dyn std::error::Error>> {
        Ok(McpDiscoveryOperation::new(
            endpoint()?,
            authentication,
            EndpointPolicy::default(),
            client()?,
            limits,
        )?)
    }

    fn deadline() -> Deadline {
        Deadline::at(Instant::now() + Duration::from_secs(30))
    }

    fn response(id: u64, result: Value) -> Result<HttpResponse, Box<dyn std::error::Error>> {
        response_message(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
    }

    fn response_message(message: Value) -> Result<HttpResponse, Box<dyn std::error::Error>> {
        bounded_response(StatusCode::OK, Bytes::from(serde_json::to_vec(&message)?))
    }

    fn accepted_response() -> Result<HttpResponse, Box<dyn std::error::Error>> {
        bounded_response(StatusCode::ACCEPTED, Bytes::new())
    }

    fn bounded_response(
        status: StatusCode,
        body: Bytes,
    ) -> Result<HttpResponse, Box<dyn std::error::Error>> {
        let endpoint = endpoint()?;
        let policy = EndpointPolicy::default();
        let connection = policy.verify_connection(
            &endpoint,
            ConnectionEvidence::Tls(TlsConnectionEvidence::verified(endpoint.host())),
        )?;
        let mut headers = HeaderMap::new();
        if !body.is_empty() {
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
        }
        Ok(HttpResponse::new(
            status,
            headers,
            body,
            connection,
            bondry_transport::HttpLimits::default(),
        )?)
    }

    fn request_json(
        transition: McpDiscoveryTransition,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let McpDiscoveryTransition::Http(request) = transition else {
            return Err(std::io::Error::other("discovery did not produce an HTTP request").into());
        };
        let parts = request.into_parts();
        Ok(serde_json::from_slice(&parts.body)?)
    }

    fn enter_modern_tool_list(
        operation: &mut McpDiscoveryOperation,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let request = request_json(operation.start(deadline(), Vec::new()))?;
        let id = request["id"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("request ID is missing"))?;
        request_json(operation.resume(Ok(response(
            id,
            json!({
                "resultType": "complete",
                "supportedVersions": [LATEST_PROTOCOL_VERSION],
            }),
        )?)))
    }

    #[test]
    fn discovers_modern_tools_with_bounded_schemas_and_redacted_debug()
    -> Result<(), Box<dyn std::error::Error>> {
        let reference = SecretRef::new("keychain:mcp")?;
        let mut operation = operation(
            McpAuthentication::Bearer(reference.clone()),
            McpDiscoveryLimits::default(),
        )?;
        assert_eq!(operation.secret_references(), &[reference]);
        assert!(!format!("{operation:?}").contains("opaque=value"));

        let secret = ResolvedSecret::current(SecretValue::new(b"private-token".to_vec())?);
        let McpDiscoveryTransition::Http(request) = operation.start(deadline(), vec![secret])
        else {
            return Err(std::io::Error::other("discovery did not start").into());
        };
        assert!(!format!("{operation:?}").contains("private-token"));
        let parts = request.into_parts();
        assert_eq!(parts.headers[header::AUTHORIZATION], "Bearer private-token");
        assert!(parts.headers[header::AUTHORIZATION].is_sensitive());
        let discover: Value = serde_json::from_slice(&parts.body)?;
        let discover_id = discover["id"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("discover ID is missing"))?;

        let list = request_json(operation.resume(Ok(response(
            discover_id,
            json!({
                "resultType": "complete",
                "supportedVersions": [LATEST_PROTOCOL_VERSION],
            }),
        )?)))?;
        let list_id = list["id"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("list ID is missing"))?;
        let completion = operation.resume(Ok(response(
            list_id,
            json!({
                "resultType": "complete",
                "tools": [{
                    "name": "battery:status",
                    "description": "Returns private battery state",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "detail": { "type": "boolean" } },
                        "required": ["detail"],
                        "additionalProperties": false,
                    },
                }],
            }),
        )?));
        let McpDiscoveryTransition::Complete(Ok(result)) = completion else {
            return Err(std::io::Error::other("discovery did not complete").into());
        };
        assert_eq!(result.version(), McpProtocolVersion::V2026_07_28);
        assert_eq!(result.tools().len(), 1);
        let tool = &result.tools()[0];
        assert_eq!(tool.name(), "battery:status");
        assert_eq!(tool.description(), Some("Returns private battery state"));
        assert!(
            tool.binding()
                .validate_input(&json!({ "detail": true }))
                .is_ok()
        );
        assert!(!format!("{result:?}").contains("private battery state"));
        Ok(())
    }

    #[test]
    fn falls_back_to_legacy_only_for_negotiation_failures() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut legacy = operation(McpAuthentication::None, McpDiscoveryLimits::default())?;
        let discover = request_json(legacy.start(deadline(), Vec::new()))?;
        let discover_id = discover["id"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("discover ID is missing"))?;
        let initialize = request_json(legacy.resume(Ok(response_message(json!({
            "jsonrpc": "2.0",
            "id": discover_id,
            "error": { "code": -32601, "message": "Method not found" },
        }))?)))?;
        let initialize_id = initialize["id"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("initialize ID is missing"))?;
        let initialized = request_json(legacy.resume(Ok(response(
            initialize_id,
            json!({ "protocolVersion": "2025-11-25" }),
        )?)))?;
        assert!(initialized.get("id").is_none());
        let list = request_json(legacy.resume(Ok(accepted_response()?)))?;
        let list_id = list["id"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("list ID is missing"))?;
        let completion = legacy.resume(Ok(response(
            list_id,
            json!({ "tools": [{ "name": "ping", "inputSchema": { "type": "object" } }] }),
        )?));
        assert!(matches!(
            completion,
            McpDiscoveryTransition::Complete(Ok(result))
                if result.version() == McpProtocolVersion::V2025_11_25
                    && result.tools()[0].name() == "ping"
        ));

        let mut invalid = operation(McpAuthentication::None, McpDiscoveryLimits::default())?;
        let discover = request_json(invalid.start(deadline(), Vec::new()))?;
        let id = discover["id"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("discover ID is missing"))?;
        let completion = invalid.resume(Ok(response_message(json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "resultType": "complete" },
        }))?));
        assert!(matches!(
            completion,
            McpDiscoveryTransition::Complete(Err(McpDiscoveryError::InvalidResponse))
        ));
        Ok(())
    }

    #[test]
    fn rejects_tool_count_and_schema_limits() -> Result<(), Box<dyn std::error::Error>> {
        let limits = McpDiscoveryLimits::new(1, 64 * 1024, 64 * 1024)?;
        let mut count_limited = operation(McpAuthentication::None, limits)?;
        let list = enter_modern_tool_list(&mut count_limited)?;
        let id = list["id"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("list ID is missing"))?;
        let completion = count_limited.resume(Ok(response(
            id,
            json!({
                "resultType": "complete",
                "tools": [
                    { "name": "one", "inputSchema": { "type": "object" } },
                    { "name": "two", "inputSchema": { "type": "object" } },
                ],
            }),
        )?));
        assert!(matches!(
            completion,
            McpDiscoveryTransition::Complete(Err(McpDiscoveryError::ToolLimitExceeded))
        ));

        let limits = McpDiscoveryLimits::new(1, 16, 64 * 1024)?;
        let mut schema_limited = operation(McpAuthentication::None, limits)?;
        let list = enter_modern_tool_list(&mut schema_limited)?;
        let id = list["id"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("list ID is missing"))?;
        let completion = schema_limited.resume(Ok(response(
            id,
            json!({
                "resultType": "complete",
                "tools": [{ "name": "one", "inputSchema": { "type": "object" } }],
            }),
        )?));
        assert!(matches!(
            completion,
            McpDiscoveryTransition::Complete(Err(McpDiscoveryError::InvalidToolSchema))
        ));
        Ok(())
    }

    #[test]
    fn rejects_invalid_credentials_before_emitting_an_action()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut operation = operation(
            McpAuthentication::Bearer(SecretRef::new("keychain:mcp")?),
            McpDiscoveryLimits::default(),
        )?;
        let secret = ResolvedSecret::current(SecretValue::new(b"not a bearer".to_vec())?);
        assert!(matches!(
            operation.start(deadline(), vec![secret]),
            McpDiscoveryTransition::Complete(Err(McpDiscoveryError::SecretUnavailable))
        ));
        assert!(matches!(
            operation.start(deadline(), Vec::new()),
            McpDiscoveryTransition::Complete(Err(McpDiscoveryError::InvalidState))
        ));
        Ok(())
    }
}
