use std::{fmt, slice, sync::Arc};

use bondry_delivery_store::{
    DeliveryFailure, DeliveryId, DeliveryResultCategory, DeliveryResultMetadata,
};
use bondry_egress::{
    AttemptContext, AttemptDisposition, DeliveryKind, DeliveryOperation, EventPayload,
    KindOperationError, KindTransition, MAX_EVENT_PAYLOAD_BYTES, MAX_JSON_NESTING_DEPTH,
    OperationMode, RetryableFailure, TransportCompletion,
};
use bondry_mcp_proto::{
    McpClient, McpClientError, McpClientRequestError, McpClientResponse, McpProtocolVersion,
    McpResponseDecoder, McpTool, McpToolCallOutcome,
};
use bondry_secrets::{ResolvedSecret, SecretRef};
use bondry_transport::{
    EndpointPolicy, HttpRequest, MAX_HTTP_HEADER_BYTES, MAX_HTTP_REQUEST_BODY_BYTES,
    NetworkEndpoint, NetworkScheme, TransportError,
};
use http::{HeaderValue, Method, header};
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::McpLimits;

/// Authentication for a fixed MCP Streamable HTTP endpoint.
#[derive(Clone, Eq, PartialEq)]
pub enum McpAuthentication {
    /// No credential is attached.
    None,
    /// A current host-owned secret is sent as an RFC 6750 bearer token.
    Bearer(SecretRef),
}

impl fmt::Debug for McpAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::None => "McpAuthentication::None",
            Self::Bearer(_) => "McpAuthentication::Bearer([REFERENCE])",
        })
    }
}

impl McpAuthentication {
    pub(crate) const fn secret_reference(&self) -> Option<&SecretRef> {
        match self {
            Self::None => None,
            Self::Bearer(reference) => Some(reference),
        }
    }
}

/// A discovered tool name and compiled JSON input schema.
#[derive(Clone)]
pub struct McpToolBinding {
    name: Arc<str>,
    schema: Arc<Value>,
    validator: Arc<jsonschema::Validator>,
}

impl McpToolBinding {
    /// Compiles a discovered tool schema under the configured bound.
    pub fn new(tool: &McpTool, limits: McpLimits) -> Result<Self, McpToolBindingError> {
        Self::from_parts(tool.name(), tool.input_schema().clone(), limits)
    }

    /// Compiles a tool binding supplied by a trusted configuration surface.
    pub fn from_parts(
        name: &str,
        schema: Value,
        limits: McpLimits,
    ) -> Result<Self, McpToolBindingError> {
        Self::from_parts_with_schema_limit(name, schema, limits.schema_bytes())
    }

    pub(crate) fn from_parts_with_schema_limit(
        name: &str,
        schema: Value,
        schema_bytes: usize,
    ) -> Result<Self, McpToolBindingError> {
        if name.trim().is_empty() || name.chars().any(char::is_control) {
            return Err(McpToolBindingError::InvalidName);
        }
        let encoded =
            serde_json::to_vec(&schema).map_err(|_| McpToolBindingError::InvalidSchema)?;
        if encoded.len() > schema_bytes {
            return Err(McpToolBindingError::SchemaTooLarge);
        }
        if !schema.is_object() || !jsonschema::draft202012::meta::is_valid(&schema) {
            return Err(McpToolBindingError::InvalidSchema);
        }
        let validator = jsonschema::draft202012::new(&schema)
            .map_err(|_| McpToolBindingError::InvalidSchema)?;
        Ok(Self {
            name: Arc::from(name),
            schema: Arc::new(schema),
            validator: Arc::new(validator),
        })
    }

    /// Returns the fixed tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the validated discovered input schema.
    #[must_use]
    pub fn input_schema(&self) -> &Value {
        &self.schema
    }

    /// Validates a prospective input during host route configuration.
    pub fn validate_input(&self, input: &Value) -> Result<(), McpInputError> {
        if !input.is_object() || json_nesting_depth(input) > MAX_JSON_NESTING_DEPTH {
            return Err(McpInputError::InvalidShape);
        }
        if !self.validator.is_valid(input) {
            return Err(McpInputError::SchemaMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for McpToolBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpToolBinding")
            .field("name", &self.name)
            .field(
                "schema_bytes",
                &serde_json::to_vec(self.schema.as_ref()).map_or(0, |value| value.len()),
            )
            .finish()
    }
}

/// Immutable sans-I/O configuration for one fixed MCP tool.
pub struct McpDeliveryKind {
    configuration: Arc<McpConfiguration>,
}

impl McpDeliveryKind {
    /// Configures one negotiated MCP endpoint and fixed tool binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: NetworkEndpoint,
        authentication: McpAuthentication,
        policy: EndpointPolicy,
        client: McpClient,
        version: McpProtocolVersion,
        tool: McpToolBinding,
        limits: McpLimits,
    ) -> Result<Self, McpConfigurationError> {
        if !matches!(
            endpoint.scheme(),
            NetworkScheme::Http | NetworkScheme::Https
        ) {
            return Err(McpConfigurationError::UnsupportedScheme);
        }
        let probe = client
            .call_tool(
                0,
                version,
                tool.name(),
                Value::Object(serde_json::Map::new()),
            )
            .map_err(|_| McpConfigurationError::InvalidProtocolShape)?
            .into_parts();
        let header_bytes = probe
            .headers()
            .iter()
            .fold(0_usize, |total, (name, value)| {
                total
                    .saturating_add(name.as_str().len())
                    .saturating_add(value.as_bytes().len())
                    .saturating_add(4)
            });
        if header_bytes > MAX_HTTP_HEADER_BYTES {
            return Err(McpConfigurationError::InvalidProtocolShape);
        }
        let body_overhead = probe.body().len().saturating_sub(2);
        let max_payload_bytes =
            MAX_EVENT_PAYLOAD_BYTES.min(MAX_HTTP_REQUEST_BODY_BYTES.saturating_sub(body_overhead));
        if max_payload_bytes == 0 {
            return Err(McpConfigurationError::InvalidProtocolShape);
        }
        let summary = Arc::from(redacted_target(&endpoint, tool.name()));
        Ok(Self {
            configuration: Arc::new(McpConfiguration {
                endpoint,
                authentication,
                policy,
                client,
                version,
                tool,
                limits,
                max_payload_bytes,
                summary,
                automatic_retry: false,
            }),
        })
    }

    /// Explicitly permits route retry policy after ambiguous MCP failures.
    #[must_use]
    pub fn with_automatic_retry(mut self) -> Self {
        Arc::make_mut(&mut self.configuration).automatic_retry = true;
        self
    }
}

impl fmt::Debug for McpDeliveryKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpDeliveryKind")
            .field("target", &self.configuration.summary)
            .field("authentication", &self.configuration.authentication)
            .field("policy", &self.configuration.policy)
            .field("version", &self.configuration.version)
            .field("tool", &self.configuration.tool.name)
            .field("limits", &self.configuration.limits)
            .field("automatic_retry", &self.configuration.automatic_retry)
            .finish()
    }
}

impl DeliveryKind for McpDeliveryKind {
    fn name(&self) -> &'static str {
        "mcp"
    }

    fn target_summary(&self) -> &str {
        &self.configuration.summary
    }

    fn supports_call(&self) -> bool {
        true
    }

    fn permits_automatic_retry(&self) -> bool {
        self.configuration.automatic_retry
    }

    fn max_payload_bytes(&self) -> usize {
        self.configuration.max_payload_bytes
    }

    fn validate_payload(
        &self,
        _mode: OperationMode,
        payload: &EventPayload,
    ) -> Result<(), KindOperationError> {
        let value = serde_json::from_slice(payload.as_bytes())
            .map_err(|_| KindOperationError::InvalidEvent)?;
        self.configuration
            .tool
            .validate_input(&value)
            .map_err(|_| KindOperationError::InvalidEvent)
    }

    fn operation(
        &self,
        mode: OperationMode,
        _delivery: DeliveryId,
        payload: EventPayload,
    ) -> Result<Box<dyn DeliveryOperation>, KindOperationError> {
        self.validate_payload(mode, &payload)?;
        Ok(Box::new(McpOperation {
            configuration: Arc::clone(&self.configuration),
            mode,
            payload,
            decoder: None,
            state: OperationState::Ready,
        }))
    }
}

#[derive(Clone)]
struct McpConfiguration {
    endpoint: NetworkEndpoint,
    authentication: McpAuthentication,
    policy: EndpointPolicy,
    client: McpClient,
    version: McpProtocolVersion,
    tool: McpToolBinding,
    limits: McpLimits,
    max_payload_bytes: usize,
    summary: Arc<str>,
    automatic_retry: bool,
}

impl McpConfiguration {
    fn secret_reference(&self) -> Option<&SecretRef> {
        self.authentication.secret_reference()
    }
}

struct McpOperation {
    configuration: Arc<McpConfiguration>,
    mode: OperationMode,
    payload: EventPayload,
    decoder: Option<McpResponseDecoder>,
    state: OperationState,
}

impl DeliveryOperation for McpOperation {
    fn secret_references(&self) -> &[SecretRef] {
        self.configuration
            .secret_reference()
            .map_or(&[], slice::from_ref)
    }

    fn start(&mut self, context: AttemptContext, secrets: Vec<ResolvedSecret>) -> KindTransition {
        if self.state != OperationState::Ready {
            self.state = OperationState::Complete;
            return KindTransition::Complete(AttemptDisposition::Failed(DeliveryFailure::Internal));
        }
        match self.compose_request(context, &secrets) {
            Ok((request, decoder)) => {
                self.decoder = Some(decoder);
                self.state = OperationState::AwaitingHttp;
                KindTransition::Http(Box::new(request))
            }
            Err(disposition) => {
                self.state = OperationState::Complete;
                KindTransition::Complete(disposition)
            }
        }
    }

    fn resume(
        &mut self,
        _context: AttemptContext,
        completion: TransportCompletion,
    ) -> KindTransition {
        if self.state != OperationState::AwaitingHttp {
            return KindTransition::Complete(AttemptDisposition::Failed(DeliveryFailure::Internal));
        }
        self.state = OperationState::Complete;
        let Some(decoder) = self.decoder.take() else {
            return KindTransition::Complete(AttemptDisposition::Failed(DeliveryFailure::Internal));
        };
        match completion {
            TransportCompletion::Http(Ok(response)) => self.classify_response(decoder, response),
            TransportCompletion::Http(Err(error)) => {
                KindTransition::Complete(classify_transport(error))
            }
        }
    }
}

impl McpOperation {
    fn compose_request(
        &self,
        context: AttemptContext,
        secrets: &[ResolvedSecret],
    ) -> Result<(HttpRequest, McpResponseDecoder), AttemptDisposition> {
        let expected_secrets = usize::from(self.configuration.secret_reference().is_some());
        if secrets.len() != expected_secrets {
            return Err(AttemptDisposition::Failed(
                DeliveryFailure::SecretUnavailable,
            ));
        }
        let arguments = serde_json::from_slice(self.payload.as_bytes())
            .map_err(|_| AttemptDisposition::Failed(DeliveryFailure::Internal))?;
        let parts = self
            .configuration
            .client
            .call_tool(
                1,
                self.configuration.version,
                self.configuration.tool.name(),
                arguments,
            )
            .map_err(classify_request_encoding)?
            .into_parts();
        let (mut headers, body, decoder) = parts.into_values();
        if let McpAuthentication::Bearer(_) = &self.configuration.authentication {
            let mut value = bearer_header(secrets.first().ok_or(AttemptDisposition::Failed(
                DeliveryFailure::SecretUnavailable,
            ))?)
            .map_err(|()| AttemptDisposition::Failed(DeliveryFailure::SecretUnavailable))?;
            value.set_sensitive(true);
            headers.insert(header::AUTHORIZATION, value);
        }
        let request = HttpRequest::new(
            Method::POST,
            self.configuration.endpoint.clone(),
            headers,
            body,
            context.deadline(),
            self.configuration.policy.clone(),
            self.configuration.limits.response(),
        )
        .map_err(classify_request_error)?;
        Ok((request, decoder))
    }

    fn classify_response(
        &self,
        decoder: McpResponseDecoder,
        response: bondry_transport::HttpResponse,
    ) -> KindTransition {
        let response_bytes = u32::try_from(response.body().len()).unwrap_or(u32::MAX);
        match decoder.decode(response.status(), response.headers(), response.body()) {
            Ok(McpClientResponse::ToolCall(result)) => {
                let bytes = result.json().len();
                if bytes > self.configuration.limits.result_bytes()
                    || result.nesting_depth() > MAX_JSON_NESTING_DEPTH
                {
                    return KindTransition::Complete(invalid_result(bytes));
                }
                let category = match result.outcome() {
                    McpToolCallOutcome::Succeeded => DeliveryResultCategory::Succeeded,
                    McpToolCallOutcome::Failed => DeliveryResultCategory::Failed,
                };
                let metadata =
                    DeliveryResultMetadata::new(category, u32::try_from(bytes).unwrap_or(u32::MAX));
                if self.mode == OperationMode::Call {
                    KindTransition::CompleteWithResult {
                        disposition: AttemptDisposition::Delivered(Some(metadata)),
                        result: result.json().clone(),
                    }
                } else {
                    KindTransition::Complete(AttemptDisposition::Delivered(Some(metadata)))
                }
            }
            Ok(_) => KindTransition::Complete(invalid_result(response.body().len())),
            Err(error) => KindTransition::Complete(classify_client(error, response_bytes)),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OperationState {
    Ready,
    AwaitingHttp,
    Complete,
}

/// Invalid fixed MCP route configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpConfigurationError {
    /// MCP egress supports only HTTP and HTTPS endpoints.
    #[error("MCP endpoint must use HTTP or HTTPS")]
    UnsupportedScheme,
    /// Tool routing headers or the minimum request exceed transport bounds.
    #[error("MCP protocol shape exceeds transport bounds")]
    InvalidProtocolShape,
}

/// Invalid discovered MCP tool binding.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpToolBindingError {
    /// The tool name is empty or contains control characters.
    #[error("MCP tool name is invalid")]
    InvalidName,
    /// The encoded input schema exceeds the configured bound.
    #[error("MCP tool input schema exceeds the configured bound")]
    SchemaTooLarge,
    /// The input schema is not valid JSON Schema 2020-12.
    #[error("MCP tool input schema is invalid")]
    InvalidSchema,
}

/// Input rejected by one compiled MCP tool schema.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum McpInputError {
    /// Input is not a bounded JSON object.
    #[error("MCP tool input shape is invalid")]
    InvalidShape,
    /// Input does not satisfy the discovered schema.
    #[error("MCP tool input does not match its schema")]
    SchemaMismatch,
}

fn invalid_result(bytes: usize) -> AttemptDisposition {
    AttemptDisposition::FailedWithResult {
        failure: DeliveryFailure::ReceiverRejected,
        result: DeliveryResultMetadata::new(
            DeliveryResultCategory::Invalid,
            u32::try_from(bytes).unwrap_or(u32::MAX),
        ),
    }
}

fn classify_client(error: McpClientError, bytes: u32) -> AttemptDisposition {
    match error {
        McpClientError::PeerUnavailable | McpClientError::UnexpectedHttpStatus => {
            AttemptDisposition::Retryable(RetryableFailure::ReceiverRejected)
        }
        McpClientError::UnsupportedResponseMode
        | McpClientError::InvalidContentType
        | McpClientError::InvalidJson
        | McpClientError::InvalidEnvelope
        | McpClientError::MismatchedResponseId => AttemptDisposition::FailedWithResult {
            failure: DeliveryFailure::ReceiverRejected,
            result: DeliveryResultMetadata::new(DeliveryResultCategory::Invalid, bytes),
        },
        McpClientError::UnsupportedProtocolVersion
        | McpClientError::MethodNotFound
        | McpClientError::RequestRejected
        | McpClientError::RemoteFailure
        | McpClientError::ToolListTooLarge => {
            AttemptDisposition::Failed(DeliveryFailure::ReceiverRejected)
        }
    }
}

fn classify_request_encoding(_error: McpClientRequestError) -> AttemptDisposition {
    AttemptDisposition::Failed(DeliveryFailure::Internal)
}

fn classify_request_error(error: TransportError) -> AttemptDisposition {
    match error {
        TransportError::Policy(_) | TransportError::TlsFailed => {
            AttemptDisposition::Failed(DeliveryFailure::EndpointPolicy)
        }
        TransportError::RequestTooLarge
        | TransportError::InvalidLimits
        | TransportError::UnsupportedEndpoint
        | TransportError::InvalidMessage
        | TransportError::ResponseTooLarge
        | TransportError::DeadlineExceeded
        | TransportError::ConnectionFailed
        | TransportError::InvalidResponse => AttemptDisposition::Failed(DeliveryFailure::Internal),
    }
}

fn classify_transport(error: TransportError) -> AttemptDisposition {
    match error {
        TransportError::DeadlineExceeded => {
            AttemptDisposition::Retryable(RetryableFailure::DeadlineExceeded)
        }
        TransportError::ConnectionFailed | TransportError::InvalidResponse => {
            AttemptDisposition::Retryable(RetryableFailure::TransportUnavailable)
        }
        TransportError::Policy(_) | TransportError::TlsFailed => {
            AttemptDisposition::Failed(DeliveryFailure::EndpointPolicy)
        }
        TransportError::ResponseTooLarge => invalid_result(0),
        TransportError::RequestTooLarge
        | TransportError::InvalidLimits
        | TransportError::UnsupportedEndpoint
        | TransportError::InvalidMessage => AttemptDisposition::Failed(DeliveryFailure::Internal),
    }
}

pub(crate) fn bearer_header(secret: &ResolvedSecret) -> Result<HeaderValue, ()> {
    let token = secret.current_value().expose();
    let padding = token
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(token.len());
    if padding == 0
        || !token[..padding].iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        || !token[padding..].iter().all(|byte| *byte == b'=')
    {
        return Err(());
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(7 + token.len()));
    encoded.extend_from_slice(b"Bearer ");
    encoded.extend_from_slice(token);
    HeaderValue::from_bytes(&encoded).map_err(|_| ())
}

fn json_nesting_depth(value: &Value) -> usize {
    match value {
        Value::Array(values) => 1 + values.iter().map(json_nesting_depth).max().unwrap_or(0),
        Value::Object(values) => 1 + values.values().map(json_nesting_depth).max().unwrap_or(0),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => 0,
    }
}

fn redacted_target(endpoint: &NetworkEndpoint, tool: &str) -> String {
    format!(
        "{}://{}:{}#{}",
        endpoint.scheme().as_str(),
        endpoint.host(),
        endpoint.port(),
        tool
    )
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use bondry_delivery_store::{DeliveryFailure, DeliveryId, DeliveryResultCategory};
    use bondry_egress::{
        AttemptContext, AttemptDisposition, DeliveryKind, KindOperationError, KindTransition,
        OperationMode, PayloadContract, PayloadField, PayloadFieldName, PayloadFieldType,
        PayloadLimit, TransportCompletion,
    };
    use bondry_mcp_proto::{McpClient, McpClientInfo, McpProtocolVersion};
    use bondry_secrets::{ResolvedSecret, SecretRef, SecretValue};
    use bondry_transport::{
        ConnectionEvidence, Deadline, EndpointPolicy, HttpResponse, NetworkEndpoint,
        TlsConnectionEvidence, TransportError,
    };
    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, StatusCode, header};
    use serde_json::{Value, json};

    use super::{
        McpAuthentication, McpConfigurationError, McpDeliveryKind, McpInputError, McpToolBinding,
        McpToolBindingError,
    };
    use crate::McpLimits;

    const CALL_RESPONSE: &str =
        include_str!("../../../../fixtures/protocol-v1/mcp/tools-call.response.json");

    fn endpoint(value: &str) -> Result<NetworkEndpoint, Box<dyn std::error::Error>> {
        Ok(NetworkEndpoint::new(value.parse()?)?)
    }

    fn client() -> Result<McpClient, Box<dyn std::error::Error>> {
        Ok(McpClient::new(McpClientInfo::new(
            "bondry-egress",
            "0.2.0",
        )?))
    }

    fn binding() -> Result<McpToolBinding, Box<dyn std::error::Error>> {
        Ok(McpToolBinding::from_parts(
            "battery:status",
            json!({
                "type": "object",
                "properties": { "detail": { "type": "boolean" } },
                "required": ["detail"],
                "additionalProperties": false,
            }),
            McpLimits::default(),
        )?)
    }

    fn kind(
        authentication: McpAuthentication,
    ) -> Result<McpDeliveryKind, Box<dyn std::error::Error>> {
        Ok(McpDeliveryKind::new(
            endpoint("https://example.com/private?opaque=value")?,
            authentication,
            EndpointPolicy::default(),
            client()?,
            McpProtocolVersion::V2026_07_28,
            binding()?,
            McpLimits::default(),
        )?)
    }

    fn payload(detail: bool) -> Result<bondry_egress::EventPayload, Box<dyn std::error::Error>> {
        let contract = PayloadContract::new(
            [PayloadField::new(
                PayloadFieldName::new("detail")?,
                PayloadFieldType::Boolean,
                true,
            )],
            PayloadLimit::default(),
        )?;
        Ok(contract.validate(Bytes::from(format!("{{\"detail\":{detail}}}")))?)
    }

    fn context() -> AttemptContext {
        AttemptContext::new(0, Deadline::at(Instant::now()))
    }

    fn response(mut result: Value) -> Result<HttpResponse, Box<dyn std::error::Error>> {
        result["id"] = Value::from(1);
        let endpoint = endpoint("https://example.com/private")?;
        let policy = EndpointPolicy::default();
        let connection = policy.verify_connection(
            &endpoint,
            ConnectionEvidence::Tls(TlsConnectionEvidence::verified(endpoint.host())),
        )?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        Ok(HttpResponse::new(
            StatusCode::OK,
            headers,
            Bytes::from(serde_json::to_vec(&result)?),
            connection,
            McpLimits::default().response(),
        )?)
    }

    #[test]
    fn compiles_schema_and_rejects_invalid_inputs_before_operation()
    -> Result<(), Box<dyn std::error::Error>> {
        let binding = binding()?;
        assert!(binding.validate_input(&json!({ "detail": true })).is_ok());
        assert_eq!(
            binding.validate_input(&json!({ "detail": "yes" })),
            Err(McpInputError::SchemaMismatch)
        );
        assert_eq!(
            McpToolBinding::from_parts("tool", json!({ "type": "unknown" }), McpLimits::default())
                .err(),
            Some(McpToolBindingError::InvalidSchema)
        );

        let kind = kind(McpAuthentication::None)?;
        let invalid_contract = PayloadContract::new(
            [PayloadField::new(
                PayloadFieldName::new("detail")?,
                PayloadFieldType::String,
                true,
            )],
            PayloadLimit::default(),
        )?;
        let invalid = invalid_contract.validate(Bytes::from_static(br#"{"detail":"yes"}"#))?;
        assert_eq!(
            kind.validate_payload(OperationMode::Emit, &invalid),
            Err(KindOperationError::InvalidEvent)
        );
        Ok(())
    }

    #[test]
    fn composes_sensitive_bearer_request_and_redacts_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let kind = kind(McpAuthentication::Bearer(SecretRef::new("keychain:mcp")?))?;
        assert!(!kind.permits_automatic_retry());
        assert!(!kind.target_summary().contains("opaque=value"));
        assert!(!format!("{kind:?}").contains("opaque=value"));
        let mut operation = kind.operation(
            OperationMode::Emit,
            DeliveryId::new("mcp_emit")?,
            payload(true)?,
        )?;
        let secret = ResolvedSecret::current(SecretValue::new(b"token+/==".to_vec())?);
        let KindTransition::Http(request) = operation.start(context(), vec![secret]) else {
            return Err(std::io::Error::other("HTTP request was not produced").into());
        };
        assert!(!format!("{request:?}").contains("token+/=="));
        let parts = request.into_parts();
        assert_eq!(parts.endpoint.path_and_query(), "/private?opaque=value");
        assert_eq!(parts.headers[header::AUTHORIZATION], "Bearer token+/==");
        assert!(parts.headers[header::AUTHORIZATION].is_sensitive());
        Ok(())
    }

    #[test]
    fn emit_discards_result_and_call_returns_only_bounded_raw_json()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture: Value = serde_json::from_str(CALL_RESPONSE)?;
        for mode in [OperationMode::Emit, OperationMode::Call] {
            let kind = kind(McpAuthentication::None)?;
            let mut operation = kind.operation(
                mode,
                DeliveryId::new(if mode == OperationMode::Emit {
                    "mcp_emit_result"
                } else {
                    "mcp_call_result"
                })?,
                payload(true)?,
            )?;
            assert!(matches!(
                operation.start(context(), Vec::new()),
                KindTransition::Http(_)
            ));
            let transition = operation.resume(
                context(),
                TransportCompletion::Http(Ok(response(fixture.clone())?)),
            );
            match (mode, transition) {
                (
                    OperationMode::Emit,
                    KindTransition::Complete(AttemptDisposition::Delivered(Some(metadata))),
                ) => {
                    assert_eq!(metadata.category(), DeliveryResultCategory::Succeeded);
                    assert!(metadata.bytes() > 0);
                }
                (
                    OperationMode::Call,
                    KindTransition::CompleteWithResult {
                        disposition: AttemptDisposition::Delivered(Some(metadata)),
                        result,
                    },
                ) => {
                    assert_eq!(metadata.category(), DeliveryResultCategory::Succeeded);
                    assert_eq!(usize::try_from(metadata.bytes())?, result.len());
                    assert!(!result.is_empty());
                }
                _ => return Err(std::io::Error::other("unexpected MCP result").into()),
            }
        }
        Ok(())
    }

    #[test]
    fn invalid_responses_fail_closed_with_redacted_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let kind = kind(McpAuthentication::None)?;
        let mut operation = kind.operation(
            OperationMode::Call,
            DeliveryId::new("mcp_invalid")?,
            payload(true)?,
        )?;
        assert!(matches!(
            operation.start(context(), Vec::new()),
            KindTransition::Http(_)
        ));
        let transition = operation.resume(
            context(),
            TransportCompletion::Http(Err(TransportError::ResponseTooLarge)),
        );
        assert!(matches!(
            transition,
            KindTransition::Complete(AttemptDisposition::FailedWithResult {
                failure: DeliveryFailure::ReceiverRejected,
                result,
            }) if result.category() == DeliveryResultCategory::Invalid
        ));
        Ok(())
    }

    #[test]
    fn retry_requires_explicit_kind_opt_in() -> Result<(), Box<dyn std::error::Error>> {
        let kind = kind(McpAuthentication::None)?;
        assert!(!kind.permits_automatic_retry());
        assert!(kind.with_automatic_retry().permits_automatic_retry());
        assert!(matches!(
            McpDeliveryKind::new(
                endpoint("wss://example.com/mcp")?,
                McpAuthentication::None,
                EndpointPolicy::default(),
                client()?,
                McpProtocolVersion::V2026_07_28,
                binding()?,
                McpLimits::default(),
            ),
            Err(McpConfigurationError::UnsupportedScheme)
        ));
        Ok(())
    }
}
