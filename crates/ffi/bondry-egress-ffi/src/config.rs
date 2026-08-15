use std::{sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use bondry_delivery_store::{PersistentDeliveryLogLimits, RouteId};
use bondry_egress::{
    DeliveryKind, GlobalAdmissionLimit, PayloadContract, PayloadField, PayloadFieldName,
    PayloadFieldType, PayloadLimit, RequestTimeout, RetryPolicy, Route, RouteAdmissionLimit,
    RouteRegistry, RouteRegistryLimit,
};
use bondry_egress_mcp::{
    McpAuthentication, McpDeliveryKind, McpDiscoveryLimits, McpDiscoveryOperation, McpLimits,
    McpToolBinding,
};
use bondry_egress_runtime::EgressRuntimeLimits;
use bondry_egress_webhook::{
    SecretUrlTemplate, UrlTemplateLimits, WebhookAuthentication, WebhookDeliveryKind, WebhookLimits,
};
use bondry_mcp_proto::{McpClient, McpClientInfo, McpProtocolVersion};
use bondry_secrets::SecretRef;
use bondry_transport::{AdditionalTrustAnchor, EndpointPolicy, NetworkEndpoint};
use serde::Deserialize;
use serde_json::Value;

pub(crate) const MAX_RUNTIME_CONFIGURATION_BYTES: usize = 64 * 1024;
pub(crate) const MAX_ROUTE_CONFIGURATION_BYTES: usize = 128 * 1024;
pub(crate) const MAX_DISCOVERY_CONFIGURATION_BYTES: usize = 128 * 1024;

const CONFIGURATION_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigurationError {
    Json,
    Invalid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeConfiguration {
    version: u32,
    #[serde(default)]
    registry: RegistryConfiguration,
    #[serde(default)]
    runtime: RuntimeLimitsConfiguration,
    #[serde(default)]
    delivery_log: DeliveryLogConfiguration,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RegistryConfiguration {
    max_routes: u16,
    global_refill_per_second: u16,
    global_capacity: u16,
}

impl Default for RegistryConfiguration {
    fn default() -> Self {
        let admission = GlobalAdmissionLimit::default();
        Self {
            max_routes: RouteRegistryLimit::default().get(),
            global_refill_per_second: admission.refill_per_second(),
            global_capacity: admission.capacity(),
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuntimeLimitsConfiguration {
    global_pending_deliveries: u16,
    route_pending_deliveries: u16,
    global_pending_bytes: usize,
    route_pending_bytes: usize,
    global_in_flight: u8,
    route_in_flight: u8,
    call_in_flight: u8,
    drain_timeout_milliseconds: u64,
}

impl Default for RuntimeLimitsConfiguration {
    fn default() -> Self {
        let limits = EgressRuntimeLimits::default();
        Self {
            global_pending_deliveries: limits.global_pending_deliveries(),
            route_pending_deliveries: limits.route_pending_deliveries(),
            global_pending_bytes: limits.global_pending_bytes(),
            route_pending_bytes: limits.route_pending_bytes(),
            global_in_flight: limits.global_in_flight(),
            route_in_flight: limits.route_in_flight(),
            call_in_flight: limits.call_in_flight(),
            drain_timeout_milliseconds: u64::try_from(limits.drain_timeout().as_millis())
                .unwrap_or(u64::MAX),
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DeliveryLogConfiguration {
    max_records: u32,
    max_bytes: u64,
    retention_seconds: u64,
}

impl Default for DeliveryLogConfiguration {
    fn default() -> Self {
        let limits = PersistentDeliveryLogLimits::default();
        Self {
            max_records: limits.records(),
            max_bytes: limits.bytes(),
            retention_seconds: limits.retention().as_secs(),
        }
    }
}

pub(crate) struct ValidatedRuntimeConfiguration {
    pub(crate) registry: RouteRegistry,
    pub(crate) runtime: EgressRuntimeLimits,
    pub(crate) delivery_log: PersistentDeliveryLogLimits,
}

pub(crate) fn runtime_configuration(
    bytes: &[u8],
) -> Result<ValidatedRuntimeConfiguration, ConfigurationError> {
    let configuration: RuntimeConfiguration = parse_configuration(bytes)?;
    if configuration.version != CONFIGURATION_VERSION {
        return Err(ConfigurationError::Invalid);
    }
    let registry_limit = RouteRegistryLimit::new(configuration.registry.max_routes)
        .map_err(|_| ConfigurationError::Invalid)?;
    let global_admission = GlobalAdmissionLimit::new(
        configuration.registry.global_refill_per_second,
        configuration.registry.global_capacity,
    )
    .map_err(|_| ConfigurationError::Invalid)?;
    let runtime = EgressRuntimeLimits::new(
        configuration.runtime.global_pending_deliveries,
        configuration.runtime.route_pending_deliveries,
        configuration.runtime.global_pending_bytes,
        configuration.runtime.route_pending_bytes,
        configuration.runtime.global_in_flight,
        configuration.runtime.route_in_flight,
        configuration.runtime.call_in_flight,
        Duration::from_millis(configuration.runtime.drain_timeout_milliseconds),
    )
    .map_err(|_| ConfigurationError::Invalid)?;
    let delivery_log = PersistentDeliveryLogLimits::new(
        configuration.delivery_log.max_records,
        configuration.delivery_log.max_bytes,
        Duration::from_secs(configuration.delivery_log.retention_seconds),
    )
    .map_err(|_| ConfigurationError::Invalid)?;
    Ok(ValidatedRuntimeConfiguration {
        registry: RouteRegistry::new(registry_limit, global_admission),
        runtime,
        delivery_log,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteConfiguration {
    version: u32,
    id: String,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    payload: PayloadConfiguration,
    #[serde(default = "default_request_timeout_milliseconds")]
    request_timeout_milliseconds: u64,
    #[serde(default)]
    retry: RetryConfiguration,
    #[serde(default)]
    admission: AdmissionConfiguration,
    kind: RouteKindConfiguration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadConfiguration {
    #[serde(default = "default_payload_bytes")]
    max_bytes: usize,
    fields: Vec<PayloadFieldConfiguration>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadFieldConfiguration {
    name: String,
    #[serde(rename = "type")]
    field_type: PayloadType,
    #[serde(default)]
    required: bool,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PayloadType {
    Any,
    Null,
    Boolean,
    Number,
    String,
    Array,
    Object,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RetryConfiguration {
    retries: u8,
    base_milliseconds: u64,
    cap_milliseconds: u64,
}

impl Default for RetryConfiguration {
    fn default() -> Self {
        let retry = RetryPolicy::default();
        Self {
            retries: retry.retries(),
            base_milliseconds: u64::try_from(retry.base().as_millis()).unwrap_or(u64::MAX),
            cap_milliseconds: u64::try_from(retry.cap().as_millis()).unwrap_or(u64::MAX),
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AdmissionConfiguration {
    refill_per_second: u16,
    capacity: u16,
}

impl Default for AdmissionConfiguration {
    fn default() -> Self {
        let admission = RouteAdmissionLimit::default();
        Self {
            refill_per_second: admission.refill_per_second(),
            capacity: admission.capacity(),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum RouteKindConfiguration {
    Webhook {
        authentication: AuthenticationConfiguration,
        #[serde(default)]
        policy: PolicyConfiguration,
        #[serde(default)]
        limits: WebhookLimitsConfiguration,
    },
    Mcp {
        endpoint: String,
        authentication: McpAuthenticationConfiguration,
        #[serde(default)]
        policy: PolicyConfiguration,
        protocol_version: String,
        tool: McpToolConfiguration,
        #[serde(default)]
        limits: McpLimitsConfiguration,
        #[serde(default)]
        automatic_retry: bool,
    },
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum McpAuthenticationConfiguration {
    None,
    Bearer { secret_ref: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpToolConfiguration {
    name: String,
    input_schema: Value,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum AuthenticationConfiguration {
    None {
        endpoint: String,
    },
    Bearer {
        endpoint: String,
        secret_ref: String,
    },
    Hmac {
        endpoint: String,
        secret_ref: String,
    },
    UrlTemplate {
        template: String,
        secret_ref: String,
    },
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct PolicyConfiguration {
    allow_hostname_loopback_cleartext: bool,
    allow_private_cleartext: bool,
    allow_link_local_cleartext: bool,
    additional_trust_anchors_base64: Vec<String>,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct WebhookLimitsConfiguration {
    body_bytes: usize,
    response_body_bytes: usize,
    url_template_bytes: usize,
    expanded_url_bytes: usize,
}

impl Default for WebhookLimitsConfiguration {
    fn default() -> Self {
        let webhook = WebhookLimits::default();
        let template = UrlTemplateLimits::default();
        Self {
            body_bytes: webhook.body_bytes(),
            response_body_bytes: webhook.response().max_response_body_bytes(),
            url_template_bytes: template.template_bytes(),
            expanded_url_bytes: template.expanded_bytes(),
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct McpLimitsConfiguration {
    schema_bytes: usize,
    result_bytes: usize,
}

impl Default for McpLimitsConfiguration {
    fn default() -> Self {
        let limits = McpLimits::default();
        Self {
            schema_bytes: limits.schema_bytes(),
            result_bytes: limits.result_bytes(),
        }
    }
}

pub(crate) fn route_configuration(bytes: &[u8]) -> Result<Route, ConfigurationError> {
    let configuration: RouteConfiguration = parse_configuration(bytes)?;
    if configuration.version != CONFIGURATION_VERSION {
        return Err(ConfigurationError::Invalid);
    }
    let payload = PayloadContract::new(
        configuration
            .payload
            .fields
            .into_iter()
            .map(|field| {
                let name =
                    PayloadFieldName::new(field.name).map_err(|_| ConfigurationError::Invalid)?;
                Ok(PayloadField::new(
                    name,
                    decode_payload_type(field.field_type),
                    field.required,
                ))
            })
            .collect::<Result<Vec<_>, ConfigurationError>>()?,
        PayloadLimit::new(configuration.payload.max_bytes)
            .map_err(|_| ConfigurationError::Invalid)?,
    )
    .map_err(|_| ConfigurationError::Invalid)?;
    let retry = RetryPolicy::new(
        configuration.retry.retries,
        Duration::from_millis(configuration.retry.base_milliseconds),
        Duration::from_millis(configuration.retry.cap_milliseconds),
    )
    .map_err(|_| ConfigurationError::Invalid)?;
    let admission = RouteAdmissionLimit::new(
        configuration.admission.refill_per_second,
        configuration.admission.capacity,
    )
    .map_err(|_| ConfigurationError::Invalid)?;
    let kind: Arc<dyn DeliveryKind> = match configuration.kind {
        RouteKindConfiguration::Webhook {
            authentication,
            policy,
            limits,
        } => Arc::new(decode_webhook_kind(authentication, policy, limits)?),
        RouteKindConfiguration::Mcp {
            endpoint,
            authentication,
            policy,
            protocol_version,
            tool,
            limits,
            automatic_retry,
        } => {
            let limits = McpLimits::new(limits.schema_bytes, limits.result_bytes)
                .map_err(|_| ConfigurationError::Invalid)?;
            let tool = McpToolBinding::from_parts(&tool.name, tool.input_schema, limits)
                .map_err(|_| ConfigurationError::Invalid)?;
            let mut kind = McpDeliveryKind::new(
                decode_endpoint(&endpoint)?,
                decode_mcp_authentication(authentication)?,
                decode_policy(policy)?,
                mcp_client()?,
                McpProtocolVersion::parse(&protocol_version).ok_or(ConfigurationError::Invalid)?,
                tool,
                limits,
            )
            .map_err(|_| ConfigurationError::Invalid)?;
            if automatic_retry {
                kind = kind.with_automatic_retry();
            }
            Arc::new(kind)
        }
    };
    Ok(Route::new(
        RouteId::new(configuration.id).map_err(|_| ConfigurationError::Invalid)?,
        configuration.enabled,
        payload,
        RequestTimeout::new(Duration::from_millis(
            configuration.request_timeout_milliseconds,
        ))
        .map_err(|_| ConfigurationError::Invalid)?,
        retry,
        admission,
        kind,
    ))
}

fn decode_webhook_kind(
    authentication: AuthenticationConfiguration,
    policy: PolicyConfiguration,
    limits: WebhookLimitsConfiguration,
) -> Result<WebhookDeliveryKind, ConfigurationError> {
    let webhook_limits = WebhookLimits::new(limits.body_bytes, limits.response_body_bytes)
        .map_err(|_| ConfigurationError::Invalid)?;
    let template_limits =
        UrlTemplateLimits::new(limits.url_template_bytes, limits.expanded_url_bytes)
            .map_err(|_| ConfigurationError::Invalid)?;
    let policy = decode_policy(policy)?;
    match authentication {
        AuthenticationConfiguration::None { endpoint } => WebhookDeliveryKind::new(
            decode_endpoint(&endpoint)?,
            WebhookAuthentication::None,
            policy,
            webhook_limits,
        )
        .map_err(|_| ConfigurationError::Invalid),
        AuthenticationConfiguration::Bearer {
            endpoint,
            secret_ref,
        } => WebhookDeliveryKind::new(
            decode_endpoint(&endpoint)?,
            WebhookAuthentication::Bearer(decode_secret_reference(secret_ref)?),
            policy,
            webhook_limits,
        )
        .map_err(|_| ConfigurationError::Invalid),
        AuthenticationConfiguration::Hmac {
            endpoint,
            secret_ref,
        } => WebhookDeliveryKind::new(
            decode_endpoint(&endpoint)?,
            WebhookAuthentication::Hmac(decode_secret_reference(secret_ref)?),
            policy,
            webhook_limits,
        )
        .map_err(|_| ConfigurationError::Invalid),
        AuthenticationConfiguration::UrlTemplate {
            template,
            secret_ref,
        } => Ok(WebhookDeliveryKind::with_url_template(
            SecretUrlTemplate::new(
                template,
                decode_secret_reference(secret_ref)?,
                template_limits,
            )
            .map_err(|_| ConfigurationError::Invalid)?,
            policy,
            webhook_limits,
        )),
    }
}

fn decode_mcp_authentication(
    authentication: McpAuthenticationConfiguration,
) -> Result<McpAuthentication, ConfigurationError> {
    match authentication {
        McpAuthenticationConfiguration::None => Ok(McpAuthentication::None),
        McpAuthenticationConfiguration::Bearer { secret_ref } => Ok(McpAuthentication::Bearer(
            decode_secret_reference(secret_ref)?,
        )),
    }
}

fn decode_secret_reference(value: String) -> Result<SecretRef, ConfigurationError> {
    SecretRef::new(value).map_err(|_| ConfigurationError::Invalid)
}

fn mcp_client() -> Result<McpClient, ConfigurationError> {
    McpClientInfo::new("bondry-egress", env!("CARGO_PKG_VERSION"))
        .map(McpClient::new)
        .map_err(|_| ConfigurationError::Invalid)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpDiscoveryConfiguration {
    version: u32,
    endpoint: String,
    authentication: McpAuthenticationConfiguration,
    #[serde(default)]
    policy: PolicyConfiguration,
    #[serde(default)]
    limits: McpDiscoveryLimitsConfiguration,
    #[serde(default = "default_request_timeout_milliseconds")]
    request_timeout_milliseconds: u64,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct McpDiscoveryLimitsConfiguration {
    tools: usize,
    schema_bytes: usize,
    response_bytes: usize,
}

impl Default for McpDiscoveryLimitsConfiguration {
    fn default() -> Self {
        let limits = McpDiscoveryLimits::default();
        Self {
            tools: limits.tools(),
            schema_bytes: limits.schema_bytes(),
            response_bytes: limits.response_bytes(),
        }
    }
}

pub(crate) struct ValidatedMcpDiscoveryConfiguration {
    pub(crate) operation: McpDiscoveryOperation,
    pub(crate) timeout: Duration,
}

pub(crate) fn mcp_discovery_configuration(
    bytes: &[u8],
) -> Result<ValidatedMcpDiscoveryConfiguration, ConfigurationError> {
    let configuration: McpDiscoveryConfiguration = parse_configuration(bytes)?;
    if configuration.version != CONFIGURATION_VERSION {
        return Err(ConfigurationError::Invalid);
    }
    let limits = McpDiscoveryLimits::new(
        configuration.limits.tools,
        configuration.limits.schema_bytes,
        configuration.limits.response_bytes,
    )
    .map_err(|_| ConfigurationError::Invalid)?;
    let timeout = RequestTimeout::new(Duration::from_millis(
        configuration.request_timeout_milliseconds,
    ))
    .map_err(|_| ConfigurationError::Invalid)?
    .get();
    let operation = McpDiscoveryOperation::new(
        decode_endpoint(&configuration.endpoint)?,
        decode_mcp_authentication(configuration.authentication)?,
        decode_policy(configuration.policy)?,
        mcp_client()?,
        limits,
    )
    .map_err(|_| ConfigurationError::Invalid)?;
    Ok(ValidatedMcpDiscoveryConfiguration { operation, timeout })
}

fn parse_configuration<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
) -> Result<T, ConfigurationError> {
    serde_json::from_slice(bytes).map_err(|error| {
        if error.is_syntax() || error.is_eof() {
            ConfigurationError::Json
        } else {
            ConfigurationError::Invalid
        }
    })
}

fn decode_endpoint(endpoint: &str) -> Result<NetworkEndpoint, ConfigurationError> {
    NetworkEndpoint::new(
        endpoint
            .parse::<http::Uri>()
            .map_err(|_| ConfigurationError::Invalid)?,
    )
    .map_err(|_| ConfigurationError::Invalid)
}

fn decode_payload_type(field_type: PayloadType) -> PayloadFieldType {
    match field_type {
        PayloadType::Any => PayloadFieldType::Any,
        PayloadType::Null => PayloadFieldType::Null,
        PayloadType::Boolean => PayloadFieldType::Boolean,
        PayloadType::Number => PayloadFieldType::Number,
        PayloadType::String => PayloadFieldType::String,
        PayloadType::Array => PayloadFieldType::Array,
        PayloadType::Object => PayloadFieldType::Object,
    }
}

fn decode_policy(configuration: PolicyConfiguration) -> Result<EndpointPolicy, ConfigurationError> {
    let mut policy = EndpointPolicy::default();
    if configuration.allow_hostname_loopback_cleartext {
        policy = policy.allowing_hostname_loopback_cleartext();
    }
    if configuration.allow_private_cleartext {
        policy = policy.allowing_private_cleartext();
    }
    if configuration.allow_link_local_cleartext {
        policy = policy.allowing_link_local_cleartext();
    }
    for encoded in configuration.additional_trust_anchors_base64 {
        let anchor = STANDARD
            .decode(encoded)
            .map_err(|_| ConfigurationError::Invalid)?;
        policy = policy
            .with_additional_trust_anchor(
                AdditionalTrustAnchor::from_der(anchor).map_err(|_| ConfigurationError::Invalid)?,
            )
            .map_err(|_| ConfigurationError::Invalid)?;
    }
    Ok(policy)
}

const fn enabled_by_default() -> bool {
    true
}

fn default_request_timeout_milliseconds() -> u64 {
    u64::try_from(RequestTimeout::default().get().as_millis()).unwrap_or(u64::MAX)
}

const fn default_payload_bytes() -> usize {
    bondry_egress::DEFAULT_EVENT_PAYLOAD_BYTES
}

#[cfg(test)]
mod tests {
    use super::{mcp_discovery_configuration, route_configuration, runtime_configuration};

    #[test]
    fn defaults_runtime_but_rejects_unknown_fields() {
        assert!(runtime_configuration(br#"{"version":1}"#).is_ok());
        assert!(runtime_configuration(br#"{"version":1,"unknown":true}"#).is_err());
    }

    #[test]
    fn validates_one_exclusive_url_template_route() {
        let route = br#"{
          "version": 1,
          "id": "ntfy",
          "payload": {
            "fields": [{"name":"event","type":"string","required":true}]
          },
          "kind": {
            "type": "webhook",
            "authentication": {
              "type": "url_template",
              "template": "https://ntfy.sh/{secret}",
              "secret_ref": "keychain:ntfy-topic"
            }
          }
        }"#;
        assert!(route_configuration(route).is_ok());
    }

    #[test]
    fn rejects_unknown_kind_and_authentication_fields() {
        let kind = br#"{
          "version":1,
          "id":"route",
          "payload":{"fields":[]},
          "kind":{"type":"webhook","authentication":{"type":"none","endpoint":"https://example.com","extra":true},"extra":true}
        }"#;
        assert!(route_configuration(kind).is_err());
    }

    #[test]
    fn validates_mcp_route_and_discovery_configuration() {
        let route = br#"{
          "version":1,
          "id":"mcp",
          "payload":{"fields":[{"name":"detail","type":"boolean"}]},
          "kind":{
            "type":"mcp",
            "endpoint":"https://example.com/mcp",
            "authentication":{"type":"bearer","secret_ref":"keychain:mcp"},
            "protocol_version":"2026-07-28",
            "tool":{"name":"battery:status","input_schema":{"type":"object"}}
          }
        }"#;
        assert!(route_configuration(route).is_ok());

        let discovery = br#"{
          "version":1,
          "endpoint":"https://example.com/mcp",
          "authentication":{"type":"none"}
        }"#;
        assert!(mcp_discovery_configuration(discovery).is_ok());
    }
}
