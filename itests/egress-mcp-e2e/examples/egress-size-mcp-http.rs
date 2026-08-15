#![doc = "Linked-size probe for local MCP egress over HTTP."]

use std::{error::Error, sync::Arc, time::Duration};

use bondry_delivery_store::{DeliveryId, RouteId};
use bondry_egress::{
    PayloadContract, PayloadField, PayloadFieldName, PayloadFieldType, PayloadLimit,
    RequestTimeout, RetryPolicy, Route, RouteAdmissionLimit, RouteRegistry,
};
use bondry_egress_mcp::{
    McpAuthentication, McpDeliveryKind, McpDiscoveryOperation, McpDiscoveryTransition, McpLimits,
    McpToolBinding,
};
use bondry_egress_runtime::{EgressRuntime, EgressRuntimeLimits, InMemoryDeliveryLog};
use bondry_mcp_proto::{McpClient, McpClientInfo, McpProtocolVersion};
use bondry_secrets::{ResolvedSecret, SecretProvider, SecretProviderError, SecretRef};
use bondry_transport::{Deadline, EndpointPolicy, HttpTransport, NetworkEndpoint};
use bondry_transport_net::NetHttpTransport;
use bytes::Bytes;
use serde_json::json;

struct ProbeSecrets;

impl SecretProvider for ProbeSecrets {
    fn resolve(&self, _: &SecretRef) -> Result<ResolvedSecret, SecretProviderError> {
        Err(SecretProviderError::NotFound)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let endpoint = NetworkEndpoint::new("http://127.0.0.1:1/mcp".parse()?)?;
    let client = McpClient::new(McpClientInfo::new("size-probe", "0.2.0")?);
    let mut discovery = McpDiscoveryOperation::new(
        endpoint.clone(),
        McpAuthentication::None,
        EndpointPolicy::default(),
        client.clone(),
        Default::default(),
    )?;
    let deadline = Deadline::at(std::time::Instant::now() + Duration::from_secs(1));
    let transport = NetHttpTransport::new()?;
    let mut transition = discovery.start(deadline, Vec::new());
    loop {
        match transition {
            McpDiscoveryTransition::Http(request) => {
                transition = discovery.resume(transport.send(*request).await);
            }
            McpDiscoveryTransition::Complete(result) => {
                std::hint::black_box(result.err());
                break;
            }
        }
    }

    let binding = McpToolBinding::from_parts(
        "probe.status",
        json!({
            "type": "object",
            "properties": { "detail": { "type": "boolean" } },
            "required": ["detail"],
            "additionalProperties": false,
        }),
        McpLimits::default(),
    )?;
    let kind = McpDeliveryKind::new(
        endpoint,
        McpAuthentication::None,
        EndpointPolicy::default(),
        client,
        McpProtocolVersion::V2026_07_28,
        binding,
        McpLimits::default(),
    )?;
    let route_id = RouteId::new("size-probe")?;
    let route = Route::new(
        route_id.clone(),
        true,
        PayloadContract::new(
            [PayloadField::new(
                PayloadFieldName::new("detail")?,
                PayloadFieldType::Boolean,
                true,
            )],
            PayloadLimit::default(),
        )?,
        RequestTimeout::new(Duration::from_secs(1))?,
        RetryPolicy::without_retries(),
        RouteAdmissionLimit::default(),
        Arc::new(kind),
    );
    let mut runtime = EgressRuntime::start(
        RouteRegistry::default(),
        EgressRuntimeLimits::default(),
        Arc::new(InMemoryDeliveryLog::default()),
        Arc::new(ProbeSecrets),
        Arc::new(NetHttpTransport::new()?),
    )?;
    runtime.register_route(route)?;
    let _ = std::hint::black_box(runtime.call(
        route_id,
        DeliveryId::new("size-probe-delivery")?,
        Bytes::from_static(br#"{"detail":true}"#),
    ));
    runtime.stop()?;
    Ok(())
}
