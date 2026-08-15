#![doc = "Linked-size probe for webhook egress over HTTPS."]

use std::{error::Error, sync::Arc, time::Duration};

use bondry_delivery_store::{DeliveryId, RouteId};
use bondry_egress::{
    PayloadContract, PayloadField, PayloadFieldName, PayloadFieldType, PayloadLimit,
    RequestTimeout, RetryPolicy, Route, RouteAdmissionLimit, RouteRegistry,
};
use bondry_egress_runtime::{EgressRuntime, EgressRuntimeLimits, InMemoryDeliveryLog};
use bondry_egress_webhook::{
    SecretUrlTemplate, UrlTemplateLimits, WebhookDeliveryKind, WebhookLimits,
};
use bondry_secrets::{ResolvedSecret, SecretProvider, SecretProviderError, SecretRef, SecretValue};
use bondry_transport::EndpointPolicy;
use bondry_transport_net::NetHttpTransport;
use bytes::Bytes;

struct ProbeSecrets;

impl SecretProvider for ProbeSecrets {
    fn resolve(&self, _: &SecretRef) -> Result<ResolvedSecret, SecretProviderError> {
        SecretValue::new(b"size-probe".to_vec())
            .map(ResolvedSecret::current)
            .map_err(|_| SecretProviderError::InvalidMaterial)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let payload = PayloadContract::new(
        [PayloadField::new(
            PayloadFieldName::new("message")?,
            PayloadFieldType::String,
            true,
        )],
        PayloadLimit::default(),
    )?;
    let template = SecretUrlTemplate::new(
        "https://127.0.0.1:1/{secret}".to_owned(),
        SecretRef::new("probe:topic")?,
        UrlTemplateLimits::default(),
    )?;
    let route_id = RouteId::new("size-probe")?;
    let route = Route::new(
        route_id.clone(),
        true,
        payload,
        RequestTimeout::new(Duration::from_secs(1))?,
        RetryPolicy::default(),
        RouteAdmissionLimit::default(),
        Arc::new(WebhookDeliveryKind::with_url_template(
            template,
            EndpointPolicy::default(),
            WebhookLimits::default(),
        )),
    );
    let mut runtime = EgressRuntime::start(
        RouteRegistry::default(),
        EgressRuntimeLimits::default(),
        Arc::new(InMemoryDeliveryLog::default()),
        Arc::new(ProbeSecrets),
        Arc::new(NetHttpTransport::new()?),
    )?;
    runtime.register_route(route)?;
    runtime.emit(
        route_id,
        DeliveryId::new("size-probe-delivery")?,
        Bytes::from_static(br#"{"message":"probe"}"#),
    )?;
    runtime.stop()?;
    Ok(())
}
