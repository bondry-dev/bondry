#![doc = "Minimal runtime-host baseline for Rust egress linked-size probes."]

use std::{error::Error, sync::Arc};

use bondry_egress::RouteRegistry;
use bondry_egress_runtime::{EgressRuntime, EgressRuntimeLimits, InMemoryDeliveryLog};
use bondry_secrets::{ResolvedSecret, SecretProvider, SecretProviderError, SecretRef};
use bondry_transport::{HttpRequest, HttpResponse, HttpTransport, TransportError, TransportFuture};

struct BaselineSecrets;

impl SecretProvider for BaselineSecrets {
    fn resolve(&self, _: &SecretRef) -> Result<ResolvedSecret, SecretProviderError> {
        Err(SecretProviderError::NotFound)
    }
}

struct BaselineTransport;

impl HttpTransport for BaselineTransport {
    fn send(&self, _: HttpRequest) -> TransportFuture<'_, Result<HttpResponse, TransportError>> {
        Box::pin(async { Err(TransportError::UnsupportedEndpoint) })
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut runtime = EgressRuntime::start(
        RouteRegistry::default(),
        EgressRuntimeLimits::default(),
        Arc::new(InMemoryDeliveryLog::default()),
        Arc::new(BaselineSecrets),
        Arc::new(BaselineTransport),
    )?;
    std::hint::black_box(runtime.routes()?);
    runtime.stop()?;
    Ok(())
}
