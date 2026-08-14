#![doc = "Pure REST capability protocol handling for Bondry."]

use std::sync::Arc;

use bondry_core::{
    AdapterId, AutomationService, CapabilityDescriptor, CapabilityDiscoveryError, CapabilityEffect,
    CapabilityId, DenialReason, DispatchError, IdentifierError, Invocation, InvocationIdGenerator,
    Principal, SystemInvocationIdGenerator,
};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use serde_json::{Value, json};

/// The stable root path for REST API version one.
pub const REST_V1_PATH: &str = "/api/v1";

const CAPABILITIES_PATH: &str = "/api/v1/capabilities";
const CAPABILITY_PREFIX: &str = "/api/v1/capabilities/";

/// Exposes authorized Bondry capabilities through a versioned REST API.
pub struct RestAdapter {
    service: Arc<dyn AutomationService>,
    adapter: AdapterId,
    invocation_ids: Arc<dyn InvocationIdGenerator>,
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

impl RestAdapter {
    /// Creates a REST adapter with the stable `rest` adapter identifier.
    pub fn new(service: Arc<dyn AutomationService>) -> Result<Self, IdentifierError> {
        Ok(Self {
            service,
            adapter: AdapterId::new("rest")?,
            invocation_ids: Arc::new(SystemInvocationIdGenerator),
        })
    }

    /// Creates a REST adapter with explicit grant and identifier-generation dependencies.
    #[must_use]
    pub const fn with_dependencies(
        service: Arc<dyn AutomationService>,
        adapter: AdapterId,
        invocation_ids: Arc<dyn InvocationIdGenerator>,
    ) -> Self {
        Self {
            service,
            adapter,
            invocation_ids,
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
        path == REST_V1_PATH || path.starts_with("/api/v1/")
    }

    /// Handles one authenticated, bounded request.
    pub async fn handle(&self, request: Request<Bytes>, principal: Principal) -> Response<Bytes> {
        self.route(RequestContext::new(request, principal)).await
    }

    async fn route(&self, request: RequestContext) -> Response<Bytes> {
        let path = request.request().uri().path();
        match (request.request().method(), path) {
            (&Method::GET, REST_V1_PATH) => root_response(),
            (&Method::GET, CAPABILITIES_PATH) => self.list_capabilities(request.principal()).await,
            (&Method::GET, _) if capability_name(path).is_some() => {
                self.get_capability(request.principal(), path).await
            }
            (&Method::POST, _) if capability_name(path).is_some() => {
                self.invoke_capability(request).await
            }
            (_, REST_V1_PATH | CAPABILITIES_PATH) => method_not_allowed("GET"),
            (_, _) if capability_name(path).is_some() => method_not_allowed("GET, POST"),
            _ => error_response(StatusCode::NOT_FOUND, "not_found"),
        }
    }

    async fn list_capabilities(&self, principal: &bondry_core::Principal) -> Response<Bytes> {
        match self.service.capabilities(principal, &self.adapter) {
            Ok(capabilities) => json_response(
                StatusCode::OK,
                json!({
                    "capabilities": capabilities
                        .iter()
                        .map(capability_json)
                        .collect::<Vec<_>>(),
                }),
            ),
            Err(CapabilityDiscoveryError::PolicyUnavailable) => {
                error_response(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable")
            }
        }
    }

    async fn get_capability(
        &self,
        principal: &bondry_core::Principal,
        path: &str,
    ) -> Response<Bytes> {
        let Some(name) = capability_name(path) else {
            return error_response(StatusCode::NOT_FOUND, "not_found");
        };
        let Ok(capability) = CapabilityId::new(name) else {
            return error_response(StatusCode::NOT_FOUND, "not_found");
        };
        match self.service.capabilities(principal, &self.adapter) {
            Ok(capabilities) => capabilities
                .iter()
                .find(|descriptor| descriptor.id() == &capability)
                .map_or_else(
                    || error_response(StatusCode::NOT_FOUND, "not_found"),
                    |descriptor| json_response(StatusCode::OK, capability_json(descriptor)),
                ),
            Err(CapabilityDiscoveryError::PolicyUnavailable) => {
                error_response(StatusCode::SERVICE_UNAVAILABLE, "policy_unavailable")
            }
        }
    }

    async fn invoke_capability(&self, request: RequestContext) -> Response<Bytes> {
        let Some(name) = capability_name(request.request().uri().path()) else {
            return error_response(StatusCode::NOT_FOUND, "not_found");
        };
        let Ok(capability) = CapabilityId::new(name) else {
            return error_response(StatusCode::NOT_FOUND, "not_found");
        };
        if !request.request().body().is_empty()
            && !has_json_content_type(request.request().headers())
        {
            return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type");
        }
        let input = if request.request().body().is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(request.request().body()) {
                Ok(input) => input,
                Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid_json"),
            }
        };
        let invocation = match self.invocation_ids.generate() {
            Ok(id) => Invocation::new(
                id,
                self.adapter.clone(),
                request.principal().clone(),
                capability,
                input,
            ),
            Err(_) => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "identifier_generation_unavailable",
                );
            }
        };
        let invocation_id = invocation.id().as_str().to_owned();
        match self.service.dispatch(invocation).await {
            Ok(output) => json_response(
                StatusCode::OK,
                json!({ "invocationId": invocation_id, "result": output }),
            ),
            Err(DispatchError::CapabilityNotFound(_))
            | Err(DispatchError::AccessDenied(DenialReason::NotGranted)) => {
                invocation_error(StatusCode::NOT_FOUND, "not_found", &invocation_id, None)
            }
            Err(DispatchError::InvalidInput) => invocation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_input",
                &invocation_id,
                None,
            ),
            Err(DispatchError::Handler(error)) => invocation_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "capability_failed",
                &invocation_id,
                Some(error.code().as_str()),
            ),
            Err(DispatchError::AccessDenied(DenialReason::PolicyUnavailable)) => invocation_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "policy_unavailable",
                &invocation_id,
                None,
            ),
            Err(DispatchError::Audit(_)) => invocation_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit_unavailable",
                &invocation_id,
                None,
            ),
        }
    }
}

fn root_response() -> Response<Bytes> {
    json_response(
        StatusCode::OK,
        json!({
            "version": "v1",
            "resources": {
                "capabilities": CAPABILITIES_PATH,
                "invoke": "/api/v1/capabilities/{capabilityId}",
            },
        }),
    )
}

fn capability_name(path: &str) -> Option<&str> {
    let name = path.strip_prefix(CAPABILITY_PREFIX)?;
    if name.is_empty() || name.contains('/') {
        return None;
    }
    Some(name)
}

fn capability_json(descriptor: &CapabilityDescriptor) -> Value {
    json!({
        "id": descriptor.id().as_str(),
        "summary": descriptor.summary(),
        "effect": match descriptor.effect() {
            CapabilityEffect::ReadOnly => "read_only",
            CapabilityEffect::Mutating => "mutating",
        },
        "inputSchema": descriptor.input_schema(),
    })
}

fn has_json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value.to_str().is_ok_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
    })
}

fn method_not_allowed(allowed: &'static str) -> Response<Bytes> {
    let mut response = error_response(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
    response
        .headers_mut()
        .insert(header::ALLOW, http::HeaderValue::from_static(allowed));
    response
}

fn error_response(status: StatusCode, code: &'static str) -> Response<Bytes> {
    json_response(status, json!({ "error": code }))
}

fn invocation_error(
    status: StatusCode,
    error: &'static str,
    invocation_id: &str,
    code: Option<&str>,
) -> Response<Bytes> {
    let mut value = json!({
        "error": error,
        "invocationId": invocation_id,
    });
    if let Some(code) = code {
        value["code"] = Value::String(code.to_owned());
    }
    json_response(status, value)
}

fn json_response(status: StatusCode, value: Value) -> Response<Bytes> {
    let mut response = Response::new(Bytes::from(serde_json::to_vec(&value).unwrap_or_default()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
}
