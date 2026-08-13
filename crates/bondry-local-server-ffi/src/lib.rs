#![doc = "Versioned C ABI for Bondry local REST and MCP servers."]

use std::{
    ffi::c_void,
    net::IpAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bondry_core::{
    AdapterId, AuditError, AutomationService, CapabilityDescriptor, CapabilityDiscoveryError,
    CapabilityEffect, CapabilityId, DenialReason, DispatchError, DispatchFuture, HandlerError,
    HandlerErrorCode, Invocation, Principal, PrincipalId, PrincipalKind,
};
use bondry_http::{
    Authentication, AuthenticationError, BearerAuthenticator, BearerTokenVerifier, HttpAdapter,
    LocalHttpServer, OriginPolicy, RateLimits, ServerConfiguration, ServerStartError,
};
use bondry_mcp::{McpAdapter, McpServerInfo};
use bondry_rest::RestAdapter;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::oneshot;

/// The first JSON server-configuration contract version.
pub const BONDRY_SERVER_CONFIGURATION_VERSION_V1: u32 = 1;
/// Capacity of the terminated textual IP address in a server-address record.
pub const BONDRY_SERVER_ADDRESS_CAPACITY_V1: usize = 46;
/// The requested local address or port could not be bound.
pub const BONDRY_STATUS_SERVER_BIND: i32 = 29;
/// The local server could not start.
pub const BONDRY_STATUS_SERVER_START: i32 = 30;
/// The local server did not stop cleanly.
pub const BONDRY_STATUS_SERVER_STOP: i32 = 31;

const BONDRY_STATUS_OK: i32 = 0;
const BONDRY_STATUS_NULL_POINTER: i32 = 1;
const BONDRY_STATUS_INVALID_LENGTH: i32 = 2;
const BONDRY_STATUS_INVALID_ARGUMENT: i32 = 5;
const BONDRY_STATUS_BUFFER_TOO_SMALL: i32 = 6;
const BONDRY_STATUS_INVALID_JSON: i32 = 7;
const BONDRY_STATUS_PAYLOAD_TOO_LARGE: i32 = 8;
const BONDRY_STATUS_AUTHENTICATION_REJECTED: i32 = 23;
const BONDRY_STATUS_INTERNAL_FAILURE: i32 = 255;
const BONDRY_IDENTIFIER_CAPACITY_V1: usize = 129;
const BONDRY_AUDIT_DETAIL_CAPACITY_V1: usize = 129;
const BONDRY_MAX_JSON_PAYLOAD_LENGTH_V1: usize = 1_048_576;
const BONDRY_PRINCIPAL_KIND_USER_V1: u32 = 1;
const BONDRY_PRINCIPAL_KIND_APPLICATION_V1: u32 = 2;
const BONDRY_PRINCIPAL_KIND_SYSTEM_V1: u32 = 3;
const BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1: u32 = 1;
const BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1: u32 = 2;
const BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1: u32 = 3;
const BONDRY_DISPATCH_OUTCOME_AUDIT_UNAVAILABLE_V1: u32 = 4;
const BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1: u32 = 5;
const BONDRY_DISPATCH_OUTCOME_INVALID_INPUT_V1: u32 = 6;
const MAX_CONFIGURATION_LENGTH: usize = 65_536;
const MAX_QUERY_ATTEMPTS: usize = 4;
const INITIAL_DISCOVERY_CAPACITY: usize = 4_096;

/// The runtime's opaque encrypted-store handle.
#[repr(C)]
pub struct BondryStoreHandle {
    _private: [u8; 0],
}

/// An opaque running-server handle owned by the caller.
#[repr(C)]
pub struct BondryServerHandle {
    _private: [u8; 0],
}

#[repr(C)]
struct BondryPrincipalV1 {
    id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    kind: u32,
}

#[repr(C)]
struct BondryDispatchResultV1 {
    outcome: u32,
    output_json: *const u8,
    output_json_length: usize,
    detail_code: [u8; BONDRY_AUDIT_DETAIL_CAPACITY_V1],
    has_detail_code: u8,
}

type BondryDispatchCompletionV1 =
    unsafe extern "C" fn(completion_context: *mut c_void, result: *const BondryDispatchResultV1);

unsafe extern "C" {
    fn bondry_store_retain_v1(
        store: *const BondryStoreHandle,
        out_store: *mut *mut BondryStoreHandle,
    ) -> i32;
    fn bondry_store_close_v1(store: *mut BondryStoreHandle) -> i32;
    fn bondry_token_authenticate_v1(
        store: *const BondryStoreHandle,
        token: *const u8,
        token_length: usize,
        out_principal: *mut BondryPrincipalV1,
    ) -> i32;
    fn bondry_capabilities_discover_json_v1(
        store: *const BondryStoreHandle,
        principal_id: *const u8,
        principal_id_length: usize,
        principal_kind: u32,
        adapter_id: *const u8,
        adapter_id_length: usize,
        output_json: *mut u8,
        capacity: usize,
        out_length: *mut usize,
    ) -> i32;
    fn bondry_dispatch_principal_v1(
        store: *const BondryStoreHandle,
        invocation_id: *const u8,
        invocation_id_length: usize,
        adapter_id: *const u8,
        adapter_id_length: usize,
        principal_id: *const u8,
        principal_id_length: usize,
        principal_kind: u32,
        capability_id: *const u8,
        capability_id_length: usize,
        input_json: *const u8,
        input_json_length: usize,
        completion: BondryDispatchCompletionV1,
        completion_context: *mut c_void,
    ) -> i32;
}

struct ServerHandle {
    server: LocalHttpServer,
}

struct RuntimeHandle {
    store: *mut BondryStoreHandle,
    discovery_capacity: AtomicUsize,
}

// SAFETY: The retained runtime handle exposes only synchronized, thread-safe operations.
unsafe impl Send for RuntimeHandle {}
// SAFETY: Its ownership unit remains live until every shared server reference is released.
unsafe impl Sync for RuntimeHandle {}

impl RuntimeHandle {
    unsafe fn retain(store: *const BondryStoreHandle) -> Result<Arc<Self>, i32> {
        let mut retained = ptr::null_mut();
        // SAFETY: The caller keeps store live for this synchronous retain operation.
        let status = unsafe { bondry_store_retain_v1(store, &mut retained) };
        if status != BONDRY_STATUS_OK {
            return Err(status);
        }
        if retained.is_null() {
            return Err(BONDRY_STATUS_INTERNAL_FAILURE);
        }
        Ok(Arc::new(Self {
            store: retained,
            discovery_capacity: AtomicUsize::new(INITIAL_DISCOVERY_CAPACITY),
        }))
    }

    fn discover(
        &self,
        principal: &Principal,
        adapter: &AdapterId,
    ) -> Result<Vec<CapabilityDescriptor>, CapabilityDiscoveryError> {
        let principal_id = principal.id().as_str().as_bytes();
        let adapter_id = adapter.as_str().as_bytes();
        let principal_kind = encode_principal_kind(principal.kind());
        let capacity = self
            .discovery_capacity
            .load(Ordering::Relaxed)
            .min(BONDRY_MAX_JSON_PAYLOAD_LENGTH_V1);
        let mut output = vec![0; capacity];
        for _ in 0..MAX_QUERY_ATTEMPTS {
            let mut actual_length = 0;
            // SAFETY: The output allocation and all borrowed inputs remain valid for this call.
            let status = unsafe {
                bondry_capabilities_discover_json_v1(
                    self.store,
                    principal_id.as_ptr(),
                    principal_id.len(),
                    principal_kind,
                    adapter_id.as_ptr(),
                    adapter_id.len(),
                    output.as_mut_ptr(),
                    output.len(),
                    &mut actual_length,
                )
            };
            if status == BONDRY_STATUS_BUFFER_TOO_SMALL {
                if actual_length <= output.len()
                    || actual_length > BONDRY_MAX_JSON_PAYLOAD_LENGTH_V1
                {
                    return Err(CapabilityDiscoveryError::PolicyUnavailable);
                }
                self.discovery_capacity
                    .fetch_max(actual_length, Ordering::Relaxed);
                output.resize(actual_length, 0);
                continue;
            }
            if status != BONDRY_STATUS_OK || actual_length > output.len() {
                return Err(CapabilityDiscoveryError::PolicyUnavailable);
            }
            self.discovery_capacity
                .fetch_max(actual_length, Ordering::Relaxed);
            output.truncate(actual_length);
            return decode_capabilities(&output)
                .map_err(|()| CapabilityDiscoveryError::PolicyUnavailable);
        }
        Err(CapabilityDiscoveryError::PolicyUnavailable)
    }

    async fn dispatch(&self, invocation: Invocation) -> Result<Value, DispatchError> {
        let invocation_id = invocation.id().as_str().as_bytes();
        let adapter_id = invocation.adapter().as_str().as_bytes();
        let principal_id = invocation.principal().id().as_str().as_bytes();
        let principal_kind = encode_principal_kind(invocation.principal().kind());
        let capability = invocation.capability().clone();
        let capability_id = capability.as_str().as_bytes();
        let input = serde_json::to_vec(invocation.input())
            .map_err(|_| DispatchError::Audit(AuditError::Unavailable))?;
        let (sender, receiver) = oneshot::channel();
        let completion = Box::into_raw(Box::new(DispatchCompletion { sender })).cast::<c_void>();
        // SAFETY: Every borrowed buffer remains live for this call. A successful call transfers
        // the completion allocation to exactly one callback.
        let status = unsafe {
            bondry_dispatch_principal_v1(
                self.store,
                invocation_id.as_ptr(),
                invocation_id.len(),
                adapter_id.as_ptr(),
                adapter_id.len(),
                principal_id.as_ptr(),
                principal_id.len(),
                principal_kind,
                capability_id.as_ptr(),
                capability_id.len(),
                input.as_ptr(),
                input.len(),
                complete_dispatch,
                completion,
            )
        };
        if status != BONDRY_STATUS_OK {
            // SAFETY: Immediate runtime failures never invoke or consume the completion callback.
            unsafe { drop(Box::from_raw(completion.cast::<DispatchCompletion>())) };
            return Err(DispatchError::AccessDenied(DenialReason::PolicyUnavailable));
        }
        let result = receiver
            .await
            .map_err(|_| DispatchError::Audit(AuditError::Unavailable))?
            .map_err(|()| DispatchError::Audit(AuditError::Unavailable))?;
        decode_dispatch_result(result, capability)
    }
}

impl Drop for RuntimeHandle {
    fn drop(&mut self) {
        // SAFETY: This type owns exactly one retained handle and drops it exactly once.
        let _ = unsafe { bondry_store_close_v1(self.store) };
    }
}

struct RuntimeAutomationService {
    runtime: Arc<RuntimeHandle>,
}

impl AutomationService for RuntimeAutomationService {
    fn capabilities(
        &self,
        principal: &Principal,
        adapter: &AdapterId,
    ) -> Result<Vec<CapabilityDescriptor>, CapabilityDiscoveryError> {
        self.runtime.discover(principal, adapter)
    }

    fn dispatch(&self, invocation: Invocation) -> DispatchFuture<'_> {
        Box::pin(self.runtime.dispatch(invocation))
    }
}

struct RuntimeBearerVerifier {
    runtime: Arc<RuntimeHandle>,
}

impl BearerTokenVerifier for RuntimeBearerVerifier {
    fn verify(&self, token: &str) -> Result<Principal, AuthenticationError> {
        let mut record = BondryPrincipalV1 {
            id: [0; BONDRY_IDENTIFIER_CAPACITY_V1],
            kind: 0,
        };
        // SAFETY: The token is borrowed for this call and record is writable.
        let status = unsafe {
            bondry_token_authenticate_v1(
                self.runtime.store,
                token.as_ptr(),
                token.len(),
                &mut record,
            )
        };
        if status == BONDRY_STATUS_AUTHENTICATION_REJECTED {
            return Err(AuthenticationError::Rejected);
        }
        if status != BONDRY_STATUS_OK {
            return Err(AuthenticationError::Unavailable);
        }
        let id = terminated_utf8(&record.id).map_err(|()| AuthenticationError::Unavailable)?;
        let id = PrincipalId::new(id).map_err(|_| AuthenticationError::Unavailable)?;
        let kind = decode_principal_kind(record.kind).ok_or(AuthenticationError::Unavailable)?;
        Ok(Principal::new(id, kind))
    }
}

/// The bound local address returned after server startup.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryServerAddressV1 {
    /// UTF-8 IP address, terminated with zero.
    pub address: [u8; BONDRY_SERVER_ADDRESS_CAPACITY_V1],
    /// Bound TCP port.
    pub port: u16,
}

impl BondryServerAddressV1 {
    fn from_server(server: &LocalHttpServer) -> Self {
        let address = server.local_address();
        Self {
            address: terminated(&address.ip().to_string()),
            port: address.port(),
        }
    }

    const fn zeroed() -> Self {
        Self {
            address: [0; BONDRY_SERVER_ADDRESS_CAPACITY_V1],
            port: 0,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InputConfiguration {
    version: u32,
    bind_address: String,
    port: u16,
    authentication: InputAuthentication,
    adapters: Vec<InputAdapter>,
    mcp_server: Option<InputMcpServer>,
    allowed_origins: Vec<String>,
    requests_per_minute: u32,
    authentication_failures_per_minute: u32,
    max_body_bytes: usize,
    max_connections: usize,
    header_read_timeout_milliseconds: u64,
    request_timeout_milliseconds: u64,
    shutdown_grace_period_milliseconds: u64,
    allow_cleartext_network: bool,
    allow_unauthenticated_network: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InputAuthentication {
    mode: InputAuthenticationMode,
    principal_id: Option<String>,
    principal_kind: Option<InputPrincipalKind>,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum InputAuthenticationMode {
    Bearer,
    Disabled,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InputPrincipalKind {
    User,
    Application,
    System,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum InputAdapter {
    Rest,
    Mcp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InputMcpServer {
    name: String,
    title: Option<String>,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SerializedCapability {
    id: String,
    summary: String,
    effect: SerializedCapabilityEffect,
    input_schema: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SerializedCapabilityEffect {
    ReadOnly,
    Mutating,
}

struct DispatchCompletion {
    sender: oneshot::Sender<Result<OwnedDispatchResult, ()>>,
}

struct OwnedDispatchResult {
    outcome: u32,
    output: Vec<u8>,
    detail: Option<String>,
}

/// Starts enabled REST and MCP adapters from a validated JSON configuration.
///
/// # Safety
///
/// `store` must be a live runtime handle. The configuration must be readable for its declared
/// length. Both output pointers must be writable. The returned server handle must be stopped once.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_server_start_v1(
    store: *const BondryStoreHandle,
    configuration_json: *const u8,
    configuration_json_length: usize,
    out_server: *mut *mut BondryServerHandle,
    out_address: *mut BondryServerAddressV1,
) -> i32 {
    if out_server.is_null() || out_address.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: Both output pointers are non-null and writable by contract.
    unsafe {
        out_server.write(ptr::null_mut());
        out_address.write(BondryServerAddressV1::zeroed());
    }
    catch_status(|| {
        if store.is_null() || configuration_json.is_null() {
            return BONDRY_STATUS_NULL_POINTER;
        }
        if configuration_json_length > isize::MAX as usize {
            return BONDRY_STATUS_INVALID_LENGTH;
        }
        if configuration_json_length > MAX_CONFIGURATION_LENGTH {
            return BONDRY_STATUS_PAYLOAD_TOO_LARGE;
        }
        // SAFETY: The bounded configuration buffer is readable by contract.
        let bytes = unsafe { slice::from_raw_parts(configuration_json, configuration_json_length) };
        let value: Value = match serde_json::from_slice(bytes) {
            Ok(value) => value,
            Err(_) => return BONDRY_STATUS_INVALID_JSON,
        };
        let input: InputConfiguration = match serde_json::from_value(value) {
            Ok(input) => input,
            Err(_) => return BONDRY_STATUS_INVALID_ARGUMENT,
        };
        // SAFETY: The caller guarantees store remains live for this synchronous retain.
        let runtime = match unsafe { RuntimeHandle::retain(store) } {
            Ok(runtime) => runtime,
            Err(status) => return status,
        };
        let server = match start_server(runtime, input) {
            Ok(server) => server,
            Err(status) => return status,
        };
        let address = BondryServerAddressV1::from_server(&server);
        let handle = Box::new(ServerHandle { server });
        // SAFETY: Outputs receive one server ownership unit and its bound address.
        unsafe {
            out_address.write(address);
            out_server.write(Box::into_raw(handle).cast::<BondryServerHandle>());
        }
        BONDRY_STATUS_OK
    })
}

/// Stops a running local server and consumes its handle. Passing null is a no-op.
///
/// # Safety
///
/// A non-null value must be a live handle returned by `bondry_server_start_v1` and must not be used
/// or stopped again after this function begins.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_server_stop_v1(server: *mut BondryServerHandle) -> i32 {
    if server.is_null() {
        return BONDRY_STATUS_OK;
    }
    catch_status(|| {
        // SAFETY: The caller transfers exactly one live server ownership unit.
        let mut handle = unsafe { Box::from_raw(server.cast::<ServerHandle>()) };
        match handle.server.stop() {
            Ok(()) => BONDRY_STATUS_OK,
            Err(_) => BONDRY_STATUS_SERVER_STOP,
        }
    })
}

fn start_server(
    runtime: Arc<RuntimeHandle>,
    input: InputConfiguration,
) -> Result<LocalHttpServer, i32> {
    if input.version != BONDRY_SERVER_CONFIGURATION_VERSION_V1 || input.adapters.is_empty() {
        return Err(BONDRY_STATUS_INVALID_ARGUMENT);
    }
    let bind_address = input
        .bind_address
        .parse::<IpAddr>()
        .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
    let authentication = authentication(runtime.clone(), &input.authentication)?;
    let limits = RateLimits::new(
        input.requests_per_minute,
        input.authentication_failures_per_minute,
    )
    .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
    let mut origins = OriginPolicy::deny_browser_origins();
    for origin in &input.allowed_origins {
        origins = origins
            .allowing(origin)
            .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
    }
    let mut configuration = ServerConfiguration::new(authentication)
        .with_bind_address(bind_address)
        .with_port(input.port)
        .with_origin_policy(origins)
        .with_rate_limits(limits)
        .with_max_body_bytes(input.max_body_bytes)
        .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?
        .with_max_connections(input.max_connections)
        .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?
        .with_timeouts(
            Duration::from_millis(input.header_read_timeout_milliseconds),
            Duration::from_millis(input.request_timeout_milliseconds),
            Duration::from_millis(input.shutdown_grace_period_milliseconds),
        )
        .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
    if input.allow_cleartext_network {
        configuration = configuration.allowing_cleartext_network();
    }
    if input.allow_unauthenticated_network {
        configuration = configuration.allowing_unauthenticated_network();
    }

    let service: Arc<dyn AutomationService> = Arc::new(RuntimeAutomationService { runtime });
    let mut adapters: Vec<Arc<dyn HttpAdapter>> = Vec::with_capacity(input.adapters.len());
    let mut has_rest = false;
    let mut has_mcp = false;
    for adapter in input.adapters {
        match adapter {
            InputAdapter::Rest if !has_rest => {
                has_rest = true;
                adapters.push(Arc::new(
                    RestAdapter::new(service.clone())
                        .map_err(|_| BONDRY_STATUS_INTERNAL_FAILURE)?,
                ));
            }
            InputAdapter::Mcp if !has_mcp => {
                has_mcp = true;
                adapters.push(Arc::new(
                    McpAdapter::new(service.clone(), mcp_server_info(input.mcp_server.as_ref())?)
                        .map_err(|_| BONDRY_STATUS_INTERNAL_FAILURE)?,
                ));
            }
            _ => return Err(BONDRY_STATUS_INVALID_ARGUMENT),
        }
    }
    if !has_mcp && input.mcp_server.is_some() {
        return Err(BONDRY_STATUS_INVALID_ARGUMENT);
    }
    LocalHttpServer::start(configuration, adapters).map_err(server_start_status)
}

fn authentication(
    runtime: Arc<RuntimeHandle>,
    input: &InputAuthentication,
) -> Result<Authentication, i32> {
    match input.mode {
        InputAuthenticationMode::Bearer
            if input.principal_id.is_none() && input.principal_kind.is_none() =>
        {
            let verifier: Arc<dyn BearerTokenVerifier> =
                Arc::new(RuntimeBearerVerifier { runtime });
            Ok(Authentication::required(Arc::new(
                BearerAuthenticator::new(verifier),
            )))
        }
        InputAuthenticationMode::Disabled => {
            let id = input
                .principal_id
                .as_deref()
                .ok_or(BONDRY_STATUS_INVALID_ARGUMENT)?;
            let kind = input.principal_kind.ok_or(BONDRY_STATUS_INVALID_ARGUMENT)?;
            let id = PrincipalId::new(id).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
            Ok(Authentication::disabled(Principal::new(
                id,
                match kind {
                    InputPrincipalKind::User => PrincipalKind::User,
                    InputPrincipalKind::Application => PrincipalKind::Application,
                    InputPrincipalKind::System => PrincipalKind::System,
                },
            )))
        }
        InputAuthenticationMode::Bearer => Err(BONDRY_STATUS_INVALID_ARGUMENT),
    }
}

fn mcp_server_info(input: Option<&InputMcpServer>) -> Result<McpServerInfo, i32> {
    let input = input.ok_or(BONDRY_STATUS_INVALID_ARGUMENT)?;
    let mut info = McpServerInfo::new(&input.name, &input.version)
        .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
    if let Some(title) = &input.title {
        info = info
            .with_title(title)
            .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
    }
    Ok(info)
}

fn server_start_status(error: ServerStartError) -> i32 {
    match error {
        ServerStartError::Configuration(_) | ServerStartError::NoAdapters => {
            BONDRY_STATUS_INVALID_ARGUMENT
        }
        ServerStartError::Bind(_) => BONDRY_STATUS_SERVER_BIND,
        ServerStartError::Runtime(_) | ServerStartError::Thread(_) | ServerStartError::Startup => {
            BONDRY_STATUS_SERVER_START
        }
    }
}

fn decode_capabilities(bytes: &[u8]) -> Result<Vec<CapabilityDescriptor>, ()> {
    let serialized: Vec<SerializedCapability> = serde_json::from_slice(bytes).map_err(|_| ())?;
    serialized
        .into_iter()
        .map(|capability| {
            let id = CapabilityId::new(capability.id).map_err(|_| ())?;
            let effect = match capability.effect {
                SerializedCapabilityEffect::ReadOnly => CapabilityEffect::ReadOnly,
                SerializedCapabilityEffect::Mutating => CapabilityEffect::Mutating,
            };
            CapabilityDescriptor::new(id, capability.summary, effect)
                .map_err(|_| ())?
                .with_input_schema(capability.input_schema)
                .map_err(|_| ())
        })
        .collect()
}

fn decode_dispatch_result(
    result: OwnedDispatchResult,
    capability: CapabilityId,
) -> Result<Value, DispatchError> {
    match result.outcome {
        BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1 => serde_json::from_slice(&result.output)
            .map_err(|_| DispatchError::Audit(AuditError::Unavailable)),
        BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1 => {
            Err(DispatchError::CapabilityNotFound(capability))
        }
        BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1 => Err(DispatchError::AccessDenied(
            if result.detail.as_deref() == Some("policy_unavailable") {
                DenialReason::PolicyUnavailable
            } else {
                DenialReason::NotGranted
            },
        )),
        BONDRY_DISPATCH_OUTCOME_AUDIT_UNAVAILABLE_V1 => {
            Err(DispatchError::Audit(AuditError::Unavailable))
        }
        BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1 => {
            let detail = result
                .detail
                .ok_or(DispatchError::Audit(AuditError::Unavailable))?;
            let code = HandlerErrorCode::new(detail)
                .map_err(|_| DispatchError::Audit(AuditError::Unavailable))?;
            Err(DispatchError::Handler(HandlerError::new(code)))
        }
        BONDRY_DISPATCH_OUTCOME_INVALID_INPUT_V1 => Err(DispatchError::InvalidInput),
        _ => Err(DispatchError::Audit(AuditError::Unavailable)),
    }
}

unsafe extern "C" fn complete_dispatch(
    context: *mut c_void,
    result: *const BondryDispatchResultV1,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: An accepted dispatch transfers exactly one completion allocation to this callback.
    let completion = unsafe { Box::from_raw(context.cast::<DispatchCompletion>()) };
    let copied = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The runtime keeps result fields borrowed and readable for this callback.
        unsafe { copy_dispatch_result(result) }
    }))
    .map_err(|_| ())
    .and_then(|result| result);
    let _ = completion.sender.send(copied);
}

unsafe fn copy_dispatch_result(
    result: *const BondryDispatchResultV1,
) -> Result<OwnedDispatchResult, ()> {
    let result = unsafe { result.as_ref() }.ok_or(())?;
    if result.output_json_length > BONDRY_MAX_JSON_PAYLOAD_LENGTH_V1
        || result.output_json_length > isize::MAX as usize
    {
        return Err(());
    }
    let output = if result.output_json_length == 0 {
        Vec::new()
    } else {
        if result.output_json.is_null() {
            return Err(());
        }
        // SAFETY: The runtime guarantees this payload is readable for the callback duration.
        unsafe { slice::from_raw_parts(result.output_json, result.output_json_length) }.to_vec()
    };
    let detail = match result.has_detail_code {
        0 => None,
        1 => Some(terminated_utf8(&result.detail_code)?.to_owned()),
        _ => return Err(()),
    };
    Ok(OwnedDispatchResult {
        outcome: result.outcome,
        output,
        detail,
    })
}

fn encode_principal_kind(kind: PrincipalKind) -> u32 {
    match kind {
        PrincipalKind::User => BONDRY_PRINCIPAL_KIND_USER_V1,
        PrincipalKind::Application => BONDRY_PRINCIPAL_KIND_APPLICATION_V1,
        PrincipalKind::System => BONDRY_PRINCIPAL_KIND_SYSTEM_V1,
    }
}

fn decode_principal_kind(kind: u32) -> Option<PrincipalKind> {
    match kind {
        BONDRY_PRINCIPAL_KIND_USER_V1 => Some(PrincipalKind::User),
        BONDRY_PRINCIPAL_KIND_APPLICATION_V1 => Some(PrincipalKind::Application),
        BONDRY_PRINCIPAL_KIND_SYSTEM_V1 => Some(PrincipalKind::System),
        _ => None,
    }
}

fn terminated_utf8<const N: usize>(bytes: &[u8; N]) -> Result<&str, ()> {
    let length = bytes.iter().position(|byte| *byte == 0).ok_or(())?;
    std::str::from_utf8(&bytes[..length]).map_err(|_| ())
}

fn terminated<const N: usize>(value: &str) -> [u8; N] {
    let mut output = [0; N];
    let length = value.len().min(N.saturating_sub(1));
    output[..length].copy_from_slice(&value.as_bytes()[..length]);
    output
}

fn catch_status(operation: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(BONDRY_STATUS_INTERNAL_FAILURE)
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::c_void,
        io::{Read, Write},
        net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
        ptr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use bondry_runtime_ffi::{
        BONDRY_STATUS_OK, BondryCapabilityCompletionV1, BondryInvocationV1, BondryIssuedTokenV1,
        BondryStoreHandle as RuntimeStoreHandle, bondry_capability_register_with_schema_v1,
        bondry_capability_unregister_v1, bondry_client_create_v1, bondry_grant_add_v1,
        bondry_issued_token_clear_v1, bondry_store_close_v1, bondry_store_open_v1,
        bondry_token_issue_v1,
    };
    use serde_json::{Value, json};
    use tempfile::tempdir;

    use super::{
        BONDRY_STATUS_INVALID_ARGUMENT, BONDRY_STATUS_INVALID_JSON, BONDRY_STATUS_NULL_POINTER,
        BONDRY_STATUS_PAYLOAD_TOO_LARGE, BONDRY_STATUS_SERVER_BIND, BondryServerAddressV1,
        BondryServerHandle, BondryStoreHandle, bondry_server_start_v1, bondry_server_stop_v1,
    };

    const READ_ONLY_EFFECT: u32 = 1;
    const HANDLER_SUCCEEDED: u32 = 1;

    #[test]
    fn validates_configuration_and_initializes_outputs() -> Result<(), Box<dyn std::error::Error>> {
        let store = TestStore::open()?;
        let mut server = ptr::dangling_mut::<BondryServerHandle>();
        let mut address = BondryServerAddressV1 {
            address: [1; 46],
            port: 1,
        };

        assert_eq!(
            unsafe {
                bondry_server_start_v1(
                    store.server_handle(),
                    b"{}".as_ptr(),
                    2,
                    ptr::null_mut(),
                    &mut address,
                )
            },
            BONDRY_STATUS_NULL_POINTER
        );
        assert_eq!(
            start(
                store.server_handle(),
                b"not-json",
                &mut server,
                &mut address
            ),
            BONDRY_STATUS_INVALID_JSON
        );
        assert!(server.is_null());
        assert_eq!(address.port, 0);
        assert!(address.address.iter().all(|byte| *byte == 0));

        for invalid in [
            configuration(json!([]), Value::Null, bearer_authentication()),
            configuration(
                json!(["rest", "rest"]),
                Value::Null,
                bearer_authentication(),
            ),
            configuration(json!(["mcp"]), Value::Null, bearer_authentication()),
            configuration(
                json!(["rest"]),
                json!({ "name": "app", "version": "1" }),
                bearer_authentication(),
            ),
            configuration(
                json!(["rest"]),
                Value::Null,
                json!({ "mode": "disabled", "principalId": null, "principalKind": null }),
            ),
        ] {
            assert_eq!(
                start(store.server_handle(), &invalid, &mut server, &mut address,),
                BONDRY_STATUS_INVALID_ARGUMENT
            );
            assert!(server.is_null());
        }

        let oversized = vec![b' '; 65_537];
        assert_eq!(
            start(store.server_handle(), &oversized, &mut server, &mut address,),
            BONDRY_STATUS_PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            unsafe { bondry_server_stop_v1(ptr::null_mut()) },
            BONDRY_STATUS_OK
        );
        Ok(())
    }

    #[test]
    fn starts_routes_and_stops_both_adapters() -> Result<(), Box<dyn std::error::Error>> {
        let store = TestStore::open()?;
        let input = configuration(
            json!(["rest", "mcp"]),
            json!({ "name": "test-app", "title": "Test App", "version": "1.0" }),
            disabled_authentication(),
        );
        let (server, address) = start_successfully(store.server_handle(), &input)?;

        let response = request(
            address.port,
            "GET /api/v1 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )?;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"version\":\"v1\""));
        let response = request(address.port, "GET /mcp HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed"));

        assert_eq!(unsafe { bondry_server_stop_v1(server) }, BONDRY_STATUS_OK);
        Ok(())
    }

    #[test]
    fn reports_port_conflicts() -> Result<(), Box<dyn std::error::Error>> {
        let store = TestStore::open()?;
        let input = configuration(json!(["rest"]), Value::Null, disabled_authentication());
        let (first, first_address) = start_successfully(store.server_handle(), &input)?;

        let mut conflicting: Value = serde_json::from_slice(&input)?;
        conflicting["port"] = json!(first_address.port);
        let conflicting = serde_json::to_vec(&conflicting)?;
        let mut second = ptr::null_mut();
        let mut second_address = BondryServerAddressV1::zeroed();
        assert_eq!(
            start(
                store.server_handle(),
                &conflicting,
                &mut second,
                &mut second_address,
            ),
            BONDRY_STATUS_SERVER_BIND
        );
        assert!(second.is_null());
        assert_eq!(unsafe { bondry_server_stop_v1(first) }, BONDRY_STATUS_OK);
        Ok(())
    }

    #[test]
    fn authenticates_through_the_runtime_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let store = TestStore::open()?;
        let token = store.issue_token()?;
        let input = configuration(json!(["rest"]), Value::Null, bearer_authentication());
        let (server, address) = start_successfully(store.server_handle(), &input)?;

        let rejected = request(
            address.port,
            "GET /api/v1 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )?;
        assert!(rejected.starts_with("HTTP/1.1 401 Unauthorized"));
        let accepted = request(
            address.port,
            &format!(
                "GET /api/v1 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n\r\n"
            ),
        )?;
        assert!(accepted.starts_with("HTTP/1.1 200 OK"));
        assert!(!accepted.contains(&token));
        assert_eq!(unsafe { bondry_server_stop_v1(server) }, BONDRY_STATUS_OK);
        Ok(())
    }

    #[test]
    fn discovers_and_dispatches_live_runtime_capabilities() -> Result<(), Box<dyn std::error::Error>>
    {
        let store = TestStore::open()?;
        let releases = Arc::new(AtomicUsize::new(0));
        let context = Box::into_raw(Box::new(releases.clone())).cast::<c_void>();
        let schema =
            br#"{"type":"object","properties":{"value":{"type":"integer"}},"required":["value"]}"#;
        assert_eq!(
            unsafe {
                bondry_capability_register_with_schema_v1(
                    store.handle,
                    b"battery.read".as_ptr(),
                    12,
                    b"Read battery state".as_ptr(),
                    18,
                    READ_ONLY_EFFECT,
                    schema.as_ptr(),
                    schema.len(),
                    context,
                    Some(test_handler),
                    Some(release_handler),
                )
            },
            BONDRY_STATUS_OK
        );
        let mut changed = 0;
        assert_eq!(
            unsafe {
                bondry_grant_add_v1(
                    store.handle,
                    b"local-test".as_ptr(),
                    10,
                    b"rest".as_ptr(),
                    4,
                    b"battery.read".as_ptr(),
                    12,
                    &mut changed,
                )
            },
            BONDRY_STATUS_OK
        );
        let input = configuration(json!(["rest"]), Value::Null, disabled_authentication());
        let (server, address) = start_successfully(store.server_handle(), &input)?;

        let listed = request(
            address.port,
            "GET /api/v1/capabilities HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )?;
        assert!(listed.contains("battery.read"));
        assert!(listed.contains("inputSchema"));
        let called = request(
            address.port,
            "POST /api/v1/capabilities/battery.read HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"value\":7}",
        )?;
        assert!(called.starts_with("HTTP/1.1 200 OK"));
        assert!(called.contains("\"result\":{\"value\":7}"));

        assert_eq!(unsafe { bondry_server_stop_v1(server) }, BONDRY_STATUS_OK);
        assert_eq!(
            unsafe {
                bondry_capability_unregister_v1(
                    store.handle,
                    b"battery.read".as_ptr(),
                    12,
                    &mut changed,
                )
            },
            BONDRY_STATUS_OK
        );
        assert_eq!(releases.load(Ordering::SeqCst), 1);
        Ok(())
    }

    unsafe extern "C" fn test_handler(
        _context: *mut c_void,
        invocation: *const BondryInvocationV1,
        completion: BondryCapabilityCompletionV1,
        completion_context: *mut c_void,
    ) {
        let Some(invocation) = (unsafe { invocation.as_ref() }) else {
            return;
        };
        // SAFETY: The runtime guarantees the input payload is borrowed for this callback.
        let input = unsafe {
            std::slice::from_raw_parts(invocation.input_json, invocation.input_json_length)
        };
        // SAFETY: The test completes the invocation exactly once with a borrowed payload.
        unsafe {
            completion(
                completion_context,
                HANDLER_SUCCEEDED,
                input.as_ptr(),
                input.len(),
            );
        }
    }

    unsafe extern "C" fn release_handler(context: *mut c_void) {
        if !context.is_null() {
            // SAFETY: Registration transferred exactly one Box allocation to this callback.
            let releases = unsafe { Box::from_raw(context.cast::<Arc<AtomicUsize>>()) };
            releases.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct TestStore {
        _directory: tempfile::TempDir,
        handle: *mut RuntimeStoreHandle,
    }

    impl TestStore {
        fn open() -> Result<Self, Box<dyn std::error::Error>> {
            let directory = tempdir()?;
            let path = directory.path().join("bondry.db");
            let path = path.to_str().ok_or("temporary path is not UTF-8")?;
            let key = [0x73; 32];
            let mut handle = ptr::null_mut();
            assert_eq!(
                unsafe {
                    bondry_store_open_v1(
                        path.as_ptr(),
                        path.len(),
                        key.as_ptr(),
                        key.len(),
                        &mut handle,
                    )
                },
                BONDRY_STATUS_OK
            );
            if handle.is_null() {
                return Err("runtime returned a null store".into());
            }
            Ok(Self {
                _directory: directory,
                handle,
            })
        }

        fn server_handle(&self) -> *const BondryStoreHandle {
            self.handle.cast::<BondryStoreHandle>()
        }

        fn issue_token(&self) -> Result<String, Box<dyn std::error::Error>> {
            let mut client: bondry_runtime_ffi::BondryClientV1 = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe {
                    bondry_client_create_v1(self.handle, b"HTTP Client".as_ptr(), 11, &mut client)
                },
                BONDRY_STATUS_OK
            );
            let client_id = terminated_bytes(&client.id)?;
            let mut token: BondryIssuedTokenV1 = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe {
                    bondry_token_issue_v1(
                        self.handle,
                        client_id.as_ptr(),
                        client_id.len(),
                        ptr::null(),
                        0,
                        0,
                        0,
                        &mut token,
                    )
                },
                BONDRY_STATUS_OK
            );
            let secret = std::str::from_utf8(terminated_bytes(&token.secret)?)?.to_owned();
            assert_eq!(
                unsafe { bondry_issued_token_clear_v1(&mut token) },
                BONDRY_STATUS_OK
            );
            Ok(secret)
        }
    }

    impl Drop for TestStore {
        fn drop(&mut self) {
            let _ = unsafe { bondry_store_close_v1(self.handle) };
        }
    }

    fn terminated_bytes(bytes: &[u8]) -> Result<&[u8], Box<dyn std::error::Error>> {
        let length = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or("record is not terminated")?;
        Ok(&bytes[..length])
    }

    fn configuration(adapters: Value, mcp_server: Value, authentication: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "version": 1,
            "bindAddress": "127.0.0.1",
            "port": 0,
            "authentication": authentication,
            "adapters": adapters,
            "mcpServer": mcp_server,
            "allowedOrigins": [],
            "requestsPerMinute": 120,
            "authenticationFailuresPerMinute": 30,
            "maxBodyBytes": 1_048_576,
            "maxConnections": 64,
            "headerReadTimeoutMilliseconds": 5_000,
            "requestTimeoutMilliseconds": 30_000,
            "shutdownGracePeriodMilliseconds": 2_000,
            "allowCleartextNetwork": false,
            "allowUnauthenticatedNetwork": false,
        }))
        .unwrap_or_default()
    }

    fn bearer_authentication() -> Value {
        json!({ "mode": "bearer", "principalId": null, "principalKind": null })
    }

    fn disabled_authentication() -> Value {
        json!({
            "mode": "disabled",
            "principalId": "local-test",
            "principalKind": "application",
        })
    }

    fn start(
        store: *const BondryStoreHandle,
        input: &[u8],
        server: &mut *mut BondryServerHandle,
        address: &mut BondryServerAddressV1,
    ) -> i32 {
        // SAFETY: Test buffers and output storage remain live for the complete call.
        unsafe { bondry_server_start_v1(store, input.as_ptr(), input.len(), server, address) }
    }

    fn start_successfully(
        store: *const BondryStoreHandle,
        input: &[u8],
    ) -> Result<(*mut BondryServerHandle, BondryServerAddressV1), Box<dyn std::error::Error>> {
        let mut server = ptr::null_mut();
        let mut address = BondryServerAddressV1::zeroed();
        if start(store, input, &mut server, &mut address) != BONDRY_STATUS_OK || server.is_null() {
            return Err("server did not start".into());
        }
        Ok((server, address))
    }

    fn request(port: u16, request: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect_timeout(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            Duration::from_secs(1),
        )?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        let request = request.replacen("\r\n\r\n", "\r\nConnection: close\r\n\r\n", 1);
        stream.write_all(request.as_bytes())?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }
}
