use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
    sync::Arc,
    time::Instant,
};

use bondry_delivery_store::{
    DeliveryFailure, DeliveryId, DeliveryLogError, DeliveryOutcome, DeliveryRecord,
    DeliveryResultCategory, DeliveryState, RouteId,
};
use bondry_egress::{
    AdmissionError, KindOperationError, PayloadError, RouteRegistryError, RouteSummary,
};
use bondry_egress_mcp::{
    MAX_MCP_RESULT_BYTES, MIN_MCP_RESULT_BYTES, McpDiscoveryError, McpDiscoveryOperation,
    McpDiscoveryResult, McpDiscoveryTransition,
};
use bondry_egress_runtime::{
    EgressRuntime, EgressRuntimeError, EgressRuntimeStartError, EgressRuntimeStopError,
};
use bondry_secrets::{SecretProvider, SecretProviderError};
use bondry_transport::{HttpTransport, TransportError};
use bytes::Bytes;
use serde::Serialize;

use crate::{
    BondryHTTPTransportV1, BondrySecretProviderV1,
    config::{
        ConfigurationError, MAX_DISCOVERY_CONFIGURATION_BYTES, MAX_ROUTE_CONFIGURATION_BYTES,
        MAX_RUNTIME_CONFIGURATION_BYTES, mcp_discovery_configuration, route_configuration,
        runtime_configuration,
    },
    secrets::ForeignSecretProvider,
    store::{BondryStoreHandle, ForeignDeliveryLog},
    transport::ForeignHttpTransport,
};

const BONDRY_STATUS_OK: i32 = 0;
const BONDRY_STATUS_NULL_POINTER: i32 = 1;
const BONDRY_STATUS_INVALID_LENGTH: i32 = 2;
const BONDRY_STATUS_INVALID_UTF8: i32 = 3;
const BONDRY_STATUS_INVALID_ARGUMENT: i32 = 5;
const BONDRY_STATUS_BUFFER_TOO_SMALL: i32 = 6;
const BONDRY_STATUS_INVALID_JSON: i32 = 7;
const BONDRY_STATUS_PAYLOAD_TOO_LARGE: i32 = 8;
const BONDRY_STATUS_NOT_FOUND: i32 = 20;
const BONDRY_STATUS_ALREADY_EXISTS: i32 = 28;
const BONDRY_STATUS_CAPACITY_EXHAUSTED: i32 = 32;
const BONDRY_STATUS_INTERNAL_FAILURE: i32 = 255;

/// Egress could not create its executor or recover durable state.
pub const BONDRY_STATUS_EGRESS_START_FAILED: i32 = 34;
/// Egress could not join its executor during shutdown.
pub const BONDRY_STATUS_EGRESS_STOP_FAILED: i32 = 35;
/// The bounded runtime command queue is full.
pub const BONDRY_STATUS_EGRESS_BUSY: i32 = 36;
/// The runtime has stopped accepting operations.
pub const BONDRY_STATUS_EGRESS_STOPPED: i32 = 37;
/// The route is already draining.
pub const BONDRY_STATUS_EGRESS_ROUTE_DRAINING: i32 = 38;
/// The pending-delivery count is exhausted.
pub const BONDRY_STATUS_EGRESS_PENDING_CAPACITY: i32 = 39;
/// The retained payload-byte budget is exhausted.
pub const BONDRY_STATUS_EGRESS_PENDING_BYTES: i32 = 40;
/// Process-wide admission rate was exceeded.
pub const BONDRY_STATUS_EGRESS_GLOBAL_RATE_LIMITED: i32 = 41;
/// Per-route admission rate was exceeded.
pub const BONDRY_STATUS_EGRESS_ROUTE_RATE_LIMITED: i32 = 42;
/// The route is disabled.
pub const BONDRY_STATUS_EGRESS_ROUTE_DISABLED: i32 = 43;
/// The route kind does not support the requested operation.
pub const BONDRY_STATUS_EGRESS_UNSUPPORTED_OPERATION: i32 = 44;
/// Durable delivery state could not be safely read or written.
pub const BONDRY_STATUS_EGRESS_DELIVERY_LOG: i32 = 45;
/// The independent host-call lane is full.
pub const BONDRY_STATUS_EGRESS_CALL_CAPACITY: i32 = 46;
/// An accepted host call reached a terminal delivery failure.
pub const BONDRY_STATUS_EGRESS_CALL_FAILED: i32 = 47;
/// A completed call result exceeded the caller's explicit return bound.
pub const BONDRY_STATUS_EGRESS_RESULT_TOO_LARGE: i32 = 48;
/// Host-owned discovery credentials were absent or invalid.
pub const BONDRY_STATUS_EGRESS_DISCOVERY_SECRET: i32 = 49;
/// Discovery connection evidence violated endpoint or TLS policy.
pub const BONDRY_STATUS_EGRESS_DISCOVERY_ENDPOINT_POLICY: i32 = 50;
/// Discovery exceeded its absolute configuration-time deadline.
pub const BONDRY_STATUS_EGRESS_DISCOVERY_DEADLINE: i32 = 51;
/// The explicit discovery endpoint could not service the operation.
pub const BONDRY_STATUS_EGRESS_DISCOVERY_UNAVAILABLE: i32 = 52;
/// The discovery response exceeded its configured byte bound.
pub const BONDRY_STATUS_EGRESS_DISCOVERY_RESPONSE_TOO_LARGE: i32 = 53;
/// The discovery endpoint supports no compatible protocol revision.
pub const BONDRY_STATUS_EGRESS_DISCOVERY_UNSUPPORTED_PROTOCOL: i32 = 54;
/// The discovery endpoint selected an unsupported streaming response mode.
pub const BONDRY_STATUS_EGRESS_DISCOVERY_UNSUPPORTED_RESPONSE_MODE: i32 = 55;
/// The discovery endpoint rejected a valid request.
pub const BONDRY_STATUS_EGRESS_DISCOVERY_REJECTED: i32 = 56;
/// Discovery returned invalid MCP framing.
pub const BONDRY_STATUS_EGRESS_DISCOVERY_INVALID_RESPONSE: i32 = 57;
/// Discovery returned more tools than the configured bound.
pub const BONDRY_STATUS_EGRESS_DISCOVERY_TOOL_LIMIT: i32 = 58;
/// Discovery returned an invalid or oversized tool schema.
pub const BONDRY_STATUS_EGRESS_DISCOVERY_INVALID_SCHEMA: i32 = 59;

const IDENTIFIER_CAPACITY: usize = 129;

/// Opaque running egress handle owned by the caller.
#[repr(C)]
pub struct BondryEgressHandle {
    _private: [u8; 0],
}

struct EgressHandle {
    runtime: EgressRuntime,
    secrets: Arc<ForeignSecretProvider>,
    transport: Arc<ForeignHttpTransport>,
}

/// Opaque owned result of one successful host `call`.
#[repr(C)]
pub struct BondryEgressCallResult {
    _private: [u8; 0],
}

struct EgressCallResult {
    json: Bytes,
    category: u32,
}

/// Opaque owned JSON result of one successful MCP discovery operation.
#[repr(C)]
pub struct BondryEgressMcpDiscoveryResult {
    _private: [u8; 0],
}

struct EgressMcpDiscoveryResult {
    json: Bytes,
}

/// Fixed non-sensitive delivery status.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryEgressDeliveryStatusV1 {
    /// Zero-terminated route identifier.
    pub route_id: [u8; IDENTIFIER_CAPACITY],
    /// Zero-terminated delivery identifier.
    pub delivery_id: [u8; IDENTIFIER_CAPACITY],
    /// Original acceptance time in Unix milliseconds.
    pub accepted_at_unix_ms: u64,
    /// Most recent transition time in Unix milliseconds.
    pub updated_at_unix_ms: u64,
    /// Number of transport attempts started.
    pub attempts: u16,
    /// Pending or terminal state constant from `bondry.h`.
    pub state: u32,
    /// Terminal outcome constant from `bondry.h`.
    pub outcome: u32,
    /// Failure category from `bondry.h` when outcome is failed.
    pub failure: u32,
    /// Optional result category from `bondry.h`.
    pub result_category: u32,
    /// Bounded result size when a result category is present.
    pub result_bytes: u32,
}

impl BondryEgressDeliveryStatusV1 {
    const fn zeroed() -> Self {
        Self {
            route_id: [0; IDENTIFIER_CAPACITY],
            delivery_id: [0; IDENTIFIER_CAPACITY],
            accepted_at_unix_ms: 0,
            updated_at_unix_ms: 0,
            attempts: 0,
            state: 0,
            outcome: 0,
            failure: 0,
            result_category: 0,
            result_bytes: 0,
        }
    }
}

/// Starts bounded egress using a retained store and host callback descriptors.
///
/// # Safety
///
/// All pointers must remain valid for this call. On success, `out_egress` receives one handle
/// that must be passed exactly once to `bondry_egress_stop_v1`.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_egress_start_v1(
    store: *const BondryStoreHandle,
    runtime_configuration_json: *const u8,
    runtime_configuration_json_length: usize,
    transport: *const BondryHTTPTransportV1,
    secrets: *const BondrySecretProviderV1,
    out_egress: *mut *mut BondryEgressHandle,
) -> i32 {
    if out_egress.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    unsafe { out_egress.write(ptr::null_mut()) };
    catch_status(|| {
        if store.is_null() || transport.is_null() || secrets.is_null() {
            return BONDRY_STATUS_NULL_POINTER;
        }
        let configuration = match unsafe {
            required_bytes(
                runtime_configuration_json,
                runtime_configuration_json_length,
                MAX_RUNTIME_CONFIGURATION_BYTES,
            )
        } {
            Ok(bytes) => match runtime_configuration(bytes) {
                Ok(configuration) => configuration,
                Err(error) => return configuration_status(error),
            },
            Err(status) => return status,
        };
        let log = match unsafe { ForeignDeliveryLog::derive(store, configuration.delivery_log) } {
            Ok(log) => Arc::new(log),
            Err(()) => return BONDRY_STATUS_EGRESS_DELIVERY_LOG,
        };
        let secret_provider = match unsafe { ForeignSecretProvider::retain(&*secrets) } {
            Ok(provider) => Arc::new(provider),
            Err(()) => return BONDRY_STATUS_INVALID_ARGUMENT,
        };
        let http_transport = match unsafe { ForeignHttpTransport::retain(&*transport) } {
            Ok(transport) => Arc::new(transport),
            Err(()) => return BONDRY_STATUS_INVALID_ARGUMENT,
        };
        let runtime_secrets: Arc<dyn SecretProvider> = secret_provider.clone();
        let runtime_transport: Arc<dyn HttpTransport> = http_transport.clone();
        let runtime = match EgressRuntime::start(
            configuration.registry,
            configuration.runtime,
            log,
            runtime_secrets,
            runtime_transport,
        ) {
            Ok(runtime) => runtime,
            Err(error) => return start_error_status(error),
        };
        let handle = Box::new(EgressHandle {
            runtime,
            secrets: secret_provider,
            transport: http_transport,
        });
        unsafe { out_egress.write(Box::into_raw(handle).cast()) };
        BONDRY_STATUS_OK
    })
}

/// Stops admission, drains bounded work, and consumes the handle.
///
/// # Safety
///
/// A non-null handle must be live and exclusively owned for this call. It is consumed even when
/// shutdown reports an error. Null is allowed.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_egress_stop_v1(egress: *mut BondryEgressHandle) -> i32 {
    if egress.is_null() {
        return BONDRY_STATUS_OK;
    }
    catch_status(|| {
        let mut handle = unsafe { Box::from_raw(egress.cast::<EgressHandle>()) };
        match handle.runtime.stop() {
            Ok(()) => BONDRY_STATUS_OK,
            Err(error) => stop_error_status(error),
        }
    })
}

/// Registers one strictly validated route configuration.
///
/// # Safety
///
/// The handle must be live. Configuration bytes must remain readable for this call.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_egress_route_register_v1(
    egress: *const BondryEgressHandle,
    configuration_json: *const u8,
    configuration_json_length: usize,
) -> i32 {
    with_handle(egress, |handle| {
        let bytes = match unsafe {
            required_bytes(
                configuration_json,
                configuration_json_length,
                MAX_ROUTE_CONFIGURATION_BYTES,
            )
        } {
            Ok(bytes) => bytes,
            Err(status) => return status,
        };
        let route = match route_configuration(bytes) {
            Ok(route) => route,
            Err(error) => return configuration_status(error),
        };
        runtime_status(handle.runtime.register_route(route))
    })
}

/// Opens admission for a disabled route.
///
/// # Safety
///
/// The handle must be live. Route bytes must remain readable for this call.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_egress_route_enable_v1(
    egress: *const BondryEgressHandle,
    route_id: *const u8,
    route_id_length: usize,
) -> i32 {
    route_operation(egress, route_id, route_id_length, |runtime, route| {
        runtime.enable_route(route)
    })
}

/// Closes admission and waits for the route's bounded drain.
///
/// # Safety
///
/// The handle must be live. Route bytes must remain readable for this call.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_egress_route_disable_v1(
    egress: *const BondryEgressHandle,
    route_id: *const u8,
    route_id_length: usize,
) -> i32 {
    route_operation(egress, route_id, route_id_length, |runtime, route| {
        runtime.disable_route(route)
    })
}

/// Closes admission, drains bounded work, and removes the route.
///
/// # Safety
///
/// The handle must be live. Route bytes must remain readable for this call.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_egress_route_unregister_v1(
    egress: *const BondryEgressHandle,
    route_id: *const u8,
    route_id_length: usize,
) -> i32 {
    route_operation(egress, route_id, route_id_length, |runtime, route| {
        runtime.unregister_route(route)
    })
}

/// Serializes stable route summaries without secret material.
///
/// # Safety
///
/// The handle and output length must be live. A non-null output must be writable for `capacity`
/// bytes and must not overlap the output length.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_egress_routes_json_v1(
    egress: *const BondryEgressHandle,
    output_json: *mut u8,
    capacity: usize,
    out_length: *mut usize,
) -> i32 {
    if !out_length.is_null() {
        unsafe { out_length.write(0) };
    }
    with_handle(egress, |handle| {
        let routes = match handle.runtime.routes() {
            Ok(routes) => routes,
            Err(error) => return runtime_error_status(error),
        };
        let routes = routes
            .iter()
            .map(RouteSummaryJson::from)
            .collect::<Vec<_>>();
        let encoded = match serde_json::to_vec(&routes) {
            Ok(encoded) => encoded,
            Err(_) => return BONDRY_STATUS_INTERNAL_FAILURE,
        };
        write_bytes(&encoded, output_json, capacity, out_length)
    })
}

/// Validates, persists, and enqueues one event without waiting for delivery.
///
/// # Safety
///
/// The handle must be live. All input buffers must remain readable for this call.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_egress_emit_v1(
    egress: *const BondryEgressHandle,
    route_id: *const u8,
    route_id_length: usize,
    delivery_id: *const u8,
    delivery_id_length: usize,
    payload_json: *const u8,
    payload_json_length: usize,
) -> i32 {
    with_handle(egress, |handle| {
        let route = match unsafe { required_identifier(route_id, route_id_length) }
            .and_then(|value| RouteId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT))
        {
            Ok(route) => route,
            Err(status) => return status,
        };
        let delivery = match unsafe { required_identifier(delivery_id, delivery_id_length) }
            .and_then(|value| DeliveryId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT))
        {
            Ok(delivery) => delivery,
            Err(status) => return status,
        };
        let payload = match unsafe {
            required_bytes(
                payload_json,
                payload_json_length,
                bondry_egress::MAX_EVENT_PAYLOAD_BYTES,
            )
        } {
            Ok(payload) => Bytes::copy_from_slice(payload),
            Err(status) => return status,
        };
        runtime_status(handle.runtime.emit(route, delivery, payload))
    })
}

/// Executes one MCP-only call and returns one opaque owned result.
///
/// # Safety
///
/// The handle must be live. Input buffers must remain readable for this call. `out_result` must be
/// writable and receives ownership only on success.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_egress_call_v1(
    egress: *const BondryEgressHandle,
    route_id: *const u8,
    route_id_length: usize,
    delivery_id: *const u8,
    delivery_id_length: usize,
    payload_json: *const u8,
    payload_json_length: usize,
    max_result_bytes: usize,
    out_result: *mut *mut BondryEgressCallResult,
) -> i32 {
    if out_result.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    unsafe { out_result.write(ptr::null_mut()) };
    with_handle(egress, |handle| {
        if !(MIN_MCP_RESULT_BYTES..=MAX_MCP_RESULT_BYTES).contains(&max_result_bytes) {
            return BONDRY_STATUS_INVALID_ARGUMENT;
        }
        let route = match unsafe { required_identifier(route_id, route_id_length) }
            .and_then(|value| RouteId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT))
        {
            Ok(route) => route,
            Err(status) => return status,
        };
        let delivery = match unsafe { required_identifier(delivery_id, delivery_id_length) }
            .and_then(|value| DeliveryId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT))
        {
            Ok(delivery) => delivery,
            Err(status) => return status,
        };
        let payload = match unsafe {
            required_bytes(
                payload_json,
                payload_json_length,
                bondry_egress::MAX_EVENT_PAYLOAD_BYTES,
            )
        } {
            Ok(payload) => Bytes::copy_from_slice(payload),
            Err(status) => return status,
        };
        let result = match handle.runtime.call(route, delivery, payload) {
            Ok(result) => result,
            Err(error) => return runtime_error_status(error),
        };
        let (_, metadata, json) = result.into_parts();
        if json.len() > max_result_bytes {
            return BONDRY_STATUS_EGRESS_RESULT_TOO_LARGE;
        }
        let result = Box::new(EgressCallResult {
            json,
            category: encode_result_category(metadata.category()),
        });
        unsafe { out_result.write(Box::into_raw(result).cast()) };
        BONDRY_STATUS_OK
    })
}

/// Borrows raw JSON and non-sensitive category from one owned call result.
///
/// # Safety
///
/// The result must be live. All output pointers must be writable and non-overlapping. Returned
/// bytes remain valid only until `bondry_egress_call_result_release_v1` consumes the result.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_egress_call_result_json_v1(
    result: *const BondryEgressCallResult,
    out_json: *mut *const u8,
    out_length: *mut usize,
    out_category: *mut u32,
) -> i32 {
    if out_json.is_null() || out_length.is_null() || out_category.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    unsafe {
        out_json.write(ptr::null());
        out_length.write(0);
        out_category.write(0);
    }
    catch_status(|| {
        if result.is_null() {
            return BONDRY_STATUS_NULL_POINTER;
        }
        let result = unsafe { &*result.cast::<EgressCallResult>() };
        unsafe {
            out_json.write(result.json.as_ptr());
            out_length.write(result.json.len());
            out_category.write(result.category);
        }
        BONDRY_STATUS_OK
    })
}

/// Releases one opaque call result. Null is allowed.
///
/// # Safety
///
/// A non-null result must be live and exclusively owned. It is consumed exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_egress_call_result_release_v1(result: *mut BondryEgressCallResult) {
    if result.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(result.cast::<EgressCallResult>()));
    }));
}

/// Runs one explicit configuration-time MCP discovery against a supplied endpoint.
///
/// # Safety
///
/// The egress handle must be live. Configuration bytes must remain readable for this call.
/// `out_result` must be writable and receives ownership only on success.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_egress_mcp_discover_v1(
    egress: *const BondryEgressHandle,
    configuration_json: *const u8,
    configuration_json_length: usize,
    out_result: *mut *mut BondryEgressMcpDiscoveryResult,
) -> i32 {
    if out_result.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    unsafe { out_result.write(ptr::null_mut()) };
    with_handle(egress, |handle| {
        let bytes = match unsafe {
            required_bytes(
                configuration_json,
                configuration_json_length,
                MAX_DISCOVERY_CONFIGURATION_BYTES,
            )
        } {
            Ok(bytes) => bytes,
            Err(status) => return status,
        };
        let configuration = match mcp_discovery_configuration(bytes) {
            Ok(configuration) => configuration,
            Err(error) => return configuration_status(error),
        };
        let result = match execute_discovery(
            configuration.operation,
            configuration.timeout,
            &handle.secrets,
            Arc::clone(&handle.transport),
        ) {
            Ok(result) => result,
            Err(error) => return discovery_error_status(error),
        };
        let json = match serde_json::to_vec(&McpDiscoveryResultJson::from(&result)) {
            Ok(json) => Bytes::from(json),
            Err(_) => return BONDRY_STATUS_INTERNAL_FAILURE,
        };
        let result = Box::new(EgressMcpDiscoveryResult { json });
        unsafe { out_result.write(Box::into_raw(result).cast()) };
        BONDRY_STATUS_OK
    })
}

/// Borrows the validated host-facing JSON from one owned discovery result.
///
/// # Safety
///
/// The result must be live. Output pointers must be writable and non-overlapping. Returned bytes
/// remain valid only until `bondry_egress_mcp_discovery_result_release_v1` consumes the result.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_egress_mcp_discovery_result_json_v1(
    result: *const BondryEgressMcpDiscoveryResult,
    out_json: *mut *const u8,
    out_length: *mut usize,
) -> i32 {
    if out_json.is_null() || out_length.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    unsafe {
        out_json.write(ptr::null());
        out_length.write(0);
    }
    catch_status(|| {
        if result.is_null() {
            return BONDRY_STATUS_NULL_POINTER;
        }
        let result = unsafe { &*result.cast::<EgressMcpDiscoveryResult>() };
        unsafe {
            out_json.write(result.json.as_ptr());
            out_length.write(result.json.len());
        }
        BONDRY_STATUS_OK
    })
}

/// Releases one opaque discovery result. Null is allowed.
///
/// # Safety
///
/// A non-null result must be live and exclusively owned. It is consumed exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_egress_mcp_discovery_result_release_v1(
    result: *mut BondryEgressMcpDiscoveryResult,
) {
    if result.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(result.cast::<EgressMcpDiscoveryResult>()));
    }));
}

/// Loads one persisted delivery status without payload or credential data.
///
/// # Safety
///
/// The handle and delivery bytes must be live. Outputs must be writable and non-overlapping.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_egress_delivery_status_v1(
    egress: *const BondryEgressHandle,
    delivery_id: *const u8,
    delivery_id_length: usize,
    out_found: *mut u8,
    out_status: *mut BondryEgressDeliveryStatusV1,
) -> i32 {
    if out_found.is_null() || out_status.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    unsafe {
        out_found.write(0);
        out_status.write(BondryEgressDeliveryStatusV1::zeroed());
    }
    with_handle(egress, |handle| {
        let delivery = match unsafe { required_identifier(delivery_id, delivery_id_length) }
            .and_then(|value| DeliveryId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT))
        {
            Ok(delivery) => delivery,
            Err(status) => return status,
        };
        match handle.runtime.delivery(delivery) {
            Ok(Some(record)) => {
                let status = encode_delivery_status(&record);
                unsafe {
                    out_status.write(status);
                    out_found.write(1);
                }
                BONDRY_STATUS_OK
            }
            Ok(None) => BONDRY_STATUS_OK,
            Err(error) => runtime_error_status(error),
        }
    })
}

#[derive(Serialize)]
struct RouteSummaryJson<'a> {
    id: &'a str,
    enabled: bool,
    kind: &'static str,
    target: &'a str,
}

impl<'a> From<&'a RouteSummary> for RouteSummaryJson<'a> {
    fn from(route: &'a RouteSummary) -> Self {
        Self {
            id: route.id().as_str(),
            enabled: route.is_enabled(),
            kind: route.kind(),
            target: route.target(),
        }
    }
}

#[derive(Serialize)]
struct McpDiscoveryResultJson<'a> {
    protocol_version: &'static str,
    tools: Vec<McpDiscoveredToolJson<'a>>,
}

impl<'a> From<&'a McpDiscoveryResult> for McpDiscoveryResultJson<'a> {
    fn from(result: &'a McpDiscoveryResult) -> Self {
        Self {
            protocol_version: result.version().as_str(),
            tools: result
                .tools()
                .iter()
                .map(McpDiscoveredToolJson::from)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct McpDiscoveredToolJson<'a> {
    name: &'a str,
    description: Option<&'a str>,
    input_schema: &'a serde_json::Value,
}

impl<'a> From<&'a bondry_egress_mcp::McpDiscoveredTool> for McpDiscoveredToolJson<'a> {
    fn from(tool: &'a bondry_egress_mcp::McpDiscoveredTool) -> Self {
        Self {
            name: tool.name(),
            description: tool.description(),
            input_schema: tool.input_schema(),
        }
    }
}

fn execute_discovery(
    mut operation: McpDiscoveryOperation,
    timeout: std::time::Duration,
    secrets: &ForeignSecretProvider,
    transport: Arc<ForeignHttpTransport>,
) -> Result<McpDiscoveryResult, McpDiscoveryError> {
    let resolved = operation
        .secret_references()
        .iter()
        .map(|reference| secrets.resolve(reference))
        .collect::<Result<Vec<_>, SecretProviderError>>()
        .map_err(|_| McpDiscoveryError::SecretUnavailable)?;
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|_| McpDiscoveryError::InvalidState)?;
    let deadline = Instant::now() + timeout;
    let mut transition = operation.start(bondry_transport::Deadline::at(deadline), resolved);
    executor.block_on(async move {
        loop {
            match transition {
                McpDiscoveryTransition::Complete(result) => return result,
                McpDiscoveryTransition::Http(request) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        transition = operation.resume(Err(TransportError::DeadlineExceeded));
                        continue;
                    }
                    let completion =
                        match tokio::time::timeout(remaining, transport.send(*request)).await {
                            Ok(completion) => completion,
                            Err(_) => Err(TransportError::DeadlineExceeded),
                        };
                    transition = operation.resume(completion);
                }
            }
        }
    })
}

fn with_handle(
    egress: *const BondryEgressHandle,
    operation: impl FnOnce(&EgressHandle) -> i32,
) -> i32 {
    catch_status(|| {
        if egress.is_null() {
            return BONDRY_STATUS_NULL_POINTER;
        }
        operation(unsafe { &*egress.cast::<EgressHandle>() })
    })
}

fn route_operation(
    egress: *const BondryEgressHandle,
    route_id: *const u8,
    route_id_length: usize,
    operation: impl FnOnce(&EgressRuntime, RouteId) -> Result<(), EgressRuntimeError>,
) -> i32 {
    with_handle(egress, |handle| {
        let route = match unsafe { required_identifier(route_id, route_id_length) }
            .and_then(|value| RouteId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT))
        {
            Ok(route) => route,
            Err(status) => return status,
        };
        runtime_status(operation(&handle.runtime, route))
    })
}

fn runtime_status<T>(result: Result<T, EgressRuntimeError>) -> i32 {
    result.map_or_else(runtime_error_status, |_| BONDRY_STATUS_OK)
}

fn runtime_error_status(error: EgressRuntimeError) -> i32 {
    match error {
        EgressRuntimeError::Busy => BONDRY_STATUS_EGRESS_BUSY,
        EgressRuntimeError::Stopped => BONDRY_STATUS_EGRESS_STOPPED,
        EgressRuntimeError::Route(error) => route_error_status(error),
        EgressRuntimeError::Admission(error) => admission_error_status(error),
        EgressRuntimeError::RouteDraining => BONDRY_STATUS_EGRESS_ROUTE_DRAINING,
        EgressRuntimeError::PendingCapacity => BONDRY_STATUS_EGRESS_PENDING_CAPACITY,
        EgressRuntimeError::PendingBytes => BONDRY_STATUS_EGRESS_PENDING_BYTES,
        EgressRuntimeError::CallCapacity => BONDRY_STATUS_EGRESS_CALL_CAPACITY,
        EgressRuntimeError::CallFailed(_) => BONDRY_STATUS_EGRESS_CALL_FAILED,
        EgressRuntimeError::DeliveryLog(error) => delivery_log_error_status(error),
    }
}

const fn discovery_error_status(error: McpDiscoveryError) -> i32 {
    match error {
        McpDiscoveryError::SecretUnavailable => BONDRY_STATUS_EGRESS_DISCOVERY_SECRET,
        McpDiscoveryError::EndpointPolicy => BONDRY_STATUS_EGRESS_DISCOVERY_ENDPOINT_POLICY,
        McpDiscoveryError::DeadlineExceeded => BONDRY_STATUS_EGRESS_DISCOVERY_DEADLINE,
        McpDiscoveryError::Unavailable => BONDRY_STATUS_EGRESS_DISCOVERY_UNAVAILABLE,
        McpDiscoveryError::ResponseTooLarge => BONDRY_STATUS_EGRESS_DISCOVERY_RESPONSE_TOO_LARGE,
        McpDiscoveryError::UnsupportedProtocol => {
            BONDRY_STATUS_EGRESS_DISCOVERY_UNSUPPORTED_PROTOCOL
        }
        McpDiscoveryError::UnsupportedResponseMode => {
            BONDRY_STATUS_EGRESS_DISCOVERY_UNSUPPORTED_RESPONSE_MODE
        }
        McpDiscoveryError::Rejected => BONDRY_STATUS_EGRESS_DISCOVERY_REJECTED,
        McpDiscoveryError::InvalidResponse => BONDRY_STATUS_EGRESS_DISCOVERY_INVALID_RESPONSE,
        McpDiscoveryError::ToolLimitExceeded => BONDRY_STATUS_EGRESS_DISCOVERY_TOOL_LIMIT,
        McpDiscoveryError::InvalidToolSchema => BONDRY_STATUS_EGRESS_DISCOVERY_INVALID_SCHEMA,
        McpDiscoveryError::InvalidState | McpDiscoveryError::InvalidRequest => {
            BONDRY_STATUS_INTERNAL_FAILURE
        }
    }
}

const fn route_error_status(error: RouteRegistryError) -> i32 {
    match error {
        RouteRegistryError::AlreadyExists => BONDRY_STATUS_ALREADY_EXISTS,
        RouteRegistryError::CapacityExhausted => BONDRY_STATUS_CAPACITY_EXHAUSTED,
        RouteRegistryError::PayloadLimitUnsupported => BONDRY_STATUS_INVALID_ARGUMENT,
        RouteRegistryError::NotFound => BONDRY_STATUS_NOT_FOUND,
    }
}

const fn admission_error_status(error: AdmissionError) -> i32 {
    match error {
        AdmissionError::RouteNotFound => BONDRY_STATUS_NOT_FOUND,
        AdmissionError::RouteDisabled => BONDRY_STATUS_EGRESS_ROUTE_DISABLED,
        AdmissionError::UnsupportedOperation => BONDRY_STATUS_EGRESS_UNSUPPORTED_OPERATION,
        AdmissionError::Payload(PayloadError::TooLarge) => BONDRY_STATUS_PAYLOAD_TOO_LARGE,
        AdmissionError::Payload(PayloadError::InvalidJson) => BONDRY_STATUS_INVALID_JSON,
        AdmissionError::Payload(_) => BONDRY_STATUS_INVALID_ARGUMENT,
        AdmissionError::GlobalRateLimited => BONDRY_STATUS_EGRESS_GLOBAL_RATE_LIMITED,
        AdmissionError::RouteRateLimited => BONDRY_STATUS_EGRESS_ROUTE_RATE_LIMITED,
        AdmissionError::Kind(KindOperationError::UnsupportedOperation) => {
            BONDRY_STATUS_EGRESS_UNSUPPORTED_OPERATION
        }
        AdmissionError::Kind(_) => BONDRY_STATUS_INVALID_ARGUMENT,
    }
}

const fn delivery_log_error_status(error: DeliveryLogError) -> i32 {
    match error {
        DeliveryLogError::Conflict => BONDRY_STATUS_ALREADY_EXISTS,
        DeliveryLogError::CapacityExhausted => BONDRY_STATUS_CAPACITY_EXHAUSTED,
        DeliveryLogError::NotFound => BONDRY_STATUS_NOT_FOUND,
        DeliveryLogError::InvalidTransition | DeliveryLogError::Unavailable => {
            BONDRY_STATUS_EGRESS_DELIVERY_LOG
        }
    }
}

const fn start_error_status(error: EgressRuntimeStartError) -> i32 {
    match error {
        EgressRuntimeStartError::Recovery(error) => delivery_log_error_status(error),
        EgressRuntimeStartError::Thread
        | EgressRuntimeStartError::Runtime
        | EgressRuntimeStartError::Startup => BONDRY_STATUS_EGRESS_START_FAILED,
    }
}

const fn stop_error_status(error: EgressRuntimeStopError) -> i32 {
    match error {
        EgressRuntimeStopError::ThreadPanicked => BONDRY_STATUS_EGRESS_STOP_FAILED,
    }
}

const fn configuration_status(error: ConfigurationError) -> i32 {
    match error {
        ConfigurationError::Json => BONDRY_STATUS_INVALID_JSON,
        ConfigurationError::Invalid => BONDRY_STATUS_INVALID_ARGUMENT,
    }
}

fn encode_delivery_status(record: &DeliveryRecord) -> BondryEgressDeliveryStatusV1 {
    let mut status = BondryEgressDeliveryStatusV1::zeroed();
    copy_identifier(
        &mut status.route_id,
        record.intent().route().as_str().as_bytes(),
    );
    copy_identifier(
        &mut status.delivery_id,
        record.intent().delivery().as_str().as_bytes(),
    );
    status.accepted_at_unix_ms = record.intent().accepted_at_unix_ms();
    status.updated_at_unix_ms = record.updated_at_unix_ms();
    status.attempts = record.attempts();
    match record.state() {
        DeliveryState::Pending => status.state = 1,
        DeliveryState::Terminal(outcome) => {
            status.state = 2;
            match outcome {
                DeliveryOutcome::Delivered => status.outcome = 1,
                DeliveryOutcome::Failed(failure) => {
                    status.outcome = 2;
                    status.failure = encode_failure(failure);
                }
                DeliveryOutcome::LostOnShutdown => status.outcome = 3,
                DeliveryOutcome::UnknownAfterCrash => status.outcome = 4,
            }
        }
    }
    if let Some(result) = record.result() {
        status.result_category = encode_result_category(result.category());
        status.result_bytes = result.bytes();
    }
    status
}

const fn encode_result_category(category: DeliveryResultCategory) -> u32 {
    match category {
        DeliveryResultCategory::Succeeded => 1,
        DeliveryResultCategory::Failed => 2,
        DeliveryResultCategory::Invalid => 3,
    }
}

const fn encode_failure(failure: DeliveryFailure) -> u32 {
    match failure {
        DeliveryFailure::Cancelled => 1,
        DeliveryFailure::DeadlineExceeded => 2,
        DeliveryFailure::EndpointPolicy => 3,
        DeliveryFailure::SecretUnavailable => 4,
        DeliveryFailure::TransportUnavailable => 5,
        DeliveryFailure::ReceiverRejected => 6,
        DeliveryFailure::RetryExhausted => 7,
        DeliveryFailure::Internal => 8,
    }
}

fn copy_identifier(output: &mut [u8; IDENTIFIER_CAPACITY], input: &[u8]) {
    output[..input.len()].copy_from_slice(input);
}

fn catch_status(operation: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(BONDRY_STATUS_INTERNAL_FAILURE)
}

unsafe fn required_identifier<'a>(pointer: *const u8, length: usize) -> Result<&'a str, i32> {
    let bytes = unsafe { required_bytes(pointer, length, IDENTIFIER_CAPACITY - 1) }?;
    std::str::from_utf8(bytes).map_err(|_| BONDRY_STATUS_INVALID_UTF8)
}

unsafe fn required_bytes<'a>(
    pointer: *const u8,
    length: usize,
    maximum: usize,
) -> Result<&'a [u8], i32> {
    if pointer.is_null() {
        return Err(BONDRY_STATUS_NULL_POINTER);
    }
    if length > isize::MAX as usize {
        return Err(BONDRY_STATUS_INVALID_LENGTH);
    }
    if length > maximum {
        return Err(BONDRY_STATUS_PAYLOAD_TOO_LARGE);
    }
    Ok(unsafe { slice::from_raw_parts(pointer, length) })
}

fn write_bytes(bytes: &[u8], output: *mut u8, capacity: usize, out_length: *mut usize) -> i32 {
    if out_length.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    unsafe { out_length.write(bytes.len()) };
    if output.is_null() {
        return if capacity == 0 {
            BONDRY_STATUS_OK
        } else {
            BONDRY_STATUS_NULL_POINTER
        };
    }
    if capacity < bytes.len() {
        return BONDRY_STATUS_BUFFER_TOO_SMALL;
    }
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
    BONDRY_STATUS_OK
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::c_void,
        ptr, slice,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    use tempfile::TempDir;

    use crate::{
        BONDRY_CONNECTION_EVIDENCE_TLS_V1, BONDRY_HTTP_RESULT_RESPONSE_V1,
        BONDRY_HTTP_TRANSPORT_ABI_VERSION_V1, BONDRY_SECRET_PROVIDER_ABI_VERSION_V1,
        BondryConnectionEvidenceV1, BondryHTTPCompletionV1, BondryHTTPHeaderV1,
        BondryHTTPRequestV1, BondryHTTPResultV1, BondryHTTPTransportV1, BondrySecretProviderV1,
        BondrySecretResolutionV1,
    };

    use super::{
        BONDRY_STATUS_EGRESS_UNSUPPORTED_OPERATION, BONDRY_STATUS_OK, BondryEgressCallResult,
        BondryEgressDeliveryStatusV1, BondryEgressHandle, BondryEgressMcpDiscoveryResult,
        BondryStoreHandle, bondry_egress_call_result_json_v1, bondry_egress_call_result_release_v1,
        bondry_egress_call_v1, bondry_egress_delivery_status_v1, bondry_egress_emit_v1,
        bondry_egress_mcp_discover_v1, bondry_egress_mcp_discovery_result_json_v1,
        bondry_egress_mcp_discovery_result_release_v1, bondry_egress_route_register_v1,
        bondry_egress_routes_json_v1, bondry_egress_start_v1, bondry_egress_stop_v1,
    };

    unsafe extern "C" {
        fn bondry_store_open_v1(
            path: *const u8,
            path_length: usize,
            key: *const u8,
            key_length: usize,
            out_store: *mut *mut BondryStoreHandle,
        ) -> i32;
        fn bondry_store_close_v1(store: *mut BondryStoreHandle) -> i32;
    }

    struct MockHost {
        sends: AtomicUsize,
    }

    unsafe extern "C" fn retain_host(context: *mut c_void) -> *mut c_void {
        if !context.is_null() {
            unsafe { Arc::increment_strong_count(context.cast::<MockHost>()) };
        }
        context
    }

    unsafe extern "C" fn release_host(context: *mut c_void) {
        if !context.is_null() {
            unsafe { drop(Arc::from_raw(context.cast::<MockHost>())) };
        }
    }

    unsafe extern "C" fn send_http(
        context: *mut c_void,
        request: *const BondryHTTPRequestV1,
        completion: BondryHTTPCompletionV1,
        completion_context: *mut c_void,
    ) -> i32 {
        if context.is_null() || request.is_null() {
            return 1;
        }
        let host = unsafe { &*context.cast::<MockHost>() };
        host.sends.fetch_add(1, Ordering::Relaxed);
        let request = unsafe { &*request };
        let request_body = if request.body.is_null() {
            &[]
        } else {
            unsafe { slice::from_raw_parts(request.body, request.body_length) }
        };
        let message = serde_json::from_slice::<serde_json::Value>(request_body).ok();
        let method = message
            .as_ref()
            .and_then(|message| message.get("method"))
            .and_then(serde_json::Value::as_str);
        let id = message
            .as_ref()
            .and_then(|message| message.get("id"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let (status_code, body) = match method {
            Some("server/discover") => (
                200,
                serde_json::to_vec(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "resultType": "complete",
                        "supportedVersions": ["2026-07-28"],
                    },
                }))
                .unwrap_or_default(),
            ),
            Some("tools/list") => (
                200,
                serde_json::to_vec(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "resultType": "complete",
                        "tools": [{
                            "name": "battery:status",
                            "description": "Battery status",
                            "inputSchema": {
                                "type": "object",
                                "properties": { "detail": { "type": "boolean" } },
                            },
                        }],
                    },
                }))
                .unwrap_or_default(),
            ),
            Some("tools/call") => (
                200,
                serde_json::to_vec(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "resultType": "complete",
                        "content": [{ "type": "text", "text": "ok" }],
                    },
                }))
                .unwrap_or_default(),
            ),
            Some("notifications/initialized") => (202, Vec::new()),
            _ => (204, Vec::new()),
        };
        let content_type = BondryHTTPHeaderV1 {
            name: b"content-type".as_ptr(),
            name_length: b"content-type".len(),
            value: b"application/json".as_ptr(),
            value_length: b"application/json".len(),
        };
        let server_name = b"example.com";
        let result = BondryHTTPResultV1 {
            kind: BONDRY_HTTP_RESULT_RESPONSE_V1,
            error: 0,
            status_code,
            headers: if body.is_empty() {
                ptr::null()
            } else {
                &content_type
            },
            header_count: usize::from(!body.is_empty()),
            body: if body.is_empty() {
                ptr::null()
            } else {
                body.as_ptr()
            },
            body_length: body.len(),
            connection: BondryConnectionEvidenceV1 {
                kind: BONDRY_CONNECTION_EVIDENCE_TLS_V1,
                server_name: server_name.as_ptr(),
                server_name_length: server_name.len(),
                ip_family: 0,
                ip: [0; 16],
                port: 443,
                interface_scope: 0,
                has_interface_scope: 0,
            },
        };
        unsafe { completion(completion_context, &result) };
        BONDRY_STATUS_OK
    }

    unsafe extern "C" fn resolve_secret(
        _context: *mut c_void,
        _secret_reference: *const u8,
        _secret_reference_length: usize,
        _completion: BondrySecretResolutionV1,
        _completion_context: *mut c_void,
    ) -> i32 {
        20
    }

    #[test]
    fn runs_persistent_webhook_lifecycle_through_the_c_abi()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("egress.db");
        let path = path.to_string_lossy();
        let key = [0x42; 32];
        let mut store = ptr::null_mut();
        assert_eq!(
            unsafe {
                bondry_store_open_v1(
                    path.as_ptr(),
                    path.len(),
                    key.as_ptr(),
                    key.len(),
                    &mut store,
                )
            },
            BONDRY_STATUS_OK
        );

        let host = Arc::new(MockHost {
            sends: AtomicUsize::new(0),
        });
        let host_context = Arc::into_raw(Arc::clone(&host)).cast_mut().cast::<c_void>();
        let transport = BondryHTTPTransportV1 {
            abi_version: BONDRY_HTTP_TRANSPORT_ABI_VERSION_V1,
            struct_size: size_of::<BondryHTTPTransportV1>(),
            context: host_context,
            retain: Some(retain_host),
            release: Some(release_host),
            send: Some(send_http),
        };
        let secrets = BondrySecretProviderV1 {
            abi_version: BONDRY_SECRET_PROVIDER_ABI_VERSION_V1,
            struct_size: size_of::<BondrySecretProviderV1>(),
            context: host_context,
            retain: Some(retain_host),
            release: Some(release_host),
            resolve: Some(resolve_secret),
        };
        let runtime = br#"{"version":1}"#;
        let mut egress: *mut BondryEgressHandle = ptr::null_mut();
        assert_eq!(
            unsafe {
                bondry_egress_start_v1(
                    store,
                    runtime.as_ptr(),
                    runtime.len(),
                    &transport,
                    &secrets,
                    &mut egress,
                )
            },
            BONDRY_STATUS_OK
        );

        let route = br#"{
          "version":1,
          "id":"receiver",
          "payload":{"fields":[]},
          "kind":{"type":"webhook","authentication":{"type":"none","endpoint":"https://example.com/events"}}
        }"#;
        assert_eq!(
            unsafe { bondry_egress_route_register_v1(egress, route.as_ptr(), route.len()) },
            BONDRY_STATUS_OK
        );
        let route_id = b"receiver";
        let delivery_id = b"delivery_1";
        let payload = b"{}";
        assert_eq!(
            unsafe {
                bondry_egress_emit_v1(
                    egress,
                    route_id.as_ptr(),
                    route_id.len(),
                    delivery_id.as_ptr(),
                    delivery_id.len(),
                    payload.as_ptr(),
                    payload.len(),
                )
            },
            BONDRY_STATUS_OK
        );

        let mut status = BondryEgressDeliveryStatusV1::zeroed();
        let mut found = 0;
        for _ in 0..100 {
            assert_eq!(
                unsafe {
                    bondry_egress_delivery_status_v1(
                        egress,
                        delivery_id.as_ptr(),
                        delivery_id.len(),
                        &mut found,
                        &mut status,
                    )
                },
                BONDRY_STATUS_OK
            );
            if found == 1 && status.state == 2 {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(status.outcome, 1);
        assert_eq!(host.sends.load(Ordering::Relaxed), 1);

        let mut length = 0;
        assert_eq!(
            unsafe { bondry_egress_routes_json_v1(egress, ptr::null_mut(), 0, &mut length) },
            BONDRY_STATUS_OK
        );
        let mut routes = vec![0; length];
        assert_eq!(
            unsafe {
                bondry_egress_routes_json_v1(egress, routes.as_mut_ptr(), routes.len(), &mut length)
            },
            BONDRY_STATUS_OK
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&routes)?[0]["target"],
            "https://example.com"
        );

        let mcp_route = br#"{
          "version":1,
          "id":"mcp_receiver",
          "payload":{"fields":[{"name":"detail","type":"boolean"}]},
          "kind":{
            "type":"mcp",
            "endpoint":"https://example.com/mcp",
            "authentication":{"type":"none"},
            "protocol_version":"2026-07-28",
            "tool":{
              "name":"battery:status",
              "input_schema":{
                "type":"object",
                "properties":{"detail":{"type":"boolean"}}
              }
            }
          }
        }"#;
        assert_eq!(
            unsafe { bondry_egress_route_register_v1(egress, mcp_route.as_ptr(), mcp_route.len()) },
            BONDRY_STATUS_OK
        );
        let mcp_route_id = b"mcp_receiver";
        let call_delivery = b"call_1";
        let call_payload = br#"{"detail":true}"#;
        let mut call_result: *mut BondryEgressCallResult = ptr::null_mut();
        assert_eq!(
            unsafe {
                bondry_egress_call_v1(
                    egress,
                    mcp_route_id.as_ptr(),
                    mcp_route_id.len(),
                    call_delivery.as_ptr(),
                    call_delivery.len(),
                    call_payload.as_ptr(),
                    call_payload.len(),
                    256 * 1024,
                    &mut call_result,
                )
            },
            BONDRY_STATUS_OK
        );
        let mut call_json = ptr::null();
        let mut call_json_length = 0;
        let mut call_category = 0;
        assert_eq!(
            unsafe {
                bondry_egress_call_result_json_v1(
                    call_result,
                    &mut call_json,
                    &mut call_json_length,
                    &mut call_category,
                )
            },
            BONDRY_STATUS_OK
        );
        assert_eq!(call_category, 1);
        let call_json = unsafe { slice::from_raw_parts(call_json, call_json_length) };
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(call_json)?["content"][0]["text"],
            "ok"
        );
        unsafe { bondry_egress_call_result_release_v1(call_result) };

        let mut unsupported: *mut BondryEgressCallResult = ptr::null_mut();
        assert_eq!(
            unsafe {
                bondry_egress_call_v1(
                    egress,
                    route_id.as_ptr(),
                    route_id.len(),
                    b"unsupported_call".as_ptr(),
                    b"unsupported_call".len(),
                    payload.as_ptr(),
                    payload.len(),
                    256 * 1024,
                    &mut unsupported,
                )
            },
            BONDRY_STATUS_EGRESS_UNSUPPORTED_OPERATION
        );
        assert!(unsupported.is_null());

        let discovery_configuration = br#"{
          "version":1,
          "endpoint":"https://example.com/mcp",
          "authentication":{"type":"none"}
        }"#;
        let mut discovery_result: *mut BondryEgressMcpDiscoveryResult = ptr::null_mut();
        assert_eq!(
            unsafe {
                bondry_egress_mcp_discover_v1(
                    egress,
                    discovery_configuration.as_ptr(),
                    discovery_configuration.len(),
                    &mut discovery_result,
                )
            },
            BONDRY_STATUS_OK
        );
        let mut discovery_json = ptr::null();
        let mut discovery_json_length = 0;
        assert_eq!(
            unsafe {
                bondry_egress_mcp_discovery_result_json_v1(
                    discovery_result,
                    &mut discovery_json,
                    &mut discovery_json_length,
                )
            },
            BONDRY_STATUS_OK
        );
        let discovery_json =
            unsafe { slice::from_raw_parts(discovery_json, discovery_json_length) };
        let discovery: serde_json::Value = serde_json::from_slice(discovery_json)?;
        assert_eq!(discovery["protocol_version"], "2026-07-28");
        assert_eq!(discovery["tools"][0]["name"], "battery:status");
        unsafe { bondry_egress_mcp_discovery_result_release_v1(discovery_result) };
        assert_eq!(host.sends.load(Ordering::Relaxed), 4);

        assert_eq!(unsafe { bondry_egress_stop_v1(egress) }, BONDRY_STATUS_OK);
        assert_eq!(unsafe { bondry_store_close_v1(store) }, BONDRY_STATUS_OK);
        unsafe { release_host(host_context) };
        Ok(())
    }
}
