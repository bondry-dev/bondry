use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
    sync::Arc,
};

use bondry_delivery_store::{
    DeliveryFailure, DeliveryId, DeliveryLogError, DeliveryOutcome, DeliveryRecord,
    DeliveryResultCategory, DeliveryState, RouteId,
};
use bondry_egress::{
    AdmissionError, KindOperationError, PayloadError, RouteRegistryError, RouteSummary,
};
use bondry_egress_runtime::{
    EgressRuntime, EgressRuntimeError, EgressRuntimeStartError, EgressRuntimeStopError,
};
use bytes::Bytes;
use serde::Serialize;

use crate::{
    BondryHTTPTransportV1, BondrySecretProviderV1,
    config::{
        ConfigurationError, MAX_ROUTE_CONFIGURATION_BYTES, MAX_RUNTIME_CONFIGURATION_BYTES,
        route_configuration, runtime_configuration,
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

const IDENTIFIER_CAPACITY: usize = 129;

/// Opaque running egress handle owned by the caller.
#[repr(C)]
pub struct BondryEgressHandle {
    _private: [u8; 0],
}

struct EgressHandle {
    runtime: EgressRuntime,
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
        let runtime = match EgressRuntime::start(
            configuration.registry,
            configuration.runtime,
            log,
            secret_provider,
            http_transport,
        ) {
            Ok(runtime) => runtime,
            Err(error) => return start_error_status(error),
        };
        let handle = Box::new(EgressHandle { runtime });
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
        EgressRuntimeError::DeliveryLog(error) => delivery_log_error_status(error),
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
        status.result_category = match result.category() {
            DeliveryResultCategory::Succeeded => 1,
            DeliveryResultCategory::Failed => 2,
            DeliveryResultCategory::Invalid => 3,
        };
        status.result_bytes = result.bytes();
    }
    status
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
        ptr,
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
        BondryConnectionEvidenceV1, BondryHTTPCompletionV1, BondryHTTPRequestV1,
        BondryHTTPResultV1, BondryHTTPTransportV1, BondrySecretProviderV1,
        BondrySecretResolutionV1,
    };

    use super::{
        BONDRY_STATUS_OK, BondryEgressDeliveryStatusV1, BondryEgressHandle, BondryStoreHandle,
        bondry_egress_delivery_status_v1, bondry_egress_emit_v1, bondry_egress_route_register_v1,
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
        let server_name = b"example.com";
        let result = BondryHTTPResultV1 {
            kind: BONDRY_HTTP_RESULT_RESPONSE_V1,
            error: 0,
            status_code: 204,
            headers: ptr::null(),
            header_count: 0,
            body: ptr::null(),
            body_length: 0,
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

        assert_eq!(unsafe { bondry_egress_stop_v1(egress) }, BONDRY_STATUS_OK);
        assert_eq!(unsafe { bondry_store_close_v1(store) }, BONDRY_STATUS_OK);
        unsafe { release_host(host_context) };
        Ok(())
    }
}
