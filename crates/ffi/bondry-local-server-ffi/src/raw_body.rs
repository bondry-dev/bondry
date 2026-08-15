use std::{
    ffi::c_void,
    mem::size_of,
    net::SocketAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
    sync::Arc,
    time::Duration,
};

use bondry_http_server::{
    RawBodyCompletion, RawBodyHandler, RawBodyHandlerLimits, RawBodyLifecycle, RawBodyRegistration,
    RawBodyRegistrationError, RawBodyRequest, RawBodyResponse, RawBodyRoute,
};
use http::{HeaderName, StatusCode};

use super::{
    BONDRY_STATUS_INTERNAL_FAILURE, BONDRY_STATUS_INVALID_ARGUMENT, BONDRY_STATUS_INVALID_LENGTH,
    BONDRY_STATUS_NULL_POINTER, BONDRY_STATUS_OK, BondryServerHandle, ServerHandle, catch_status,
};

/// The first protocol-neutral raw-body handler ABI version.
pub const BONDRY_RAW_BODY_HANDLER_ABI_VERSION_V1: u32 = 1;
/// The descriptor selects exact POST requests.
pub const BONDRY_RAW_BODY_METHOD_POST_V1: u32 = 1;
/// An enabled generation admits matching requests.
pub const BONDRY_RAW_BODY_LIFECYCLE_ENABLED_V1: u32 = 1;
/// A draining generation rejects new work and waits for accepted completions.
pub const BONDRY_RAW_BODY_LIFECYCLE_DRAINING_V1: u32 = 2;
/// A detached generation has released its handler context.
pub const BONDRY_RAW_BODY_LIFECYCLE_DETACHED_V1: u32 = 3;
/// The connected peer has an IPv4 address.
pub const BONDRY_RAW_BODY_IP_ADDRESS_V4_V1: u32 = 1;
/// The connected peer has an IPv6 address.
pub const BONDRY_RAW_BODY_IP_ADDRESS_V6_V1: u32 = 2;
/// A raw-body generation did not detach before its bounded deadline.
pub const BONDRY_STATUS_RAW_BODY_DRAIN_TIMED_OUT: i32 = 60;

const BONDRY_STATUS_INVALID_UTF8: i32 = 3;
const BONDRY_STATUS_ALREADY_EXISTS: i32 = 28;
const BONDRY_STATUS_CAPACITY_EXHAUSTED: i32 = 32;
const BONDRY_STATUS_INVALID_TRANSITION: i32 = 33;
const MAX_SELECTED_HEADERS: usize = 32;

/// One borrowed byte sequence.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryRawBodyByteSliceV1 {
    /// Borrowed bytes.
    pub bytes: *const u8,
    /// Number of readable bytes.
    pub length: usize,
}

/// One selected request header borrowed only for a handler callback.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryRawBodyHeaderV1 {
    /// Borrowed normalized header-name bytes.
    pub name: *const u8,
    /// Header-name byte length.
    pub name_length: usize,
    /// Borrowed exact header-value bytes.
    pub value: *const u8,
    /// Header-value byte length.
    pub value_length: usize,
}

/// One bounded raw-body request borrowed only for a handler callback.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryRawBodyRequestV1 {
    /// Must equal `BONDRY_RAW_BODY_HANDLER_ABI_VERSION_V1`.
    pub abi_version: u32,
    /// Byte size of this request record.
    pub struct_size: usize,
    /// Borrowed exact request-target bytes.
    pub target: *const u8,
    /// Request-target byte length.
    pub target_length: usize,
    /// Borrowed selected headers, preserving duplicate values.
    pub headers: *const BondryRawBodyHeaderV1,
    /// Selected header-value count.
    pub header_count: usize,
    /// Borrowed exact raw body bytes.
    pub body: *const u8,
    /// Raw body byte length.
    pub body_length: usize,
    /// IPv4 or IPv6 address family.
    pub peer_ip_family: u32,
    /// Network-order peer address; IPv4 uses the first four bytes.
    pub peer_ip: [u8; 16],
    /// Connected peer port.
    pub peer_port: u16,
    /// IPv6 interface scope when present.
    pub peer_interface_scope: u32,
    /// One when an IPv6 interface scope is present.
    pub has_peer_interface_scope: u8,
}

/// One status-only response borrowed for a completion callback.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryRawBodyResponseV1 {
    /// Must equal `BONDRY_RAW_BODY_HANDLER_ABI_VERSION_V1`.
    pub abi_version: u32,
    /// Byte size of this response record.
    pub struct_size: usize,
    /// HTTP status code.
    pub status_code: u16,
    /// Retry delay when `has_retry_after` is one.
    pub retry_after_seconds: u64,
    /// Zero or one.
    pub has_retry_after: u8,
}

/// Retains one handler context and returns the retained ownership unit.
pub type BondryRawBodyContextRetainV1 = unsafe extern "C" fn(context: *mut c_void) -> *mut c_void;
/// Releases one retained handler context.
pub type BondryRawBodyContextReleaseV1 = unsafe extern "C" fn(context: *mut c_void);
/// Completes one accepted raw-body request exactly once.
pub type BondryRawBodyCompletionV1 =
    unsafe extern "C" fn(completion_context: *mut c_void, response: *const BondryRawBodyResponseV1);
/// Handles one callback-scoped request and owns its asynchronous completion unit.
pub type BondryRawBodyHandleV1 = unsafe extern "C" fn(
    handler_context: *mut c_void,
    request: *const BondryRawBodyRequestV1,
    completion: BondryRawBodyCompletionV1,
    completion_context: *mut c_void,
);

/// One immutable raw-body handler generation descriptor.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryRawBodyHandlerDescriptorV1 {
    /// Must equal `BONDRY_RAW_BODY_HANDLER_ABI_VERSION_V1`.
    pub abi_version: u32,
    /// Byte size of this descriptor.
    pub struct_size: usize,
    /// Must equal `BONDRY_RAW_BODY_METHOD_POST_V1`.
    pub method: u32,
    /// Borrowed exact absolute path.
    pub path: BondryRawBodyByteSliceV1,
    /// Borrowed selected header names.
    pub selected_headers: *const BondryRawBodyByteSliceV1,
    /// Selected header-name count.
    pub selected_header_count: usize,
    /// Maximum raw body bytes.
    pub max_body_bytes: usize,
    /// Maximum retained bytes for the complete request lifecycle.
    pub max_retained_bytes: usize,
    /// Maximum bytes in one selected header value.
    pub max_selected_header_bytes: usize,
    /// Maximum aggregate selected-header bytes.
    pub max_selected_headers_bytes: usize,
    /// Pre-authentication requests per peer and minute.
    pub pre_authentication_requests_per_peer_minute: u32,
    /// Pre-authentication requests per route and minute.
    pub pre_authentication_requests_per_route_minute: u32,
    /// Caller-owned context retained during registration.
    pub context: *mut c_void,
    /// Required context retain callback.
    pub retain: Option<BondryRawBodyContextRetainV1>,
    /// Required context release callback.
    pub release: Option<BondryRawBodyContextReleaseV1>,
    /// Required handler callback.
    pub handle: Option<BondryRawBodyHandleV1>,
}

/// An opaque raw-body handler generation owned by the caller.
#[repr(C)]
pub struct BondryRawBodyRegistrationHandle {
    _private: [u8; 0],
}

struct RegistrationHandle {
    registration: RawBodyRegistration,
}

struct ForeignRawBodyHandler {
    context: *mut c_void,
    release: BondryRawBodyContextReleaseV1,
    handle: BondryRawBodyHandleV1,
}

// SAFETY: Registration requires the context and callbacks to support arbitrary threads.
unsafe impl Send for ForeignRawBodyHandler {}
// SAFETY: The host contract requires concurrent callbacks and release to be thread-safe.
unsafe impl Sync for ForeignRawBodyHandler {}

impl ForeignRawBodyHandler {
    unsafe fn retain(descriptor: &BondryRawBodyHandlerDescriptorV1) -> Result<Self, i32> {
        if descriptor.context.is_null() {
            return Err(BONDRY_STATUS_NULL_POINTER);
        }
        let (Some(retain), Some(release), Some(handle)) =
            (descriptor.retain, descriptor.release, descriptor.handle)
        else {
            return Err(BONDRY_STATUS_INVALID_ARGUMENT);
        };
        // SAFETY: The caller keeps the original context live for this synchronous retain.
        let context = unsafe { retain(descriptor.context) };
        if context.is_null() {
            return Err(BONDRY_STATUS_INVALID_ARGUMENT);
        }
        Ok(Self {
            context,
            release,
            handle,
        })
    }
}

impl Drop for ForeignRawBodyHandler {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns exactly one retained foreign context.
        unsafe { (self.release)(self.context) };
    }
}

impl RawBodyHandler for ForeignRawBodyHandler {
    fn handle(&self, request: RawBodyRequest<'_>, completion: RawBodyCompletion) {
        let headers = request
            .headers()
            .iter()
            .map(|header| BondryRawBodyHeaderV1 {
                name: header.name().as_str().as_ptr(),
                name_length: header.name().as_str().len(),
                value: header.value().as_ptr(),
                value_length: header.value().len(),
            })
            .collect::<Vec<_>>();
        let peer = peer_record(request.peer());
        let record = BondryRawBodyRequestV1 {
            abi_version: BONDRY_RAW_BODY_HANDLER_ABI_VERSION_V1,
            struct_size: size_of::<BondryRawBodyRequestV1>(),
            target: request.target().as_ptr(),
            target_length: request.target().len(),
            headers: headers.as_ptr(),
            header_count: headers.len(),
            body: request.body().as_ptr(),
            body_length: request.body().len(),
            peer_ip_family: peer.family,
            peer_ip: peer.ip,
            peer_port: peer.port,
            peer_interface_scope: peer.interface_scope,
            has_peer_interface_scope: peer.has_interface_scope,
        };
        let completion = Box::into_raw(Box::new(completion)).cast::<c_void>();
        // SAFETY: Every request field remains borrowed for this callback. The callback takes one
        // completion ownership unit and must invoke it exactly once, possibly asynchronously.
        unsafe {
            (self.handle)(self.context, &record, complete_raw_body, completion);
        }
    }
}

struct PeerRecord {
    family: u32,
    ip: [u8; 16],
    port: u16,
    interface_scope: u32,
    has_interface_scope: u8,
}

fn peer_record(peer: SocketAddr) -> PeerRecord {
    let mut ip = [0; 16];
    match peer {
        SocketAddr::V4(peer) => {
            ip[..4].copy_from_slice(&peer.ip().octets());
            PeerRecord {
                family: BONDRY_RAW_BODY_IP_ADDRESS_V4_V1,
                ip,
                port: peer.port(),
                interface_scope: 0,
                has_interface_scope: 0,
            }
        }
        SocketAddr::V6(peer) => {
            ip.copy_from_slice(&peer.ip().octets());
            PeerRecord {
                family: BONDRY_RAW_BODY_IP_ADDRESS_V6_V1,
                ip,
                port: peer.port(),
                interface_scope: peer.scope_id(),
                has_interface_scope: u8::from(peer.scope_id() != 0),
            }
        }
    }
}

unsafe extern "C" fn complete_raw_body(
    context: *mut c_void,
    response: *const BondryRawBodyResponseV1,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: An accepted handler callback transfers exactly one completion allocation.
    let completion = unsafe { Box::from_raw(context.cast::<RawBodyCompletion>()) };
    let response = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: Completion records remain borrowed and readable for this callback.
        unsafe { decode_response(response) }
    }))
    .ok()
    .and_then(Result::ok)
    .unwrap_or_else(RawBodyResponse::internal_server_error);
    completion.complete(response);
}

unsafe fn decode_response(response: *const BondryRawBodyResponseV1) -> Result<RawBodyResponse, ()> {
    // SAFETY: The caller guarantees a non-null response is readable for this callback.
    let response = unsafe { response.as_ref() }.ok_or(())?;
    if response.abi_version != BONDRY_RAW_BODY_HANDLER_ABI_VERSION_V1
        || response.struct_size != size_of::<BondryRawBodyResponseV1>()
    {
        return Err(());
    }
    let retry_after = match response.has_retry_after {
        0 => None,
        1 => Some(response.retry_after_seconds),
        _ => return Err(()),
    };
    let status = StatusCode::from_u16(response.status_code).map_err(|_| ())?;
    RawBodyResponse::new(status, retry_after).map_err(|_| ())
}

/// Registers one exact raw-body handler generation on a running local server.
///
/// # Safety
///
/// `server` and `descriptor` must be live and readable. Descriptor buffers remain borrowed only
/// for this call. `out_registration` must be writable. Registration must be serialized with server
/// stop.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_server_raw_body_handler_register_v1(
    server: *const BondryServerHandle,
    descriptor: *const BondryRawBodyHandlerDescriptorV1,
    out_registration: *mut *mut BondryRawBodyRegistrationHandle,
) -> i32 {
    if out_registration.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: The validated output pointer is writable by contract.
    unsafe { out_registration.write(ptr::null_mut()) };
    catch_status(|| {
        if server.is_null() || descriptor.is_null() {
            return BONDRY_STATUS_NULL_POINTER;
        }
        // SAFETY: The caller keeps both records live for this call.
        let server = unsafe { &*server.cast::<ServerHandle>() };
        // SAFETY: The caller keeps the descriptor readable for this call.
        let descriptor = unsafe { &*descriptor };
        let route = match unsafe { decode_route(descriptor) } {
            Ok(route) => route,
            Err(status) => return status,
        };
        // SAFETY: Descriptor callbacks and context satisfy the registration contract.
        let handler = match unsafe { ForeignRawBodyHandler::retain(descriptor) } {
            Ok(handler) => handler,
            Err(status) => return status,
        };
        let registration = match server
            .server
            .register_raw_body_handler(route, Arc::new(handler))
        {
            Ok(registration) => registration,
            Err(error) => return registration_status(error),
        };
        let handle = Box::new(RegistrationHandle { registration });
        // SAFETY: The output receives exactly one registration ownership unit.
        unsafe {
            out_registration.write(Box::into_raw(handle).cast::<BondryRawBodyRegistrationHandle>())
        };
        BONDRY_STATUS_OK
    })
}

/// Atomically closes admission and waits for bounded generation detachment.
///
/// # Safety
///
/// `registration` must be one live registration handle and remain live for this call. This function
/// must not be called from that registration's handler callback.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_server_raw_body_handler_disable_v1(
    registration: *const BondryRawBodyRegistrationHandle,
    deadline_milliseconds: u64,
) -> i32 {
    if registration.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    catch_status(|| {
        // SAFETY: The caller keeps the registration live for this call.
        let registration = unsafe { &*registration.cast::<RegistrationHandle>() };
        match registration
            .registration
            .disable(Duration::from_millis(deadline_milliseconds))
        {
            Ok(()) => BONDRY_STATUS_OK,
            Err(RawBodyRegistrationError::DrainTimedOut) => BONDRY_STATUS_RAW_BODY_DRAIN_TIMED_OUT,
            Err(RawBodyRegistrationError::InvalidDrainDeadline) => BONDRY_STATUS_INVALID_ARGUMENT,
            Err(_) => BONDRY_STATUS_INTERNAL_FAILURE,
        }
    })
}

/// Reads one raw-body handler generation lifecycle.
///
/// # Safety
///
/// `registration` must be live and `out_lifecycle` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_server_raw_body_handler_lifecycle_v1(
    registration: *const BondryRawBodyRegistrationHandle,
    out_lifecycle: *mut u32,
) -> i32 {
    if registration.is_null() || out_lifecycle.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    catch_status(|| {
        // SAFETY: The caller keeps the registration live for this call.
        let registration = unsafe { &*registration.cast::<RegistrationHandle>() };
        let lifecycle = match registration.registration.lifecycle() {
            RawBodyLifecycle::Enabled => BONDRY_RAW_BODY_LIFECYCLE_ENABLED_V1,
            RawBodyLifecycle::Draining => BONDRY_RAW_BODY_LIFECYCLE_DRAINING_V1,
            RawBodyLifecycle::Detached => BONDRY_RAW_BODY_LIFECYCLE_DETACHED_V1,
        };
        // SAFETY: The validated output pointer is writable by contract.
        unsafe { out_lifecycle.write(lifecycle) };
        BONDRY_STATUS_OK
    })
}

/// Consumes a registration handle and begins draining if it is still enabled.
///
/// # Safety
///
/// A non-null value must be one live registration handle and must not be used again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_server_raw_body_handler_release_v1(
    registration: *mut BondryRawBodyRegistrationHandle,
) {
    if registration.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The caller transfers exactly one live registration ownership unit.
        unsafe { drop(Box::from_raw(registration.cast::<RegistrationHandle>())) };
    }));
}

unsafe fn decode_route(descriptor: &BondryRawBodyHandlerDescriptorV1) -> Result<RawBodyRoute, i32> {
    if descriptor.abi_version != BONDRY_RAW_BODY_HANDLER_ABI_VERSION_V1
        || descriptor.struct_size != size_of::<BondryRawBodyHandlerDescriptorV1>()
        || descriptor.method != BONDRY_RAW_BODY_METHOD_POST_V1
        || descriptor.selected_header_count > MAX_SELECTED_HEADERS
    {
        return Err(BONDRY_STATUS_INVALID_ARGUMENT);
    }
    // SAFETY: The descriptor path is borrowed for this registration call.
    let path = unsafe { borrowed_bytes(descriptor.path.bytes, descriptor.path.length) }?;
    let path = std::str::from_utf8(path).map_err(|_| BONDRY_STATUS_INVALID_UTF8)?;
    // SAFETY: The descriptor header array is borrowed for this registration call.
    let selected = unsafe {
        borrowed_slice(
            descriptor.selected_headers,
            descriptor.selected_header_count,
        )
    }?;
    let mut headers = Vec::with_capacity(selected.len());
    for selected in selected {
        // SAFETY: Each selected header is borrowed for this registration call.
        let bytes = unsafe { borrowed_bytes(selected.bytes, selected.length) }?;
        headers.push(HeaderName::from_bytes(bytes).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?);
    }
    let limits = RawBodyHandlerLimits::new(
        descriptor.max_body_bytes,
        descriptor.max_retained_bytes,
        descriptor.max_selected_header_bytes,
        descriptor.max_selected_headers_bytes,
        descriptor.pre_authentication_requests_per_peer_minute,
        descriptor.pre_authentication_requests_per_route_minute,
    )
    .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
    RawBodyRoute::post(path, headers, limits).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)
}

unsafe fn borrowed_bytes<'a>(pointer: *const u8, length: usize) -> Result<&'a [u8], i32> {
    if length == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(BONDRY_STATUS_NULL_POINTER);
    }
    if length > isize::MAX as usize {
        return Err(BONDRY_STATUS_INVALID_LENGTH);
    }
    // SAFETY: The caller guarantees the bounded buffer is readable for the enclosing call.
    Ok(unsafe { slice::from_raw_parts(pointer, length) })
}

unsafe fn borrowed_slice<'a, T>(pointer: *const T, length: usize) -> Result<&'a [T], i32> {
    if length == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(BONDRY_STATUS_NULL_POINTER);
    }
    if length > isize::MAX as usize / size_of::<T>() {
        return Err(BONDRY_STATUS_INVALID_LENGTH);
    }
    // SAFETY: The caller guarantees the bounded array is readable for the enclosing call.
    Ok(unsafe { slice::from_raw_parts(pointer, length) })
}

fn registration_status(error: RawBodyRegistrationError) -> i32 {
    match error {
        RawBodyRegistrationError::AlreadyRegistered
        | RawBodyRegistrationError::ProtocolConflict => BONDRY_STATUS_ALREADY_EXISTS,
        RawBodyRegistrationError::CapacityExhausted => BONDRY_STATUS_CAPACITY_EXHAUSTED,
        RawBodyRegistrationError::ServerStopping => BONDRY_STATUS_INVALID_TRANSITION,
        RawBodyRegistrationError::BodyLimitExceedsAggregate
        | RawBodyRegistrationError::InvalidDrainDeadline => BONDRY_STATUS_INVALID_ARGUMENT,
        RawBodyRegistrationError::DrainTimedOut => BONDRY_STATUS_RAW_BODY_DRAIN_TIMED_OUT,
    }
}
