use std::{
    ffi::c_void,
    mem,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use bondry_secrets::SecretProvider;
use bondry_webhook_ingress::{WebhookIngressResponse, WebhookIngressTime, WebhookRoute};
use bondry_webhook_verify::{PeerAddress, VerificationHeader, VerificationRequest};
use http::{HeaderName, Method, StatusCode};

use crate::{
    BONDRY_RAW_BODY_HANDLER_ABI_VERSION_V1, BONDRY_RAW_BODY_IP_ADDRESS_V4_V1,
    BONDRY_RAW_BODY_IP_ADDRESS_V6_V1, BONDRY_RAW_BODY_METHOD_POST_V1,
    BONDRY_STATUS_INTERNAL_FAILURE, BONDRY_STATUS_INVALID_ARGUMENT, BONDRY_STATUS_INVALID_JSON,
    BONDRY_STATUS_INVALID_LENGTH, BONDRY_STATUS_INVALID_UTF8, BONDRY_STATUS_NULL_POINTER,
    BONDRY_STATUS_OK, BONDRY_STATUS_PAYLOAD_TOO_LARGE, BONDRY_STATUS_UNAVAILABLE,
    BONDRY_WEBHOOK_INGRESS_ABI_VERSION_V1, BondryRawBodyByteSliceV1, BondryRawBodyCompletionV1,
    BondryRawBodyHandlerDescriptorV1, BondryRawBodyRequestV1, BondryRawBodyResponseV1,
    BondryWebhookIngressRegistrationDescriptorV1, config::ConfigurationError,
    secrets::ForeignSecretProvider, service::ForeignAutomationService, store::ForeignDedupStore,
};

const MAX_CONFIGURATION_BYTES: usize = 65_536;
const MAX_SELECTED_REQUEST_HEADERS: usize = 64;

struct HandlerContext {
    route: Arc<WebhookRoute>,
    path: Box<[u8]>,
    selected_names: Box<[Box<[u8]>]>,
    selected_slices: Box<[BondryRawBodyByteSliceV1]>,
    raw_limits: crate::config::RawLimits,
    started: Instant,
}

// SAFETY: Every pointer in the selected slices targets immutable owned storage.
unsafe impl Send for HandlerContext {}
// SAFETY: Request handling only reads immutable route metadata and synchronized dependencies.
unsafe impl Sync for HandlerContext {}

impl HandlerContext {
    fn new(route: crate::config::BuiltRoute) -> Self {
        let selected_names = route
            .route
            .selected_headers()
            .iter()
            .map(|name| name.as_str().as_bytes().to_vec().into_boxed_slice())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let selected_slices = selected_names
            .iter()
            .map(|name| BondryRawBodyByteSliceV1 {
                bytes: name.as_ptr(),
                length: name.len(),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            route: Arc::new(route.route),
            path: route.path,
            selected_names,
            selected_slices,
            raw_limits: route.raw_limits,
            started: Instant::now(),
        }
    }

    fn descriptor(&self, context: *mut c_void) -> BondryRawBodyHandlerDescriptorV1 {
        let limits = self.route.limits();
        BondryRawBodyHandlerDescriptorV1 {
            abi_version: BONDRY_RAW_BODY_HANDLER_ABI_VERSION_V1,
            struct_size: mem::size_of::<BondryRawBodyHandlerDescriptorV1>(),
            method: BONDRY_RAW_BODY_METHOD_POST_V1,
            path: BondryRawBodyByteSliceV1 {
                bytes: self.path.as_ptr(),
                length: self.path.len(),
            },
            selected_headers: self.selected_slices.as_ptr(),
            selected_header_count: self.selected_names.len(),
            max_body_bytes: limits.body_bytes(),
            max_retained_bytes: limits.retained_bytes(),
            max_selected_header_bytes: self.raw_limits.selected_header_bytes,
            max_selected_headers_bytes: self.raw_limits.selected_headers_bytes,
            pre_authentication_requests_per_peer_minute: self.raw_limits.peer_rate,
            pre_authentication_requests_per_route_minute: self.raw_limits.route_rate,
            context,
            retain: Some(retain_handler_context),
            release: Some(release_handler_context),
            handle: Some(handle_request),
        }
    }
}

/// Creates one owned raw-body handler descriptor for registration with `BondryLocalServer`.
///
/// The host services are retained synchronously. The returned handler owns one context unit; after
/// raw-body registration succeeds or fails, pass it once to
/// `bondry_webhook_ingress_handler_release_v1`.
///
/// # Safety
///
/// `descriptor` and its configuration must be readable for this call. `out_handler` must be
/// writable and must not overlap the input descriptor.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_webhook_ingress_handler_v1(
    descriptor: *const BondryWebhookIngressRegistrationDescriptorV1,
    out_handler: *mut BondryRawBodyHandlerDescriptorV1,
) -> i32 {
    if out_handler.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: The caller guarantees writable output memory.
    unsafe { out_handler.write(zeroed_handler()) };
    catch_status(|| {
        let Some(descriptor) = (unsafe { descriptor.as_ref() }) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        if descriptor.abi_version != BONDRY_WEBHOOK_INGRESS_ABI_VERSION_V1
            || descriptor.struct_size
                != mem::size_of::<BondryWebhookIngressRegistrationDescriptorV1>()
        {
            return BONDRY_STATUS_INVALID_ARGUMENT;
        }
        let configuration = match unsafe {
            bytes(
                descriptor.configuration_json,
                descriptor.configuration_json_length,
                false,
            )
        } {
            Ok(configuration) if configuration.len() <= MAX_CONFIGURATION_BYTES => configuration,
            Ok(_) => return BONDRY_STATUS_PAYLOAD_TOO_LARGE,
            Err(status) => return status,
        };
        if std::str::from_utf8(configuration).is_err() {
            return BONDRY_STATUS_INVALID_UTF8;
        }
        let service = match unsafe { ForeignAutomationService::retain(&descriptor.automation) } {
            Ok(service) => Arc::new(service),
            Err(()) => return BONDRY_STATUS_INVALID_ARGUMENT,
        };
        let store = match unsafe { ForeignDedupStore::retain(&descriptor.dedup) } {
            Ok(store) => Arc::new(store),
            Err(()) => return BONDRY_STATUS_INVALID_ARGUMENT,
        };
        let secrets = match unsafe { ForeignSecretProvider::retain(&descriptor.secrets) } {
            Ok(secrets) => Arc::new(secrets) as Arc<dyn SecretProvider>,
            Err(()) => return BONDRY_STATUS_INVALID_ARGUMENT,
        };
        let route = match crate::config::build_route(configuration, service, store, secrets) {
            Ok(route) => route,
            Err(ConfigurationError::InvalidJson) => return BONDRY_STATUS_INVALID_JSON,
            Err(ConfigurationError::Invalid) => return BONDRY_STATUS_INVALID_ARGUMENT,
            Err(ConfigurationError::PolicyUnavailable) => return BONDRY_STATUS_UNAVAILABLE,
        };
        let context = Arc::new(HandlerContext::new(route));
        let pointer = Arc::into_raw(context).cast_mut().cast::<c_void>();
        // SAFETY: The raw Arc pointer keeps all descriptor buffers live until explicit release.
        let output = unsafe { &*pointer.cast::<HandlerContext>() }.descriptor(pointer);
        // SAFETY: Output was validated and receives one owned descriptor context unit.
        unsafe { out_handler.write(output) };
        BONDRY_STATUS_OK
    })
}

/// Releases the creator-owned handler context after the local server has synchronously retained it.
///
/// # Safety
///
/// `handler` must be either null or an unreleased descriptor returned by
/// `bondry_webhook_ingress_handler_v1`. It must not be used after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_webhook_ingress_handler_release_v1(
    handler: *mut BondryRawBodyHandlerDescriptorV1,
) {
    let Some(handler) = (unsafe { handler.as_mut() }) else {
        return;
    };
    let context = handler.context;
    *handler = zeroed_handler();
    if !context.is_null() {
        // SAFETY: The generated descriptor owns exactly one Arc unit.
        drop(unsafe { Arc::from_raw(context.cast::<HandlerContext>().cast_const()) });
    }
}

unsafe extern "C" fn retain_handler_context(context: *mut c_void) -> *mut c_void {
    if context.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: Generated descriptors contain a live Arc-backed context.
    unsafe { Arc::increment_strong_count(context.cast::<HandlerContext>()) };
    context
}

unsafe extern "C" fn release_handler_context(context: *mut c_void) {
    if !context.is_null() {
        // SAFETY: Every retained context unit is released exactly once.
        drop(unsafe { Arc::from_raw(context.cast::<HandlerContext>().cast_const()) });
    }
}

unsafe extern "C" fn handle_request(
    context: *mut c_void,
    request: *const BondryRawBodyRequestV1,
    completion: BondryRawBodyCompletionV1,
    completion_context: *mut c_void,
) {
    let completion = Completion::new(completion, completion_context);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let context = unsafe { context.cast::<HandlerContext>().as_ref() }.ok_or(())?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| ())?;
        let parsed = unsafe { parse_request(context, request) }?;
        let now = request_time(context).map_err(|_| ())?;
        Ok::<_, ()>((runtime, context.route.begin(parsed.request(), now)))
    }));
    match outcome {
        Ok(Ok((_runtime, Err(response)))) => completion.respond(response),
        Ok(Ok((runtime, Ok(dispatch)))) => {
            runtime.spawn(async move {
                completion.respond(dispatch.complete().await);
            });
        }
        Ok(Err(())) | Err(_) => completion.respond_internal(),
    }
}

struct ParsedRequest<'a> {
    target: &'a str,
    headers: Vec<VerificationHeader<'a>>,
    body: &'a [u8],
    peer: PeerAddress,
}

impl ParsedRequest<'_> {
    fn request(&self) -> VerificationRequest<'_> {
        VerificationRequest::new(
            &Method::POST,
            self.target,
            &self.headers,
            self.body,
            self.peer,
        )
    }
}

unsafe fn parse_request<'a>(
    context: &HandlerContext,
    request: *const BondryRawBodyRequestV1,
) -> Result<ParsedRequest<'a>, ()> {
    let request = unsafe { request.as_ref() }.ok_or(())?;
    if request.abi_version != BONDRY_RAW_BODY_HANDLER_ABI_VERSION_V1
        || request.struct_size != mem::size_of::<BondryRawBodyRequestV1>()
        || request.header_count > MAX_SELECTED_REQUEST_HEADERS
        || request.body_length > context.route.limits().body_bytes()
    {
        return Err(());
    }
    let target = std::str::from_utf8(
        unsafe { bytes(request.target, request.target_length, false) }.map_err(|_| ())?,
    )
    .map_err(|_| ())?;
    let body = unsafe { bytes(request.body, request.body_length, true) }.map_err(|_| ())?;
    let raw_headers = unsafe { records(request.headers, request.header_count) }?;
    let mut aggregate = 0_usize;
    let mut headers = Vec::with_capacity(raw_headers.len());
    for header in raw_headers {
        let name = unsafe { bytes(header.name, header.name_length, false) }.map_err(|_| ())?;
        let name = HeaderName::from_bytes(name).map_err(|_| ())?;
        if !context.route.selected_headers().contains(&name) {
            return Err(());
        }
        let value = unsafe { bytes(header.value, header.value_length, true) }.map_err(|_| ())?;
        if value.len() > context.raw_limits.selected_header_bytes {
            return Err(());
        }
        aggregate = aggregate
            .checked_add(name.as_str().len())
            .and_then(|aggregate| aggregate.checked_add(value.len()))
            .ok_or(())?;
        if aggregate > context.raw_limits.selected_headers_bytes {
            return Err(());
        }
        headers.push(VerificationHeader::new(name, value));
    }
    Ok(ParsedRequest {
        target,
        headers,
        body,
        peer: peer(request)?,
    })
}

fn peer(request: &BondryRawBodyRequestV1) -> Result<PeerAddress, ()> {
    match (request.peer_ip_family, request.has_peer_interface_scope) {
        (BONDRY_RAW_BODY_IP_ADDRESS_V4_V1, 0) => {
            let mut address = [0; 4];
            address.copy_from_slice(&request.peer_ip[..4]);
            Ok(PeerAddress::v4(address, request.peer_port))
        }
        (BONDRY_RAW_BODY_IP_ADDRESS_V6_V1, 0) => {
            Ok(PeerAddress::v6(request.peer_ip, request.peer_port, None))
        }
        (BONDRY_RAW_BODY_IP_ADDRESS_V6_V1, 1) => Ok(PeerAddress::v6(
            request.peer_ip,
            request.peer_port,
            Some(request.peer_interface_scope),
        )),
        _ => Err(()),
    }
}

fn request_time(context: &HandlerContext) -> Result<WebhookIngressTime, ()> {
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?;
    let unix = u64::try_from(unix.as_millis()).map_err(|_| ())?;
    let monotonic = u64::try_from(context.started.elapsed().as_millis()).map_err(|_| ())?;
    Ok(WebhookIngressTime::new(unix, monotonic))
}

struct Completion {
    callback: BondryRawBodyCompletionV1,
    context: *mut c_void,
    pending: bool,
}

// SAFETY: The raw-body completion contract permits completion from arbitrary threads.
unsafe impl Send for Completion {}

impl Completion {
    const fn new(callback: BondryRawBodyCompletionV1, context: *mut c_void) -> Self {
        Self {
            callback,
            context,
            pending: true,
        }
    }

    fn respond(mut self, response: WebhookIngressResponse) {
        self.pending = false;
        self.call(
            response.status(),
            response.error_code(),
            response.retry_after_seconds(),
        );
    }

    fn respond_internal(mut self) {
        self.pending = false;
        self.call(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("internal_error"),
            None,
        );
    }

    fn call(&self, status: StatusCode, error: Option<&'static str>, retry_after: Option<u64>) {
        let (error_code, error_code_length) = error
            .map(|error| (error.as_ptr(), error.len()))
            .unwrap_or((ptr::null(), 0));
        let response = BondryRawBodyResponseV1 {
            abi_version: BONDRY_RAW_BODY_HANDLER_ABI_VERSION_V1,
            struct_size: mem::size_of::<BondryRawBodyResponseV1>(),
            status_code: status.as_u16(),
            error_code,
            error_code_length,
            retry_after_seconds: retry_after.unwrap_or(0),
            has_retry_after: u8::from(retry_after.is_some()),
        };
        // SAFETY: Response fields remain borrowed for this callback.
        unsafe { (self.callback)(self.context, &response) };
    }
}

impl Drop for Completion {
    fn drop(&mut self) {
        if self.pending {
            self.pending = false;
            self.call(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some("internal_error"),
                None,
            );
        }
    }
}

unsafe fn bytes<'a>(pointer: *const u8, length: usize, allow_empty: bool) -> Result<&'a [u8], i32> {
    if length == 0 {
        return if allow_empty {
            Ok(&[])
        } else {
            Err(BONDRY_STATUS_INVALID_LENGTH)
        };
    }
    if pointer.is_null() {
        return Err(BONDRY_STATUS_NULL_POINTER);
    }
    if length > isize::MAX as usize {
        return Err(BONDRY_STATUS_INVALID_LENGTH);
    }
    // SAFETY: The caller guarantees readable memory for the declared length.
    Ok(unsafe { slice::from_raw_parts(pointer, length) })
}

unsafe fn records<'a, T>(pointer: *const T, count: usize) -> Result<&'a [T], ()> {
    if count == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() || count > isize::MAX as usize / mem::size_of::<T>() {
        return Err(());
    }
    // SAFETY: The caller guarantees readable records for the declared count.
    Ok(unsafe { slice::from_raw_parts(pointer, count) })
}

fn catch_status(operation: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(BONDRY_STATUS_INTERNAL_FAILURE)
}

const fn zeroed_handler() -> BondryRawBodyHandlerDescriptorV1 {
    BondryRawBodyHandlerDescriptorV1 {
        abi_version: 0,
        struct_size: 0,
        method: 0,
        path: BondryRawBodyByteSliceV1 {
            bytes: ptr::null(),
            length: 0,
        },
        selected_headers: ptr::null(),
        selected_header_count: 0,
        max_body_bytes: 0,
        max_retained_bytes: 0,
        max_selected_header_bytes: 0,
        max_selected_headers_bytes: 0,
        pre_authentication_requests_per_peer_minute: 0,
        pre_authentication_requests_per_route_minute: 0,
        context: ptr::null_mut(),
        retain: None,
        release: None,
        handle: None,
    }
}
