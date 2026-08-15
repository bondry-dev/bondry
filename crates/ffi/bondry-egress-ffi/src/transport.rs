use std::{
    ffi::c_void,
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    slice,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Instant,
};

use bondry_transport::{
    ConnectionEvidence, HttpRequest, HttpResponse, HttpTransport, IpAddress, MAX_HTTP_HEADER_BYTES,
    MAX_HTTP_HEADERS, MAX_NETWORK_ENDPOINT_BYTES, PeerAddress, PolicyError, TlsConnectionEvidence,
    TransportError, TransportFuture,
};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

/// ABI version of the host HTTP transport descriptor.
pub const BONDRY_HTTP_TRANSPORT_ABI_VERSION_V1: u32 = 1;
/// The host completed an HTTP response.
pub const BONDRY_HTTP_RESULT_RESPONSE_V1: u32 = 1;
/// The host completed with a transport error.
pub const BONDRY_HTTP_RESULT_ERROR_V1: u32 = 2;
/// No usable connection evidence was supplied.
pub const BONDRY_CONNECTION_EVIDENCE_MISSING_V1: u32 = 0;
/// A TLS handshake verified a server name.
pub const BONDRY_CONNECTION_EVIDENCE_TLS_V1: u32 = 1;
/// A cleartext connection reports its actual peer.
pub const BONDRY_CONNECTION_EVIDENCE_CLEARTEXT_V1: u32 = 2;
/// An IPv4 peer address.
pub const BONDRY_IP_ADDRESS_V4_V1: u32 = 1;
/// An IPv6 peer address.
pub const BONDRY_IP_ADDRESS_V6_V1: u32 = 2;
/// Invalid transport limits.
pub const BONDRY_TRANSPORT_ERROR_INVALID_LIMITS_V1: u32 = 1;
/// Unsupported endpoint protocol.
pub const BONDRY_TRANSPORT_ERROR_UNSUPPORTED_ENDPOINT_V1: u32 = 2;
/// Request exceeded a bound.
pub const BONDRY_TRANSPORT_ERROR_REQUEST_TOO_LARGE_V1: u32 = 3;
/// Response exceeded a bound.
pub const BONDRY_TRANSPORT_ERROR_RESPONSE_TOO_LARGE_V1: u32 = 4;
/// Connection evidence was absent.
pub const BONDRY_TRANSPORT_ERROR_MISSING_EVIDENCE_V1: u32 = 5;
/// Connection evidence did not match the endpoint.
pub const BONDRY_TRANSPORT_ERROR_EVIDENCE_MISMATCH_V1: u32 = 6;
/// The authenticated TLS name did not match the endpoint.
pub const BONDRY_TRANSPORT_ERROR_TLS_IDENTITY_MISMATCH_V1: u32 = 7;
/// Cleartext loopback lacked explicit endpoint intent.
pub const BONDRY_TRANSPORT_ERROR_LOOPBACK_INTENT_REQUIRED_V1: u32 = 8;
/// Private-network cleartext was not enabled.
pub const BONDRY_TRANSPORT_ERROR_PRIVATE_CLEARTEXT_DENIED_V1: u32 = 9;
/// Link-local cleartext was not enabled.
pub const BONDRY_TRANSPORT_ERROR_LINK_LOCAL_CLEARTEXT_DENIED_V1: u32 = 10;
/// A link-local peer omitted its interface scope.
pub const BONDRY_TRANSPORT_ERROR_LINK_LOCAL_SCOPE_REQUIRED_V1: u32 = 11;
/// The cleartext peer is never eligible.
pub const BONDRY_TRANSPORT_ERROR_CLEARTEXT_DENIED_V1: u32 = 12;
/// Redirects are forbidden.
pub const BONDRY_TRANSPORT_ERROR_REDIRECT_DENIED_V1: u32 = 13;
/// The absolute deadline elapsed.
pub const BONDRY_TRANSPORT_ERROR_DEADLINE_EXCEEDED_V1: u32 = 14;
/// Name resolution or connection establishment failed.
pub const BONDRY_TRANSPORT_ERROR_CONNECTION_FAILED_V1: u32 = 15;
/// TLS setup or validation failed.
pub const BONDRY_TRANSPORT_ERROR_TLS_FAILED_V1: u32 = 16;
/// The peer produced an invalid HTTP response.
pub const BONDRY_TRANSPORT_ERROR_INVALID_RESPONSE_V1: u32 = 17;
/// The request or callback message was malformed.
pub const BONDRY_TRANSPORT_ERROR_INVALID_MESSAGE_V1: u32 = 18;

const STATUS_OK: i32 = 0;

/// One borrowed byte string in an HTTP callback.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryByteSliceV1 {
    /// Borrowed bytes.
    pub bytes: *const u8,
    /// Number of readable bytes.
    pub length: usize,
}

/// One borrowed HTTP header.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryHTTPHeaderV1 {
    /// Borrowed header-name bytes.
    pub name: *const u8,
    /// Header-name byte length.
    pub name_length: usize,
    /// Borrowed header-value bytes.
    pub value: *const u8,
    /// Header-value byte length.
    pub value_length: usize,
}

/// Route-owned endpoint policy sent with every host transport request.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryEndpointPolicyV1 {
    /// One permits a hostname to reach a verified loopback peer over cleartext.
    pub allow_hostname_loopback_cleartext: u8,
    /// One permits verified RFC 1918 or ULA peers over cleartext.
    pub allow_private_cleartext: u8,
    /// One permits verified scoped link-local peers over cleartext.
    pub allow_link_local_cleartext: u8,
    /// Borrowed DER roots added without disabling ordinary TLS verification.
    pub additional_trust_anchors: *const BondryByteSliceV1,
    /// Number of borrowed roots.
    pub additional_trust_anchor_count: usize,
}

/// One bounded HTTP request borrowed only for the synchronous send callback.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryHTTPRequestV1 {
    /// Borrowed ASCII HTTP method.
    pub method: *const u8,
    /// Method byte length.
    pub method_length: usize,
    /// Borrowed absolute URL, including any ephemeral secret expansion.
    pub url: *const u8,
    /// URL byte length.
    pub url_length: usize,
    /// Borrowed request headers.
    pub headers: *const BondryHTTPHeaderV1,
    /// Header count.
    pub header_count: usize,
    /// Borrowed exact request body.
    pub body: *const u8,
    /// Request body byte length.
    pub body_length: usize,
    /// Remaining absolute deadline rounded up to milliseconds.
    pub timeout_milliseconds: u64,
    /// Maximum accepted response body bytes.
    pub max_response_body_bytes: usize,
    /// Endpoint policy the host must enforce before sending application bytes.
    pub policy: BondryEndpointPolicyV1,
}

/// Connection evidence returned by the host transport.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryConnectionEvidenceV1 {
    /// Missing, TLS, or cleartext evidence kind.
    pub kind: u32,
    /// Borrowed authenticated server name for TLS evidence.
    pub server_name: *const u8,
    /// Authenticated server-name byte length.
    pub server_name_length: usize,
    /// IPv4 or IPv6 family for cleartext evidence.
    pub ip_family: u32,
    /// Network-order peer address; IPv4 uses the first four bytes.
    pub ip: [u8; 16],
    /// Actual connected peer port.
    pub port: u16,
    /// Link-local interface scope when present.
    pub interface_scope: u32,
    /// One when interface scope is present.
    pub has_interface_scope: u8,
}

/// Bounded host HTTP completion borrowed only for the completion callback.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryHTTPResultV1 {
    /// Response or error result kind.
    pub kind: u32,
    /// Stable transport error when kind is error.
    pub error: u32,
    /// HTTP status when kind is response.
    pub status_code: u16,
    /// Borrowed response headers.
    pub headers: *const BondryHTTPHeaderV1,
    /// Response header count.
    pub header_count: usize,
    /// Borrowed exact response body.
    pub body: *const u8,
    /// Response body byte length.
    pub body_length: usize,
    /// Established connection evidence.
    pub connection: BondryConnectionEvidenceV1,
}

/// Retains one host callback context and returns the retained unit.
pub type BondryContextRetainV1 = unsafe extern "C" fn(context: *mut c_void) -> *mut c_void;
/// Releases one retained host callback context.
pub type BondryContextReleaseV1 = unsafe extern "C" fn(context: *mut c_void);
/// Completes one accepted transport operation exactly once.
pub type BondryHTTPCompletionV1 =
    unsafe extern "C" fn(completion_context: *mut c_void, result: *const BondryHTTPResultV1);
/// Starts one host HTTP operation without retaining request pointers.
pub type BondryHTTPSendV1 = unsafe extern "C" fn(
    transport_context: *mut c_void,
    request: *const BondryHTTPRequestV1,
    completion: BondryHTTPCompletionV1,
    completion_context: *mut c_void,
) -> i32;

/// Versioned host HTTP transport callbacks.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryHTTPTransportV1 {
    /// Must equal `BONDRY_HTTP_TRANSPORT_ABI_VERSION_V1`.
    pub abi_version: u32,
    /// Byte size of this descriptor.
    pub struct_size: usize,
    /// Caller-owned context retained during egress startup.
    pub context: *mut c_void,
    /// Required context retain callback.
    pub retain: Option<BondryContextRetainV1>,
    /// Required context release callback.
    pub release: Option<BondryContextReleaseV1>,
    /// Required asynchronous send callback.
    pub send: Option<BondryHTTPSendV1>,
}

pub(crate) struct ForeignHttpTransport {
    context: *mut c_void,
    release: BondryContextReleaseV1,
    send: BondryHTTPSendV1,
}

// SAFETY: Descriptor registration requires callbacks and context to support arbitrary threads.
unsafe impl Send for ForeignHttpTransport {}
// SAFETY: The retained context must be safe for concurrent requests by contract.
unsafe impl Sync for ForeignHttpTransport {}

impl ForeignHttpTransport {
    pub(crate) unsafe fn retain(descriptor: &BondryHTTPTransportV1) -> Result<Self, ()> {
        if descriptor.abi_version != BONDRY_HTTP_TRANSPORT_ABI_VERSION_V1
            || descriptor.struct_size != std::mem::size_of::<BondryHTTPTransportV1>()
            || descriptor.context.is_null()
        {
            return Err(());
        }
        let (Some(retain), Some(release), Some(send)) =
            (descriptor.retain, descriptor.release, descriptor.send)
        else {
            return Err(());
        };
        // SAFETY: The caller keeps the original context live for this synchronous retain.
        let context = unsafe { retain(descriptor.context) };
        if context.is_null() {
            return Err(());
        }
        Ok(Self {
            context,
            release,
            send,
        })
    }
}

impl Drop for ForeignHttpTransport {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns exactly one retained foreign context.
        unsafe { (self.release)(self.context) };
    }
}

impl HttpTransport for ForeignHttpTransport {
    fn send(
        &self,
        request: HttpRequest,
    ) -> TransportFuture<'_, Result<HttpResponse, TransportError>> {
        let parts = request.into_parts();
        let remaining = parts
            .deadline
            .instant()
            .saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Box::pin(std::future::ready(Err(TransportError::DeadlineExceeded)));
        }
        let endpoint = parts.endpoint.uri().to_string();
        let headers = parts
            .headers
            .iter()
            .map(|(name, value)| BondryHTTPHeaderV1 {
                name: name.as_str().as_ptr(),
                name_length: name.as_str().len(),
                value: value.as_bytes().as_ptr(),
                value_length: value.as_bytes().len(),
            })
            .collect::<Vec<_>>();
        let anchors = parts
            .policy
            .additional_trust_anchors()
            .iter()
            .map(|anchor| BondryByteSliceV1 {
                bytes: anchor.as_der().as_ptr(),
                length: anchor.as_der().len(),
            })
            .collect::<Vec<_>>();
        let method = parts.method.as_str();
        let timeout_milliseconds = u64::try_from(remaining.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let ffi_request = BondryHTTPRequestV1 {
            method: method.as_ptr(),
            method_length: method.len(),
            url: endpoint.as_ptr(),
            url_length: endpoint.len(),
            headers: headers.as_ptr(),
            header_count: headers.len(),
            body: parts.body.as_ptr(),
            body_length: parts.body.len(),
            timeout_milliseconds,
            max_response_body_bytes: parts.limits.max_response_body_bytes(),
            policy: BondryEndpointPolicyV1 {
                allow_hostname_loopback_cleartext: u8::from(
                    parts.policy.allows_hostname_loopback_cleartext(),
                ),
                allow_private_cleartext: u8::from(parts.policy.allows_private_cleartext()),
                allow_link_local_cleartext: u8::from(parts.policy.allows_link_local_cleartext()),
                additional_trust_anchors: anchors.as_ptr(),
                additional_trust_anchor_count: anchors.len(),
            },
        };
        let completion = Arc::new(CompletionState::new(parts.limits.max_response_body_bytes()));
        let completion_context = Arc::into_raw(Arc::clone(&completion))
            .cast_mut()
            .cast::<c_void>();
        // SAFETY: All request views remain readable for this call. The callback owns one Arc unit.
        let status = unsafe {
            (self.send)(
                self.context,
                &ffi_request,
                complete_http,
                completion_context,
            )
        };
        if status != STATUS_OK {
            // SAFETY: A rejected send must not invoke the completion and did not consume this unit.
            unsafe { drop(Arc::from_raw(completion_context.cast::<CompletionState>())) };
            return Box::pin(std::future::ready(Err(TransportError::ConnectionFailed)));
        }
        Box::pin(ForeignTransportFuture {
            completion,
            endpoint: parts.endpoint,
            policy: parts.policy,
            limits: parts.limits,
        })
    }
}

struct CompletionState {
    state: Mutex<Completion>,
    max_response_body_bytes: usize,
}

#[derive(Default)]
enum Completion {
    #[default]
    Pending,
    Waiting(Waker),
    Ready(Result<OwnedResult, TransportError>),
    Consumed,
}

impl CompletionState {
    fn new(max_response_body_bytes: usize) -> Self {
        Self {
            state: Mutex::new(Completion::Pending),
            max_response_body_bytes,
        }
    }

    fn complete(&self, result: Result<OwnedResult, TransportError>) {
        let wake = {
            let mut state = lock(&self.state);
            match std::mem::replace(&mut *state, Completion::Ready(result)) {
                Completion::Waiting(waker) => Some(waker),
                Completion::Pending => None,
                previous @ (Completion::Ready(_) | Completion::Consumed) => {
                    *state = previous;
                    None
                }
            }
        };
        if let Some(waker) = wake {
            waker.wake();
        }
    }
}

struct ForeignTransportFuture {
    completion: Arc<CompletionState>,
    endpoint: bondry_transport::NetworkEndpoint,
    policy: bondry_transport::EndpointPolicy,
    limits: bondry_transport::HttpLimits,
}

impl Future for ForeignTransportFuture {
    type Output = Result<HttpResponse, TransportError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut state = lock(&this.completion.state);
        match &mut *state {
            Completion::Pending => {
                *state = Completion::Waiting(context.waker().clone());
                Poll::Pending
            }
            Completion::Waiting(waker) => {
                waker.clone_from(context.waker());
                Poll::Pending
            }
            Completion::Ready(_) => {
                let Completion::Ready(result) =
                    std::mem::replace(&mut *state, Completion::Consumed)
                else {
                    return Poll::Ready(Err(TransportError::InvalidResponse));
                };
                Poll::Ready(result.and_then(|result| {
                    let connection = this
                        .policy
                        .verify_connection(&this.endpoint, result.connection)?;
                    HttpResponse::new(
                        result.status,
                        result.headers,
                        result.body,
                        connection,
                        this.limits,
                    )
                }))
            }
            Completion::Consumed => Poll::Ready(Err(TransportError::InvalidResponse)),
        }
    }
}

struct OwnedResult {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    connection: ConnectionEvidence,
}

unsafe extern "C" fn complete_http(
    completion_context: *mut c_void,
    result: *const BondryHTTPResultV1,
) {
    if completion_context.is_null() {
        return;
    }
    // SAFETY: An accepted send transfers exactly one Arc unit to exactly one callback.
    let completion = unsafe { Arc::from_raw(completion_context.cast::<CompletionState>()) };
    let parsed = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The callback contract keeps result and its borrowed fields readable here.
        unsafe { parse_result(result, completion.max_response_body_bytes) }
    }))
    .unwrap_or(Err(TransportError::InvalidResponse));
    completion.complete(parsed);
}

unsafe fn parse_result(
    result: *const BondryHTTPResultV1,
    max_response_body_bytes: usize,
) -> Result<OwnedResult, TransportError> {
    if result.is_null() {
        return Err(TransportError::InvalidResponse);
    }
    // SAFETY: The caller guarantees a readable result for this callback.
    let result = unsafe { &*result };
    match result.kind {
        BONDRY_HTTP_RESULT_ERROR_V1 => Err(decode_transport_error(result.error)),
        BONDRY_HTTP_RESULT_RESPONSE_V1 if result.error == 0 => {
            let status = StatusCode::from_u16(result.status_code)
                .map_err(|_| TransportError::InvalidResponse)?;
            if result.header_count > MAX_HTTP_HEADERS {
                return Err(TransportError::ResponseTooLarge);
            }
            let raw_headers = unsafe { borrowed_slice(result.headers, result.header_count) }?;
            let mut headers = HeaderMap::with_capacity(raw_headers.len());
            let mut header_bytes = 0_usize;
            for header in raw_headers {
                let name = unsafe { borrowed_bytes(header.name, header.name_length) }?;
                let value = unsafe { borrowed_bytes(header.value, header.value_length) }?;
                header_bytes = header_bytes
                    .saturating_add(name.len())
                    .saturating_add(value.len())
                    .saturating_add(4);
                if header_bytes > MAX_HTTP_HEADER_BYTES {
                    return Err(TransportError::ResponseTooLarge);
                }
                let name =
                    HeaderName::from_bytes(name).map_err(|_| TransportError::InvalidResponse)?;
                let value =
                    HeaderValue::from_bytes(value).map_err(|_| TransportError::InvalidResponse)?;
                headers.append(name, value);
            }
            if result.body_length > max_response_body_bytes {
                return Err(TransportError::ResponseTooLarge);
            }
            let body = unsafe { borrowed_bytes(result.body, result.body_length) }?;
            Ok(OwnedResult {
                status,
                headers,
                body: Bytes::copy_from_slice(body),
                connection: unsafe { decode_connection(&result.connection) }?,
            })
        }
        _ => Err(TransportError::InvalidResponse),
    }
}

unsafe fn decode_connection(
    evidence: &BondryConnectionEvidenceV1,
) -> Result<ConnectionEvidence, TransportError> {
    match evidence.kind {
        BONDRY_CONNECTION_EVIDENCE_MISSING_V1 => Ok(ConnectionEvidence::Missing),
        BONDRY_CONNECTION_EVIDENCE_TLS_V1 => {
            let server_name =
                unsafe { borrowed_bytes(evidence.server_name, evidence.server_name_length) }?;
            if server_name.is_empty() || server_name.len() > MAX_NETWORK_ENDPOINT_BYTES {
                return Err(TransportError::InvalidResponse);
            }
            let server_name =
                std::str::from_utf8(server_name).map_err(|_| TransportError::InvalidResponse)?;
            Ok(ConnectionEvidence::Tls(TlsConnectionEvidence::verified(
                server_name,
            )))
        }
        BONDRY_CONNECTION_EVIDENCE_CLEARTEXT_V1 => {
            let ip = match evidence.ip_family {
                BONDRY_IP_ADDRESS_V4_V1 => IpAddress::V4([
                    evidence.ip[0],
                    evidence.ip[1],
                    evidence.ip[2],
                    evidence.ip[3],
                ]),
                BONDRY_IP_ADDRESS_V6_V1 => IpAddress::V6(evidence.ip),
                _ => return Err(TransportError::InvalidResponse),
            };
            if evidence.port == 0 || evidence.has_interface_scope > 1 {
                return Err(TransportError::InvalidResponse);
            }
            let mut peer = PeerAddress::new(ip, evidence.port);
            if evidence.has_interface_scope == 1 {
                if evidence.interface_scope == 0 {
                    return Err(TransportError::InvalidResponse);
                }
                peer = peer.with_interface_scope(evidence.interface_scope);
            }
            Ok(ConnectionEvidence::Cleartext(peer))
        }
        _ => Err(TransportError::InvalidResponse),
    }
}

fn decode_transport_error(error: u32) -> TransportError {
    match error {
        BONDRY_TRANSPORT_ERROR_INVALID_LIMITS_V1 => TransportError::InvalidLimits,
        BONDRY_TRANSPORT_ERROR_UNSUPPORTED_ENDPOINT_V1 => TransportError::UnsupportedEndpoint,
        BONDRY_TRANSPORT_ERROR_REQUEST_TOO_LARGE_V1 => TransportError::RequestTooLarge,
        BONDRY_TRANSPORT_ERROR_RESPONSE_TOO_LARGE_V1 => TransportError::ResponseTooLarge,
        BONDRY_TRANSPORT_ERROR_MISSING_EVIDENCE_V1 => {
            TransportError::Policy(PolicyError::MissingEvidence)
        }
        BONDRY_TRANSPORT_ERROR_EVIDENCE_MISMATCH_V1 => {
            TransportError::Policy(PolicyError::EvidenceMismatch)
        }
        BONDRY_TRANSPORT_ERROR_TLS_IDENTITY_MISMATCH_V1 => {
            TransportError::Policy(PolicyError::TlsIdentityMismatch)
        }
        BONDRY_TRANSPORT_ERROR_LOOPBACK_INTENT_REQUIRED_V1 => {
            TransportError::Policy(PolicyError::LoopbackIntentRequired)
        }
        BONDRY_TRANSPORT_ERROR_PRIVATE_CLEARTEXT_DENIED_V1 => {
            TransportError::Policy(PolicyError::PrivateCleartextDenied)
        }
        BONDRY_TRANSPORT_ERROR_LINK_LOCAL_CLEARTEXT_DENIED_V1 => {
            TransportError::Policy(PolicyError::LinkLocalCleartextDenied)
        }
        BONDRY_TRANSPORT_ERROR_LINK_LOCAL_SCOPE_REQUIRED_V1 => {
            TransportError::Policy(PolicyError::LinkLocalScopeRequired)
        }
        BONDRY_TRANSPORT_ERROR_CLEARTEXT_DENIED_V1 => {
            TransportError::Policy(PolicyError::CleartextDenied)
        }
        BONDRY_TRANSPORT_ERROR_REDIRECT_DENIED_V1 => {
            TransportError::Policy(PolicyError::RedirectDenied)
        }
        BONDRY_TRANSPORT_ERROR_DEADLINE_EXCEEDED_V1 => TransportError::DeadlineExceeded,
        BONDRY_TRANSPORT_ERROR_CONNECTION_FAILED_V1 => TransportError::ConnectionFailed,
        BONDRY_TRANSPORT_ERROR_TLS_FAILED_V1 => TransportError::TlsFailed,
        BONDRY_TRANSPORT_ERROR_INVALID_MESSAGE_V1 => TransportError::InvalidMessage,
        _ => TransportError::InvalidResponse,
    }
}

unsafe fn borrowed_slice<'a, T>(
    pointer: *const T,
    length: usize,
) -> Result<&'a [T], TransportError> {
    if length == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() || length > isize::MAX as usize / std::mem::size_of::<T>().max(1) {
        return Err(TransportError::InvalidResponse);
    }
    // SAFETY: The callback contract guarantees readable memory for the declared element count.
    Ok(unsafe { slice::from_raw_parts(pointer, length) })
}

unsafe fn borrowed_bytes<'a>(
    pointer: *const u8,
    length: usize,
) -> Result<&'a [u8], TransportError> {
    unsafe { borrowed_slice(pointer, length) }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use bondry_transport::{EndpointPolicy, PolicyError, TransportError};

    use super::{
        BONDRY_CONNECTION_EVIDENCE_TLS_V1, BONDRY_HTTP_RESULT_ERROR_V1,
        BONDRY_HTTP_RESULT_RESPONSE_V1, BONDRY_TRANSPORT_ERROR_DEADLINE_EXCEEDED_V1,
        BondryConnectionEvidenceV1, BondryHTTPResultV1, parse_result,
    };

    fn tls_result(server_name: &[u8]) -> BondryHTTPResultV1 {
        BondryHTTPResultV1 {
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
        }
    }

    #[test]
    fn rejects_oversized_response_before_reading_its_body() {
        let mut result = tls_result(b"example.com");
        result.body_length = 4097;
        assert!(matches!(
            unsafe { parse_result(&result, 4096) },
            Err(TransportError::ResponseTooLarge)
        ));
    }

    #[test]
    fn independently_rejects_mismatched_tls_evidence() -> Result<(), Box<dyn std::error::Error>> {
        let result = unsafe { parse_result(&tls_result(b"other.example"), 4096) }?;
        let endpoint = bondry_transport::NetworkEndpoint::new("https://example.com/hook".parse()?)?;
        assert_eq!(
            EndpointPolicy::default().verify_connection(&endpoint, result.connection),
            Err(PolicyError::TlsIdentityMismatch)
        );
        Ok(())
    }

    #[test]
    fn maps_host_errors_without_reading_response_fields() {
        let result = BondryHTTPResultV1 {
            kind: BONDRY_HTTP_RESULT_ERROR_V1,
            error: BONDRY_TRANSPORT_ERROR_DEADLINE_EXCEEDED_V1,
            status_code: 0,
            headers: ptr::null(),
            header_count: usize::MAX,
            body: ptr::null(),
            body_length: usize::MAX,
            connection: BondryConnectionEvidenceV1 {
                kind: u32::MAX,
                server_name: ptr::null(),
                server_name_length: usize::MAX,
                ip_family: u32::MAX,
                ip: [0; 16],
                port: 0,
                interface_scope: 0,
                has_interface_scope: u8::MAX,
            },
        };
        assert!(matches!(
            unsafe { parse_result(&result, 4096) },
            Err(TransportError::DeadlineExceeded)
        ));
    }
}
