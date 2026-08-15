use std::ffi::c_void;

/// Successful completion.
pub const BONDRY_STATUS_OK: i32 = 0;
/// A required pointer was null.
pub const BONDRY_STATUS_NULL_POINTER: i32 = 1;
/// A byte slice had an invalid length.
pub const BONDRY_STATUS_INVALID_LENGTH: i32 = 2;
/// A string was not valid UTF-8.
pub const BONDRY_STATUS_INVALID_UTF8: i32 = 3;
/// A typed value was malformed or outside its range.
pub const BONDRY_STATUS_INVALID_ARGUMENT: i32 = 5;
/// A caller-owned output was too small.
pub const BONDRY_STATUS_BUFFER_TOO_SMALL: i32 = 6;
/// Configuration or payload JSON was malformed.
pub const BONDRY_STATUS_INVALID_JSON: i32 = 7;
/// A bounded payload exceeded its limit.
pub const BONDRY_STATUS_PAYLOAD_TOO_LARGE: i32 = 8;
/// Persisted or callback data violated its contract.
pub const BONDRY_STATUS_INVALID_DATA: i32 = 14;
/// A required policy, secret, or backing service was unavailable.
pub const BONDRY_STATUS_UNAVAILABLE: i32 = 15;
/// A requested replay record was not found.
pub const BONDRY_STATUS_NOT_FOUND: i32 = 20;
/// Replay-protection capacity was exhausted.
pub const BONDRY_STATUS_CAPACITY_EXHAUSTED: i32 = 32;
/// A replay-state transition was invalid.
pub const BONDRY_STATUS_INVALID_TRANSITION: i32 = 33;
/// Bondry stopped an internal failure at the ABI boundary.
pub const BONDRY_STATUS_INTERNAL_FAILURE: i32 = 255;

/// Protocol-neutral service descriptor ABI version.
pub const BONDRY_AUTOMATION_SERVICE_ABI_VERSION_V1: u32 = 1;
/// Concurrent service callback model.
pub const BONDRY_SERVICE_THREADING_CONCURRENT_V1: u32 = 1;
/// Replay-store descriptor ABI version.
pub const BONDRY_DEDUP_STORE_ABI_VERSION_V1: u32 = 1;
/// Serialized replay-store callback model.
pub const BONDRY_DEDUP_THREADING_SERIALIZED_V1: u32 = 1;
/// Persistent store durability.
pub const BONDRY_STORE_DURABILITY_PERSISTENT_V1: u32 = 2;
/// Secret-provider descriptor ABI version.
pub const BONDRY_WEBHOOK_SECRET_PROVIDER_ABI_VERSION_V1: u32 = 1;
/// Raw-body handler descriptor ABI version.
pub const BONDRY_RAW_BODY_HANDLER_ABI_VERSION_V1: u32 = 1;
/// POST raw-body route method.
pub const BONDRY_RAW_BODY_METHOD_POST_V1: u32 = 1;
/// IPv4 peer record.
pub const BONDRY_RAW_BODY_IP_ADDRESS_V4_V1: u32 = 1;
/// IPv6 peer record.
pub const BONDRY_RAW_BODY_IP_ADDRESS_V6_V1: u32 = 2;

pub(crate) const BONDRY_PRINCIPAL_KIND_USER_V1: u32 = 1;
pub(crate) const BONDRY_PRINCIPAL_KIND_APPLICATION_V1: u32 = 2;
pub(crate) const BONDRY_PRINCIPAL_KIND_SYSTEM_V1: u32 = 3;
pub(crate) const BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1: u32 = 1;
pub(crate) const BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1: u32 = 2;
pub(crate) const BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1: u32 = 3;
pub(crate) const BONDRY_DISPATCH_OUTCOME_AUDIT_UNAVAILABLE_V1: u32 = 4;
pub(crate) const BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1: u32 = 5;
pub(crate) const BONDRY_DISPATCH_OUTCOME_INVALID_INPUT_V1: u32 = 6;
pub(crate) const BONDRY_DEDUP_CLAIMED_V1: u32 = 1;
pub(crate) const BONDRY_DEDUP_DUPLICATE_V1: u32 = 2;
pub(crate) const BONDRY_DEDUP_STATE_IN_FLIGHT_V1: u32 = 1;
pub(crate) const BONDRY_DEDUP_STATE_COMPLETED_V1: u32 = 2;
pub(crate) const BONDRY_DEDUP_STATE_UNKNOWN_V1: u32 = 3;
pub(crate) const BONDRY_DEDUP_RETAIN_COMPLETED_V1: u32 = 1;
pub(crate) const BONDRY_DEDUP_EXPIRE_COMPLETED_V1: u32 = 2;
pub(crate) const BONDRY_DEDUP_RESOLVE_COMPLETED_V1: u32 = 1;
pub(crate) const BONDRY_DEDUP_RESOLVE_RETRY_ALLOWED_V1: u32 = 2;

/// Retains one callback context ownership unit.
pub type BondryContextRetainV1 = unsafe extern "C" fn(context: *mut c_void) -> *mut c_void;
/// Releases one callback context ownership unit.
pub type BondryContextReleaseV1 = unsafe extern "C" fn(context: *mut c_void);

/// Result borrowed for one automation dispatch completion callback.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryDispatchResultV1 {
    /// Stable dispatch outcome.
    pub outcome: u32,
    /// Optional JSON handler output.
    pub output_json: *const u8,
    /// Handler output byte length.
    pub output_json_length: usize,
    /// Optional terminated detail code.
    pub detail_code: [u8; 129],
    /// One when a detail code is present.
    pub has_detail_code: u8,
}

/// Receives one accepted automation dispatch result.
pub type BondryDispatchCompletionV1 =
    unsafe extern "C" fn(context: *mut c_void, result: *const BondryDispatchResultV1);
/// Lists capabilities; a null zero-capacity output returns success and the required length.
pub type BondryAutomationCapabilitiesV1 = unsafe extern "C" fn(
    context: *mut c_void,
    principal_id: *const u8,
    principal_id_length: usize,
    principal_kind: u32,
    adapter_id: *const u8,
    adapter_id_length: usize,
    output_json: *mut u8,
    capacity: usize,
    out_length: *mut usize,
) -> i32;
/// Dispatches one fixed host-authenticated invocation.
pub type BondryAutomationDispatchV1 = unsafe extern "C" fn(
    context: *mut c_void,
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

/// Versioned protocol-neutral service supplied by the existing runtime.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryAutomationServiceV1 {
    /// Descriptor ABI version.
    pub abi_version: u32,
    /// Descriptor byte size.
    pub struct_size: usize,
    /// Callback threading model.
    pub threading_model: u32,
    /// Caller-owned context retained at handler creation.
    pub context: *mut c_void,
    /// Required retain callback.
    pub retain: Option<BondryContextRetainV1>,
    /// Required release callback.
    pub release: Option<BondryContextReleaseV1>,
    /// Required capability-discovery callback.
    pub capabilities: Option<BondryAutomationCapabilitiesV1>,
    /// Required asynchronous dispatch callback.
    pub dispatch: Option<BondryAutomationDispatchV1>,
}

/// Fixed replay record used by queries and administrative visitors.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryDedupRecordV1 {
    /// Terminated route identifier.
    pub route_id: [u8; 129],
    /// Terminated verifier namespace.
    pub verifier_namespace: [u8; 129],
    /// Hashed normalized delivery identity.
    pub delivery_hash: [u8; 32],
    /// Stable replay state.
    pub state: u32,
    /// Most recent transition in Unix milliseconds.
    pub updated_at_unix_ms: u64,
}

/// Visits one unknown replay record; zero stops iteration.
pub type BondryDedupUnknownVisitorV1 =
    unsafe extern "C" fn(context: *mut c_void, record: *const BondryDedupRecordV1) -> u8;
/// Atomically claims one replay key.
pub type BondryDedupClaimV1 = unsafe extern "C" fn(
    context: *mut c_void,
    route_id: *const u8,
    route_id_length: usize,
    verifier_namespace: *const u8,
    verifier_namespace_length: usize,
    delivery_hash: *const u8,
    delivery_hash_length: usize,
    policy: u32,
    updated_at_unix_ms: u64,
    out_result: *mut u32,
    out_state: *mut u32,
) -> i32;
/// Transitions one replay key.
pub type BondryDedupTransitionV1 = unsafe extern "C" fn(
    context: *mut c_void,
    route_id: *const u8,
    route_id_length: usize,
    verifier_namespace: *const u8,
    verifier_namespace_length: usize,
    delivery_hash: *const u8,
    delivery_hash_length: usize,
    updated_at_unix_ms: u64,
) -> i32;
/// Queries one replay key.
pub type BondryDedupQueryV1 = unsafe extern "C" fn(
    context: *mut c_void,
    route_id: *const u8,
    route_id_length: usize,
    verifier_namespace: *const u8,
    verifier_namespace_length: usize,
    delivery_hash: *const u8,
    delivery_hash_length: usize,
    out_found: *mut u8,
    out_record: *mut BondryDedupRecordV1,
) -> i32;
/// Recovers unfinished replay claims.
pub type BondryDedupRecoverV1 =
    unsafe extern "C" fn(context: *mut c_void, updated_at_unix_ms: u64, out_count: *mut u64) -> i32;
/// Resolves one unknown replay key.
pub type BondryDedupResolveV1 = unsafe extern "C" fn(
    context: *mut c_void,
    route_id: *const u8,
    route_id_length: usize,
    verifier_namespace: *const u8,
    verifier_namespace_length: usize,
    delivery_hash: *const u8,
    delivery_hash_length: usize,
    resolution: u32,
    updated_at_unix_ms: u64,
) -> i32;
/// Visits unknown replay records.
pub type BondryDedupVisitUnknownV1 = unsafe extern "C" fn(
    context: *mut c_void,
    visitor: BondryDedupUnknownVisitorV1,
    visitor_context: *mut c_void,
) -> i32;
/// Clears completed replay records before one cutoff.
pub type BondryDedupClearCompletedV1 = unsafe extern "C" fn(
    context: *mut c_void,
    updated_before_unix_ms: u64,
    out_count: *mut u64,
) -> i32;

/// Versioned persistent replay-protection store supplied by the existing runtime.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryDedupStoreV1 {
    /// Descriptor ABI version.
    pub abi_version: u32,
    /// Descriptor byte size.
    pub struct_size: usize,
    /// Callback threading model.
    pub threading_model: u32,
    /// Backing-store durability.
    pub durability: u32,
    /// Caller-owned context retained at handler creation.
    pub context: *mut c_void,
    /// Required retain callback.
    pub retain: Option<BondryContextRetainV1>,
    /// Required release callback.
    pub release: Option<BondryContextReleaseV1>,
    /// Required atomic claim callback.
    pub claim: Option<BondryDedupClaimV1>,
    /// Required completion callback.
    pub complete: Option<BondryDedupTransitionV1>,
    /// Required uncertainty callback.
    pub mark_unknown: Option<BondryDedupTransitionV1>,
    /// Required pre-dispatch claim release callback.
    pub release_claim: Option<BondryDedupTransitionV1>,
    /// Required query callback.
    pub query: Option<BondryDedupQueryV1>,
    /// Required restart-recovery callback.
    pub recover: Option<BondryDedupRecoverV1>,
    /// Required unknown-resolution callback.
    pub resolve_unknown: Option<BondryDedupResolveV1>,
    /// Required unknown visitor callback.
    pub visit_unknown: Option<BondryDedupVisitUnknownV1>,
    /// Required completed cleanup callback.
    pub clear_completed: Option<BondryDedupClearCompletedV1>,
}

/// Receives borrowed rotating secret material synchronously.
pub type BondryWebhookSecretResolutionV1 = unsafe extern "C" fn(
    context: *mut c_void,
    current: *const u8,
    current_length: usize,
    previous: *const u8,
    previous_length: usize,
    has_previous: u8,
);
/// Resolves one non-secret reference and completes before returning success.
pub type BondryWebhookSecretResolveV1 = unsafe extern "C" fn(
    context: *mut c_void,
    secret_reference: *const u8,
    secret_reference_length: usize,
    completion: BondryWebhookSecretResolutionV1,
    completion_context: *mut c_void,
) -> i32;

/// Versioned host secret provider retained with one handler generation.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryWebhookSecretProviderV1 {
    /// Descriptor ABI version.
    pub abi_version: u32,
    /// Descriptor byte size.
    pub struct_size: usize,
    /// Caller-owned context retained at handler creation.
    pub context: *mut c_void,
    /// Required retain callback.
    pub retain: Option<BondryContextRetainV1>,
    /// Required release callback.
    pub release: Option<BondryContextReleaseV1>,
    /// Required synchronous resolution callback.
    pub resolve: Option<BondryWebhookSecretResolveV1>,
}

/// Borrowed byte slice in a raw-body descriptor.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryRawBodyByteSliceV1 {
    /// Borrowed bytes.
    pub bytes: *const u8,
    /// Borrowed byte length.
    pub length: usize,
}

/// Borrowed selected request header preserving duplicates.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryRawBodyHeaderV1 {
    /// Normalized header name.
    pub name: *const u8,
    /// Header-name length.
    pub name_length: usize,
    /// Exact header value.
    pub value: *const u8,
    /// Header-value length.
    pub value_length: usize,
}

/// Callback-scoped bounded raw-body request.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryRawBodyRequestV1 {
    /// Raw-body handler ABI version.
    pub abi_version: u32,
    /// Record byte size.
    pub struct_size: usize,
    /// Exact request target.
    pub target: *const u8,
    /// Request-target length.
    pub target_length: usize,
    /// Selected headers.
    pub headers: *const BondryRawBodyHeaderV1,
    /// Selected-header count.
    pub header_count: usize,
    /// Exact raw body.
    pub body: *const u8,
    /// Raw-body length.
    pub body_length: usize,
    /// Stable peer address family.
    pub peer_ip_family: u32,
    /// Network-order peer address.
    pub peer_ip: [u8; 16],
    /// Peer port.
    pub peer_port: u16,
    /// Optional IPv6 interface scope.
    pub peer_interface_scope: u32,
    /// One when interface scope is present.
    pub has_peer_interface_scope: u8,
}

/// Status-only raw-body response.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryRawBodyResponseV1 {
    /// Raw-body handler ABI version.
    pub abi_version: u32,
    /// Record byte size.
    pub struct_size: usize,
    /// HTTP status code.
    pub status_code: u16,
    /// Optional stable safe error code.
    pub error_code: *const u8,
    /// Error-code length.
    pub error_code_length: usize,
    /// Optional retry delay.
    pub retry_after_seconds: u64,
    /// One when retry delay is present.
    pub has_retry_after: u8,
}

/// Completes one raw-body request exactly once.
pub type BondryRawBodyCompletionV1 =
    unsafe extern "C" fn(context: *mut c_void, response: *const BondryRawBodyResponseV1);
/// Handles one callback-scoped raw-body request.
pub type BondryRawBodyHandleV1 = unsafe extern "C" fn(
    context: *mut c_void,
    request: *const BondryRawBodyRequestV1,
    completion: BondryRawBodyCompletionV1,
    completion_context: *mut c_void,
);

/// One immutable raw-body handler generation descriptor.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryRawBodyHandlerDescriptorV1 {
    /// Raw-body handler ABI version.
    pub abi_version: u32,
    /// Descriptor byte size.
    pub struct_size: usize,
    /// Stable accepted method.
    pub method: u32,
    /// Exact registered path.
    pub path: BondryRawBodyByteSliceV1,
    /// Selected normalized header names.
    pub selected_headers: *const BondryRawBodyByteSliceV1,
    /// Selected-header count.
    pub selected_header_count: usize,
    /// Maximum raw body bytes.
    pub max_body_bytes: usize,
    /// Maximum request-lifecycle retained bytes.
    pub max_retained_bytes: usize,
    /// Maximum one selected-header value.
    pub max_selected_header_bytes: usize,
    /// Maximum aggregate selected-header bytes.
    pub max_selected_headers_bytes: usize,
    /// Pre-authentication requests per peer and minute.
    pub pre_authentication_requests_per_peer_minute: u32,
    /// Pre-authentication requests per route and minute.
    pub pre_authentication_requests_per_route_minute: u32,
    /// Owned generation context.
    pub context: *mut c_void,
    /// Required context retain callback.
    pub retain: Option<BondryContextRetainV1>,
    /// Required context release callback.
    pub release: Option<BondryContextReleaseV1>,
    /// Required request handler callback.
    pub handle: Option<BondryRawBodyHandleV1>,
}

/// All host-owned services and route configuration for one handler generation.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryWebhookIngressRegistrationDescriptorV1 {
    /// Must equal `BONDRY_WEBHOOK_INGRESS_ABI_VERSION_V1`.
    pub abi_version: u32,
    /// Byte size of this descriptor.
    pub struct_size: usize,
    /// Bounded UTF-8 route configuration JSON.
    pub configuration_json: *const u8,
    /// Configuration byte length.
    pub configuration_json_length: usize,
    /// Existing runtime's protocol-neutral dispatcher.
    pub automation: BondryAutomationServiceV1,
    /// Existing runtime's persistent replay store.
    pub dedup: BondryDedupStoreV1,
    /// Host secret provider retained for this generation.
    pub secrets: BondryWebhookSecretProviderV1,
}
