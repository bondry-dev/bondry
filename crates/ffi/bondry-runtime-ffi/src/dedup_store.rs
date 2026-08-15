use std::{
    ffi::c_void,
    mem, ptr, slice,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bondry_delivery_store::{
    DedupClaim, DedupClaimPolicy, DedupKey, DedupRecord, DedupResolution, DedupState, DedupStore,
    DedupStoreError, DedupStoreLimits, RouteId, TrustedDeliveryIdHash, VerifierNamespace,
};
use bondry_store_sqlcipher::SqlCipherDedupStore;

use crate::{
    BONDRY_STATUS_CAPACITY_EXHAUSTED, BONDRY_STATUS_INVALID_ARGUMENT, BONDRY_STATUS_INVALID_LENGTH,
    BONDRY_STATUS_INVALID_TRANSITION, BONDRY_STATUS_NOT_FOUND, BONDRY_STATUS_NULL_POINTER,
    BONDRY_STATUS_OK, BONDRY_STATUS_TIME_UNAVAILABLE, BONDRY_STATUS_UNAVAILABLE, BondryStoreHandle,
    auth::store_handle, catch_status, records::terminated, required_utf8,
};

/// ABI version of the replay-protection store descriptor.
pub const BONDRY_DEDUP_STORE_ABI_VERSION_V1: u32 = 1;
/// The store may be called concurrently and serializes persistent state transitions.
pub const BONDRY_DEDUP_THREADING_SERIALIZED_V1: u32 = 1;
/// Persistent store durability.
pub const BONDRY_STORE_DURABILITY_PERSISTENT_V1: u32 = 2;
/// A new replay identity was claimed.
pub const BONDRY_DEDUP_CLAIMED_V1: u32 = 1;
/// The replay identity already exists.
pub const BONDRY_DEDUP_DUPLICATE_V1: u32 = 2;
/// The delivery is currently in flight.
pub const BONDRY_DEDUP_STATE_IN_FLIGHT_V1: u32 = 1;
/// The delivery completed.
pub const BONDRY_DEDUP_STATE_COMPLETED_V1: u32 = 2;
/// The delivery outcome is uncertain.
pub const BONDRY_DEDUP_STATE_UNKNOWN_V1: u32 = 3;
/// Completed state remains until explicit administration.
pub const BONDRY_DEDUP_RETAIN_COMPLETED_V1: u32 = 1;
/// Completed state may expire after the configured retention.
pub const BONDRY_DEDUP_EXPIRE_COMPLETED_V1: u32 = 2;
/// Resolve an uncertain delivery as completed.
pub const BONDRY_DEDUP_RESOLVE_COMPLETED_V1: u32 = 1;
/// Remove an uncertain record and permit an explicit retry.
pub const BONDRY_DEDUP_RESOLVE_RETRY_ALLOWED_V1: u32 = 2;

const IDENTIFIER_CAPACITY: usize = 129;

/// Fixed replay record borrowed by visitor callbacks or written into caller-owned memory.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryDedupRecordV1 {
    /// UTF-8 route identifier terminated with zero.
    pub route_id: [u8; IDENTIFIER_CAPACITY],
    /// UTF-8 verifier namespace terminated with zero.
    pub verifier_namespace: [u8; IDENTIFIER_CAPACITY],
    /// SHA-256 hash of the verifier-normalized delivery identity.
    pub delivery_hash: [u8; 32],
    /// Stable replay-state constant.
    pub state: u32,
    /// Most recent transition in Unix milliseconds.
    pub updated_at_unix_ms: u64,
}

impl BondryDedupRecordV1 {
    const fn zeroed() -> Self {
        Self {
            route_id: [0; IDENTIFIER_CAPACITY],
            verifier_namespace: [0; IDENTIFIER_CAPACITY],
            delivery_hash: [0; 32],
            state: 0,
            updated_at_unix_ms: 0,
        }
    }

    fn from_record(record: &DedupRecord) -> Self {
        Self {
            route_id: terminated(record.key().route().as_str()),
            verifier_namespace: terminated(record.key().namespace().as_str()),
            delivery_hash: *record.key().delivery_hash().as_bytes(),
            state: encode_state(record.state()),
            updated_at_unix_ms: record.updated_at_unix_ms(),
        }
    }
}

/// Retains one replay-store context ownership unit.
pub type BondryDedupContextRetainV1 = unsafe extern "C" fn(context: *mut c_void) -> *mut c_void;
/// Releases one replay-store context ownership unit.
pub type BondryDedupContextReleaseV1 = unsafe extern "C" fn(context: *mut c_void);
/// Visits one unknown record; returning zero stops iteration.
pub type BondryDedupUnknownVisitorV1 =
    unsafe extern "C" fn(visitor_context: *mut c_void, record: *const BondryDedupRecordV1) -> u8;
/// Atomically claims one trusted delivery identity.
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
/// Transitions one exact replay key with an optional timestamp.
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
/// Loads one exact replay record.
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
/// Recovers every unfinished replay claim as unknown.
pub type BondryDedupRecoverV1 =
    unsafe extern "C" fn(context: *mut c_void, updated_at_unix_ms: u64, out_count: *mut u64) -> i32;
/// Resolves one unknown replay record by explicit administration.
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
/// Visits unknown records without holding the store lock during callbacks.
pub type BondryDedupVisitUnknownV1 = unsafe extern "C" fn(
    context: *mut c_void,
    visitor: BondryDedupUnknownVisitorV1,
    visitor_context: *mut c_void,
) -> i32;
/// Removes completed records older than a caller-selected cutoff.
pub type BondryDedupClearCompletedV1 = unsafe extern "C" fn(
    context: *mut c_void,
    updated_before_unix_ms: u64,
    out_count: *mut u64,
) -> i32;

/// Versioned persistent replay-protection operations over one existing encrypted store.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryDedupStoreV1 {
    /// Must equal `BONDRY_DEDUP_STORE_ABI_VERSION_V1`.
    pub abi_version: u32,
    /// Byte size of this descriptor.
    pub struct_size: usize,
    /// Must equal `BONDRY_DEDUP_THREADING_SERIALIZED_V1`.
    pub threading_model: u32,
    /// Must equal `BONDRY_STORE_DURABILITY_PERSISTENT_V1`.
    pub durability: u32,
    /// Owned replay-store context.
    pub context: *mut c_void,
    /// Required context retain callback.
    pub retain: Option<BondryDedupContextRetainV1>,
    /// Required context release callback.
    pub release: Option<BondryDedupContextReleaseV1>,
    /// Required atomic claim callback.
    pub claim: Option<BondryDedupClaimV1>,
    /// Required in-flight to completed transition.
    pub complete: Option<BondryDedupTransitionV1>,
    /// Required in-flight to unknown transition.
    pub mark_unknown: Option<BondryDedupTransitionV1>,
    /// Required removal of one known pre-dispatch claim.
    pub release_claim: Option<BondryDedupTransitionV1>,
    /// Required exact record query.
    pub query: Option<BondryDedupQueryV1>,
    /// Required restart recovery operation.
    pub recover: Option<BondryDedupRecoverV1>,
    /// Required explicit unknown resolution.
    pub resolve_unknown: Option<BondryDedupResolveV1>,
    /// Required bounded unknown-record iteration.
    pub visit_unknown: Option<BondryDedupVisitUnknownV1>,
    /// Required explicit completed-record cleanup.
    pub clear_completed: Option<BondryDedupClearCompletedV1>,
}

impl BondryDedupStoreV1 {
    const fn zeroed() -> Self {
        Self {
            abi_version: 0,
            struct_size: 0,
            threading_model: 0,
            durability: 0,
            context: ptr::null_mut(),
            retain: None,
            release: None,
            claim: None,
            complete: None,
            mark_unknown: None,
            release_claim: None,
            query: None,
            recover: None,
            resolve_unknown: None,
            visit_unknown: None,
            clear_completed: None,
        }
    }
}

struct DedupContext {
    store: SqlCipherDedupStore,
}

/// Derives one owned persistent replay-store descriptor from the existing runtime store.
///
/// The first descriptor derived from a newly opened handle recovers restart-left in-flight records.
///
/// # Safety
///
/// `store` must remain live for this call. `out_dedup` must be writable. On success the caller
/// must invoke the descriptor's release callback exactly once.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_store_dedup_v1(
    store: *const BondryStoreHandle,
    max_records: u32,
    max_bytes: u64,
    retention_seconds: u64,
    out_dedup: *mut BondryDedupStoreV1,
) -> i32 {
    if out_dedup.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: The caller guarantees writable output memory.
    unsafe { out_dedup.write(BondryDedupStoreV1::zeroed()) };
    catch_status(|| {
        let Ok(handle) = store_handle(store) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let limits = match DedupStoreLimits::new(
            max_records,
            max_bytes,
            Duration::from_secs(retention_seconds),
        ) {
            Ok(limits) => limits,
            Err(_) => return BONDRY_STATUS_INVALID_ARGUMENT,
        };
        let dedup = SqlCipherDedupStore::new(handle.store.clone(), limits);
        let mut recovered = match handle.dedup_recovered.lock() {
            Ok(recovered) => recovered,
            Err(_) => return BONDRY_STATUS_UNAVAILABLE,
        };
        if !*recovered {
            let now = match unix_milliseconds() {
                Ok(now) => now,
                Err(status) => return status,
            };
            if let Err(error) = dedup.recover_in_flight(now) {
                return store_status(error);
            }
            *recovered = true;
        }
        drop(recovered);
        let context = Arc::new(DedupContext { store: dedup });
        let descriptor = BondryDedupStoreV1 {
            abi_version: BONDRY_DEDUP_STORE_ABI_VERSION_V1,
            struct_size: mem::size_of::<BondryDedupStoreV1>(),
            threading_model: BONDRY_DEDUP_THREADING_SERIALIZED_V1,
            durability: BONDRY_STORE_DURABILITY_PERSISTENT_V1,
            context: Arc::into_raw(context).cast_mut().cast::<c_void>(),
            retain: Some(retain_context),
            release: Some(release_context),
            claim: Some(claim),
            complete: Some(complete),
            mark_unknown: Some(mark_unknown),
            release_claim: Some(release_claim),
            query: Some(query),
            recover: Some(recover),
            resolve_unknown: Some(resolve_unknown),
            visit_unknown: Some(visit_unknown),
            clear_completed: Some(clear_completed),
        };
        // SAFETY: Output was validated and receives the descriptor ownership unit.
        unsafe { out_dedup.write(descriptor) };
        BONDRY_STATUS_OK
    })
}

unsafe extern "C" fn retain_context(context: *mut c_void) -> *mut c_void {
    if context.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: Descriptor contexts are live Arc-backed pointers.
    unsafe { Arc::increment_strong_count(context.cast::<DedupContext>()) };
    context
}

unsafe extern "C" fn release_context(context: *mut c_void) {
    if !context.is_null() {
        // SAFETY: Each descriptor ownership unit is released exactly once.
        drop(unsafe { Arc::from_raw(context.cast::<DedupContext>().cast_const()) });
    }
}

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn claim(
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
) -> i32 {
    if out_result.is_null() || out_state.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    catch_status(|| {
        // SAFETY: Both outputs were validated.
        unsafe {
            out_result.write(0);
            out_state.write(0);
        }
        let context = match unsafe { context_ref(context) } {
            Ok(context) => context,
            Err(status) => return status,
        };
        let key = match unsafe {
            parse_key(
                route_id,
                route_id_length,
                verifier_namespace,
                verifier_namespace_length,
                delivery_hash,
                delivery_hash_length,
            )
        } {
            Ok(key) => key,
            Err(status) => return status,
        };
        let policy = match policy {
            BONDRY_DEDUP_RETAIN_COMPLETED_V1 => DedupClaimPolicy::RetainCompleted,
            BONDRY_DEDUP_EXPIRE_COMPLETED_V1 => DedupClaimPolicy::ExpireCompleted,
            _ => return BONDRY_STATUS_INVALID_ARGUMENT,
        };
        match context.store.claim(key, policy, updated_at_unix_ms) {
            Ok(DedupClaim::Claimed) => {
                // SAFETY: Outputs remain writable for this call.
                unsafe { out_result.write(BONDRY_DEDUP_CLAIMED_V1) };
                BONDRY_STATUS_OK
            }
            Ok(DedupClaim::Duplicate(state)) => {
                // SAFETY: Outputs remain writable for this call.
                unsafe {
                    out_result.write(BONDRY_DEDUP_DUPLICATE_V1);
                    out_state.write(encode_state(state));
                }
                BONDRY_STATUS_OK
            }
            Err(error) => store_status(error),
        }
    })
}

unsafe extern "C" fn complete(
    context: *mut c_void,
    route_id: *const u8,
    route_id_length: usize,
    verifier_namespace: *const u8,
    verifier_namespace_length: usize,
    delivery_hash: *const u8,
    delivery_hash_length: usize,
    updated_at_unix_ms: u64,
) -> i32 {
    unsafe {
        transition(
            context,
            route_id,
            route_id_length,
            verifier_namespace,
            verifier_namespace_length,
            delivery_hash,
            delivery_hash_length,
            |store, key| store.complete(key, updated_at_unix_ms),
        )
    }
}

unsafe extern "C" fn mark_unknown(
    context: *mut c_void,
    route_id: *const u8,
    route_id_length: usize,
    verifier_namespace: *const u8,
    verifier_namespace_length: usize,
    delivery_hash: *const u8,
    delivery_hash_length: usize,
    updated_at_unix_ms: u64,
) -> i32 {
    unsafe {
        transition(
            context,
            route_id,
            route_id_length,
            verifier_namespace,
            verifier_namespace_length,
            delivery_hash,
            delivery_hash_length,
            |store, key| store.mark_unknown(key, updated_at_unix_ms),
        )
    }
}

unsafe extern "C" fn release_claim(
    context: *mut c_void,
    route_id: *const u8,
    route_id_length: usize,
    verifier_namespace: *const u8,
    verifier_namespace_length: usize,
    delivery_hash: *const u8,
    delivery_hash_length: usize,
    _updated_at_unix_ms: u64,
) -> i32 {
    unsafe {
        transition(
            context,
            route_id,
            route_id_length,
            verifier_namespace,
            verifier_namespace_length,
            delivery_hash,
            delivery_hash_length,
            DedupStore::release_claim,
        )
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn transition(
    context_pointer: *mut c_void,
    route_id: *const u8,
    route_id_length: usize,
    verifier_namespace: *const u8,
    verifier_namespace_length: usize,
    delivery_hash: *const u8,
    delivery_hash_length: usize,
    operation: impl FnOnce(&SqlCipherDedupStore, &DedupKey) -> Result<(), DedupStoreError>,
) -> i32 {
    catch_status(|| {
        let context = match unsafe { context_ref(context_pointer) } {
            Ok(context) => context,
            Err(status) => return status,
        };
        let key = match unsafe {
            parse_key(
                route_id,
                route_id_length,
                verifier_namespace,
                verifier_namespace_length,
                delivery_hash,
                delivery_hash_length,
            )
        } {
            Ok(key) => key,
            Err(status) => return status,
        };
        operation(&context.store, &key).map_or_else(store_status, |()| BONDRY_STATUS_OK)
    })
}

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn query(
    context: *mut c_void,
    route_id: *const u8,
    route_id_length: usize,
    verifier_namespace: *const u8,
    verifier_namespace_length: usize,
    delivery_hash: *const u8,
    delivery_hash_length: usize,
    out_found: *mut u8,
    out_record: *mut BondryDedupRecordV1,
) -> i32 {
    if out_found.is_null() || out_record.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    catch_status(|| {
        // SAFETY: Both outputs were validated.
        unsafe {
            out_found.write(0);
            out_record.write(BondryDedupRecordV1::zeroed());
        }
        let context = match unsafe { context_ref(context) } {
            Ok(context) => context,
            Err(status) => return status,
        };
        let key = match unsafe {
            parse_key(
                route_id,
                route_id_length,
                verifier_namespace,
                verifier_namespace_length,
                delivery_hash,
                delivery_hash_length,
            )
        } {
            Ok(key) => key,
            Err(status) => return status,
        };
        match context.store.record(&key) {
            Ok(Some(record)) => {
                // SAFETY: Both outputs remain writable for this call.
                unsafe {
                    out_found.write(1);
                    out_record.write(BondryDedupRecordV1::from_record(&record));
                }
                BONDRY_STATUS_OK
            }
            Ok(None) => BONDRY_STATUS_OK,
            Err(error) => store_status(error),
        }
    })
}

unsafe extern "C" fn recover(
    context: *mut c_void,
    updated_at_unix_ms: u64,
    out_count: *mut u64,
) -> i32 {
    if out_count.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    catch_status(|| {
        // SAFETY: Output was validated.
        unsafe { out_count.write(0) };
        let context = match unsafe { context_ref(context) } {
            Ok(context) => context,
            Err(status) => return status,
        };
        match context.store.recover_in_flight(updated_at_unix_ms) {
            Ok(count) => {
                // SAFETY: Output remains writable for this call.
                unsafe { out_count.write(count) };
                BONDRY_STATUS_OK
            }
            Err(error) => store_status(error),
        }
    })
}

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn resolve_unknown(
    context: *mut c_void,
    route_id: *const u8,
    route_id_length: usize,
    verifier_namespace: *const u8,
    verifier_namespace_length: usize,
    delivery_hash: *const u8,
    delivery_hash_length: usize,
    resolution: u32,
    updated_at_unix_ms: u64,
) -> i32 {
    catch_status(|| {
        let context = match unsafe { context_ref(context) } {
            Ok(context) => context,
            Err(status) => return status,
        };
        let key = match unsafe {
            parse_key(
                route_id,
                route_id_length,
                verifier_namespace,
                verifier_namespace_length,
                delivery_hash,
                delivery_hash_length,
            )
        } {
            Ok(key) => key,
            Err(status) => return status,
        };
        let resolution = match resolution {
            BONDRY_DEDUP_RESOLVE_COMPLETED_V1 => DedupResolution::Completed,
            BONDRY_DEDUP_RESOLVE_RETRY_ALLOWED_V1 => DedupResolution::RetryAllowed,
            _ => return BONDRY_STATUS_INVALID_ARGUMENT,
        };
        context
            .store
            .resolve_unknown(&key, resolution, updated_at_unix_ms)
            .map_or_else(store_status, |()| BONDRY_STATUS_OK)
    })
}

unsafe extern "C" fn visit_unknown(
    context: *mut c_void,
    visitor: BondryDedupUnknownVisitorV1,
    visitor_context: *mut c_void,
) -> i32 {
    catch_status(|| {
        let context = match unsafe { context_ref(context) } {
            Ok(context) => context,
            Err(status) => return status,
        };
        let mut callback = |record: &DedupRecord| {
            let record = BondryDedupRecordV1::from_record(record);
            // SAFETY: The fixed record remains borrowed for this synchronous visitor call.
            unsafe { visitor(visitor_context, &record) != 0 }
        };
        context
            .store
            .visit_unknown(&mut callback)
            .map_or_else(store_status, |()| BONDRY_STATUS_OK)
    })
}

unsafe extern "C" fn clear_completed(
    context: *mut c_void,
    updated_before_unix_ms: u64,
    out_count: *mut u64,
) -> i32 {
    if out_count.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    catch_status(|| {
        // SAFETY: Output was validated.
        unsafe { out_count.write(0) };
        let context = match unsafe { context_ref(context) } {
            Ok(context) => context,
            Err(status) => return status,
        };
        match context.store.clear_completed_before(updated_before_unix_ms) {
            Ok(count) => {
                // SAFETY: Output remains writable for this call.
                unsafe { out_count.write(count) };
                BONDRY_STATUS_OK
            }
            Err(error) => store_status(error),
        }
    })
}

unsafe fn context_ref<'a>(pointer: *mut c_void) -> Result<&'a DedupContext, i32> {
    // SAFETY: Descriptor callbacks receive a live context pointer.
    unsafe { pointer.cast::<DedupContext>().as_ref() }.ok_or(BONDRY_STATUS_NULL_POINTER)
}

#[allow(clippy::too_many_arguments)]
unsafe fn parse_key(
    route_id: *const u8,
    route_id_length: usize,
    verifier_namespace: *const u8,
    verifier_namespace_length: usize,
    delivery_hash: *const u8,
    delivery_hash_length: usize,
) -> Result<DedupKey, i32> {
    // SAFETY: Callers preserve all declared input buffers for the callback duration.
    let route = unsafe { required_utf8(route_id, route_id_length) }
        .and_then(|value| RouteId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT))?;
    // SAFETY: Callers preserve all declared input buffers for the callback duration.
    let namespace = unsafe { required_utf8(verifier_namespace, verifier_namespace_length) }
        .and_then(|value| {
            VerifierNamespace::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)
        })?;
    if delivery_hash.is_null() {
        return Err(BONDRY_STATUS_NULL_POINTER);
    }
    if delivery_hash_length != 32 {
        return Err(BONDRY_STATUS_INVALID_LENGTH);
    }
    // SAFETY: The caller guarantees exactly 32 readable bytes.
    let hash = unsafe { slice::from_raw_parts(delivery_hash, 32) };
    let mut hash_bytes = [0; 32];
    hash_bytes.copy_from_slice(hash);
    Ok(DedupKey::new(
        route,
        namespace,
        TrustedDeliveryIdHash::from_bytes(hash_bytes),
    ))
}

const fn encode_state(state: DedupState) -> u32 {
    match state {
        DedupState::InFlight => BONDRY_DEDUP_STATE_IN_FLIGHT_V1,
        DedupState::Completed => BONDRY_DEDUP_STATE_COMPLETED_V1,
        DedupState::Unknown => BONDRY_DEDUP_STATE_UNKNOWN_V1,
    }
}

const fn store_status(error: DedupStoreError) -> i32 {
    match error {
        DedupStoreError::CapacityExhausted => BONDRY_STATUS_CAPACITY_EXHAUSTED,
        DedupStoreError::NotFound => BONDRY_STATUS_NOT_FOUND,
        DedupStoreError::InvalidTransition => BONDRY_STATUS_INVALID_TRANSITION,
        DedupStoreError::Unavailable => BONDRY_STATUS_UNAVAILABLE,
    }
}

fn unix_milliseconds() -> Result<u64, i32> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BONDRY_STATUS_TIME_UNAVAILABLE)?;
    u64::try_from(duration.as_millis()).map_err(|_| BONDRY_STATUS_TIME_UNAVAILABLE)
}

#[cfg(test)]
mod tests {
    use std::{ffi::c_void, ptr};

    use bondry_delivery_store::{
        DEFAULT_DEDUP_STORE_BYTES, DEFAULT_DEDUP_STORE_RECORDS, DEFAULT_DEDUP_STORE_RETENTION,
    };
    use tempfile::TempDir;

    use super::{
        BONDRY_DEDUP_CLAIMED_V1, BONDRY_DEDUP_DUPLICATE_V1, BONDRY_DEDUP_RETAIN_COMPLETED_V1,
        BONDRY_DEDUP_STATE_IN_FLIGHT_V1, BONDRY_DEDUP_STATE_UNKNOWN_V1, BondryDedupRecordV1,
        BondryDedupStoreV1, bondry_store_dedup_v1,
    };
    use crate::{
        BONDRY_STATUS_INVALID_ARGUMENT, BONDRY_STATUS_OK, BondryStoreHandle, bondry_store_close_v1,
        bondry_store_open_v1,
    };

    #[test]
    fn descriptor_drives_persistent_replay_transitions() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("dedup.db");
        let path = path.to_str().ok_or("non-UTF-8 test path")?.as_bytes();
        let key = [0x41; 32];
        let mut store = ptr::null_mut::<BondryStoreHandle>();
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
        let mut invalid = BondryDedupStoreV1::zeroed();
        assert_eq!(
            unsafe { bondry_store_dedup_v1(store, 0, 0, 0, &mut invalid) },
            BONDRY_STATUS_INVALID_ARGUMENT
        );
        let mut descriptor = derive(store)?;
        let route = b"webhook.route";
        let namespace = b"provider:v1";
        let hash = [0x52; 32];
        let claim = descriptor.claim.ok_or("missing claim")?;
        let transition = descriptor.mark_unknown.ok_or("missing mark unknown")?;
        let query = descriptor.query.ok_or("missing query")?;
        let visit = descriptor.visit_unknown.ok_or("missing visit unknown")?;
        let mut result = 0;
        let mut state = 0;
        assert_eq!(
            unsafe {
                claim(
                    descriptor.context,
                    route.as_ptr(),
                    route.len(),
                    namespace.as_ptr(),
                    namespace.len(),
                    hash.as_ptr(),
                    hash.len(),
                    BONDRY_DEDUP_RETAIN_COMPLETED_V1,
                    1_000,
                    &mut result,
                    &mut state,
                )
            },
            BONDRY_STATUS_OK
        );
        assert_eq!(result, BONDRY_DEDUP_CLAIMED_V1);
        assert_eq!(
            unsafe {
                claim(
                    descriptor.context,
                    route.as_ptr(),
                    route.len(),
                    namespace.as_ptr(),
                    namespace.len(),
                    hash.as_ptr(),
                    hash.len(),
                    BONDRY_DEDUP_RETAIN_COMPLETED_V1,
                    1_001,
                    &mut result,
                    &mut state,
                )
            },
            BONDRY_STATUS_OK
        );
        assert_eq!(result, BONDRY_DEDUP_DUPLICATE_V1);
        assert_eq!(state, BONDRY_DEDUP_STATE_IN_FLIGHT_V1);
        assert_eq!(
            unsafe {
                transition(
                    descriptor.context,
                    route.as_ptr(),
                    route.len(),
                    namespace.as_ptr(),
                    namespace.len(),
                    hash.as_ptr(),
                    hash.len(),
                    1_002,
                )
            },
            BONDRY_STATUS_OK
        );
        let mut found = 0;
        let mut record = BondryDedupRecordV1::zeroed();
        assert_eq!(
            unsafe {
                query(
                    descriptor.context,
                    route.as_ptr(),
                    route.len(),
                    namespace.as_ptr(),
                    namespace.len(),
                    hash.as_ptr(),
                    hash.len(),
                    &mut found,
                    &mut record,
                )
            },
            BONDRY_STATUS_OK
        );
        assert_eq!(found, 1);
        assert_eq!(record.state, BONDRY_DEDUP_STATE_UNKNOWN_V1);
        let mut visited = 0_usize;
        assert_eq!(
            unsafe {
                visit(
                    descriptor.context,
                    count_unknown,
                    (&mut visited as *mut usize).cast::<c_void>(),
                )
            },
            BONDRY_STATUS_OK
        );
        assert_eq!(visited, 1);
        let release = descriptor.release.take().ok_or("missing release")?;
        unsafe { release(descriptor.context) };
        assert_eq!(unsafe { bondry_store_close_v1(store) }, BONDRY_STATUS_OK);
        Ok(())
    }

    #[test]
    fn first_descriptor_after_reopen_recovers_in_flight_records()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("dedup-recovery.db");
        let path = path.to_str().ok_or("non-UTF-8 test path")?.as_bytes();
        let key = [0x62; 32];
        let route = b"webhook.route";
        let namespace = b"provider:v1";
        let hash = [0x73; 32];

        let mut store = ptr::null_mut::<BondryStoreHandle>();
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
        let mut descriptor = derive(store)?;
        let mut result = 0;
        let mut state = 0;
        assert_eq!(
            unsafe {
                descriptor.claim.ok_or("missing claim")?(
                    descriptor.context,
                    route.as_ptr(),
                    route.len(),
                    namespace.as_ptr(),
                    namespace.len(),
                    hash.as_ptr(),
                    hash.len(),
                    BONDRY_DEDUP_RETAIN_COMPLETED_V1,
                    1_000,
                    &mut result,
                    &mut state,
                )
            },
            BONDRY_STATUS_OK
        );
        unsafe { descriptor.release.take().ok_or("missing release")?(descriptor.context) };
        assert_eq!(unsafe { bondry_store_close_v1(store) }, BONDRY_STATUS_OK);

        store = ptr::null_mut();
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
        let mut descriptor = derive(store)?;
        let mut found = 0;
        let mut record = BondryDedupRecordV1::zeroed();
        assert_eq!(
            unsafe {
                descriptor.query.ok_or("missing query")?(
                    descriptor.context,
                    route.as_ptr(),
                    route.len(),
                    namespace.as_ptr(),
                    namespace.len(),
                    hash.as_ptr(),
                    hash.len(),
                    &mut found,
                    &mut record,
                )
            },
            BONDRY_STATUS_OK
        );
        assert_eq!(found, 1);
        assert_eq!(record.state, BONDRY_DEDUP_STATE_UNKNOWN_V1);
        unsafe { descriptor.release.take().ok_or("missing release")?(descriptor.context) };
        assert_eq!(unsafe { bondry_store_close_v1(store) }, BONDRY_STATUS_OK);
        Ok(())
    }

    fn derive(
        store: *const BondryStoreHandle,
    ) -> Result<BondryDedupStoreV1, Box<dyn std::error::Error>> {
        let mut descriptor = BondryDedupStoreV1::zeroed();
        let status = unsafe {
            bondry_store_dedup_v1(
                store,
                DEFAULT_DEDUP_STORE_RECORDS,
                DEFAULT_DEDUP_STORE_BYTES,
                DEFAULT_DEDUP_STORE_RETENTION.as_secs(),
                &mut descriptor,
            )
        };
        if status != BONDRY_STATUS_OK {
            return Err(format!("dedup descriptor failed: {status}").into());
        }
        Ok(descriptor)
    }

    unsafe extern "C" fn count_unknown(
        context: *mut c_void,
        _record: *const BondryDedupRecordV1,
    ) -> u8 {
        if let Some(count) = unsafe { context.cast::<usize>().as_mut() } {
            *count += 1;
        }
        1
    }
}
