use std::{ffi::c_void, mem, ptr, slice, sync::Arc};

use bondry_delivery_store::{
    DeliveryFailure, DeliveryId, DeliveryIntent, DeliveryLog, DeliveryLogError, DeliveryOutcome,
    DeliveryRecord, DeliveryResultCategory, DeliveryResultMetadata, DeliveryState,
    PersistentDeliveryLogLimits, RouteId,
};
use bondry_store_sqlcipher::SqlCipherDeliveryLog;

use crate::{
    BONDRY_STATUS_ALREADY_EXISTS, BONDRY_STATUS_CAPACITY_EXHAUSTED, BONDRY_STATUS_INVALID_ARGUMENT,
    BONDRY_STATUS_INVALID_TRANSITION, BONDRY_STATUS_NOT_FOUND, BONDRY_STATUS_NULL_POINTER,
    BONDRY_STATUS_OK, BONDRY_STATUS_UNAVAILABLE, BondryStoreHandle, StoreHandle, catch_status,
};

/// ABI version of the delivery-log descriptor.
pub const BONDRY_DELIVERY_LOG_ABI_VERSION_V1: u32 = 1;
/// The descriptor may be called from any thread and serializes storage access internally.
pub const BONDRY_STORE_THREADING_SERIALIZED_V1: u32 = 1;
/// A delivery remains pending.
pub const BONDRY_DELIVERY_STATE_PENDING_V1: u32 = 1;
/// A delivery has one terminal outcome.
pub const BONDRY_DELIVERY_STATE_TERMINAL_V1: u32 = 2;
/// A pending delivery has no terminal outcome.
pub const BONDRY_DELIVERY_OUTCOME_NONE_V1: u32 = 0;
/// The receiver accepted the delivery.
pub const BONDRY_DELIVERY_OUTCOME_DELIVERED_V1: u32 = 1;
/// Delivery terminated with a failure category.
pub const BONDRY_DELIVERY_OUTCOME_FAILED_V1: u32 = 2;
/// Graceful shutdown ended before delivery finished.
pub const BONDRY_DELIVERY_OUTCOME_LOST_ON_SHUTDOWN_V1: u32 = 3;
/// A durable pending intent was found after restart.
pub const BONDRY_DELIVERY_OUTCOME_UNKNOWN_AFTER_CRASH_V1: u32 = 4;
/// No delivery failure is present.
pub const BONDRY_DELIVERY_FAILURE_NONE_V1: u32 = 0;
/// Route shutdown or disable cancelled delivery.
pub const BONDRY_DELIVERY_FAILURE_CANCELLED_V1: u32 = 1;
/// The attempt exceeded its deadline.
pub const BONDRY_DELIVERY_FAILURE_DEADLINE_EXCEEDED_V1: u32 = 2;
/// Endpoint security policy rejected the target.
pub const BONDRY_DELIVERY_FAILURE_ENDPOINT_POLICY_V1: u32 = 3;
/// Required secret material was unavailable.
pub const BONDRY_DELIVERY_FAILURE_SECRET_UNAVAILABLE_V1: u32 = 4;
/// The transport was unavailable.
pub const BONDRY_DELIVERY_FAILURE_TRANSPORT_UNAVAILABLE_V1: u32 = 5;
/// The receiver rejected the operation.
pub const BONDRY_DELIVERY_FAILURE_RECEIVER_REJECTED_V1: u32 = 6;
/// The bounded retry policy was exhausted.
pub const BONDRY_DELIVERY_FAILURE_RETRY_EXHAUSTED_V1: u32 = 7;
/// An internal invariant prevented delivery.
pub const BONDRY_DELIVERY_FAILURE_INTERNAL_V1: u32 = 8;
/// No result metadata is present.
pub const BONDRY_DELIVERY_RESULT_NONE_V1: u32 = 0;
/// A valid successful result was returned.
pub const BONDRY_DELIVERY_RESULT_SUCCEEDED_V1: u32 = 1;
/// A valid failed result was returned.
pub const BONDRY_DELIVERY_RESULT_FAILED_V1: u32 = 2;
/// A result violated its framing or size contract.
pub const BONDRY_DELIVERY_RESULT_INVALID_V1: u32 = 3;

const IDENTIFIER_CAPACITY: usize = 129;

/// Fixed delivery status returned by the store descriptor without sensitive data.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryDeliveryRecordV1 {
    /// UTF-8 route identifier terminated with zero.
    pub route_id: [u8; IDENTIFIER_CAPACITY],
    /// UTF-8 delivery identifier terminated with zero.
    pub delivery_id: [u8; IDENTIFIER_CAPACITY],
    /// Original acceptance time in Unix milliseconds.
    pub accepted_at_unix_ms: u64,
    /// Most recent transition time in Unix milliseconds.
    pub updated_at_unix_ms: u64,
    /// Number of attempts started.
    pub attempts: u16,
    /// Pending or terminal state constant.
    pub state: u32,
    /// Terminal outcome constant, or none while pending.
    pub outcome: u32,
    /// Failure category for a failed outcome, otherwise none.
    pub failure: u32,
    /// Optional result category, otherwise none.
    pub result_category: u32,
    /// Bounded result size when a result category is present.
    pub result_bytes: u32,
}

impl BondryDeliveryRecordV1 {
    const fn zeroed() -> Self {
        Self {
            route_id: [0; IDENTIFIER_CAPACITY],
            delivery_id: [0; IDENTIFIER_CAPACITY],
            accepted_at_unix_ms: 0,
            updated_at_unix_ms: 0,
            attempts: 0,
            state: 0,
            outcome: BONDRY_DELIVERY_OUTCOME_NONE_V1,
            failure: BONDRY_DELIVERY_FAILURE_NONE_V1,
            result_category: BONDRY_DELIVERY_RESULT_NONE_V1,
            result_bytes: 0,
        }
    }
}

/// Releases the descriptor's single owned context unit.
pub type BondryDeliveryLogReleaseV1 = unsafe extern "C" fn(context: *mut c_void);
/// Inserts an intent before any transport submission.
pub type BondryDeliveryLogInsertIntentV1 = unsafe extern "C" fn(
    context: *mut c_void,
    route_id: *const u8,
    route_id_length: usize,
    delivery_id: *const u8,
    delivery_id_length: usize,
    accepted_at_unix_ms: u64,
) -> i32;
/// Records a strictly increasing attempt count.
pub type BondryDeliveryLogRecordAttemptV1 = unsafe extern "C" fn(
    context: *mut c_void,
    delivery_id: *const u8,
    delivery_id_length: usize,
    attempts: u16,
    updated_at_unix_ms: u64,
) -> i32;
/// Records one terminal outcome.
pub type BondryDeliveryLogRecordOutcomeV1 = unsafe extern "C" fn(
    context: *mut c_void,
    delivery_id: *const u8,
    delivery_id_length: usize,
    outcome: u32,
    failure: u32,
    result_category: u32,
    result_bytes: u32,
    updated_at_unix_ms: u64,
) -> i32;
/// Loads one delivery record.
pub type BondryDeliveryLogQueryV1 = unsafe extern "C" fn(
    context: *mut c_void,
    delivery_id: *const u8,
    delivery_id_length: usize,
    out_found: *mut u8,
    out_record: *mut BondryDeliveryRecordV1,
) -> i32;
/// Marks every unfinished intent unknown after restart.
pub type BondryDeliveryLogRecoverV1 = unsafe extern "C" fn(
    context: *mut c_void,
    updated_at_unix_ms: u64,
    out_recovered: *mut u64,
) -> i32;

/// Versioned persistent delivery-log descriptor derived from one retained store.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryDeliveryLogV1 {
    /// Must equal `BONDRY_DELIVERY_LOG_ABI_VERSION_V1`.
    pub abi_version: u32,
    /// Byte size of this descriptor.
    pub struct_size: usize,
    /// Serialized-threading model constant.
    pub threading_model: u32,
    /// Owned callback context released exactly once.
    pub context: *mut c_void,
    /// Required context release callback.
    pub release: Option<BondryDeliveryLogReleaseV1>,
    /// Required atomic intent insertion callback.
    pub insert_intent: Option<BondryDeliveryLogInsertIntentV1>,
    /// Required atomic attempt callback.
    pub record_attempt: Option<BondryDeliveryLogRecordAttemptV1>,
    /// Required atomic outcome callback.
    pub record_outcome: Option<BondryDeliveryLogRecordOutcomeV1>,
    /// Required status query callback.
    pub query: Option<BondryDeliveryLogQueryV1>,
    /// Required atomic recovery callback.
    pub recover: Option<BondryDeliveryLogRecoverV1>,
}

impl BondryDeliveryLogV1 {
    const fn zeroed() -> Self {
        Self {
            abi_version: 0,
            struct_size: 0,
            threading_model: 0,
            context: ptr::null_mut(),
            release: None,
            insert_intent: None,
            record_attempt: None,
            record_outcome: None,
            query: None,
            recover: None,
        }
    }
}

/// Derives a persistent delivery-log descriptor from the existing opaque store handle.
///
/// # Safety
///
/// `store` must remain live for this call. `out_log` must be writable and must be released exactly
/// once through its release callback after success. No descriptor ownership transfers on failure.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_store_delivery_log_v1(
    store: *const BondryStoreHandle,
    max_records: u32,
    max_bytes: u64,
    retention_seconds: u64,
    out_log: *mut BondryDeliveryLogV1,
) -> i32 {
    if out_log.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: The caller guarantees writable output memory.
    unsafe { out_log.write(BondryDeliveryLogV1::zeroed()) };
    catch_status(|| {
        if store.is_null() {
            return BONDRY_STATUS_NULL_POINTER;
        }
        let Ok(limits) = PersistentDeliveryLogLimits::new(
            max_records,
            max_bytes,
            std::time::Duration::from_secs(retention_seconds),
        ) else {
            return BONDRY_STATUS_INVALID_ARGUMENT;
        };
        // SAFETY: The caller guarantees a live Arc-backed store for this synchronous operation.
        let store = unsafe { &*store.cast::<StoreHandle>() };
        let log = Arc::new(SqlCipherDeliveryLog::new(Arc::clone(&store.store), limits));
        let descriptor = BondryDeliveryLogV1 {
            abi_version: BONDRY_DELIVERY_LOG_ABI_VERSION_V1,
            struct_size: mem::size_of::<BondryDeliveryLogV1>(),
            threading_model: BONDRY_STORE_THREADING_SERIALIZED_V1,
            context: Arc::into_raw(log).cast_mut().cast::<c_void>(),
            release: Some(release_delivery_log),
            insert_intent: Some(insert_intent),
            record_attempt: Some(record_attempt),
            record_outcome: Some(record_outcome),
            query: Some(query_delivery),
            recover: Some(recover_unfinished),
        };
        // SAFETY: out_log was validated and receives one descriptor ownership unit.
        unsafe { out_log.write(descriptor) };
        BONDRY_STATUS_OK
    })
}

unsafe extern "C" fn release_delivery_log(context: *mut c_void) {
    if context.is_null() {
        return;
    }
    let _ = catch_status(|| {
        // SAFETY: The descriptor transfers exactly one Arc ownership unit to this callback.
        unsafe { drop(Arc::from_raw(context.cast::<SqlCipherDeliveryLog>())) };
        BONDRY_STATUS_OK
    });
}

unsafe extern "C" fn insert_intent(
    context: *mut c_void,
    route_id: *const u8,
    route_id_length: usize,
    delivery_id: *const u8,
    delivery_id_length: usize,
    accepted_at_unix_ms: u64,
) -> i32 {
    catch_status(|| {
        let Ok(log) = (unsafe { delivery_log(context) }) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let Ok(route) = (unsafe { parse_route_id(route_id, route_id_length) }) else {
            return BONDRY_STATUS_INVALID_ARGUMENT;
        };
        let Ok(delivery) = (unsafe { parse_delivery_id(delivery_id, delivery_id_length) }) else {
            return BONDRY_STATUS_INVALID_ARGUMENT;
        };
        delivery_error_status(log.insert_intent(DeliveryIntent::new(
            route,
            delivery,
            accepted_at_unix_ms,
        )))
    })
}

unsafe extern "C" fn record_attempt(
    context: *mut c_void,
    delivery_id: *const u8,
    delivery_id_length: usize,
    attempts: u16,
    updated_at_unix_ms: u64,
) -> i32 {
    catch_status(|| {
        let Ok(log) = (unsafe { delivery_log(context) }) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let Ok(delivery) = (unsafe { parse_delivery_id(delivery_id, delivery_id_length) }) else {
            return BONDRY_STATUS_INVALID_ARGUMENT;
        };
        delivery_error_status(log.record_attempt(&delivery, attempts, updated_at_unix_ms))
    })
}

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn record_outcome(
    context: *mut c_void,
    delivery_id: *const u8,
    delivery_id_length: usize,
    outcome: u32,
    failure: u32,
    result_category: u32,
    result_bytes: u32,
    updated_at_unix_ms: u64,
) -> i32 {
    catch_status(|| {
        let Ok(log) = (unsafe { delivery_log(context) }) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let Ok(delivery) = (unsafe { parse_delivery_id(delivery_id, delivery_id_length) }) else {
            return BONDRY_STATUS_INVALID_ARGUMENT;
        };
        let Some(outcome) = decode_outcome(outcome, failure) else {
            return BONDRY_STATUS_INVALID_ARGUMENT;
        };
        let Some(result) = decode_result(result_category, result_bytes) else {
            return BONDRY_STATUS_INVALID_ARGUMENT;
        };
        delivery_error_status(log.record_outcome(&delivery, outcome, updated_at_unix_ms, result))
    })
}

unsafe extern "C" fn query_delivery(
    context: *mut c_void,
    delivery_id: *const u8,
    delivery_id_length: usize,
    out_found: *mut u8,
    out_record: *mut BondryDeliveryRecordV1,
) -> i32 {
    if out_found.is_null() || out_record.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: The caller guarantees writable output pointers.
    unsafe {
        out_found.write(0);
        out_record.write(BondryDeliveryRecordV1::zeroed());
    }
    catch_status(|| {
        let Ok(log) = (unsafe { delivery_log(context) }) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let Ok(delivery) = (unsafe { parse_delivery_id(delivery_id, delivery_id_length) }) else {
            return BONDRY_STATUS_INVALID_ARGUMENT;
        };
        let record = match log.delivery(&delivery) {
            Ok(record) => record,
            Err(error) => return delivery_error(error),
        };
        let Some(record) = record else {
            return BONDRY_STATUS_OK;
        };
        // SAFETY: Outputs remain writable for this call.
        unsafe {
            out_record.write(encode_record(&record));
            out_found.write(1);
        }
        BONDRY_STATUS_OK
    })
}

unsafe extern "C" fn recover_unfinished(
    context: *mut c_void,
    updated_at_unix_ms: u64,
    out_recovered: *mut u64,
) -> i32 {
    if out_recovered.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: The caller guarantees writable output memory.
    unsafe { out_recovered.write(0) };
    catch_status(|| {
        let Ok(log) = (unsafe { delivery_log(context) }) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        match log.recover_unfinished(updated_at_unix_ms) {
            Ok(recovered) => {
                // SAFETY: out_recovered remains writable for this call.
                unsafe { out_recovered.write(recovered) };
                BONDRY_STATUS_OK
            }
            Err(error) => delivery_error(error),
        }
    })
}

unsafe fn delivery_log<'a>(context: *mut c_void) -> Result<&'a SqlCipherDeliveryLog, ()> {
    if context.is_null() {
        return Err(());
    }
    // SAFETY: The descriptor keeps its Arc allocation live until release.
    Ok(unsafe { &*context.cast::<SqlCipherDeliveryLog>() })
}

unsafe fn identifier<'a>(bytes: *const u8, length: usize) -> Result<&'a str, ()> {
    if bytes.is_null() || length > isize::MAX as usize {
        return Err(());
    }
    // SAFETY: The callback contract requires readable input for the declared length.
    std::str::from_utf8(unsafe { slice::from_raw_parts(bytes, length) }).map_err(|_| ())
}

unsafe fn parse_route_id(bytes: *const u8, length: usize) -> Result<RouteId, ()> {
    // SAFETY: The caller forwards the same readable identifier contract.
    RouteId::new(unsafe { identifier(bytes, length) }?).map_err(|_| ())
}

unsafe fn parse_delivery_id(bytes: *const u8, length: usize) -> Result<DeliveryId, ()> {
    // SAFETY: The caller forwards the same readable identifier contract.
    DeliveryId::new(unsafe { identifier(bytes, length) }?).map_err(|_| ())
}

fn delivery_error_status(result: Result<(), DeliveryLogError>) -> i32 {
    result.map_or_else(delivery_error, |()| BONDRY_STATUS_OK)
}

fn delivery_error(error: DeliveryLogError) -> i32 {
    match error {
        DeliveryLogError::Conflict => BONDRY_STATUS_ALREADY_EXISTS,
        DeliveryLogError::CapacityExhausted => BONDRY_STATUS_CAPACITY_EXHAUSTED,
        DeliveryLogError::NotFound => BONDRY_STATUS_NOT_FOUND,
        DeliveryLogError::InvalidTransition => BONDRY_STATUS_INVALID_TRANSITION,
        DeliveryLogError::Unavailable => BONDRY_STATUS_UNAVAILABLE,
    }
}

fn decode_outcome(outcome: u32, failure: u32) -> Option<DeliveryOutcome> {
    match (outcome, failure) {
        (BONDRY_DELIVERY_OUTCOME_DELIVERED_V1, BONDRY_DELIVERY_FAILURE_NONE_V1) => {
            Some(DeliveryOutcome::Delivered)
        }
        (BONDRY_DELIVERY_OUTCOME_FAILED_V1, failure) => {
            decode_failure(failure).map(DeliveryOutcome::Failed)
        }
        (BONDRY_DELIVERY_OUTCOME_LOST_ON_SHUTDOWN_V1, BONDRY_DELIVERY_FAILURE_NONE_V1) => {
            Some(DeliveryOutcome::LostOnShutdown)
        }
        _ => None,
    }
}

fn decode_failure(failure: u32) -> Option<DeliveryFailure> {
    match failure {
        BONDRY_DELIVERY_FAILURE_CANCELLED_V1 => Some(DeliveryFailure::Cancelled),
        BONDRY_DELIVERY_FAILURE_DEADLINE_EXCEEDED_V1 => Some(DeliveryFailure::DeadlineExceeded),
        BONDRY_DELIVERY_FAILURE_ENDPOINT_POLICY_V1 => Some(DeliveryFailure::EndpointPolicy),
        BONDRY_DELIVERY_FAILURE_SECRET_UNAVAILABLE_V1 => Some(DeliveryFailure::SecretUnavailable),
        BONDRY_DELIVERY_FAILURE_TRANSPORT_UNAVAILABLE_V1 => {
            Some(DeliveryFailure::TransportUnavailable)
        }
        BONDRY_DELIVERY_FAILURE_RECEIVER_REJECTED_V1 => Some(DeliveryFailure::ReceiverRejected),
        BONDRY_DELIVERY_FAILURE_RETRY_EXHAUSTED_V1 => Some(DeliveryFailure::RetryExhausted),
        BONDRY_DELIVERY_FAILURE_INTERNAL_V1 => Some(DeliveryFailure::Internal),
        _ => None,
    }
}

fn decode_result(category: u32, bytes: u32) -> Option<Option<DeliveryResultMetadata>> {
    match category {
        BONDRY_DELIVERY_RESULT_NONE_V1 if bytes == 0 => Some(None),
        BONDRY_DELIVERY_RESULT_SUCCEEDED_V1 => Some(Some(DeliveryResultMetadata::new(
            DeliveryResultCategory::Succeeded,
            bytes,
        ))),
        BONDRY_DELIVERY_RESULT_FAILED_V1 => Some(Some(DeliveryResultMetadata::new(
            DeliveryResultCategory::Failed,
            bytes,
        ))),
        BONDRY_DELIVERY_RESULT_INVALID_V1 => Some(Some(DeliveryResultMetadata::new(
            DeliveryResultCategory::Invalid,
            bytes,
        ))),
        _ => None,
    }
}

fn encode_record(record: &DeliveryRecord) -> BondryDeliveryRecordV1 {
    let (state, outcome, failure) = match record.state() {
        DeliveryState::Pending => (
            BONDRY_DELIVERY_STATE_PENDING_V1,
            BONDRY_DELIVERY_OUTCOME_NONE_V1,
            BONDRY_DELIVERY_FAILURE_NONE_V1,
        ),
        DeliveryState::Terminal(outcome) => {
            let (outcome, failure) = encode_outcome(outcome);
            (BONDRY_DELIVERY_STATE_TERMINAL_V1, outcome, failure)
        }
    };
    let (result_category, result_bytes) =
        record
            .result()
            .map_or((BONDRY_DELIVERY_RESULT_NONE_V1, 0), |result| {
                let category = match result.category() {
                    DeliveryResultCategory::Succeeded => BONDRY_DELIVERY_RESULT_SUCCEEDED_V1,
                    DeliveryResultCategory::Failed => BONDRY_DELIVERY_RESULT_FAILED_V1,
                    DeliveryResultCategory::Invalid => BONDRY_DELIVERY_RESULT_INVALID_V1,
                };
                (category, result.bytes())
            });
    BondryDeliveryRecordV1 {
        route_id: terminated(record.intent().route().as_str()),
        delivery_id: terminated(record.intent().delivery().as_str()),
        accepted_at_unix_ms: record.intent().accepted_at_unix_ms(),
        updated_at_unix_ms: record.updated_at_unix_ms(),
        attempts: record.attempts(),
        state,
        outcome,
        failure,
        result_category,
        result_bytes,
    }
}

fn encode_outcome(outcome: DeliveryOutcome) -> (u32, u32) {
    match outcome {
        DeliveryOutcome::Delivered => (
            BONDRY_DELIVERY_OUTCOME_DELIVERED_V1,
            BONDRY_DELIVERY_FAILURE_NONE_V1,
        ),
        DeliveryOutcome::Failed(failure) => {
            (BONDRY_DELIVERY_OUTCOME_FAILED_V1, encode_failure(failure))
        }
        DeliveryOutcome::LostOnShutdown => (
            BONDRY_DELIVERY_OUTCOME_LOST_ON_SHUTDOWN_V1,
            BONDRY_DELIVERY_FAILURE_NONE_V1,
        ),
        DeliveryOutcome::UnknownAfterCrash => (
            BONDRY_DELIVERY_OUTCOME_UNKNOWN_AFTER_CRASH_V1,
            BONDRY_DELIVERY_FAILURE_NONE_V1,
        ),
    }
}

const fn encode_failure(failure: DeliveryFailure) -> u32 {
    match failure {
        DeliveryFailure::Cancelled => BONDRY_DELIVERY_FAILURE_CANCELLED_V1,
        DeliveryFailure::DeadlineExceeded => BONDRY_DELIVERY_FAILURE_DEADLINE_EXCEEDED_V1,
        DeliveryFailure::EndpointPolicy => BONDRY_DELIVERY_FAILURE_ENDPOINT_POLICY_V1,
        DeliveryFailure::SecretUnavailable => BONDRY_DELIVERY_FAILURE_SECRET_UNAVAILABLE_V1,
        DeliveryFailure::TransportUnavailable => BONDRY_DELIVERY_FAILURE_TRANSPORT_UNAVAILABLE_V1,
        DeliveryFailure::ReceiverRejected => BONDRY_DELIVERY_FAILURE_RECEIVER_REJECTED_V1,
        DeliveryFailure::RetryExhausted => BONDRY_DELIVERY_FAILURE_RETRY_EXHAUSTED_V1,
        DeliveryFailure::Internal => BONDRY_DELIVERY_FAILURE_INTERNAL_V1,
    }
}

fn terminated(value: &str) -> [u8; IDENTIFIER_CAPACITY] {
    let mut output = [0; IDENTIFIER_CAPACITY];
    output[..value.len()].copy_from_slice(value.as_bytes());
    output
}

#[cfg(test)]
mod tests {
    use std::{mem::MaybeUninit, ptr};

    use tempfile::TempDir;

    use super::{
        BONDRY_DELIVERY_FAILURE_NONE_V1, BONDRY_DELIVERY_LOG_ABI_VERSION_V1,
        BONDRY_DELIVERY_OUTCOME_DELIVERED_V1, BONDRY_DELIVERY_OUTCOME_NONE_V1,
        BONDRY_DELIVERY_RESULT_NONE_V1, BONDRY_DELIVERY_STATE_PENDING_V1,
        BONDRY_DELIVERY_STATE_TERMINAL_V1, BondryDeliveryLogV1, BondryDeliveryRecordV1,
        bondry_store_delivery_log_v1,
    };
    use crate::{BONDRY_STATUS_OK, BondryStoreHandle, bondry_store_close_v1, bondry_store_open_v1};

    #[test]
    fn descriptor_owns_and_drives_one_persistent_log() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("delivery.db");
        let path = path.to_string_lossy();
        let key = [0x42; 32];
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
        let mut descriptor = MaybeUninit::<BondryDeliveryLogV1>::uninit();
        assert_eq!(
            unsafe {
                bondry_store_delivery_log_v1(
                    store,
                    1_024,
                    1_024 * 1_024,
                    86_400,
                    descriptor.as_mut_ptr(),
                )
            },
            BONDRY_STATUS_OK
        );
        let descriptor = unsafe { descriptor.assume_init() };
        assert_eq!(descriptor.abi_version, BONDRY_DELIVERY_LOG_ABI_VERSION_V1);
        let route = b"watchdog";
        let delivery = b"delivery_1";
        assert_eq!(
            unsafe {
                descriptor.insert_intent.ok_or("missing insert")?(
                    descriptor.context,
                    route.as_ptr(),
                    route.len(),
                    delivery.as_ptr(),
                    delivery.len(),
                    100,
                )
            },
            BONDRY_STATUS_OK
        );
        let mut found = 0;
        let mut record = MaybeUninit::<BondryDeliveryRecordV1>::uninit();
        assert_eq!(
            unsafe {
                descriptor.query.ok_or("missing query")?(
                    descriptor.context,
                    delivery.as_ptr(),
                    delivery.len(),
                    &mut found,
                    record.as_mut_ptr(),
                )
            },
            BONDRY_STATUS_OK
        );
        let record = unsafe { record.assume_init() };
        assert_eq!(found, 1);
        assert_eq!(record.state, BONDRY_DELIVERY_STATE_PENDING_V1);
        assert_eq!(record.outcome, BONDRY_DELIVERY_OUTCOME_NONE_V1);
        assert_eq!(
            unsafe {
                descriptor.record_attempt.ok_or("missing attempt")?(
                    descriptor.context,
                    delivery.as_ptr(),
                    delivery.len(),
                    1,
                    110,
                )
            },
            BONDRY_STATUS_OK
        );
        assert_eq!(
            unsafe {
                descriptor.record_outcome.ok_or("missing outcome")?(
                    descriptor.context,
                    delivery.as_ptr(),
                    delivery.len(),
                    BONDRY_DELIVERY_OUTCOME_DELIVERED_V1,
                    BONDRY_DELIVERY_FAILURE_NONE_V1,
                    BONDRY_DELIVERY_RESULT_NONE_V1,
                    0,
                    120,
                )
            },
            BONDRY_STATUS_OK
        );
        let mut terminal = MaybeUninit::<BondryDeliveryRecordV1>::uninit();
        assert_eq!(
            unsafe {
                descriptor.query.ok_or("missing query")?(
                    descriptor.context,
                    delivery.as_ptr(),
                    delivery.len(),
                    &mut found,
                    terminal.as_mut_ptr(),
                )
            },
            BONDRY_STATUS_OK
        );
        assert_eq!(
            unsafe { terminal.assume_init() }.state,
            BONDRY_DELIVERY_STATE_TERMINAL_V1
        );
        unsafe { descriptor.release.ok_or("missing release")?(descriptor.context) };
        assert_eq!(unsafe { bondry_store_close_v1(store) }, BONDRY_STATUS_OK);
        Ok(())
    }
}
