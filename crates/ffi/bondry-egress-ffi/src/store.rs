use std::{ffi::c_void, mem, ptr};

use bondry_delivery_store::{
    DeliveryFailure, DeliveryId, DeliveryIntent, DeliveryLog, DeliveryLogError, DeliveryOutcome,
    DeliveryRecord, DeliveryResultCategory, DeliveryResultMetadata, DeliveryState,
    PersistentDeliveryLogLimits, RouteId, StoreDurability,
};

const STATUS_OK: i32 = 0;
const STATUS_INVALID_ARGUMENT: i32 = 5;
const STATUS_NOT_FOUND: i32 = 20;
const STATUS_ALREADY_EXISTS: i32 = 28;
const STATUS_CAPACITY_EXHAUSTED: i32 = 32;
const STATUS_INVALID_TRANSITION: i32 = 33;

const DELIVERY_LOG_ABI_VERSION_V1: u32 = 1;
const STORE_THREADING_SERIALIZED_V1: u32 = 1;
const DELIVERY_STATE_PENDING_V1: u32 = 1;
const DELIVERY_STATE_TERMINAL_V1: u32 = 2;
const DELIVERY_OUTCOME_NONE_V1: u32 = 0;
const DELIVERY_OUTCOME_DELIVERED_V1: u32 = 1;
const DELIVERY_OUTCOME_FAILED_V1: u32 = 2;
const DELIVERY_OUTCOME_LOST_ON_SHUTDOWN_V1: u32 = 3;
const DELIVERY_OUTCOME_UNKNOWN_AFTER_CRASH_V1: u32 = 4;
const DELIVERY_FAILURE_NONE_V1: u32 = 0;
const DELIVERY_FAILURE_CANCELLED_V1: u32 = 1;
const DELIVERY_FAILURE_DEADLINE_EXCEEDED_V1: u32 = 2;
const DELIVERY_FAILURE_ENDPOINT_POLICY_V1: u32 = 3;
const DELIVERY_FAILURE_SECRET_UNAVAILABLE_V1: u32 = 4;
const DELIVERY_FAILURE_TRANSPORT_UNAVAILABLE_V1: u32 = 5;
const DELIVERY_FAILURE_RECEIVER_REJECTED_V1: u32 = 6;
const DELIVERY_FAILURE_RETRY_EXHAUSTED_V1: u32 = 7;
const DELIVERY_FAILURE_INTERNAL_V1: u32 = 8;
const DELIVERY_RESULT_NONE_V1: u32 = 0;
const DELIVERY_RESULT_SUCCEEDED_V1: u32 = 1;
const DELIVERY_RESULT_FAILED_V1: u32 = 2;
const DELIVERY_RESULT_INVALID_V1: u32 = 3;
const IDENTIFIER_CAPACITY: usize = 129;

#[repr(C)]
/// Opaque store handle supplied by `bondry-runtime-ffi`.
pub struct BondryStoreHandle {
    _private: [u8; 0],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct BondryDeliveryRecordV1 {
    route_id: [u8; IDENTIFIER_CAPACITY],
    delivery_id: [u8; IDENTIFIER_CAPACITY],
    accepted_at_unix_ms: u64,
    updated_at_unix_ms: u64,
    attempts: u16,
    state: u32,
    outcome: u32,
    failure: u32,
    result_category: u32,
    result_bytes: u32,
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
            outcome: 0,
            failure: 0,
            result_category: 0,
            result_bytes: 0,
        }
    }
}

type Release = unsafe extern "C" fn(*mut c_void);
type InsertIntent =
    unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize, u64) -> i32;
type RecordAttempt = unsafe extern "C" fn(*mut c_void, *const u8, usize, u16, u64) -> i32;
type RecordOutcome =
    unsafe extern "C" fn(*mut c_void, *const u8, usize, u32, u32, u32, u32, u64) -> i32;
type Query = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    usize,
    *mut u8,
    *mut BondryDeliveryRecordV1,
) -> i32;
type Recover = unsafe extern "C" fn(*mut c_void, u64, *mut u64) -> i32;

#[derive(Clone, Copy)]
#[repr(C)]
struct BondryDeliveryLogV1 {
    abi_version: u32,
    struct_size: usize,
    threading_model: u32,
    context: *mut c_void,
    release: Option<Release>,
    insert_intent: Option<InsertIntent>,
    record_attempt: Option<RecordAttempt>,
    record_outcome: Option<RecordOutcome>,
    query: Option<Query>,
    recover: Option<Recover>,
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

unsafe extern "C" {
    fn bondry_store_delivery_log_v1(
        store: *const BondryStoreHandle,
        max_records: u32,
        max_bytes: u64,
        retention_seconds: u64,
        out_log: *mut BondryDeliveryLogV1,
    ) -> i32;
}

pub(crate) struct ForeignDeliveryLog {
    descriptor: BondryDeliveryLogV1,
}

// SAFETY: The descriptor explicitly promises synchronized calls from arbitrary threads.
unsafe impl Send for ForeignDeliveryLog {}
// SAFETY: Every operation is atomic and the descriptor serializes its backing store.
unsafe impl Sync for ForeignDeliveryLog {}

impl ForeignDeliveryLog {
    pub(crate) unsafe fn derive(
        store: *const BondryStoreHandle,
        limits: PersistentDeliveryLogLimits,
    ) -> Result<Self, ()> {
        let mut descriptor = BondryDeliveryLogV1::zeroed();
        // SAFETY: The caller keeps store live for this synchronous descriptor derivation.
        let status = unsafe {
            bondry_store_delivery_log_v1(
                store,
                limits.records(),
                limits.bytes(),
                limits.retention().as_secs(),
                &mut descriptor,
            )
        };
        if status != STATUS_OK {
            return Err(());
        }
        if !valid_descriptor(&descriptor) {
            if !descriptor.context.is_null() {
                if let Some(release) = descriptor.release {
                    // SAFETY: A successful derivation transferred exactly one descriptor unit.
                    unsafe { release(descriptor.context) };
                }
            }
            return Err(());
        }
        Ok(Self { descriptor })
    }
}

impl Drop for ForeignDeliveryLog {
    fn drop(&mut self) {
        if let Some(release) = self.descriptor.release {
            // SAFETY: This wrapper owns exactly one validated descriptor context.
            unsafe { release(self.descriptor.context) };
        }
    }
}

impl DeliveryLog for ForeignDeliveryLog {
    fn durability(&self) -> StoreDurability {
        StoreDurability::Persistent
    }

    fn insert_intent(&self, intent: DeliveryIntent) -> Result<(), DeliveryLogError> {
        let route = intent.route().as_str().as_bytes();
        let delivery = intent.delivery().as_str().as_bytes();
        // SAFETY: Descriptor validation requires this callback and a live synchronized context.
        let status = unsafe {
            self.descriptor
                .insert_intent
                .ok_or(DeliveryLogError::Unavailable)?(
                self.descriptor.context,
                route.as_ptr(),
                route.len(),
                delivery.as_ptr(),
                delivery.len(),
                intent.accepted_at_unix_ms(),
            )
        };
        decode_status(status)
    }

    fn record_attempt(
        &self,
        delivery: &DeliveryId,
        attempts: u16,
        updated_at_unix_ms: u64,
    ) -> Result<(), DeliveryLogError> {
        let delivery = delivery.as_str().as_bytes();
        // SAFETY: Descriptor validation requires this callback and a live synchronized context.
        let status = unsafe {
            self.descriptor
                .record_attempt
                .ok_or(DeliveryLogError::Unavailable)?(
                self.descriptor.context,
                delivery.as_ptr(),
                delivery.len(),
                attempts,
                updated_at_unix_ms,
            )
        };
        decode_status(status)
    }

    fn record_outcome(
        &self,
        delivery: &DeliveryId,
        outcome: DeliveryOutcome,
        updated_at_unix_ms: u64,
        result: Option<DeliveryResultMetadata>,
    ) -> Result<(), DeliveryLogError> {
        let delivery = delivery.as_str().as_bytes();
        let (outcome, failure) = encode_outcome(outcome);
        let (result_category, result_bytes) = encode_result(result);
        // SAFETY: Descriptor validation requires this callback and a live synchronized context.
        let status = unsafe {
            self.descriptor
                .record_outcome
                .ok_or(DeliveryLogError::Unavailable)?(
                self.descriptor.context,
                delivery.as_ptr(),
                delivery.len(),
                outcome,
                failure,
                result_category,
                result_bytes,
                updated_at_unix_ms,
            )
        };
        decode_status(status)
    }

    fn delivery(&self, delivery: &DeliveryId) -> Result<Option<DeliveryRecord>, DeliveryLogError> {
        let delivery = delivery.as_str().as_bytes();
        let mut found = 0;
        let mut record = BondryDeliveryRecordV1::zeroed();
        // SAFETY: Descriptor validation requires this callback and writable outputs.
        let status = unsafe {
            self.descriptor.query.ok_or(DeliveryLogError::Unavailable)?(
                self.descriptor.context,
                delivery.as_ptr(),
                delivery.len(),
                &mut found,
                &mut record,
            )
        };
        decode_status(status)?;
        match found {
            0 => Ok(None),
            1 => decode_record(&record).map(Some),
            _ => Err(DeliveryLogError::Unavailable),
        }
    }

    fn recover_unfinished(&self, updated_at_unix_ms: u64) -> Result<u64, DeliveryLogError> {
        let mut recovered = 0;
        // SAFETY: Descriptor validation requires this callback and a writable output.
        let status = unsafe {
            self.descriptor
                .recover
                .ok_or(DeliveryLogError::Unavailable)?(
                self.descriptor.context,
                updated_at_unix_ms,
                &mut recovered,
            )
        };
        decode_status(status)?;
        Ok(recovered)
    }
}

fn valid_descriptor(descriptor: &BondryDeliveryLogV1) -> bool {
    descriptor.abi_version == DELIVERY_LOG_ABI_VERSION_V1
        && descriptor.struct_size == mem::size_of::<BondryDeliveryLogV1>()
        && descriptor.threading_model == STORE_THREADING_SERIALIZED_V1
        && !descriptor.context.is_null()
        && descriptor.release.is_some()
        && descriptor.insert_intent.is_some()
        && descriptor.record_attempt.is_some()
        && descriptor.record_outcome.is_some()
        && descriptor.query.is_some()
        && descriptor.recover.is_some()
}

fn decode_status(status: i32) -> Result<(), DeliveryLogError> {
    match status {
        STATUS_OK => Ok(()),
        STATUS_ALREADY_EXISTS => Err(DeliveryLogError::Conflict),
        STATUS_CAPACITY_EXHAUSTED => Err(DeliveryLogError::CapacityExhausted),
        STATUS_NOT_FOUND => Err(DeliveryLogError::NotFound),
        STATUS_INVALID_ARGUMENT | STATUS_INVALID_TRANSITION => {
            Err(DeliveryLogError::InvalidTransition)
        }
        _ => Err(DeliveryLogError::Unavailable),
    }
}

fn encode_outcome(outcome: DeliveryOutcome) -> (u32, u32) {
    match outcome {
        DeliveryOutcome::Delivered => (DELIVERY_OUTCOME_DELIVERED_V1, DELIVERY_FAILURE_NONE_V1),
        DeliveryOutcome::Failed(failure) => (DELIVERY_OUTCOME_FAILED_V1, encode_failure(failure)),
        DeliveryOutcome::LostOnShutdown => (
            DELIVERY_OUTCOME_LOST_ON_SHUTDOWN_V1,
            DELIVERY_FAILURE_NONE_V1,
        ),
        DeliveryOutcome::UnknownAfterCrash => (
            DELIVERY_OUTCOME_UNKNOWN_AFTER_CRASH_V1,
            DELIVERY_FAILURE_NONE_V1,
        ),
    }
}

const fn encode_failure(failure: DeliveryFailure) -> u32 {
    match failure {
        DeliveryFailure::Cancelled => DELIVERY_FAILURE_CANCELLED_V1,
        DeliveryFailure::DeadlineExceeded => DELIVERY_FAILURE_DEADLINE_EXCEEDED_V1,
        DeliveryFailure::EndpointPolicy => DELIVERY_FAILURE_ENDPOINT_POLICY_V1,
        DeliveryFailure::SecretUnavailable => DELIVERY_FAILURE_SECRET_UNAVAILABLE_V1,
        DeliveryFailure::TransportUnavailable => DELIVERY_FAILURE_TRANSPORT_UNAVAILABLE_V1,
        DeliveryFailure::ReceiverRejected => DELIVERY_FAILURE_RECEIVER_REJECTED_V1,
        DeliveryFailure::RetryExhausted => DELIVERY_FAILURE_RETRY_EXHAUSTED_V1,
        DeliveryFailure::Internal => DELIVERY_FAILURE_INTERNAL_V1,
    }
}

fn encode_result(result: Option<DeliveryResultMetadata>) -> (u32, u32) {
    result.map_or((DELIVERY_RESULT_NONE_V1, 0), |result| {
        let category = match result.category() {
            DeliveryResultCategory::Succeeded => DELIVERY_RESULT_SUCCEEDED_V1,
            DeliveryResultCategory::Failed => DELIVERY_RESULT_FAILED_V1,
            DeliveryResultCategory::Invalid => DELIVERY_RESULT_INVALID_V1,
        };
        (category, result.bytes())
    })
}

fn decode_record(record: &BondryDeliveryRecordV1) -> Result<DeliveryRecord, DeliveryLogError> {
    let route =
        RouteId::new(terminated(&record.route_id)?).map_err(|_| DeliveryLogError::Unavailable)?;
    let delivery = DeliveryId::new(terminated(&record.delivery_id)?)
        .map_err(|_| DeliveryLogError::Unavailable)?;
    let state = match (record.state, record.outcome, record.failure) {
        (DELIVERY_STATE_PENDING_V1, DELIVERY_OUTCOME_NONE_V1, DELIVERY_FAILURE_NONE_V1) => {
            DeliveryState::Pending
        }
        (DELIVERY_STATE_TERMINAL_V1, outcome, failure) => {
            DeliveryState::Terminal(decode_outcome(outcome, failure)?)
        }
        _ => return Err(DeliveryLogError::Unavailable),
    };
    let result = decode_result(record.result_category, record.result_bytes)?;
    Ok(DeliveryRecord::from_stored_parts(
        DeliveryIntent::new(route, delivery, record.accepted_at_unix_ms),
        record.attempts,
        state,
        record.updated_at_unix_ms,
        result,
    ))
}

fn decode_outcome(outcome: u32, failure: u32) -> Result<DeliveryOutcome, DeliveryLogError> {
    match (outcome, failure) {
        (DELIVERY_OUTCOME_DELIVERED_V1, DELIVERY_FAILURE_NONE_V1) => Ok(DeliveryOutcome::Delivered),
        (DELIVERY_OUTCOME_FAILED_V1, failure) => {
            decode_failure(failure).map(DeliveryOutcome::Failed)
        }
        (DELIVERY_OUTCOME_LOST_ON_SHUTDOWN_V1, DELIVERY_FAILURE_NONE_V1) => {
            Ok(DeliveryOutcome::LostOnShutdown)
        }
        (DELIVERY_OUTCOME_UNKNOWN_AFTER_CRASH_V1, DELIVERY_FAILURE_NONE_V1) => {
            Ok(DeliveryOutcome::UnknownAfterCrash)
        }
        _ => Err(DeliveryLogError::Unavailable),
    }
}

fn decode_failure(failure: u32) -> Result<DeliveryFailure, DeliveryLogError> {
    match failure {
        DELIVERY_FAILURE_CANCELLED_V1 => Ok(DeliveryFailure::Cancelled),
        DELIVERY_FAILURE_DEADLINE_EXCEEDED_V1 => Ok(DeliveryFailure::DeadlineExceeded),
        DELIVERY_FAILURE_ENDPOINT_POLICY_V1 => Ok(DeliveryFailure::EndpointPolicy),
        DELIVERY_FAILURE_SECRET_UNAVAILABLE_V1 => Ok(DeliveryFailure::SecretUnavailable),
        DELIVERY_FAILURE_TRANSPORT_UNAVAILABLE_V1 => Ok(DeliveryFailure::TransportUnavailable),
        DELIVERY_FAILURE_RECEIVER_REJECTED_V1 => Ok(DeliveryFailure::ReceiverRejected),
        DELIVERY_FAILURE_RETRY_EXHAUSTED_V1 => Ok(DeliveryFailure::RetryExhausted),
        DELIVERY_FAILURE_INTERNAL_V1 => Ok(DeliveryFailure::Internal),
        _ => Err(DeliveryLogError::Unavailable),
    }
}

fn decode_result(
    category: u32,
    bytes: u32,
) -> Result<Option<DeliveryResultMetadata>, DeliveryLogError> {
    match category {
        DELIVERY_RESULT_NONE_V1 if bytes == 0 => Ok(None),
        DELIVERY_RESULT_SUCCEEDED_V1 => Ok(Some(DeliveryResultMetadata::new(
            DeliveryResultCategory::Succeeded,
            bytes,
        ))),
        DELIVERY_RESULT_FAILED_V1 => Ok(Some(DeliveryResultMetadata::new(
            DeliveryResultCategory::Failed,
            bytes,
        ))),
        DELIVERY_RESULT_INVALID_V1 => Ok(Some(DeliveryResultMetadata::new(
            DeliveryResultCategory::Invalid,
            bytes,
        ))),
        _ => Err(DeliveryLogError::Unavailable),
    }
}

fn terminated(bytes: &[u8; IDENTIFIER_CAPACITY]) -> Result<&str, DeliveryLogError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(DeliveryLogError::Unavailable)?;
    std::str::from_utf8(&bytes[..end]).map_err(|_| DeliveryLogError::Unavailable)
}

#[cfg(test)]
mod tests {
    use std::{ptr, sync::Arc};

    use bondry_delivery_store::{
        DeliveryId, DeliveryIntent, DeliveryLog, DeliveryOutcome, DeliveryState,
        PersistentDeliveryLogLimits, RouteId,
    };
    use tempfile::TempDir;

    use super::{BondryStoreHandle, ForeignDeliveryLog, STATUS_OK};

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

    #[test]
    fn round_trips_the_runtime_store_descriptor() -> Result<(), Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("egress.db");
        let path = path.to_string_lossy();
        let key = [0x24; 32];
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
            STATUS_OK
        );
        let log =
            unsafe { ForeignDeliveryLog::derive(store, PersistentDeliveryLogLimits::default()) }
                .map_err(|()| "descriptor derivation failed")?;
        assert_eq!(unsafe { bondry_store_close_v1(store) }, STATUS_OK);
        let log: Arc<dyn DeliveryLog> = Arc::new(log);
        let delivery = DeliveryId::new("delivery_ffi")?;
        log.insert_intent(DeliveryIntent::new(
            RouteId::new("route_ffi")?,
            delivery.clone(),
            100,
        ))?;
        log.record_attempt(&delivery, 1, 110)?;
        log.record_outcome(&delivery, DeliveryOutcome::Delivered, 120, None)?;
        assert_eq!(
            log.delivery(&delivery)?.map(|record| record.state()),
            Some(DeliveryState::Terminal(DeliveryOutcome::Delivered))
        );
        Ok(())
    }
}
