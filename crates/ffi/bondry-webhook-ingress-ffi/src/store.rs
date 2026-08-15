use std::{
    ffi::c_void,
    panic::{AssertUnwindSafe, catch_unwind},
};

use bondry_delivery_store::{
    DedupClaim, DedupClaimPolicy, DedupKey, DedupRecord, DedupResolution, DedupState, DedupStore,
    DedupStoreError, RouteId, StoreDurability, TrustedDeliveryIdHash, VerifierNamespace,
};

use crate::{
    BONDRY_DEDUP_CLAIMED_V1, BONDRY_DEDUP_DUPLICATE_V1, BONDRY_DEDUP_EXPIRE_COMPLETED_V1,
    BONDRY_DEDUP_RESOLVE_COMPLETED_V1, BONDRY_DEDUP_RESOLVE_RETRY_ALLOWED_V1,
    BONDRY_DEDUP_RETAIN_COMPLETED_V1, BONDRY_DEDUP_STATE_COMPLETED_V1,
    BONDRY_DEDUP_STATE_IN_FLIGHT_V1, BONDRY_DEDUP_STATE_UNKNOWN_V1,
    BONDRY_DEDUP_STORE_ABI_VERSION_V1, BONDRY_DEDUP_THREADING_SERIALIZED_V1,
    BONDRY_STATUS_CAPACITY_EXHAUSTED, BONDRY_STATUS_INVALID_TRANSITION, BONDRY_STATUS_NOT_FOUND,
    BONDRY_STATUS_OK, BONDRY_STORE_DURABILITY_PERSISTENT_V1, BondryDedupRecordV1,
    BondryDedupStoreV1,
};

pub(crate) struct ForeignDedupStore {
    descriptor: BondryDedupStoreV1,
}

// SAFETY: Descriptor validation requires serialized operations callable from arbitrary threads.
unsafe impl Send for ForeignDedupStore {}
// SAFETY: The runtime descriptor synchronizes every persistent transition.
unsafe impl Sync for ForeignDedupStore {}

impl ForeignDedupStore {
    pub(crate) unsafe fn retain(descriptor: &BondryDedupStoreV1) -> Result<Self, ()> {
        if descriptor.abi_version != BONDRY_DEDUP_STORE_ABI_VERSION_V1
            || descriptor.struct_size != size_of::<BondryDedupStoreV1>()
            || descriptor.threading_model != BONDRY_DEDUP_THREADING_SERIALIZED_V1
            || descriptor.durability != BONDRY_STORE_DURABILITY_PERSISTENT_V1
            || descriptor.context.is_null()
        {
            return Err(());
        }
        let (
            Some(retain),
            Some(release),
            Some(claim),
            Some(complete),
            Some(mark_unknown),
            Some(release_claim),
            Some(query),
            Some(recover),
            Some(resolve_unknown),
            Some(visit_unknown),
            Some(clear_completed),
        ) = (
            descriptor.retain,
            descriptor.release,
            descriptor.claim,
            descriptor.complete,
            descriptor.mark_unknown,
            descriptor.release_claim,
            descriptor.query,
            descriptor.recover,
            descriptor.resolve_unknown,
            descriptor.visit_unknown,
            descriptor.clear_completed,
        )
        else {
            return Err(());
        };
        // SAFETY: The registration descriptor remains live during this synchronous retain.
        let context = unsafe { retain(descriptor.context) };
        if context.is_null() {
            return Err(());
        }
        Ok(Self {
            descriptor: BondryDedupStoreV1 {
                context,
                retain: Some(retain),
                release: Some(release),
                claim: Some(claim),
                complete: Some(complete),
                mark_unknown: Some(mark_unknown),
                release_claim: Some(release_claim),
                query: Some(query),
                recover: Some(recover),
                resolve_unknown: Some(resolve_unknown),
                visit_unknown: Some(visit_unknown),
                clear_completed: Some(clear_completed),
                ..*descriptor
            },
        })
    }

    fn transition(
        &self,
        callback: Option<crate::BondryDedupTransitionV1>,
        key: &DedupKey,
        updated_at_unix_ms: u64,
    ) -> Result<(), DedupStoreError> {
        let callback = callback.ok_or(DedupStoreError::Unavailable)?;
        let (route, namespace, hash) = key_parts(key);
        // SAFETY: Key buffers remain borrowed for this synchronous descriptor call.
        let status = unsafe {
            callback(
                self.descriptor.context,
                route.as_ptr(),
                route.len(),
                namespace.as_ptr(),
                namespace.len(),
                hash.as_ptr(),
                hash.len(),
                updated_at_unix_ms,
            )
        };
        decode_status(status)
    }
}

impl Drop for ForeignDedupStore {
    fn drop(&mut self) {
        if let Some(release) = self.descriptor.release {
            // SAFETY: This wrapper owns one retained descriptor context.
            unsafe { release(self.descriptor.context) };
        }
    }
}

impl DedupStore for ForeignDedupStore {
    fn durability(&self) -> StoreDurability {
        StoreDurability::Persistent
    }

    fn claim(
        &self,
        key: DedupKey,
        policy: DedupClaimPolicy,
        updated_at_unix_ms: u64,
    ) -> Result<DedupClaim, DedupStoreError> {
        let callback = self.descriptor.claim.ok_or(DedupStoreError::Unavailable)?;
        let (route, namespace, hash) = key_parts(&key);
        let policy = match policy {
            DedupClaimPolicy::RetainCompleted => BONDRY_DEDUP_RETAIN_COMPLETED_V1,
            DedupClaimPolicy::ExpireCompleted => BONDRY_DEDUP_EXPIRE_COMPLETED_V1,
        };
        let mut result = 0;
        let mut state = 0;
        // SAFETY: Key buffers and outputs remain valid for this synchronous descriptor call.
        let status = unsafe {
            callback(
                self.descriptor.context,
                route.as_ptr(),
                route.len(),
                namespace.as_ptr(),
                namespace.len(),
                hash.as_ptr(),
                hash.len(),
                policy,
                updated_at_unix_ms,
                &mut result,
                &mut state,
            )
        };
        decode_status(status)?;
        match result {
            BONDRY_DEDUP_CLAIMED_V1 if state == 0 => Ok(DedupClaim::Claimed),
            BONDRY_DEDUP_DUPLICATE_V1 => decode_state(state).map(DedupClaim::Duplicate),
            _ => Err(DedupStoreError::Unavailable),
        }
    }

    fn complete(&self, key: &DedupKey, updated_at_unix_ms: u64) -> Result<(), DedupStoreError> {
        self.transition(self.descriptor.complete, key, updated_at_unix_ms)
    }

    fn mark_unknown(&self, key: &DedupKey, updated_at_unix_ms: u64) -> Result<(), DedupStoreError> {
        self.transition(self.descriptor.mark_unknown, key, updated_at_unix_ms)
    }

    fn release_claim(&self, key: &DedupKey) -> Result<(), DedupStoreError> {
        self.transition(self.descriptor.release_claim, key, 0)
    }

    fn record(&self, key: &DedupKey) -> Result<Option<DedupRecord>, DedupStoreError> {
        let callback = self.descriptor.query.ok_or(DedupStoreError::Unavailable)?;
        let (route, namespace, hash) = key_parts(key);
        let mut found = 0;
        let mut record = zeroed_record();
        // SAFETY: Key buffers and outputs remain valid for this synchronous descriptor call.
        let status = unsafe {
            callback(
                self.descriptor.context,
                route.as_ptr(),
                route.len(),
                namespace.as_ptr(),
                namespace.len(),
                hash.as_ptr(),
                hash.len(),
                &mut found,
                &mut record,
            )
        };
        decode_status(status)?;
        match found {
            0 => Ok(None),
            1 => decode_record(&record).map(Some),
            _ => Err(DedupStoreError::Unavailable),
        }
    }

    fn recover_in_flight(&self, updated_at_unix_ms: u64) -> Result<u64, DedupStoreError> {
        let callback = self
            .descriptor
            .recover
            .ok_or(DedupStoreError::Unavailable)?;
        let mut count = 0;
        // SAFETY: Output remains writable for this synchronous descriptor call.
        let status = unsafe { callback(self.descriptor.context, updated_at_unix_ms, &mut count) };
        decode_status(status)?;
        Ok(count)
    }

    fn resolve_unknown(
        &self,
        key: &DedupKey,
        resolution: DedupResolution,
        updated_at_unix_ms: u64,
    ) -> Result<(), DedupStoreError> {
        let callback = self
            .descriptor
            .resolve_unknown
            .ok_or(DedupStoreError::Unavailable)?;
        let (route, namespace, hash) = key_parts(key);
        let resolution = match resolution {
            DedupResolution::Completed => BONDRY_DEDUP_RESOLVE_COMPLETED_V1,
            DedupResolution::RetryAllowed => BONDRY_DEDUP_RESOLVE_RETRY_ALLOWED_V1,
        };
        // SAFETY: Key buffers remain valid for this synchronous descriptor call.
        let status = unsafe {
            callback(
                self.descriptor.context,
                route.as_ptr(),
                route.len(),
                namespace.as_ptr(),
                namespace.len(),
                hash.as_ptr(),
                hash.len(),
                resolution,
                updated_at_unix_ms,
            )
        };
        decode_status(status)
    }

    fn visit_unknown(
        &self,
        visitor: &mut dyn FnMut(&DedupRecord) -> bool,
    ) -> Result<(), DedupStoreError> {
        let callback = self
            .descriptor
            .visit_unknown
            .ok_or(DedupStoreError::Unavailable)?;
        let mut context = VisitContext {
            visitor,
            failed: false,
        };
        // SAFETY: The stack visitor context remains valid for this synchronous descriptor call.
        let status = unsafe {
            callback(
                self.descriptor.context,
                visit_record,
                (&mut context as *mut VisitContext<'_>).cast::<c_void>(),
            )
        };
        decode_status(status)?;
        if context.failed {
            return Err(DedupStoreError::Unavailable);
        }
        Ok(())
    }

    fn clear_completed_before(&self, updated_before_unix_ms: u64) -> Result<u64, DedupStoreError> {
        let callback = self
            .descriptor
            .clear_completed
            .ok_or(DedupStoreError::Unavailable)?;
        let mut count = 0;
        // SAFETY: Output remains writable for this synchronous descriptor call.
        let status =
            unsafe { callback(self.descriptor.context, updated_before_unix_ms, &mut count) };
        decode_status(status)?;
        Ok(count)
    }
}

struct VisitContext<'a> {
    visitor: &'a mut dyn FnMut(&DedupRecord) -> bool,
    failed: bool,
}

unsafe extern "C" fn visit_record(context: *mut c_void, record: *const BondryDedupRecordV1) -> u8 {
    let Some(context) = (unsafe { context.cast::<VisitContext<'_>>().as_mut() }) else {
        return 0;
    };
    let Some(record) = (unsafe { record.as_ref() }) else {
        context.failed = true;
        return 0;
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        decode_record(record).map(|record| (context.visitor)(&record))
    }));
    match result {
        Ok(Ok(keep_going)) => u8::from(keep_going),
        Ok(Err(_)) | Err(_) => {
            context.failed = true;
            0
        }
    }
}

fn key_parts(key: &DedupKey) -> (&[u8], &[u8], &[u8; 32]) {
    (
        key.route().as_str().as_bytes(),
        key.namespace().as_str().as_bytes(),
        key.delivery_hash().as_bytes(),
    )
}

fn decode_record(record: &BondryDedupRecordV1) -> Result<DedupRecord, DedupStoreError> {
    let route =
        RouteId::new(terminated(&record.route_id)?).map_err(|_| DedupStoreError::Unavailable)?;
    let namespace = VerifierNamespace::new(terminated(&record.verifier_namespace)?)
        .map_err(|_| DedupStoreError::Unavailable)?;
    let key = DedupKey::new(
        route,
        namespace,
        TrustedDeliveryIdHash::from_bytes(record.delivery_hash),
    );
    Ok(DedupRecord::from_stored_parts(
        key,
        decode_state(record.state)?,
        record.updated_at_unix_ms,
    ))
}

fn terminated(bytes: &[u8]) -> Result<&str, DedupStoreError> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(DedupStoreError::Unavailable)?;
    if end == 0 || bytes[end + 1..].iter().any(|byte| *byte != 0) {
        return Err(DedupStoreError::Unavailable);
    }
    std::str::from_utf8(&bytes[..end]).map_err(|_| DedupStoreError::Unavailable)
}

const fn decode_state(state: u32) -> Result<DedupState, DedupStoreError> {
    match state {
        BONDRY_DEDUP_STATE_IN_FLIGHT_V1 => Ok(DedupState::InFlight),
        BONDRY_DEDUP_STATE_COMPLETED_V1 => Ok(DedupState::Completed),
        BONDRY_DEDUP_STATE_UNKNOWN_V1 => Ok(DedupState::Unknown),
        _ => Err(DedupStoreError::Unavailable),
    }
}

const fn decode_status(status: i32) -> Result<(), DedupStoreError> {
    match status {
        BONDRY_STATUS_OK => Ok(()),
        BONDRY_STATUS_CAPACITY_EXHAUSTED => Err(DedupStoreError::CapacityExhausted),
        BONDRY_STATUS_NOT_FOUND => Err(DedupStoreError::NotFound),
        BONDRY_STATUS_INVALID_TRANSITION => Err(DedupStoreError::InvalidTransition),
        _ => Err(DedupStoreError::Unavailable),
    }
}

const fn zeroed_record() -> BondryDedupRecordV1 {
    BondryDedupRecordV1 {
        route_id: [0; 129],
        verifier_namespace: [0; 129],
        delivery_hash: [0; 32],
        state: 0,
        updated_at_unix_ms: 0,
    }
}
