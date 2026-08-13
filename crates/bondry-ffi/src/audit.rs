use bondry_core::PrincipalId;
use bondry_store_sqlcipher::AuditQueryLimit;

use crate::{
    BONDRY_STATUS_INVALID_ARGUMENT, BONDRY_STATUS_INVALID_DATA, BONDRY_STATUS_NULL_POINTER,
    BondryAuditEventV1, BondryStoreHandle, catch_status, required_utf8, store_error_status,
    write_records,
};

/// Lists the newest audit events in descending sequence order.
///
/// # Safety
///
/// A non-null output must be writable for `capacity` records. `out_count` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_audit_recent_v1(
    store: *const BondryStoreHandle,
    limit: u32,
    output: *mut BondryAuditEventV1,
    capacity: usize,
    out_count: *mut usize,
) -> i32 {
    audit_query(
        store,
        std::ptr::null(),
        0,
        limit,
        output,
        capacity,
        out_count,
    )
}

/// Lists the newest audit events for one principal in descending sequence order.
///
/// # Safety
///
/// The principal identifier must be readable. A non-null output must be writable for
/// `capacity` records, and `out_count` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_audit_for_principal_v1(
    store: *const BondryStoreHandle,
    principal_id: *const u8,
    principal_id_length: usize,
    limit: u32,
    output: *mut BondryAuditEventV1,
    capacity: usize,
    out_count: *mut usize,
) -> i32 {
    audit_query(
        store,
        principal_id,
        principal_id_length,
        limit,
        output,
        capacity,
        out_count,
    )
}

#[allow(clippy::too_many_arguments)]
fn audit_query(
    store: *const BondryStoreHandle,
    principal_id: *const u8,
    principal_id_length: usize,
    limit: u32,
    output: *mut BondryAuditEventV1,
    capacity: usize,
    out_count: *mut usize,
) -> i32 {
    if out_count.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: The caller guarantees out_count points to writable memory.
    unsafe { out_count.write(0) };
    catch_status(|| {
        let Ok(handle) = crate::auth::store_handle(store) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let Ok(limit) = AuditQueryLimit::new(limit) else {
            return BONDRY_STATUS_INVALID_ARGUMENT;
        };
        let events = if principal_id.is_null() && principal_id_length == 0 {
            handle.store.recent_audit_events(limit)
        } else {
            let principal = match unsafe { required_utf8(principal_id, principal_id_length) }
                .and_then(|value| {
                    PrincipalId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)
                }) {
                Ok(principal) => principal,
                Err(status) => return status,
            };
            handle.store.audit_events_for_principal(&principal, limit)
        };
        let events = match events {
            Ok(events) => events,
            Err(error) => return store_error_status(&error),
        };
        let records = match events
            .iter()
            .map(BondryAuditEventV1::try_from_stored)
            .collect::<Option<Vec<_>>>()
        {
            Some(records) => records,
            None => return BONDRY_STATUS_INVALID_DATA,
        };
        write_records(&records, output, capacity, out_count)
    })
}
