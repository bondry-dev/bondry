use bondry_core::{AdapterId, CapabilityGrant, CapabilityId, GrantStore, PrincipalId};

use crate::{
    BONDRY_STATUS_INVALID_ARGUMENT, BONDRY_STATUS_NULL_POINTER, BONDRY_STATUS_OK,
    BONDRY_STATUS_UNAVAILABLE, BondryGrantV1, BondryStoreHandle, catch_status, required_utf8,
    write_records,
};

/// Adds an exact authorization grant and reports whether state changed.
///
/// # Safety
///
/// Input buffers must be readable for their declared lengths. `out_changed` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_grant_add_v1(
    store: *const BondryStoreHandle,
    principal_id: *const u8,
    principal_id_length: usize,
    adapter_id: *const u8,
    adapter_id_length: usize,
    capability_id: *const u8,
    capability_id_length: usize,
    out_changed: *mut u8,
) -> i32 {
    update_grant(
        store,
        principal_id,
        principal_id_length,
        adapter_id,
        adapter_id_length,
        capability_id,
        capability_id_length,
        out_changed,
        true,
    )
}

/// Removes an exact authorization grant and reports whether state changed.
///
/// # Safety
///
/// Input buffers must be readable for their declared lengths. `out_changed` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_grant_remove_v1(
    store: *const BondryStoreHandle,
    principal_id: *const u8,
    principal_id_length: usize,
    adapter_id: *const u8,
    adapter_id_length: usize,
    capability_id: *const u8,
    capability_id_length: usize,
    out_changed: *mut u8,
) -> i32 {
    update_grant(
        store,
        principal_id,
        principal_id_length,
        adapter_id,
        adapter_id_length,
        capability_id,
        capability_id_length,
        out_changed,
        false,
    )
}

/// Lists exact grants for one principal in stable adapter and capability order.
///
/// # Safety
///
/// The principal identifier must be readable. A non-null output must be writable for `capacity`
/// records, and `out_count` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_grants_list_v1(
    store: *const BondryStoreHandle,
    principal_id: *const u8,
    principal_id_length: usize,
    output: *mut BondryGrantV1,
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
        let principal = match unsafe { parse_principal(principal_id, principal_id_length) } {
            Ok(principal) => principal,
            Err(status) => return status,
        };
        match handle.store.grants_for_principal(&principal) {
            Ok(grants) => {
                let records = grants
                    .iter()
                    .map(BondryGrantV1::from_grant)
                    .collect::<Vec<_>>();
                write_records(&records, output, capacity, out_count)
            }
            Err(_) => BONDRY_STATUS_UNAVAILABLE,
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn update_grant(
    store: *const BondryStoreHandle,
    principal_id: *const u8,
    principal_id_length: usize,
    adapter_id: *const u8,
    adapter_id_length: usize,
    capability_id: *const u8,
    capability_id_length: usize,
    out_changed: *mut u8,
    add: bool,
) -> i32 {
    if out_changed.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    catch_status(|| {
        let Ok(handle) = crate::auth::store_handle(store) else {
            // SAFETY: The caller guarantees out_changed points to writable memory.
            unsafe { out_changed.write(0) };
            return BONDRY_STATUS_NULL_POINTER;
        };
        let grant = match unsafe {
            parse_grant(
                principal_id,
                principal_id_length,
                adapter_id,
                adapter_id_length,
                capability_id,
                capability_id_length,
            )
        } {
            Ok(grant) => grant,
            Err(status) => {
                // SAFETY: The caller guarantees out_changed points to writable memory.
                unsafe { out_changed.write(0) };
                return status;
            }
        };
        // SAFETY: out_changed is writable and input parsing no longer borrows its memory.
        unsafe { out_changed.write(0) };
        let result = if add {
            handle.store.add_grant(grant)
        } else {
            handle.store.remove_grant(&grant)
        };
        match result {
            Ok(changed) => {
                // SAFETY: out_changed was validated above.
                unsafe { out_changed.write(u8::from(changed)) };
                BONDRY_STATUS_OK
            }
            Err(_) => BONDRY_STATUS_UNAVAILABLE,
        }
    })
}

unsafe fn parse_grant(
    principal_id: *const u8,
    principal_id_length: usize,
    adapter_id: *const u8,
    adapter_id_length: usize,
    capability_id: *const u8,
    capability_id_length: usize,
) -> Result<CapabilityGrant, i32> {
    // SAFETY: The public entry point requires readable input buffers.
    let principal = unsafe { parse_principal(principal_id, principal_id_length) }?;
    // SAFETY: The public entry point requires readable input buffers.
    let adapter = unsafe { required_utf8(adapter_id, adapter_id_length) }
        .and_then(|value| AdapterId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT))?;
    // SAFETY: The public entry point requires readable input buffers.
    let capability = unsafe { required_utf8(capability_id, capability_id_length) }
        .and_then(|value| CapabilityId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT))?;
    Ok(CapabilityGrant::new(principal, adapter, capability))
}

unsafe fn parse_principal(bytes: *const u8, length: usize) -> Result<PrincipalId, i32> {
    // SAFETY: The caller guarantees the identifier buffer is readable.
    unsafe { required_utf8(bytes, length) }
        .and_then(|value| PrincipalId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT))
}
