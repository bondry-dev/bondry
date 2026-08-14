use std::{ptr, time::Duration};

use bondry_auth::{AuthenticationError, ClientName, TokenId, TokenLabel};
use bondry_core::PrincipalId;

use crate::{
    BONDRY_STATUS_AUTHENTICATION_REJECTED, BONDRY_STATUS_INVALID_ARGUMENT,
    BONDRY_STATUS_NULL_POINTER, BONDRY_STATUS_OK, BONDRY_STATUS_UNAVAILABLE, BondryClientV1,
    BondryIssuedTokenV1, BondryPrincipalV1, BondryStoreHandle, BondryTokenMetadataV1, StoreHandle,
    catch_status, client_error_status, optional_utf8, required_utf8, token_error_status,
    write_records,
};

/// Registers an enabled client and writes its non-secret metadata.
///
/// # Safety
///
/// Input buffers must be readable for their declared lengths. `out_client` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_client_create_v1(
    store: *const BondryStoreHandle,
    name: *const u8,
    name_length: usize,
    out_client: *mut BondryClientV1,
) -> i32 {
    if out_client.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    catch_status(|| {
        let name = match unsafe { required_utf8(name, name_length) } {
            Ok(name) => ClientName::new(name),
            Err(status) => {
                // SAFETY: out_client was validated above.
                unsafe { out_client.write(std::mem::zeroed()) };
                return status;
            }
        };
        // SAFETY: out_client was validated above and input parsing no longer borrows its memory.
        unsafe { out_client.write(std::mem::zeroed()) };
        let Ok(name) = name else {
            return BONDRY_STATUS_INVALID_ARGUMENT;
        };
        let Ok(handle) = store_handle(store) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        match handle.auth.create_client(name) {
            Ok(client) => {
                // SAFETY: out_client was validated above.
                unsafe { out_client.write(BondryClientV1::from_client(&client)) };
                BONDRY_STATUS_OK
            }
            Err(error) => client_error_status(error),
        }
    })
}

/// Lists all clients into caller-owned memory.
///
/// # Safety
///
/// A non-null output must be writable for `capacity` records. `out_count` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_clients_list_v1(
    store: *const BondryStoreHandle,
    output: *mut BondryClientV1,
    capacity: usize,
    out_count: *mut usize,
) -> i32 {
    if out_count.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: The caller guarantees out_count points to writable memory.
    unsafe { out_count.write(0) };
    catch_status(|| {
        let Ok(handle) = store_handle(store) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        match handle.auth.clients() {
            Ok(clients) => {
                let records = clients
                    .iter()
                    .map(BondryClientV1::from_client)
                    .collect::<Vec<_>>();
                write_records(&records, output, capacity, out_count)
            }
            Err(error) => client_error_status(error),
        }
    })
}

/// Enables or disables a registered client.
///
/// # Safety
///
/// The client identifier buffer must be readable for its declared length.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_client_set_enabled_v1(
    store: *const BondryStoreHandle,
    client_id: *const u8,
    client_id_length: usize,
    enabled: u8,
) -> i32 {
    catch_status(|| {
        let Ok(handle) = store_handle(store) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        if enabled > 1 {
            return BONDRY_STATUS_INVALID_ARGUMENT;
        }
        let client_id = match unsafe { parse_principal_id(client_id, client_id_length) } {
            Ok(client_id) => client_id,
            Err(status) => return status,
        };
        handle
            .auth
            .set_client_enabled(&client_id, enabled == 1)
            .map_or_else(client_error_status, |()| BONDRY_STATUS_OK)
    })
}

/// Issues a new bearer token and writes its secret once.
///
/// # Safety
///
/// Input buffers must be readable for their declared lengths. `out_token` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_token_issue_v1(
    store: *const BondryStoreHandle,
    client_id: *const u8,
    client_id_length: usize,
    label: *const u8,
    label_length: usize,
    expires_in_seconds: u64,
    has_expiration: u8,
    out_token: *mut BondryIssuedTokenV1,
) -> i32 {
    issue_or_rotate(
        store,
        client_id,
        client_id_length,
        label,
        label_length,
        expires_in_seconds,
        has_expiration,
        out_token,
        None,
    )
}

/// Atomically revokes one token and writes its replacement secret once.
///
/// # Safety
///
/// Input buffers must be readable for their declared lengths. `out_token` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_token_rotate_v1(
    store: *const BondryStoreHandle,
    token_id: *const u8,
    token_id_length: usize,
    label: *const u8,
    label_length: usize,
    expires_in_seconds: u64,
    has_expiration: u8,
    out_token: *mut BondryIssuedTokenV1,
) -> i32 {
    issue_or_rotate(
        store,
        ptr::null(),
        0,
        label,
        label_length,
        expires_in_seconds,
        has_expiration,
        out_token,
        Some((token_id, token_id_length)),
    )
}

/// Revokes an active token and reports whether state changed.
///
/// # Safety
///
/// The token identifier must be readable for its declared length. `out_changed` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_token_revoke_v1(
    store: *const BondryStoreHandle,
    token_id: *const u8,
    token_id_length: usize,
    out_changed: *mut u8,
) -> i32 {
    if out_changed.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    catch_status(|| {
        let Ok(handle) = store_handle(store) else {
            // SAFETY: out_changed was validated above.
            unsafe { out_changed.write(0) };
            return BONDRY_STATUS_NULL_POINTER;
        };
        let token_id = match unsafe { parse_token_id(token_id, token_id_length) } {
            Ok(token_id) => token_id,
            Err(status) => {
                // SAFETY: out_changed was validated above.
                unsafe { out_changed.write(0) };
                return status;
            }
        };
        // SAFETY: out_changed was validated above and input parsing no longer borrows its memory.
        unsafe { out_changed.write(0) };
        match handle.auth.revoke_token(&token_id) {
            Ok(changed) => {
                // SAFETY: out_changed was validated above.
                unsafe { out_changed.write(u8::from(changed)) };
                BONDRY_STATUS_OK
            }
            Err(error) => token_error_status(error),
        }
    })
}

/// Lists non-secret token metadata for one client.
///
/// # Safety
///
/// The client identifier must be readable. A non-null output must be writable for `capacity`
/// records, and `out_count` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_tokens_list_v1(
    store: *const BondryStoreHandle,
    client_id: *const u8,
    client_id_length: usize,
    output: *mut BondryTokenMetadataV1,
    capacity: usize,
    out_count: *mut usize,
) -> i32 {
    if out_count.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: The caller guarantees out_count points to writable memory.
    unsafe { out_count.write(0) };
    catch_status(|| {
        let Ok(handle) = store_handle(store) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let client_id = match unsafe { parse_principal_id(client_id, client_id_length) } {
            Ok(client_id) => client_id,
            Err(status) => return status,
        };
        match handle.auth.tokens_for_client(&client_id) {
            Ok(tokens) => {
                let records = tokens
                    .iter()
                    .map(BondryTokenMetadataV1::from_metadata)
                    .collect::<Vec<_>>();
                write_records(&records, output, capacity, out_count)
            }
            Err(error) => token_error_status(error),
        }
    })
}

/// Authenticates a bearer token and writes only the resulting principal.
///
/// # Safety
///
/// The token must be readable for its declared length. `out_principal` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_token_authenticate_v1(
    store: *const BondryStoreHandle,
    token: *const u8,
    token_length: usize,
    out_principal: *mut BondryPrincipalV1,
) -> i32 {
    if out_principal.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    catch_status(|| {
        let Ok(handle) = store_handle(store) else {
            // SAFETY: out_principal was validated above.
            unsafe { out_principal.write(std::mem::zeroed()) };
            return BONDRY_STATUS_NULL_POINTER;
        };
        let authentication = match unsafe { required_utf8(token, token_length) } {
            Ok(token) => handle
                .auth
                .authenticate(token)
                .map_err(|error| match error {
                    AuthenticationError::Rejected => BONDRY_STATUS_AUTHENTICATION_REJECTED,
                    AuthenticationError::StorageUnavailable => BONDRY_STATUS_UNAVAILABLE,
                }),
            Err(status) => Err(status),
        };
        // SAFETY: out_principal was validated above and authentication no longer borrows input.
        unsafe { out_principal.write(std::mem::zeroed()) };
        match authentication {
            Ok(principal) => {
                // SAFETY: out_principal was validated above.
                unsafe { out_principal.write(BondryPrincipalV1::from_principal(&principal)) };
                BONDRY_STATUS_OK
            }
            Err(status) => status,
        }
    })
}

/// Clears a caller-owned issued-token record, including its one-time secret.
///
/// # Safety
///
/// `token` must point to a writable `BondryIssuedTokenV1` record.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_issued_token_clear_v1(token: *mut BondryIssuedTokenV1) -> i32 {
    if token.is_null() {
        return BONDRY_STATUS_OK;
    }
    catch_status(|| {
        // SAFETY: The caller guarantees token points to a writable record.
        unsafe { crate::records::clear_issued_token(token) };
        BONDRY_STATUS_OK
    })
}

#[allow(clippy::too_many_arguments)]
fn issue_or_rotate(
    store: *const BondryStoreHandle,
    client_id_bytes: *const u8,
    client_id_length: usize,
    label: *const u8,
    label_length: usize,
    expires_in_seconds: u64,
    has_expiration: u8,
    out_token: *mut BondryIssuedTokenV1,
    rotation: Option<(*const u8, usize)>,
) -> i32 {
    if out_token.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    catch_status(|| {
        let Ok(handle) = store_handle(store) else {
            clear_output_token(out_token);
            return BONDRY_STATUS_NULL_POINTER;
        };
        let label = match unsafe { token_label(label, label_length) } {
            Ok(label) => label,
            Err(status) => {
                clear_output_token(out_token);
                return status;
            }
        };
        let expiration = match expiration(expires_in_seconds, has_expiration) {
            Ok(expiration) => expiration,
            Err(status) => {
                clear_output_token(out_token);
                return status;
            }
        };
        let issued = if let Some((token_id_bytes, token_id_length)) = rotation {
            let token_id = match unsafe { parse_token_id(token_id_bytes, token_id_length) } {
                Ok(token_id) => token_id,
                Err(status) => {
                    clear_output_token(out_token);
                    return status;
                }
            };
            clear_output_token(out_token);
            handle.auth.rotate_token(&token_id, label, expiration)
        } else {
            let client_id = match unsafe { parse_principal_id(client_id_bytes, client_id_length) } {
                Ok(client_id) => client_id,
                Err(status) => {
                    clear_output_token(out_token);
                    return status;
                }
            };
            clear_output_token(out_token);
            handle.auth.issue_token(&client_id, label, expiration)
        };
        match issued {
            Ok(issued) => {
                let record = BondryIssuedTokenV1::from_issued(&issued);
                // SAFETY: out_token was validated above.
                unsafe { out_token.write(record) };
                BONDRY_STATUS_OK
            }
            Err(error) => token_error_status(error),
        }
    })
}

pub(crate) fn store_handle<'a>(store: *const BondryStoreHandle) -> Result<&'a StoreHandle, ()> {
    if store.is_null() {
        return Err(());
    }
    // SAFETY: The caller guarantees store is a live Bondry store handle.
    Ok(unsafe { &*store.cast::<StoreHandle>() })
}

unsafe fn parse_principal_id(bytes: *const u8, length: usize) -> Result<PrincipalId, i32> {
    // SAFETY: The caller guarantees the identifier buffer is readable.
    let value = unsafe { required_utf8(bytes, length) }?;
    PrincipalId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)
}

unsafe fn parse_token_id(bytes: *const u8, length: usize) -> Result<TokenId, i32> {
    // SAFETY: The caller guarantees the identifier buffer is readable.
    let value = unsafe { required_utf8(bytes, length) }?;
    TokenId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)
}

unsafe fn token_label(bytes: *const u8, length: usize) -> Result<Option<TokenLabel>, i32> {
    // SAFETY: The caller guarantees a non-null label buffer is readable.
    unsafe { optional_utf8(bytes, length) }?
        .map(TokenLabel::new)
        .transpose()
        .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)
}

fn clear_output_token(token: *mut BondryIssuedTokenV1) {
    // SAFETY: The public entry point validates this caller-owned output pointer.
    unsafe { token.write(std::mem::zeroed()) };
}

fn expiration(seconds: u64, present: u8) -> Result<Option<Duration>, i32> {
    match present {
        0 if seconds == 0 => Ok(None),
        1 if seconds > 0 => Ok(Some(Duration::from_secs(seconds))),
        _ => Err(BONDRY_STATUS_INVALID_ARGUMENT),
    }
}
