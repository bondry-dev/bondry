#![doc = "Versioned C ABI for embedding Bondry in other languages."]

use std::{
    collections::HashMap,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    ptr, slice,
    sync::{Arc, RwLock},
};

use bondry_auth::{AuthManager, AuthStore, ClientManagementError, TokenLifecycleError};
use bondry_store_sqlcipher::{DatabaseKey, SqlCipherStore, SqlCipherStoreError};

mod audit;
mod auth;
mod capabilities;
mod grants;
mod records;

pub use audit::{bondry_audit_for_principal_v1, bondry_audit_recent_v1};
pub use auth::{
    bondry_client_create_v1, bondry_client_set_enabled_v1, bondry_clients_list_v1,
    bondry_issued_token_clear_v1, bondry_token_authenticate_v1, bondry_token_issue_v1,
    bondry_token_revoke_v1, bondry_token_rotate_v1, bondry_tokens_list_v1,
};
pub use capabilities::{
    BondryCapabilityCompletionV1, BondryCapabilityInvokeV1, BondryCapabilityReleaseV1,
    BondryDispatchCompletionV1, bondry_capabilities_list_v1, bondry_capability_register_v1,
    bondry_capability_unregister_v1, bondry_dispatch_token_v1,
};
pub use grants::{bondry_grant_add_v1, bondry_grant_remove_v1, bondry_grants_list_v1};
pub use records::{
    BondryAuditEventV1, BondryCapabilityV1, BondryClientV1, BondryDispatchResultV1, BondryGrantV1,
    BondryInvocationV1, BondryIssuedTokenV1, BondryPrincipalV1, BondryTokenMetadataV1,
};

/// The first Bondry C ABI version.
pub const BONDRY_ABI_VERSION_V1: u32 = 1;

/// Successful completion.
pub const BONDRY_STATUS_OK: i32 = 0;
/// A required pointer was null.
pub const BONDRY_STATUS_NULL_POINTER: i32 = 1;
/// A byte slice had an invalid length.
pub const BONDRY_STATUS_INVALID_LENGTH: i32 = 2;
/// A string was not valid UTF-8.
pub const BONDRY_STATUS_INVALID_UTF8: i32 = 3;
/// A database path was empty or contained a null byte.
pub const BONDRY_STATUS_INVALID_PATH: i32 = 4;
/// A typed input value was malformed or outside its supported range.
pub const BONDRY_STATUS_INVALID_ARGUMENT: i32 = 5;
/// A caller-owned output array cannot hold the complete result.
pub const BONDRY_STATUS_BUFFER_TOO_SMALL: i32 = 6;
/// A JSON payload was malformed.
pub const BONDRY_STATUS_INVALID_JSON: i32 = 7;
/// A JSON payload exceeded the ABI limit.
pub const BONDRY_STATUS_PAYLOAD_TOO_LARGE: i32 = 8;
/// A database file could not be created or protected.
pub const BONDRY_STATUS_FILE_SYSTEM: i32 = 10;
/// SQLCipher could not complete an operation.
pub const BONDRY_STATUS_DATABASE: i32 = 11;
/// The database schema is newer than this Bondry build.
pub const BONDRY_STATUS_UNSUPPORTED_SCHEMA: i32 = 12;
/// The supplied database key could not decrypt the database.
pub const BONDRY_STATUS_INVALID_DATABASE_KEY: i32 = 13;
/// Persisted data violates Bondry's validated model.
pub const BONDRY_STATUS_INVALID_DATA: i32 = 14;
/// The database connection is unavailable.
pub const BONDRY_STATUS_UNAVAILABLE: i32 = 15;
/// An administrative target does not exist.
pub const BONDRY_STATUS_NOT_FOUND: i32 = 20;
/// An operation requires an enabled client.
pub const BONDRY_STATUS_CLIENT_DISABLED: i32 = 21;
/// A token is revoked or expired.
pub const BONDRY_STATUS_TOKEN_INACTIVE: i32 = 22;
/// Authentication was rejected without disclosing why.
pub const BONDRY_STATUS_AUTHENTICATION_REJECTED: i32 = 23;
/// A token lifetime cannot be represented safely.
pub const BONDRY_STATUS_INVALID_TOKEN_LIFETIME: i32 = 24;
/// Secure random generation is unavailable.
pub const BONDRY_STATUS_ENTROPY_UNAVAILABLE: i32 = 25;
/// System time is unavailable.
pub const BONDRY_STATUS_TIME_UNAVAILABLE: i32 = 26;
/// Repeated random identifier generation conflicted with stored state.
pub const BONDRY_STATUS_GENERATION_EXHAUSTED: i32 = 27;
/// A capability with the same identifier is already registered.
pub const BONDRY_STATUS_ALREADY_EXISTS: i32 = 28;
/// Bondry stopped an internal failure at the ABI boundary.
pub const BONDRY_STATUS_INTERNAL_FAILURE: i32 = 255;

/// An opaque encrypted-store handle owned by the caller.
#[repr(C)]
pub struct BondryStoreHandle {
    _private: [u8; 0],
}

struct StoreHandle {
    store: Arc<SqlCipherStore>,
    auth: AuthManager,
    capabilities: RwLock<HashMap<bondry_core::CapabilityId, capabilities::RegisteredCapability>>,
}

/// Returns the ABI version implemented by the linked library.
#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn bondry_abi_version_v1() -> u32 {
    BONDRY_ABI_VERSION_V1
}

/// Opens or creates an encrypted store and transfers its ownership to the caller.
///
/// # Safety
///
/// Non-null input pointers must reference readable memory for their declared lengths.
/// `out_store` must reference writable memory. The returned handle must be closed once.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_store_open_v1(
    path: *const u8,
    path_length: usize,
    key: *const u8,
    key_length: usize,
    out_store: *mut *mut BondryStoreHandle,
) -> i32 {
    if out_store.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }

    // SAFETY: The caller guarantees that out_store points to writable memory.
    unsafe { out_store.write(ptr::null_mut()) };

    catch_status(|| {
        if path.is_null() || key.is_null() {
            return BONDRY_STATUS_NULL_POINTER;
        }
        if path_length > isize::MAX as usize || key_length != 32 {
            return BONDRY_STATUS_INVALID_LENGTH;
        }

        // SAFETY: The caller guarantees both buffers are readable for their declared lengths.
        let path_bytes = unsafe { slice::from_raw_parts(path, path_length) };
        // SAFETY: key is non-null and key_length was validated above.
        let key_bytes = unsafe { slice::from_raw_parts(key, key_length) };

        let Ok(path_string) = std::str::from_utf8(path_bytes) else {
            return BONDRY_STATUS_INVALID_UTF8;
        };
        if path_string.is_empty() || path_bytes.contains(&0) {
            return BONDRY_STATUS_INVALID_PATH;
        }

        let Ok(database_key) = DatabaseKey::from_slice(key_bytes) else {
            return BONDRY_STATUS_INVALID_LENGTH;
        };
        let store = match SqlCipherStore::open(Path::new(path_string), &database_key) {
            Ok(store) => Arc::new(store),
            Err(error) => return store_error_status(&error),
        };
        let auth_store: Arc<dyn AuthStore> = store.clone();
        let handle = Box::new(StoreHandle {
            store,
            auth: AuthManager::from_shared(auth_store),
            capabilities: RwLock::new(HashMap::new()),
        });

        // SAFETY: out_store was validated above and receives ownership of this allocation.
        unsafe {
            out_store.write(Box::into_raw(handle).cast::<BondryStoreHandle>());
        }
        BONDRY_STATUS_OK
    })
}

/// Checks whether an open encrypted store remains responsive.
///
/// # Safety
///
/// `store` must be a live handle returned by `bondry_store_open_v1`. Closing the handle
/// concurrently with this call is not permitted.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_store_check_v1(store: *const BondryStoreHandle) -> i32 {
    catch_status(|| {
        if store.is_null() {
            return BONDRY_STATUS_NULL_POINTER;
        }

        // SAFETY: The caller guarantees that store is a live Bondry handle.
        let handle = unsafe { &*store.cast::<StoreHandle>() };
        match handle.store.check_health() {
            Ok(()) => BONDRY_STATUS_OK,
            Err(error) => store_error_status(&error),
        }
    })
}

/// Closes an encrypted store. Passing null is a no-op.
///
/// # Safety
///
/// A non-null `store` must be a live handle returned by `bondry_store_open_v1`, and the
/// caller must not use or close it again after this function begins.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_store_close_v1(store: *mut BondryStoreHandle) -> i32 {
    if store.is_null() {
        return BONDRY_STATUS_OK;
    }

    catch_status(|| {
        // SAFETY: The caller transfers ownership of a live Bondry handle exactly once.
        unsafe { drop(Box::from_raw(store.cast::<StoreHandle>())) };
        BONDRY_STATUS_OK
    })
}

fn catch_status(operation: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(BONDRY_STATUS_INTERNAL_FAILURE)
}

fn store_error_status(error: &SqlCipherStoreError) -> i32 {
    match error {
        SqlCipherStoreError::FileSystem(_) => BONDRY_STATUS_FILE_SYSTEM,
        SqlCipherStoreError::Database(_) => BONDRY_STATUS_DATABASE,
        SqlCipherStoreError::UnsupportedSchema(_) => BONDRY_STATUS_UNSUPPORTED_SCHEMA,
        SqlCipherStoreError::InvalidKey => BONDRY_STATUS_INVALID_DATABASE_KEY,
        SqlCipherStoreError::InvalidData => BONDRY_STATUS_INVALID_DATA,
        SqlCipherStoreError::Unavailable => BONDRY_STATUS_UNAVAILABLE,
    }
}

fn client_error_status(error: ClientManagementError) -> i32 {
    match error {
        ClientManagementError::NotFound => BONDRY_STATUS_NOT_FOUND,
        ClientManagementError::EntropyUnavailable => BONDRY_STATUS_ENTROPY_UNAVAILABLE,
        ClientManagementError::GenerationExhausted => BONDRY_STATUS_GENERATION_EXHAUSTED,
        ClientManagementError::TimeUnavailable => BONDRY_STATUS_TIME_UNAVAILABLE,
        ClientManagementError::StorageUnavailable => BONDRY_STATUS_UNAVAILABLE,
    }
}

fn token_error_status(error: TokenLifecycleError) -> i32 {
    match error {
        TokenLifecycleError::ClientNotFound | TokenLifecycleError::NotFound => {
            BONDRY_STATUS_NOT_FOUND
        }
        TokenLifecycleError::ClientDisabled => BONDRY_STATUS_CLIENT_DISABLED,
        TokenLifecycleError::Inactive => BONDRY_STATUS_TOKEN_INACTIVE,
        TokenLifecycleError::InvalidLifetime => BONDRY_STATUS_INVALID_TOKEN_LIFETIME,
        TokenLifecycleError::EntropyUnavailable => BONDRY_STATUS_ENTROPY_UNAVAILABLE,
        TokenLifecycleError::GenerationExhausted => BONDRY_STATUS_GENERATION_EXHAUSTED,
        TokenLifecycleError::TimeUnavailable => BONDRY_STATUS_TIME_UNAVAILABLE,
        TokenLifecycleError::StorageUnavailable => BONDRY_STATUS_UNAVAILABLE,
    }
}

unsafe fn required_utf8<'a>(bytes: *const u8, length: usize) -> Result<&'a str, i32> {
    if bytes.is_null() {
        return Err(BONDRY_STATUS_NULL_POINTER);
    }
    if length > isize::MAX as usize {
        return Err(BONDRY_STATUS_INVALID_LENGTH);
    }
    // SAFETY: Callers guarantee that non-null input buffers are readable for their length.
    let bytes = unsafe { slice::from_raw_parts(bytes, length) };
    std::str::from_utf8(bytes).map_err(|_| BONDRY_STATUS_INVALID_UTF8)
}

unsafe fn optional_utf8<'a>(bytes: *const u8, length: usize) -> Result<Option<&'a str>, i32> {
    if bytes.is_null() && length == 0 {
        return Ok(None);
    }
    // SAFETY: The caller provides the same readable-buffer guarantee.
    unsafe { required_utf8(bytes, length) }.map(Some)
}

fn write_records<T: Copy>(
    records: &[T],
    output: *mut T,
    capacity: usize,
    out_count: *mut usize,
) -> i32 {
    if out_count.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: The caller guarantees that out_count points to writable memory.
    unsafe { out_count.write(records.len()) };
    if output.is_null() {
        return if capacity == 0 {
            BONDRY_STATUS_OK
        } else {
            BONDRY_STATUS_NULL_POINTER
        };
    }
    if capacity < records.len() {
        return BONDRY_STATUS_BUFFER_TOO_SMALL;
    }
    // SAFETY: The caller guarantees output is writable for capacity elements, which is
    // at least records.len(), and foreign output cannot overlap Rust-owned records.
    unsafe { ptr::copy_nonoverlapping(records.as_ptr(), output, records.len()) };
    BONDRY_STATUS_OK
}

#[cfg(test)]
mod tests;
