#![doc = "Versioned C ABI for embedding Bondry in other languages."]

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    ptr, slice,
};

use bondry_store_sqlcipher::{DatabaseKey, SqlCipherStore, SqlCipherStoreError};

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
/// Bondry stopped an internal failure at the ABI boundary.
pub const BONDRY_STATUS_INTERNAL_FAILURE: i32 = 255;

/// An opaque encrypted-store handle owned by the caller.
#[repr(C)]
pub struct BondryStoreHandle {
    _private: [u8; 0],
}

struct StoreHandle {
    store: SqlCipherStore,
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
        if key_length != 32 {
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
            Ok(store) => store,
            Err(error) => return store_error_status(&error),
        };
        let handle = Box::new(StoreHandle { store });

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

#[cfg(test)]
mod tests;
