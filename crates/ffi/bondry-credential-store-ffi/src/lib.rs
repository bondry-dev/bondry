#![doc = "Versioned C ABI for Bondry credential storage."]
#![cfg(unix)]

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
    ptr, slice,
};

use bondry_credential_store_unix::UnixFileCredentialStore;
use bondry_secrets::{
    CredentialId, CredentialProtection, CredentialStore, CredentialStoreAccess,
    CredentialStoreCapabilities, CredentialStoreError, CredentialValue, MAX_CREDENTIAL_BYTES,
    MAX_CREDENTIAL_ID_BYTES,
};

/// The first credential-storage C ABI version.
pub const BONDRY_CREDENTIAL_ABI_VERSION_V1: u32 = 1;
/// Maximum UTF-8 encoded credential identifier size.
pub const BONDRY_MAX_CREDENTIAL_ID_LENGTH_V1: usize = MAX_CREDENTIAL_ID_BYTES;
/// Maximum credential value size.
pub const BONDRY_MAX_CREDENTIAL_LENGTH_V1: usize = MAX_CREDENTIAL_BYTES;

/// Successful completion.
pub const BONDRY_CREDENTIAL_STATUS_OK: i32 = 0;
/// A required pointer was null.
pub const BONDRY_CREDENTIAL_STATUS_NULL_POINTER: i32 = 1;
/// A byte slice had an invalid length.
pub const BONDRY_CREDENTIAL_STATUS_INVALID_LENGTH: i32 = 2;
/// A string was not valid UTF-8.
pub const BONDRY_CREDENTIAL_STATUS_INVALID_UTF8: i32 = 3;
/// A credential-store path was invalid.
pub const BONDRY_CREDENTIAL_STATUS_INVALID_PATH: i32 = 4;
/// A typed input value was malformed.
pub const BONDRY_CREDENTIAL_STATUS_INVALID_ARGUMENT: i32 = 5;
/// A caller-owned output buffer cannot hold the complete value.
pub const BONDRY_CREDENTIAL_STATUS_BUFFER_TOO_SMALL: i32 = 6;
/// Persisted material violates the credential contract.
pub const BONDRY_CREDENTIAL_STATUS_INVALID_MATERIAL: i32 = 14;
/// The configured credential backend is unavailable.
pub const BONDRY_CREDENTIAL_STATUS_UNAVAILABLE: i32 = 15;
/// A credential does not exist.
pub const BONDRY_CREDENTIAL_STATUS_NOT_FOUND: i32 = 20;
/// Filesystem or platform metadata violates the backend safety policy.
pub const BONDRY_CREDENTIAL_STATUS_UNSAFE_STORAGE: i32 = 29;
/// The caller cannot access the configured backend.
pub const BONDRY_CREDENTIAL_STATUS_ACCESS_DENIED: i32 = 30;
/// The configured credential backend is read-only.
pub const BONDRY_CREDENTIAL_STATUS_READ_ONLY: i32 = 31;
/// Bondry stopped an internal failure at the ABI boundary.
pub const BONDRY_CREDENTIAL_STATUS_INTERNAL_FAILURE: i32 = 255;

/// Filesystem permissions are the credential's at-rest protection boundary.
pub const BONDRY_CREDENTIAL_PROTECTION_ACCESS_CONTROLLED_V1: u32 = 1;
/// Credential material is bound to one operating-system installation.
pub const BONDRY_CREDENTIAL_PROTECTION_HOST_BOUND_V1: u32 = 2;
/// Credential material is bound to local security hardware.
pub const BONDRY_CREDENTIAL_PROTECTION_HARDWARE_BOUND_V1: u32 = 3;
/// Credential material is owned by an external service.
pub const BONDRY_CREDENTIAL_PROTECTION_EXTERNAL_V1: u32 = 4;

/// The credential backend can only load provisioned material.
pub const BONDRY_CREDENTIAL_STORE_ACCESS_READ_ONLY_V1: u32 = 1;
/// The credential backend can create, replace, and delete material.
pub const BONDRY_CREDENTIAL_STORE_ACCESS_READ_WRITE_V1: u32 = 2;

/// Stable credential-backend properties.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct BondryCredentialStoreCapabilitiesV1 {
    /// The credential's at-rest protection boundary.
    pub protection: u32,
    /// Whether the backend can modify material.
    pub access: u32,
    /// One when the backend can operate without interactive user presence.
    pub supports_unattended_access: u8,
}

/// An opaque credential-store handle owned by the caller.
#[repr(C)]
pub struct BondryCredentialStoreHandle {
    _private: [u8; 0],
}

struct CredentialStoreHandle {
    store: Box<dyn CredentialStore>,
}

/// Returns the credential-storage ABI version implemented by the linked library.
#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn bondry_credentials_abi_version_v1() -> u32 {
    BONDRY_CREDENTIAL_ABI_VERSION_V1
}

/// Opens an existing private Unix directory as a credential store.
///
/// # Safety
///
/// A non-null path must be readable for `path_length` bytes. `out_store` must be writable. On
/// success the returned handle must be passed exactly once to `bondry_credential_store_close_v1`.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_unix_file_credential_store_open_v1(
    path: *const u8,
    path_length: usize,
    out_store: *mut *mut BondryCredentialStoreHandle,
) -> i32 {
    if out_store.is_null() {
        return BONDRY_CREDENTIAL_STATUS_NULL_POINTER;
    }
    // SAFETY: The caller guarantees that out_store points to writable memory.
    unsafe { out_store.write(ptr::null_mut()) };
    catch_status(|| {
        let path = match unsafe { required_utf8(path, path_length) } {
            Ok(path) if !path.is_empty() && !path.as_bytes().contains(&0) => path,
            Ok(_) => return BONDRY_CREDENTIAL_STATUS_INVALID_PATH,
            Err(status) => return status,
        };
        let store = match UnixFileCredentialStore::open(Path::new(path)) {
            Ok(store) => store,
            Err(error) => return store_error_status(error),
        };
        let handle = Box::new(CredentialStoreHandle {
            store: Box::new(store),
        });
        // SAFETY: out_store was validated and receives ownership of this allocation.
        unsafe {
            out_store.write(Box::into_raw(handle).cast::<BondryCredentialStoreHandle>());
        }
        BONDRY_CREDENTIAL_STATUS_OK
    })
}

/// Reports stable properties of an open credential store.
///
/// # Safety
///
/// `store` must be a live handle returned by an open function. `out_capabilities` must be writable.
/// Closing the handle concurrently is not permitted.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_credential_store_capabilities_v1(
    store: *const BondryCredentialStoreHandle,
    out_capabilities: *mut BondryCredentialStoreCapabilitiesV1,
) -> i32 {
    if out_capabilities.is_null() {
        return BONDRY_CREDENTIAL_STATUS_NULL_POINTER;
    }
    catch_status(|| {
        let Ok(handle) = (unsafe { store_handle(store) }) else {
            return BONDRY_CREDENTIAL_STATUS_NULL_POINTER;
        };
        let capabilities = encode_capabilities(handle.store.capabilities());
        // SAFETY: The caller guarantees that out_capabilities points to writable memory.
        unsafe { out_capabilities.write(capabilities) };
        BONDRY_CREDENTIAL_STATUS_OK
    })
}

/// Loads one credential into caller-owned memory.
///
/// Passing a null output with zero capacity reports the required length. A missing credential
/// returns `BONDRY_CREDENTIAL_STATUS_NOT_FOUND` and a zero length.
///
/// # Safety
///
/// `store` must be live. A non-null identifier must be readable for `id_length` bytes. A non-null
/// output must be writable for `capacity` bytes, and `out_length` must be writable. Closing the
/// handle concurrently is not permitted.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_credential_store_load_v1(
    store: *const BondryCredentialStoreHandle,
    id: *const u8,
    id_length: usize,
    output: *mut u8,
    capacity: usize,
    out_length: *mut usize,
) -> i32 {
    if out_length.is_null() {
        return BONDRY_CREDENTIAL_STATUS_NULL_POINTER;
    }
    // SAFETY: The caller guarantees that out_length points to writable memory.
    unsafe { out_length.write(0) };
    catch_status(|| {
        let Ok(handle) = (unsafe { store_handle(store) }) else {
            return BONDRY_CREDENTIAL_STATUS_NULL_POINTER;
        };
        let id = match unsafe { credential_id(id, id_length) } {
            Ok(id) => id,
            Err(status) => return status,
        };
        let value = match handle.store.load(&id) {
            Ok(Some(value)) => value,
            Ok(None) => return BONDRY_CREDENTIAL_STATUS_NOT_FOUND,
            Err(error) => return store_error_status(error),
        };
        write_bytes(value.expose(), output, capacity, out_length)
    })
}

/// Atomically creates or replaces one credential.
///
/// # Safety
///
/// `store` must be live. Non-null input buffers must be readable for their declared lengths.
/// Closing the handle concurrently is not permitted.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_credential_store_store_v1(
    store: *const BondryCredentialStoreHandle,
    id: *const u8,
    id_length: usize,
    value: *const u8,
    value_length: usize,
) -> i32 {
    catch_status(|| {
        let Ok(handle) = (unsafe { store_handle(store) }) else {
            return BONDRY_CREDENTIAL_STATUS_NULL_POINTER;
        };
        let id = match unsafe { credential_id(id, id_length) } {
            Ok(id) => id,
            Err(status) => return status,
        };
        let value = match unsafe { credential_value(value, value_length) } {
            Ok(value) => value,
            Err(status) => return status,
        };
        match handle.store.store(&id, &value) {
            Ok(()) => BONDRY_CREDENTIAL_STATUS_OK,
            Err(error) => store_error_status(error),
        }
    })
}

/// Deletes one credential and reports whether it existed.
///
/// # Safety
///
/// `store` must be live. A non-null identifier must be readable for `id_length` bytes.
/// `out_deleted` must be writable. Closing the handle concurrently is not permitted.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_credential_store_delete_v1(
    store: *const BondryCredentialStoreHandle,
    id: *const u8,
    id_length: usize,
    out_deleted: *mut u8,
) -> i32 {
    if out_deleted.is_null() {
        return BONDRY_CREDENTIAL_STATUS_NULL_POINTER;
    }
    // SAFETY: The caller guarantees that out_deleted points to writable memory.
    unsafe { out_deleted.write(0) };
    catch_status(|| {
        let Ok(handle) = (unsafe { store_handle(store) }) else {
            return BONDRY_CREDENTIAL_STATUS_NULL_POINTER;
        };
        let id = match unsafe { credential_id(id, id_length) } {
            Ok(id) => id,
            Err(status) => return status,
        };
        match handle.store.delete(&id) {
            Ok(deleted) => {
                // SAFETY: out_deleted was validated and remains writable for this call.
                unsafe { out_deleted.write(u8::from(deleted)) };
                BONDRY_CREDENTIAL_STATUS_OK
            }
            Err(error) => store_error_status(error),
        }
    })
}

/// Closes a credential store. Passing null is a no-op.
///
/// # Safety
///
/// A non-null `store` must be live and must not be used or closed again after this call begins.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_credential_store_close_v1(
    store: *mut BondryCredentialStoreHandle,
) -> i32 {
    if store.is_null() {
        return BONDRY_CREDENTIAL_STATUS_OK;
    }
    catch_status(|| {
        // SAFETY: The caller transfers ownership of one live Box-backed handle.
        unsafe { drop(Box::from_raw(store.cast::<CredentialStoreHandle>())) };
        BONDRY_CREDENTIAL_STATUS_OK
    })
}

fn catch_status(operation: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(BONDRY_CREDENTIAL_STATUS_INTERNAL_FAILURE)
}

unsafe fn store_handle<'a>(
    store: *const BondryCredentialStoreHandle,
) -> Result<&'a CredentialStoreHandle, i32> {
    if store.is_null() {
        return Err(BONDRY_CREDENTIAL_STATUS_NULL_POINTER);
    }
    // SAFETY: The caller guarantees that store is a live handle for the duration of the call.
    Ok(unsafe { &*store.cast::<CredentialStoreHandle>() })
}

unsafe fn required_bytes<'a>(bytes: *const u8, length: usize) -> Result<&'a [u8], i32> {
    if bytes.is_null() {
        return Err(BONDRY_CREDENTIAL_STATUS_NULL_POINTER);
    }
    if length > isize::MAX as usize {
        return Err(BONDRY_CREDENTIAL_STATUS_INVALID_LENGTH);
    }
    // SAFETY: The caller guarantees that bytes is readable for length bytes.
    Ok(unsafe { slice::from_raw_parts(bytes, length) })
}

unsafe fn required_utf8<'a>(bytes: *const u8, length: usize) -> Result<&'a str, i32> {
    let bytes = unsafe { required_bytes(bytes, length) }?;
    std::str::from_utf8(bytes).map_err(|_| BONDRY_CREDENTIAL_STATUS_INVALID_UTF8)
}

unsafe fn credential_id(id: *const u8, length: usize) -> Result<CredentialId, i32> {
    let id = unsafe { required_utf8(id, length) }?;
    CredentialId::new(id).map_err(|_| BONDRY_CREDENTIAL_STATUS_INVALID_ARGUMENT)
}

unsafe fn credential_value(value: *const u8, length: usize) -> Result<CredentialValue, i32> {
    let value = unsafe { required_bytes(value, length) }?;
    CredentialValue::new(value.to_vec()).map_err(|_| BONDRY_CREDENTIAL_STATUS_INVALID_LENGTH)
}

fn write_bytes(bytes: &[u8], output: *mut u8, capacity: usize, out_length: *mut usize) -> i32 {
    // SAFETY: Every caller validates out_length before entering this helper.
    unsafe { out_length.write(bytes.len()) };
    if output.is_null() {
        return if capacity == 0 {
            BONDRY_CREDENTIAL_STATUS_OK
        } else {
            BONDRY_CREDENTIAL_STATUS_NULL_POINTER
        };
    }
    if capacity < bytes.len() {
        return BONDRY_CREDENTIAL_STATUS_BUFFER_TOO_SMALL;
    }
    // SAFETY: The caller guarantees output is writable for capacity bytes.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
    BONDRY_CREDENTIAL_STATUS_OK
}

fn encode_capabilities(
    capabilities: CredentialStoreCapabilities,
) -> BondryCredentialStoreCapabilitiesV1 {
    BondryCredentialStoreCapabilitiesV1 {
        protection: match capabilities.protection {
            CredentialProtection::AccessControlled => {
                BONDRY_CREDENTIAL_PROTECTION_ACCESS_CONTROLLED_V1
            }
            CredentialProtection::HostBound => BONDRY_CREDENTIAL_PROTECTION_HOST_BOUND_V1,
            CredentialProtection::HardwareBound => BONDRY_CREDENTIAL_PROTECTION_HARDWARE_BOUND_V1,
            CredentialProtection::External => BONDRY_CREDENTIAL_PROTECTION_EXTERNAL_V1,
        },
        access: match capabilities.access {
            CredentialStoreAccess::ReadOnly => BONDRY_CREDENTIAL_STORE_ACCESS_READ_ONLY_V1,
            CredentialStoreAccess::ReadWrite => BONDRY_CREDENTIAL_STORE_ACCESS_READ_WRITE_V1,
        },
        supports_unattended_access: u8::from(capabilities.supports_unattended_access),
    }
}

fn store_error_status(error: CredentialStoreError) -> i32 {
    match error {
        CredentialStoreError::Unavailable => BONDRY_CREDENTIAL_STATUS_UNAVAILABLE,
        CredentialStoreError::AccessDenied => BONDRY_CREDENTIAL_STATUS_ACCESS_DENIED,
        CredentialStoreError::UnsafeStorage => BONDRY_CREDENTIAL_STATUS_UNSAFE_STORAGE,
        CredentialStoreError::InvalidMaterial => BONDRY_CREDENTIAL_STATUS_INVALID_MATERIAL,
        CredentialStoreError::ReadOnly => BONDRY_CREDENTIAL_STATUS_READ_ONLY,
    }
}

#[cfg(test)]
mod tests;
