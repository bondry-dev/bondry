use std::{fs, os::unix::fs::PermissionsExt, ptr};

use tempfile::TempDir;

use super::{
    BONDRY_CREDENTIAL_ABI_VERSION_V1, BONDRY_CREDENTIAL_PROTECTION_ACCESS_CONTROLLED_V1,
    BONDRY_CREDENTIAL_STATUS_BUFFER_TOO_SMALL, BONDRY_CREDENTIAL_STATUS_INVALID_ARGUMENT,
    BONDRY_CREDENTIAL_STATUS_INVALID_LENGTH, BONDRY_CREDENTIAL_STATUS_INVALID_PATH,
    BONDRY_CREDENTIAL_STATUS_NOT_FOUND, BONDRY_CREDENTIAL_STATUS_NULL_POINTER,
    BONDRY_CREDENTIAL_STATUS_OK, BONDRY_CREDENTIAL_STATUS_UNSAFE_STORAGE,
    BONDRY_CREDENTIAL_STORE_ACCESS_READ_WRITE_V1, BONDRY_MAX_CREDENTIAL_ID_LENGTH_V1,
    BONDRY_MAX_CREDENTIAL_LENGTH_V1, BondryCredentialStoreCapabilitiesV1,
    BondryCredentialStoreHandle, bondry_credential_store_capabilities_v1,
    bondry_credential_store_close_v1, bondry_credential_store_delete_v1,
    bondry_credential_store_load_v1, bondry_credential_store_store_v1,
    bondry_credentials_abi_version_v1, bondry_unix_file_credential_store_open_v1,
};

#[test]
fn reports_abi_version() {
    assert_eq!(
        bondry_credentials_abi_version_v1(),
        BONDRY_CREDENTIAL_ABI_VERSION_V1
    );
    assert_eq!(BONDRY_MAX_CREDENTIAL_ID_LENGTH_V1, 255);
    assert_eq!(BONDRY_MAX_CREDENTIAL_LENGTH_V1, 65_536);
}

#[test]
fn exposes_capabilities_and_round_trips_credentials() -> Result<(), Box<dyn std::error::Error>> {
    let (directory, store) = open_store()?;
    let mut capabilities: BondryCredentialStoreCapabilitiesV1 = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { bondry_credential_store_capabilities_v1(store, &mut capabilities) },
        BONDRY_CREDENTIAL_STATUS_OK
    );
    assert_eq!(
        capabilities.protection,
        BONDRY_CREDENTIAL_PROTECTION_ACCESS_CONTROLLED_V1
    );
    assert_eq!(
        capabilities.access,
        BONDRY_CREDENTIAL_STORE_ACCESS_READ_WRITE_V1
    );
    assert_eq!(capabilities.supports_unattended_access, 1);

    let id = b"database-key";
    let first = b"first secret";
    assert_eq!(
        unsafe {
            bondry_credential_store_store_v1(
                store,
                id.as_ptr(),
                id.len(),
                first.as_ptr(),
                first.len(),
            )
        },
        BONDRY_CREDENTIAL_STATUS_OK
    );

    let mut length = usize::MAX;
    assert_eq!(
        unsafe {
            bondry_credential_store_load_v1(
                store,
                id.as_ptr(),
                id.len(),
                ptr::null_mut(),
                0,
                &mut length,
            )
        },
        BONDRY_CREDENTIAL_STATUS_OK
    );
    assert_eq!(length, first.len());

    let mut short = [0_u8; 2];
    assert_eq!(
        unsafe {
            bondry_credential_store_load_v1(
                store,
                id.as_ptr(),
                id.len(),
                short.as_mut_ptr(),
                short.len(),
                &mut length,
            )
        },
        BONDRY_CREDENTIAL_STATUS_BUFFER_TOO_SMALL
    );
    assert_eq!(length, first.len());

    let mut output = vec![0_u8; length];
    assert_eq!(
        unsafe {
            bondry_credential_store_load_v1(
                store,
                id.as_ptr(),
                id.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut length,
            )
        },
        BONDRY_CREDENTIAL_STATUS_OK
    );
    assert_eq!(output, first);

    let mut deleted = 0;
    assert_eq!(
        unsafe { bondry_credential_store_delete_v1(store, id.as_ptr(), id.len(), &mut deleted) },
        BONDRY_CREDENTIAL_STATUS_OK
    );
    assert_eq!(deleted, 1);
    assert_eq!(
        unsafe {
            bondry_credential_store_load_v1(
                store,
                id.as_ptr(),
                id.len(),
                ptr::null_mut(),
                0,
                &mut length,
            )
        },
        BONDRY_CREDENTIAL_STATUS_NOT_FOUND
    );
    assert_eq!(length, 0);
    close_store(store);
    drop(directory);
    Ok(())
}

#[test]
fn rejects_invalid_inputs_and_unsafe_directories() -> Result<(), Box<dyn std::error::Error>> {
    let relative = b"relative";
    let mut store = ptr::null_mut();
    assert_eq!(
        unsafe {
            bondry_unix_file_credential_store_open_v1(relative.as_ptr(), relative.len(), &mut store)
        },
        BONDRY_CREDENTIAL_STATUS_UNSAFE_STORAGE
    );
    assert!(store.is_null());

    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))?;
    let path = path_bytes(&directory)?;
    assert_eq!(
        unsafe { bondry_unix_file_credential_store_open_v1(path.as_ptr(), path.len(), &mut store) },
        BONDRY_CREDENTIAL_STATUS_UNSAFE_STORAGE
    );

    let (directory, store) = open_store()?;
    let invalid_id = b"nested/secret";
    let value = b"value";
    assert_eq!(
        unsafe {
            bondry_credential_store_store_v1(
                store,
                invalid_id.as_ptr(),
                invalid_id.len(),
                value.as_ptr(),
                value.len(),
            )
        },
        BONDRY_CREDENTIAL_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(
        unsafe { bondry_credential_store_store_v1(store, b"valid".as_ptr(), 5, value.as_ptr(), 0) },
        BONDRY_CREDENTIAL_STATUS_INVALID_LENGTH
    );
    close_store(store);
    drop(directory);
    Ok(())
}

#[test]
fn validates_required_pointers() {
    let path = b"/tmp";
    assert_eq!(
        unsafe {
            bondry_unix_file_credential_store_open_v1(path.as_ptr(), path.len(), ptr::null_mut())
        },
        BONDRY_CREDENTIAL_STATUS_NULL_POINTER
    );
    let mut store = ptr::null_mut();
    assert_eq!(
        unsafe { bondry_unix_file_credential_store_open_v1(ptr::null(), 0, &mut store) },
        BONDRY_CREDENTIAL_STATUS_NULL_POINTER
    );
    assert_eq!(
        unsafe { bondry_credential_store_close_v1(ptr::null_mut()) },
        BONDRY_CREDENTIAL_STATUS_OK
    );
    assert_eq!(
        unsafe { bondry_unix_file_credential_store_open_v1(b"".as_ptr(), 0, &mut store) },
        BONDRY_CREDENTIAL_STATUS_INVALID_PATH
    );
}

fn open_store() -> Result<(TempDir, *mut BondryCredentialStoreHandle), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = path_bytes(&directory)?;
    let mut store = ptr::null_mut();
    let status =
        unsafe { bondry_unix_file_credential_store_open_v1(path.as_ptr(), path.len(), &mut store) };
    if status != BONDRY_CREDENTIAL_STATUS_OK || store.is_null() {
        return Err(format!("credential store open failed with status {status}").into());
    }
    Ok((directory, store))
}

fn close_store(store: *mut BondryCredentialStoreHandle) {
    assert_eq!(
        unsafe { bondry_credential_store_close_v1(store) },
        BONDRY_CREDENTIAL_STATUS_OK
    );
}

fn path_bytes(directory: &TempDir) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(directory
        .path()
        .to_str()
        .ok_or("temporary path is not UTF-8")?
        .as_bytes()
        .to_vec())
}
