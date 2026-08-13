use std::{fs, ptr};

use tempfile::tempdir;

use super::{
    BONDRY_ABI_VERSION_V1, BONDRY_STATUS_INTERNAL_FAILURE, BONDRY_STATUS_INVALID_DATABASE_KEY,
    BONDRY_STATUS_INVALID_LENGTH, BONDRY_STATUS_INVALID_PATH, BONDRY_STATUS_INVALID_UTF8,
    BONDRY_STATUS_NULL_POINTER, BONDRY_STATUS_OK, BondryStoreHandle, bondry_abi_version_v1,
    bondry_store_check_v1, bondry_store_close_v1, bondry_store_open_v1, catch_status,
};

#[test]
fn reports_version_one() {
    assert_eq!(bondry_abi_version_v1(), BONDRY_ABI_VERSION_V1);
}

#[test]
fn validates_every_pointer_and_length() {
    let path = b"database.db";
    let key = [0x11_u8; 32];
    let mut handle = ptr::null_mut();

    let null_output = unsafe {
        bondry_store_open_v1(
            path.as_ptr(),
            path.len(),
            key.as_ptr(),
            key.len(),
            ptr::null_mut(),
        )
    };
    assert_eq!(null_output, BONDRY_STATUS_NULL_POINTER);

    let null_path = unsafe {
        bondry_store_open_v1(
            ptr::null(),
            path.len(),
            key.as_ptr(),
            key.len(),
            &mut handle,
        )
    };
    assert_eq!(null_path, BONDRY_STATUS_NULL_POINTER);
    assert!(handle.is_null());

    let null_key = unsafe {
        bondry_store_open_v1(
            path.as_ptr(),
            path.len(),
            ptr::null(),
            key.len(),
            &mut handle,
        )
    };
    assert_eq!(null_key, BONDRY_STATUS_NULL_POINTER);
    assert!(handle.is_null());

    let short_key = unsafe {
        bondry_store_open_v1(
            path.as_ptr(),
            path.len(),
            key.as_ptr(),
            key.len() - 1,
            &mut handle,
        )
    };
    assert_eq!(short_key, BONDRY_STATUS_INVALID_LENGTH);
    assert!(handle.is_null());
}

#[test]
fn validates_path_encoding_and_shape() {
    let key = [0x22_u8; 32];
    let mut handle = ptr::null_mut();
    let invalid_utf8 = [0xFF_u8];

    let utf8_status = unsafe {
        bondry_store_open_v1(
            invalid_utf8.as_ptr(),
            invalid_utf8.len(),
            key.as_ptr(),
            key.len(),
            &mut handle,
        )
    };
    assert_eq!(utf8_status, BONDRY_STATUS_INVALID_UTF8);
    assert!(handle.is_null());

    let empty_status =
        unsafe { bondry_store_open_v1(b"".as_ptr(), 0, key.as_ptr(), key.len(), &mut handle) };
    assert_eq!(empty_status, BONDRY_STATUS_INVALID_PATH);
    assert!(handle.is_null());

    let nul_path = b"invalid\0path";
    let nul_status = unsafe {
        bondry_store_open_v1(
            nul_path.as_ptr(),
            nul_path.len(),
            key.as_ptr(),
            key.len(),
            &mut handle,
        )
    };
    assert_eq!(nul_status, BONDRY_STATUS_INVALID_PATH);
    assert!(handle.is_null());
}

#[test]
fn opens_checks_and_closes_an_encrypted_store() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("bondry.db");
    let path_bytes = path.to_string_lossy();
    let key = [0x33_u8; 32];
    let mut handle: *mut BondryStoreHandle = ptr::null_mut();

    let open_status = unsafe {
        bondry_store_open_v1(
            path_bytes.as_ptr(),
            path_bytes.len(),
            key.as_ptr(),
            key.len(),
            &mut handle,
        )
    };
    assert_eq!(open_status, BONDRY_STATUS_OK);
    assert!(!handle.is_null());
    assert_eq!(unsafe { bondry_store_check_v1(handle) }, BONDRY_STATUS_OK);
    assert_eq!(unsafe { bondry_store_close_v1(handle) }, BONDRY_STATUS_OK);

    let raw = fs::read(path)?;
    assert!(!raw.starts_with(b"SQLite format 3\0"));
    assert!(
        !raw.windows(b"CREATE TABLE clients".len())
            .any(|window| { window == b"CREATE TABLE clients" })
    );
    Ok(())
}

#[test]
fn rejects_a_wrong_database_key() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("bondry.db");
    let path_bytes = path.to_string_lossy();
    let first_key = [0x44_u8; 32];
    let wrong_key = [0x45_u8; 32];
    let mut handle = ptr::null_mut();

    assert_eq!(
        unsafe {
            bondry_store_open_v1(
                path_bytes.as_ptr(),
                path_bytes.len(),
                first_key.as_ptr(),
                first_key.len(),
                &mut handle,
            )
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(unsafe { bondry_store_close_v1(handle) }, BONDRY_STATUS_OK);

    let status = unsafe {
        bondry_store_open_v1(
            path_bytes.as_ptr(),
            path_bytes.len(),
            wrong_key.as_ptr(),
            wrong_key.len(),
            &mut handle,
        )
    };
    assert_eq!(status, BONDRY_STATUS_INVALID_DATABASE_KEY);
    assert!(handle.is_null());
    Ok(())
}

#[test]
fn null_handle_operations_are_safe() {
    assert_eq!(
        unsafe { bondry_store_check_v1(ptr::null()) },
        BONDRY_STATUS_NULL_POINTER
    );
    assert_eq!(
        unsafe { bondry_store_close_v1(ptr::null_mut()) },
        BONDRY_STATUS_OK
    );
}

#[test]
fn catches_unwinding_at_the_abi_boundary() {
    let status = catch_status(|| std::panic::resume_unwind(Box::new("test panic")));
    assert_eq!(status, BONDRY_STATUS_INTERNAL_FAILURE);
}
