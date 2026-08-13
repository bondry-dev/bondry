use std::{fs, ptr, slice, time::SystemTime};

use bondry_core::{
    AdapterId, AuditEvent, AuditOutcome, AuditSink, CapabilityId, HandlerErrorCode, InvocationId,
    PrincipalId,
};
use tempfile::tempdir;

use super::{
    BONDRY_ABI_VERSION_V1, BONDRY_STATUS_AUTHENTICATION_REJECTED, BONDRY_STATUS_BUFFER_TOO_SMALL,
    BONDRY_STATUS_CLIENT_DISABLED, BONDRY_STATUS_INTERNAL_FAILURE, BONDRY_STATUS_INVALID_ARGUMENT,
    BONDRY_STATUS_INVALID_DATABASE_KEY, BONDRY_STATUS_INVALID_LENGTH, BONDRY_STATUS_INVALID_PATH,
    BONDRY_STATUS_INVALID_UTF8, BONDRY_STATUS_NULL_POINTER, BONDRY_STATUS_OK, BondryAuditEventV1,
    BondryClientV1, BondryIssuedTokenV1, BondryPrincipalV1, BondryStoreHandle,
    BondryTokenMetadataV1, StoreHandle, bondry_abi_version_v1, bondry_audit_for_principal_v1,
    bondry_audit_recent_v1, bondry_client_create_v1, bondry_client_set_enabled_v1,
    bondry_clients_list_v1, bondry_issued_token_clear_v1, bondry_store_check_v1,
    bondry_store_close_v1, bondry_store_open_v1, bondry_token_authenticate_v1,
    bondry_token_issue_v1, bondry_token_revoke_v1, bondry_token_rotate_v1, bondry_tokens_list_v1,
    catch_status,
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

    let oversized_path = unsafe {
        bondry_store_open_v1(
            path.as_ptr(),
            (isize::MAX as usize) + 1,
            key.as_ptr(),
            key.len(),
            &mut handle,
        )
    };
    assert_eq!(oversized_path, BONDRY_STATUS_INVALID_LENGTH);
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

#[test]
fn manages_clients_with_caller_owned_records() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, store) = open_test_store(0x51)?;
    let mut first: BondryClientV1 = unsafe { std::mem::zeroed() };
    let mut second: BondryClientV1 = unsafe { std::mem::zeroed() };

    assert_eq!(
        unsafe { bondry_client_create_v1(store, b"First".as_ptr(), 5, &mut first) },
        BONDRY_STATUS_OK
    );
    assert_eq!(utf8_field(&first.name)?, "First");
    assert_eq!(first.enabled, 1);
    assert_eq!(
        unsafe { bondry_client_create_v1(store, b"Second".as_ptr(), 6, &mut second) },
        BONDRY_STATUS_OK
    );

    let mut count = usize::MAX;
    assert_eq!(
        unsafe { bondry_clients_list_v1(store, ptr::null_mut(), 0, &mut count) },
        BONDRY_STATUS_OK
    );
    assert_eq!(count, 2);
    let mut short: BondryClientV1 = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { bondry_clients_list_v1(store, &mut short, 1, &mut count) },
        BONDRY_STATUS_BUFFER_TOO_SMALL
    );
    assert_eq!(count, 2);
    let mut clients: [BondryClientV1; 2] = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { bondry_clients_list_v1(store, clients.as_mut_ptr(), clients.len(), &mut count) },
        BONDRY_STATUS_OK
    );
    assert!(utf8_field(&clients[0].id)? < utf8_field(&clients[1].id)?);
    close_test_store(store);
    Ok(())
}

#[test]
fn issues_authenticates_rotates_revokes_and_clears_tokens() -> Result<(), Box<dyn std::error::Error>>
{
    let (_directory, store) = open_test_store(0x52)?;
    let mut client: BondryClientV1 = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { bondry_client_create_v1(store, b"Automation".as_ptr(), 10, &mut client) },
        BONDRY_STATUS_OK
    );
    let client_id = utf8_field(&client.id)?.as_bytes().to_vec();
    let mut issued: BondryIssuedTokenV1 = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            bondry_token_issue_v1(
                store,
                client_id.as_ptr(),
                client_id.len(),
                b"Primary".as_ptr(),
                7,
                3_600,
                1,
                &mut issued,
            )
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(utf8_field(&issued.metadata.label)?, "Primary");
    assert_eq!(issued.metadata.has_label, 1);
    assert_eq!(issued.metadata.has_expiration, 1);
    let original_id = utf8_field(&issued.metadata.id)?.as_bytes().to_vec();
    let original_secret = utf8_field(&issued.secret)?.as_bytes().to_vec();
    assert!(utf8_field(&issued.secret)?.starts_with("bondry_v1.token_"));

    let mut principal: BondryPrincipalV1 = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            bondry_token_authenticate_v1(
                store,
                original_secret.as_ptr(),
                original_secret.len(),
                &mut principal,
            )
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(utf8_field(&principal.id)?.as_bytes(), client_id);
    assert_eq!(principal.kind, 2);

    assert_eq!(
        unsafe { bondry_client_set_enabled_v1(store, client_id.as_ptr(), client_id.len(), 0) },
        BONDRY_STATUS_OK
    );
    assert_eq!(
        unsafe {
            bondry_token_authenticate_v1(
                store,
                original_secret.as_ptr(),
                original_secret.len(),
                &mut principal,
            )
        },
        BONDRY_STATUS_AUTHENTICATION_REJECTED
    );
    let mut blocked: BondryIssuedTokenV1 = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            bondry_token_issue_v1(
                store,
                client_id.as_ptr(),
                client_id.len(),
                ptr::null(),
                0,
                0,
                0,
                &mut blocked,
            )
        },
        BONDRY_STATUS_CLIENT_DISABLED
    );
    assert_eq!(
        unsafe { bondry_client_set_enabled_v1(store, client_id.as_ptr(), client_id.len(), 1) },
        BONDRY_STATUS_OK
    );

    let mut replacement: BondryIssuedTokenV1 = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            bondry_token_rotate_v1(
                store,
                original_id.as_ptr(),
                original_id.len(),
                ptr::null(),
                0,
                0,
                0,
                &mut replacement,
            )
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(
        unsafe {
            bondry_token_authenticate_v1(
                store,
                original_secret.as_ptr(),
                original_secret.len(),
                &mut principal,
            )
        },
        BONDRY_STATUS_AUTHENTICATION_REJECTED
    );
    let replacement_secret = utf8_field(&replacement.secret)?.as_bytes().to_vec();
    assert_eq!(
        unsafe {
            bondry_token_authenticate_v1(
                store,
                replacement_secret.as_ptr(),
                replacement_secret.len(),
                &mut principal,
            )
        },
        BONDRY_STATUS_OK
    );

    let mut token_count = 0;
    assert_eq!(
        unsafe {
            bondry_tokens_list_v1(
                store,
                client_id.as_ptr(),
                client_id.len(),
                ptr::null_mut(),
                0,
                &mut token_count,
            )
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(token_count, 2);
    let mut tokens: [BondryTokenMetadataV1; 2] = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            bondry_tokens_list_v1(
                store,
                client_id.as_ptr(),
                client_id.len(),
                tokens.as_mut_ptr(),
                tokens.len(),
                &mut token_count,
            )
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(
        tokens
            .iter()
            .filter(|token| token.has_revocation == 1)
            .count(),
        1
    );

    let replacement_id = utf8_field(&replacement.metadata.id)?.as_bytes().to_vec();
    let mut changed = 9;
    assert_eq!(
        unsafe {
            bondry_token_revoke_v1(
                store,
                replacement_id.as_ptr(),
                replacement_id.len(),
                &mut changed,
            )
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(changed, 1);
    assert_eq!(
        unsafe {
            bondry_token_revoke_v1(
                store,
                replacement_id.as_ptr(),
                replacement_id.len(),
                &mut changed,
            )
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(changed, 0);

    assert_eq!(
        unsafe { bondry_issued_token_clear_v1(&mut replacement) },
        BONDRY_STATUS_OK
    );
    assert!(record_bytes(&replacement).iter().all(|byte| *byte == 0));
    assert_eq!(
        unsafe { bondry_issued_token_clear_v1(ptr::null_mut()) },
        BONDRY_STATUS_OK
    );
    close_test_store(store);
    Ok(())
}

#[test]
fn validates_authentication_inputs_and_initializes_outputs()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, store) = open_test_store(0x53)?;
    let mut client: BondryClientV1 = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { bondry_client_create_v1(store, b" ".as_ptr(), 1, &mut client) },
        BONDRY_STATUS_INVALID_ARGUMENT
    );
    assert!(record_bytes(&client).iter().all(|byte| *byte == 0));
    assert_eq!(
        unsafe { bondry_client_create_v1(store, [0xFF_u8].as_ptr(), 1, &mut client) },
        BONDRY_STATUS_INVALID_UTF8
    );
    assert_eq!(
        unsafe {
            bondry_client_create_v1(store, b"x".as_ptr(), (isize::MAX as usize) + 1, &mut client)
        },
        BONDRY_STATUS_INVALID_LENGTH
    );
    let mut count = 99;
    assert_eq!(
        unsafe { bondry_clients_list_v1(ptr::null(), ptr::null_mut(), 0, &mut count) },
        BONDRY_STATUS_NULL_POINTER
    );
    assert_eq!(count, 0);

    assert_eq!(
        unsafe { bondry_client_create_v1(store, b"Client".as_ptr(), 6, &mut client) },
        BONDRY_STATUS_OK
    );
    let client_id = utf8_field(&client.id)?.as_bytes().to_vec();
    assert_eq!(
        unsafe { bondry_client_set_enabled_v1(store, client_id.as_ptr(), client_id.len(), 2) },
        BONDRY_STATUS_INVALID_ARGUMENT
    );
    let mut issued: BondryIssuedTokenV1 = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            bondry_token_issue_v1(
                store,
                client_id.as_ptr(),
                client_id.len(),
                ptr::null(),
                1,
                0,
                0,
                &mut issued,
            )
        },
        BONDRY_STATUS_NULL_POINTER
    );
    assert_eq!(
        unsafe {
            bondry_token_issue_v1(
                store,
                client_id.as_ptr(),
                client_id.len(),
                ptr::null(),
                0,
                0,
                1,
                &mut issued,
            )
        },
        BONDRY_STATUS_INVALID_ARGUMENT
    );
    assert!(record_bytes(&issued).iter().all(|byte| *byte == 0));
    close_test_store(store);
    Ok(())
}

#[test]
fn returns_bounded_protocol_neutral_audit_records() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, store) = open_test_store(0x54)?;
    let mut client: BondryClientV1 = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { bondry_client_create_v1(store, b"Audited".as_ptr(), 7, &mut client) },
        BONDRY_STATUS_OK
    );
    let client_id = utf8_field(&client.id)?.to_owned();
    // SAFETY: store is live for this test and points to the private handle allocation.
    let handle = unsafe { &*store.cast::<StoreHandle>() };
    handle.store.record(AuditEvent::from_parts(
        SystemTime::now(),
        InvocationId::new("request-1")?,
        PrincipalId::new(client_id.clone())?,
        AdapterId::new("rest")?,
        CapabilityId::new("battery.read")?,
        AuditOutcome::HandlerFailed(HandlerErrorCode::new("temporarily_unavailable")?),
    ))?;
    handle.store.record(AuditEvent::from_parts(
        SystemTime::now(),
        InvocationId::new("request-2")?,
        PrincipalId::new("client_other")?,
        AdapterId::new("mcp")?,
        CapabilityId::new("battery.health")?,
        AuditOutcome::Succeeded,
    ))?;

    let mut count = 99;
    assert_eq!(
        unsafe { bondry_audit_recent_v1(store, 0, ptr::null_mut(), 0, &mut count) },
        BONDRY_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(count, 0);
    assert_eq!(
        unsafe { bondry_audit_recent_v1(store, 10, ptr::null_mut(), 0, &mut count) },
        BONDRY_STATUS_OK
    );
    assert_eq!(count, 2);
    let mut events: [BondryAuditEventV1; 2] = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { bondry_audit_recent_v1(store, 10, events.as_mut_ptr(), 1, &mut count) },
        BONDRY_STATUS_BUFFER_TOO_SMALL
    );
    assert_eq!(count, 2);
    assert_eq!(
        unsafe {
            bondry_audit_for_principal_v1(
                store,
                client_id.as_ptr(),
                client_id.len(),
                10,
                events.as_mut_ptr(),
                events.len(),
                &mut count,
            )
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(count, 1);
    assert_eq!(utf8_field(&events[0].invocation_id)?, "request-1");
    assert_eq!(events[0].outcome, 5);
    assert_eq!(events[0].has_detail_code, 1);
    assert_eq!(
        utf8_field(&events[0].detail_code)?,
        "temporarily_unavailable"
    );
    close_test_store(store);
    Ok(())
}

fn open_test_store(
    key_byte: u8,
) -> Result<(tempfile::TempDir, *mut BondryStoreHandle), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let path = directory.path().join("bondry.db");
    let path = path.to_string_lossy();
    let key = [key_byte; 32];
    let mut store = ptr::null_mut();
    let status = unsafe {
        bondry_store_open_v1(
            path.as_ptr(),
            path.len(),
            key.as_ptr(),
            key.len(),
            &mut store,
        )
    };
    if status != BONDRY_STATUS_OK || store.is_null() {
        return Err(std::io::Error::other(format!("open failed with status {status}")).into());
    }
    Ok((directory, store))
}

fn close_test_store(store: *mut BondryStoreHandle) {
    assert_eq!(unsafe { bondry_store_close_v1(store) }, BONDRY_STATUS_OK);
}

fn utf8_field(bytes: &[u8]) -> Result<&str, Box<dyn std::error::Error>> {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    Ok(std::str::from_utf8(&bytes[..length])?)
}

fn record_bytes<T>(record: &T) -> &[u8] {
    // SAFETY: A shared record reference is readable for its complete object representation.
    unsafe { slice::from_raw_parts(ptr::from_ref(record).cast::<u8>(), std::mem::size_of::<T>()) }
}
