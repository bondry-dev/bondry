use std::{
    ffi::c_void,
    fs, ptr, slice,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicUsize, Ordering},
        mpsc::{self, Receiver},
    },
    time::{Duration, SystemTime},
};

use bondry_core::{
    AdapterId, AuditEvent, AuditOutcome, AuditSink, CapabilityId, HandlerErrorCode, InvocationId,
    PrincipalId,
};
use tempfile::tempdir;

use super::{
    BONDRY_ABI_VERSION_V1, BONDRY_STATUS_AUTHENTICATION_REJECTED, BONDRY_STATUS_BUFFER_TOO_SMALL,
    BONDRY_STATUS_CLIENT_DISABLED, BONDRY_STATUS_INTERNAL_FAILURE, BONDRY_STATUS_INVALID_ARGUMENT,
    BONDRY_STATUS_INVALID_DATABASE_KEY, BONDRY_STATUS_INVALID_LENGTH, BONDRY_STATUS_INVALID_PATH,
    BONDRY_STATUS_INVALID_UTF8, BONDRY_STATUS_NULL_POINTER, BONDRY_STATUS_OK,
    BONDRY_STATUS_PAYLOAD_TOO_LARGE, BondryAuditEventV1, BondryCapabilityCompletionV1,
    BondryCapabilityV1, BondryClientV1, BondryDispatchResultV1, BondryGrantV1, BondryInvocationV1,
    BondryIssuedTokenV1, BondryPrincipalV1, BondryStoreHandle, BondryTokenMetadataV1, StoreHandle,
    bondry_abi_version_v1, bondry_audit_for_principal_v1, bondry_audit_recent_v1,
    bondry_capabilities_discover_json_v1, bondry_capabilities_json_v1, bondry_capabilities_list_v1,
    bondry_capability_register_v1, bondry_capability_register_with_schema_v1,
    bondry_capability_unregister_v1, bondry_client_create_v1, bondry_client_set_enabled_v1,
    bondry_clients_list_v1, bondry_dispatch_principal_v1, bondry_dispatch_token_v1,
    bondry_grant_add_v1, bondry_grant_remove_v1, bondry_grants_list_v1,
    bondry_issued_token_clear_v1, bondry_store_check_v1, bondry_store_close_v1,
    bondry_store_open_v1, bondry_store_retain_v1, bondry_token_authenticate_v1,
    bondry_token_issue_v1, bondry_token_revoke_v1, bondry_token_rotate_v1, bondry_tokens_list_v1,
    catch_status,
    records::{
        BONDRY_AUDIT_OUTCOME_DENIED_V1, BONDRY_AUDIT_OUTCOME_SUCCEEDED_V1,
        BONDRY_CAPABILITY_EFFECT_MUTATING_V1, BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1,
        BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1, BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1,
        BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1, BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1,
        BONDRY_HANDLER_RESULT_FAILED_V1, BONDRY_HANDLER_RESULT_SUCCEEDED_V1,
        BONDRY_PRINCIPAL_KIND_SYSTEM_V1,
    },
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
fn retains_store_ownership_for_independent_components() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, store) = open_test_store(0x34)?;
    let mut retained = ptr::null_mut();

    assert_eq!(
        unsafe { bondry_store_retain_v1(store, &mut retained) },
        BONDRY_STATUS_OK
    );
    assert!(!retained.is_null());
    close_test_store(store);
    assert_eq!(unsafe { bondry_store_check_v1(retained) }, BONDRY_STATUS_OK);
    close_test_store(retained);
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

#[test]
fn manages_exact_authorization_grants() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, store) = open_test_store(0x55)?;
    let principal = b"client_policy";
    let mut changed = 9;
    assert_eq!(
        unsafe {
            bondry_grant_add_v1(
                store,
                principal.as_ptr(),
                principal.len(),
                b"rest".as_ptr(),
                4,
                b"battery.status".as_ptr(),
                14,
                &mut changed,
            )
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(changed, 1);
    assert_eq!(
        unsafe {
            bondry_grant_add_v1(
                store,
                principal.as_ptr(),
                principal.len(),
                b"rest".as_ptr(),
                4,
                b"battery.status".as_ptr(),
                14,
                &mut changed,
            )
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(changed, 0);
    assert_eq!(
        unsafe {
            bondry_grant_add_v1(
                store,
                principal.as_ptr(),
                principal.len(),
                b"mcp".as_ptr(),
                3,
                b"battery.health".as_ptr(),
                14,
                &mut changed,
            )
        },
        BONDRY_STATUS_OK
    );

    let mut count = 0;
    assert_eq!(
        unsafe {
            bondry_grants_list_v1(
                store,
                principal.as_ptr(),
                principal.len(),
                ptr::null_mut(),
                0,
                &mut count,
            )
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(count, 2);
    let mut grants: [BondryGrantV1; 2] = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            bondry_grants_list_v1(
                store,
                principal.as_ptr(),
                principal.len(),
                grants.as_mut_ptr(),
                grants.len(),
                &mut count,
            )
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(utf8_field(&grants[0].adapter_id)?, "mcp");
    assert_eq!(utf8_field(&grants[1].adapter_id)?, "rest");
    assert_eq!(utf8_field(&grants[1].capability_id)?, "battery.status");

    assert_eq!(
        unsafe {
            bondry_grant_remove_v1(
                store,
                principal.as_ptr(),
                principal.len(),
                b"rest".as_ptr(),
                4,
                b"battery.status".as_ptr(),
                14,
                &mut changed,
            )
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(changed, 1);
    assert_eq!(
        unsafe {
            bondry_grant_add_v1(
                store,
                principal.as_ptr(),
                principal.len(),
                b"invalid adapter".as_ptr(),
                15,
                b"battery.status".as_ptr(),
                14,
                &mut changed,
            )
        },
        BONDRY_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(changed, 0);
    close_test_store(store);
    Ok(())
}

#[test]
fn registers_lists_and_releases_capabilities() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, store) = open_test_store(0x56)?;
    let releases = Arc::new(AtomicUsize::new(0));
    let first = test_handler_context(releases.clone());
    assert_eq!(
        unsafe {
            bondry_capability_register_v1(
                store,
                b"battery.status".as_ptr(),
                14,
                b"Read battery status".as_ptr(),
                19,
                BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1,
                first,
                Some(test_handler),
                Some(release_test_handler),
            )
        },
        BONDRY_STATUS_OK
    );
    let second = test_handler_context(releases.clone());
    assert_eq!(
        unsafe {
            bondry_capability_register_v1(
                store,
                b"battery.configure".as_ptr(),
                17,
                b"Change battery settings".as_ptr(),
                23,
                BONDRY_CAPABILITY_EFFECT_MUTATING_V1,
                second,
                Some(test_handler),
                Some(release_test_handler),
            )
        },
        BONDRY_STATUS_OK
    );

    let duplicate = test_handler_context(releases.clone());
    assert_eq!(
        unsafe {
            bondry_capability_register_v1(
                store,
                b"battery.status".as_ptr(),
                14,
                b"Read battery status".as_ptr(),
                19,
                BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1,
                duplicate,
                Some(test_handler),
                Some(release_test_handler),
            )
        },
        super::BONDRY_STATUS_ALREADY_EXISTS
    );
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    // SAFETY: Failed registration leaves this allocation owned by the caller.
    unsafe { release_test_handler(duplicate) };

    let mut count = 0;
    assert_eq!(
        unsafe { bondry_capabilities_list_v1(store, ptr::null_mut(), 0, &mut count) },
        BONDRY_STATUS_OK
    );
    assert_eq!(count, 2);
    let mut records: [BondryCapabilityV1; 2] = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            bondry_capabilities_list_v1(store, records.as_mut_ptr(), records.len(), &mut count)
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(utf8_field(&records[0].id)?, "battery.configure");
    assert_eq!(utf8_field(&records[0].summary)?, "Change battery settings");
    assert_eq!(records[0].effect, BONDRY_CAPABILITY_EFFECT_MUTATING_V1);
    assert_eq!(utf8_field(&records[1].id)?, "battery.status");

    let mut changed = 0;
    assert_eq!(
        unsafe {
            bondry_capability_unregister_v1(store, b"battery.status".as_ptr(), 14, &mut changed)
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(changed, 1);
    assert_eq!(releases.load(Ordering::SeqCst), 2);
    close_test_store(store);
    assert_eq!(releases.load(Ordering::SeqCst), 3);
    Ok(())
}

#[test]
fn discovers_authorized_capabilities_with_input_schemas() -> Result<(), Box<dyn std::error::Error>>
{
    let (_directory, store) = open_test_store(0x5E)?;
    let releases = Arc::new(AtomicUsize::new(0));
    let context = test_handler_context(releases.clone());
    let schema =
        br#"{"type":"object","properties":{"level":{"type":"integer"}},"required":["level"]}"#;
    assert_eq!(
        unsafe {
            bondry_capability_register_with_schema_v1(
                store,
                b"battery.configure".as_ptr(),
                17,
                b"Change battery settings".as_ptr(),
                23,
                BONDRY_CAPABILITY_EFFECT_MUTATING_V1,
                schema.as_ptr(),
                schema.len(),
                context,
                Some(test_handler),
                Some(release_test_handler),
            )
        },
        BONDRY_STATUS_OK
    );
    let principal = b"desktop-client";
    let mut changed = 0;
    assert_eq!(
        unsafe {
            bondry_grant_add_v1(
                store,
                principal.as_ptr(),
                principal.len(),
                b"rest".as_ptr(),
                4,
                b"battery.configure".as_ptr(),
                17,
                &mut changed,
            )
        },
        BONDRY_STATUS_OK
    );

    let mut registered_length = 0;
    assert_eq!(
        unsafe { bondry_capabilities_json_v1(store, ptr::null_mut(), 0, &mut registered_length,) },
        BONDRY_STATUS_OK
    );
    let mut registered = vec![0_u8; registered_length];
    assert_eq!(
        unsafe {
            bondry_capabilities_json_v1(
                store,
                registered.as_mut_ptr(),
                registered.len(),
                &mut registered_length,
            )
        },
        BONDRY_STATUS_OK
    );
    let registered: serde_json::Value = serde_json::from_slice(&registered)?;
    assert_eq!(registered[0]["input_schema"]["required"][0], "level");

    let mut length = 0;
    assert_eq!(
        unsafe {
            bondry_capabilities_discover_json_v1(
                store,
                principal.as_ptr(),
                principal.len(),
                super::records::BONDRY_PRINCIPAL_KIND_APPLICATION_V1,
                b"rest".as_ptr(),
                4,
                ptr::null_mut(),
                0,
                &mut length,
            )
        },
        BONDRY_STATUS_OK
    );
    let mut output = vec![0_u8; length];
    assert_eq!(
        unsafe {
            bondry_capabilities_discover_json_v1(
                store,
                principal.as_ptr(),
                principal.len(),
                super::records::BONDRY_PRINCIPAL_KIND_APPLICATION_V1,
                b"rest".as_ptr(),
                4,
                output.as_mut_ptr(),
                output.len(),
                &mut length,
            )
        },
        BONDRY_STATUS_OK
    );
    let descriptors: serde_json::Value = serde_json::from_slice(&output)?;
    assert_eq!(descriptors[0]["id"], "battery.configure");
    assert_eq!(descriptors[0]["effect"], "mutating");
    assert_eq!(descriptors[0]["input_schema"]["type"], "object");
    assert_eq!(descriptors[0]["input_schema"]["required"][0], "level");

    close_test_store(store);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn validates_capability_registration_inputs() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, store) = open_test_store(0x57)?;
    let releases = Arc::new(AtomicUsize::new(0));
    let context = test_handler_context(releases.clone());
    assert_eq!(
        unsafe {
            bondry_capability_register_v1(
                store,
                b"invalid capability".as_ptr(),
                18,
                b"Summary".as_ptr(),
                7,
                BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1,
                context,
                Some(test_handler),
                Some(release_test_handler),
            )
        },
        BONDRY_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    assert_eq!(
        unsafe {
            bondry_capability_register_v1(
                store,
                b"valid".as_ptr(),
                5,
                b"\n".as_ptr(),
                1,
                BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1,
                context,
                Some(test_handler),
                Some(release_test_handler),
            )
        },
        BONDRY_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(
        unsafe {
            bondry_capability_register_v1(
                store,
                b"valid".as_ptr(),
                5,
                b"Summary".as_ptr(),
                7,
                99,
                context,
                Some(test_handler),
                Some(release_test_handler),
            )
        },
        BONDRY_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(
        unsafe {
            bondry_capability_register_v1(
                store,
                b"valid".as_ptr(),
                5,
                b"Summary".as_ptr(),
                7,
                BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1,
                context,
                None,
                Some(release_test_handler),
            )
        },
        BONDRY_STATUS_NULL_POINTER
    );
    // SAFETY: Every failed registration left the context caller-owned.
    unsafe { release_test_handler(context) };
    close_test_store(store);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn authenticates_authorizes_dispatches_and_audits_json() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, store) = open_test_store(0x58)?;
    let (client_id, token) = create_test_credential(store)?;
    let releases = Arc::new(AtomicUsize::new(0));
    let control = Arc::new(TestHandlerControl::default());
    let context = test_handler_context_with_control(releases.clone(), control.clone());
    assert_eq!(
        unsafe {
            bondry_capability_register_v1(
                store,
                b"battery.status".as_ptr(),
                14,
                b"Read battery status".as_ptr(),
                19,
                BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1,
                context,
                Some(test_handler),
                Some(release_test_handler),
            )
        },
        BONDRY_STATUS_OK
    );

    let denied = start_test_dispatch(store, &token, b"battery.status", br#"{"detail":true}"#)?;
    let denied = denied.recv_timeout(Duration::from_secs(1))?;
    assert_eq!(denied.outcome, BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1);
    assert_eq!(denied.detail.as_deref(), Some("not_granted"));
    assert_eq!(control.calls.load(Ordering::SeqCst), 0);

    let mut changed = 0;
    assert_eq!(
        unsafe {
            bondry_grant_add_v1(
                store,
                client_id.as_ptr(),
                client_id.len(),
                b"rest".as_ptr(),
                4,
                b"battery.status".as_ptr(),
                14,
                &mut changed,
            )
        },
        BONDRY_STATUS_OK
    );
    control.mode.store(TEST_HANDLER_SUCCESS, Ordering::SeqCst);
    let succeeded = start_test_dispatch(store, &token, b"battery.status", br#"{"detail":true}"#)?;
    let succeeded = succeeded.recv_timeout(Duration::from_secs(1))?;
    assert_eq!(succeeded.outcome, BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1);
    assert_eq!(
        succeeded.output.as_deref(),
        Some(br#"{"level":85}"#.as_slice())
    );
    assert_eq!(succeeded.detail, None);
    assert_eq!(control.calls.load(Ordering::SeqCst), 1);
    let observed = control
        .observed
        .lock()
        .map_err(|_| std::io::Error::other("observed invocation lock poisoned"))?
        .clone();
    assert_eq!(observed.principal_id, String::from_utf8(client_id.clone())?);
    assert_eq!(observed.adapter_id, "rest");
    assert_eq!(observed.capability_id, "battery.status");
    assert_eq!(observed.input, br#"{"detail":true}"#);

    control.mode.store(TEST_HANDLER_FAILURE, Ordering::SeqCst);
    let failed = start_test_dispatch(store, &token, b"battery.status", b"null")?;
    let failed = failed.recv_timeout(Duration::from_secs(1))?;
    assert_eq!(failed.outcome, BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1);
    assert_eq!(failed.detail.as_deref(), Some("temporarily_unavailable"));

    control.mode.store(TEST_HANDLER_INVALID, Ordering::SeqCst);
    let invalid = start_test_dispatch(store, &token, b"battery.status", b"null")?;
    let invalid = invalid.recv_timeout(Duration::from_secs(1))?;
    assert_eq!(invalid.outcome, BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1);
    assert_eq!(invalid.detail.as_deref(), Some("invalid_handler_result"));

    let missing = start_test_dispatch(store, &token, b"battery.missing", b"{}")?;
    assert_eq!(
        missing.recv_timeout(Duration::from_secs(1))?.outcome,
        BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1
    );

    let events = unsafe_query_audit(store, 20)?;
    assert_eq!(events.iter().filter(|event| event.outcome == 2).count(), 1);
    assert_eq!(events.iter().filter(|event| event.outcome == 3).count(), 3);
    assert_eq!(events.iter().filter(|event| event.outcome == 4).count(), 1);
    assert_eq!(events.iter().filter(|event| event.outcome == 5).count(), 2);
    assert_eq!(events.iter().filter(|event| event.outcome == 1).count(), 1);
    close_test_store(store);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn rejects_dispatch_before_accepting_callback_ownership() -> Result<(), Box<dyn std::error::Error>>
{
    let (_directory, store) = open_test_store(0x59)?;
    let (_client_id, token) = create_test_credential(store)?;

    assert_immediate_dispatch_status(
        store,
        b"invalid-token",
        b"{}",
        BONDRY_STATUS_AUTHENTICATION_REJECTED,
    );
    assert_immediate_dispatch_status(
        store,
        &token,
        b"not-json",
        super::BONDRY_STATUS_INVALID_JSON,
    );
    let oversized = vec![b' '; 1_048_577];
    assert_immediate_dispatch_status(store, &token, &oversized, BONDRY_STATUS_PAYLOAD_TOO_LARGE);
    close_test_store(store);
    Ok(())
}

#[test]
fn dispatches_trusted_principals_through_exact_grants_and_audit()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, store) = open_test_store(0x5C)?;
    let principal = b"shortcuts.local-user";
    let releases = Arc::new(AtomicUsize::new(0));
    let control = Arc::new(TestHandlerControl::default());
    let context = test_handler_context_with_control(releases.clone(), control.clone());
    assert_eq!(
        unsafe {
            bondry_capability_register_v1(
                store,
                b"battery.status".as_ptr(),
                14,
                b"Read battery status".as_ptr(),
                19,
                BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1,
                context,
                Some(test_handler),
                Some(release_test_handler),
            )
        },
        BONDRY_STATUS_OK
    );
    let mut changed = 0;
    assert_eq!(
        unsafe {
            bondry_grant_add_v1(
                store,
                principal.as_ptr(),
                principal.len(),
                b"shortcuts".as_ptr(),
                9,
                b"battery.status".as_ptr(),
                14,
                &mut changed,
            )
        },
        BONDRY_STATUS_OK
    );

    let denied = start_test_principal_dispatch(
        store,
        b"rest",
        principal,
        BONDRY_PRINCIPAL_KIND_SYSTEM_V1,
        b"battery.status",
        b"{}",
    )?;
    assert_eq!(
        denied.recv_timeout(Duration::from_secs(1))?.outcome,
        BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1
    );
    assert_eq!(control.calls.load(Ordering::SeqCst), 0);

    let succeeded = start_test_principal_dispatch(
        store,
        b"shortcuts",
        principal,
        BONDRY_PRINCIPAL_KIND_SYSTEM_V1,
        b"battery.status",
        br#"{"detail":true}"#,
    )?;
    assert_eq!(
        succeeded.recv_timeout(Duration::from_secs(1))?.outcome,
        BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1
    );
    let observed = control
        .observed
        .lock()
        .map_err(|_| std::io::Error::other("observed invocation lock poisoned"))?
        .clone();
    assert_eq!(observed.principal_id, "shortcuts.local-user");
    assert_eq!(observed.principal_kind, BONDRY_PRINCIPAL_KIND_SYSTEM_V1);
    assert_eq!(observed.adapter_id, "shortcuts");
    assert_eq!(observed.capability_id, "battery.status");
    assert_eq!(observed.input, br#"{"detail":true}"#);

    let events = unsafe_query_audit(store, 10)?;
    assert!(events.iter().any(|event| {
        owned_field(&event.principal_id) == "shortcuts.local-user"
            && owned_field(&event.adapter_id) == "rest"
            && event.outcome == BONDRY_AUDIT_OUTCOME_DENIED_V1
    }));
    assert!(events.iter().any(|event| {
        owned_field(&event.principal_id) == "shortcuts.local-user"
            && owned_field(&event.adapter_id) == "shortcuts"
            && event.outcome == BONDRY_AUDIT_OUTCOME_SUCCEEDED_V1
    }));
    close_test_store(store);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn validates_trusted_principal_dispatch_before_accepting_callback_ownership()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, store) = open_test_store(0x5D)?;
    assert_eq!(
        unsafe {
            bondry_dispatch_principal_v1(
                store,
                b"request-invalid".as_ptr(),
                15,
                b"shortcuts".as_ptr(),
                9,
                ptr::null(),
                0,
                BONDRY_PRINCIPAL_KIND_SYSTEM_V1,
                b"battery.status".as_ptr(),
                14,
                b"{}".as_ptr(),
                2,
                Some(receive_dispatch),
                ptr::null_mut(),
            )
        },
        BONDRY_STATUS_NULL_POINTER
    );
    assert_immediate_principal_dispatch_status(
        store,
        b"invalid principal",
        BONDRY_PRINCIPAL_KIND_SYSTEM_V1,
        b"{}",
        BONDRY_STATUS_INVALID_ARGUMENT,
    );
    assert_immediate_principal_dispatch_status(
        store,
        b"shortcuts.local-user",
        99,
        b"{}",
        BONDRY_STATUS_INVALID_ARGUMENT,
    );
    assert_immediate_principal_dispatch_status(
        store,
        b"shortcuts.local-user",
        BONDRY_PRINCIPAL_KIND_SYSTEM_V1,
        b"not-json",
        super::BONDRY_STATUS_INVALID_JSON,
    );
    assert_immediate_principal_dispatch_status(
        store,
        b"shortcuts.local-user",
        BONDRY_PRINCIPAL_KIND_SYSTEM_V1,
        &vec![b' '; 1_048_577],
        BONDRY_STATUS_PAYLOAD_TOO_LARGE,
    );
    close_test_store(store);
    Ok(())
}

#[test]
fn keeps_deferred_handlers_alive_after_unregister_and_close()
-> Result<(), Box<dyn std::error::Error>> {
    let (_directory, store) = open_test_store(0x5A)?;
    let (client_id, token) = create_test_credential(store)?;
    let mut changed = 0;
    assert_eq!(
        unsafe {
            bondry_grant_add_v1(
                store,
                client_id.as_ptr(),
                client_id.len(),
                b"rest".as_ptr(),
                4,
                b"battery.status".as_ptr(),
                14,
                &mut changed,
            )
        },
        BONDRY_STATUS_OK
    );
    let releases = Arc::new(AtomicUsize::new(0));
    let control = Arc::new(TestHandlerControl::default());
    control.mode.store(TEST_HANDLER_DEFERRED, Ordering::SeqCst);
    let context = test_handler_context_with_control(releases.clone(), control.clone());
    assert_eq!(
        unsafe {
            bondry_capability_register_v1(
                store,
                b"battery.status".as_ptr(),
                14,
                b"Read battery status".as_ptr(),
                19,
                BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1,
                context,
                Some(test_handler),
                Some(release_test_handler),
            )
        },
        BONDRY_STATUS_OK
    );
    let completion = start_test_dispatch(store, &token, b"battery.status", b"{}")?;
    assert!(completion.recv_timeout(Duration::from_millis(20)).is_err());
    assert_eq!(
        unsafe {
            bondry_capability_unregister_v1(store, b"battery.status".as_ptr(), 14, &mut changed)
        },
        BONDRY_STATUS_OK
    );
    assert_eq!(changed, 1);
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    close_test_store(store);
    assert_eq!(releases.load(Ordering::SeqCst), 0);

    let pending = control
        .pending
        .lock()
        .map_err(|_| std::io::Error::other("pending invocation lock poisoned"))?
        .take()
        .ok_or_else(|| std::io::Error::other("missing deferred completion"))?;
    let completion_thread = std::thread::spawn(move || pending.succeed());
    completion_thread
        .join()
        .map_err(|_| std::io::Error::other("completion thread panicked"))?;
    let result = completion.recv_timeout(Duration::from_secs(1))?;
    assert_eq!(result.outcome, BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn completes_many_dispatches_from_competing_threads() -> Result<(), Box<dyn std::error::Error>> {
    let (_directory, store) = open_test_store(0x5B)?;
    let (client_id, token) = create_test_credential(store)?;
    let mut changed = 0;
    assert_eq!(
        unsafe {
            bondry_grant_add_v1(
                store,
                client_id.as_ptr(),
                client_id.len(),
                b"rest".as_ptr(),
                4,
                b"battery.status".as_ptr(),
                14,
                &mut changed,
            )
        },
        BONDRY_STATUS_OK
    );
    let releases = Arc::new(AtomicUsize::new(0));
    let control = Arc::new(TestHandlerControl::default());
    control.mode.store(TEST_HANDLER_THREADED, Ordering::SeqCst);
    let context = test_handler_context_with_control(releases.clone(), control.clone());
    assert_eq!(
        unsafe {
            bondry_capability_register_v1(
                store,
                b"battery.status".as_ptr(),
                14,
                b"Read battery status".as_ptr(),
                19,
                BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1,
                context,
                Some(test_handler),
                Some(release_test_handler),
            )
        },
        BONDRY_STATUS_OK
    );

    let receivers = (0..128)
        .map(|_| start_test_dispatch(store, &token, b"battery.status", b"{}"))
        .collect::<Result<Vec<_>, _>>()?;
    for receiver in receivers {
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(2))?.outcome,
            BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1
        );
    }
    assert_eq!(control.calls.load(Ordering::SeqCst), 128);
    close_test_store(store);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    Ok(())
}

const TEST_HANDLER_SUCCESS: u8 = 1;
const TEST_HANDLER_FAILURE: u8 = 2;
const TEST_HANDLER_DEFERRED: u8 = 3;
const TEST_HANDLER_INVALID: u8 = 4;
const TEST_HANDLER_THREADED: u8 = 5;

#[derive(Clone, Default)]
struct ObservedInvocation {
    principal_id: String,
    principal_kind: u32,
    adapter_id: String,
    capability_id: String,
    input: Vec<u8>,
}

struct PendingHandlerCompletion {
    completion: BondryCapabilityCompletionV1,
    context: *mut c_void,
}

// SAFETY: Bondry's completion context may be completed from any thread.
unsafe impl Send for PendingHandlerCompletion {}

impl PendingHandlerCompletion {
    fn succeed(self) {
        // SAFETY: The deferred handler transfers this completion unit exactly once here.
        unsafe {
            (self.completion)(
                self.context,
                BONDRY_HANDLER_RESULT_SUCCEEDED_V1,
                br#"{"level":85}"#.as_ptr(),
                br#"{"level":85}"#.len(),
            );
        }
    }
}

#[derive(Default)]
struct TestHandlerControl {
    mode: AtomicU8,
    calls: AtomicUsize,
    observed: Mutex<ObservedInvocation>,
    pending: Mutex<Option<PendingHandlerCompletion>>,
}

struct TestHandlerContext {
    control: Arc<TestHandlerControl>,
    releases: Arc<AtomicUsize>,
}

fn test_handler_context(releases: Arc<AtomicUsize>) -> *mut c_void {
    test_handler_context_with_control(releases, Arc::new(TestHandlerControl::default()))
}

fn test_handler_context_with_control(
    releases: Arc<AtomicUsize>,
    control: Arc<TestHandlerControl>,
) -> *mut c_void {
    Box::into_raw(Box::new(TestHandlerContext { control, releases })).cast::<c_void>()
}

unsafe extern "C" fn release_test_handler(context: *mut c_void) {
    if context.is_null() {
        return;
    }
    // SAFETY: The caller transfers the one TestHandlerContext allocation exactly once.
    let context = unsafe { Box::from_raw(context.cast::<TestHandlerContext>()) };
    context.releases.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn test_handler(
    context: *mut c_void,
    invocation: *const BondryInvocationV1,
    completion: BondryCapabilityCompletionV1,
    completion_context: *mut c_void,
) {
    if context.is_null() || invocation.is_null() {
        return;
    }
    // SAFETY: Bondry keeps both callback arguments live for this invocation call.
    let context = unsafe { &*context.cast::<TestHandlerContext>() };
    // SAFETY: invocation was checked non-null and is readable during this callback.
    let invocation = unsafe { &*invocation };
    context.control.calls.fetch_add(1, Ordering::SeqCst);
    let input = if invocation.input_json.is_null() {
        Vec::new()
    } else {
        // SAFETY: Bondry guarantees the input buffer for the callback duration.
        unsafe {
            slice::from_raw_parts(invocation.input_json, invocation.input_json_length).to_vec()
        }
    };
    if let Ok(mut observed) = context.control.observed.lock() {
        *observed = ObservedInvocation {
            principal_id: owned_field(&invocation.principal_id),
            principal_kind: invocation.principal_kind,
            adapter_id: owned_field(&invocation.adapter_id),
            capability_id: owned_field(&invocation.capability_id),
            input,
        };
    }
    match context.control.mode.load(Ordering::SeqCst) {
        TEST_HANDLER_FAILURE => {
            // SAFETY: This consumes the provided completion context exactly once.
            unsafe {
                completion(
                    completion_context,
                    BONDRY_HANDLER_RESULT_FAILED_V1,
                    b"temporarily_unavailable".as_ptr(),
                    23,
                );
            }
        }
        TEST_HANDLER_DEFERRED => {
            if let Ok(mut pending) = context.control.pending.lock() {
                *pending = Some(PendingHandlerCompletion {
                    completion,
                    context: completion_context,
                });
            }
        }
        TEST_HANDLER_INVALID => {
            // SAFETY: This consumes the provided completion context exactly once.
            unsafe {
                completion(
                    completion_context,
                    BONDRY_HANDLER_RESULT_SUCCEEDED_V1,
                    b"not-json".as_ptr(),
                    8,
                );
            }
        }
        TEST_HANDLER_THREADED => {
            let pending = PendingHandlerCompletion {
                completion,
                context: completion_context,
            };
            drop(std::thread::spawn(move || pending.succeed()));
        }
        _ => {
            // SAFETY: This consumes the provided completion context exactly once.
            unsafe {
                completion(
                    completion_context,
                    BONDRY_HANDLER_RESULT_SUCCEEDED_V1,
                    br#"{"level":85}"#.as_ptr(),
                    br#"{"level":85}"#.len(),
                );
            }
        }
    }
}

#[derive(Debug)]
struct OwnedDispatchResult {
    outcome: u32,
    output: Option<Vec<u8>>,
    detail: Option<String>,
}

unsafe extern "C" fn receive_dispatch(context: *mut c_void, result: *const BondryDispatchResultV1) {
    if context.is_null() {
        return;
    }
    // SAFETY: Each accepted dispatch transfers one boxed sender to this callback.
    let sender = unsafe { Box::from_raw(context.cast::<mpsc::Sender<OwnedDispatchResult>>()) };
    let Some(result) = (unsafe { result.as_ref() }) else {
        return;
    };
    let output = if result.output_json.is_null() {
        None
    } else {
        // SAFETY: Bondry keeps successful output readable for this callback duration.
        Some(unsafe {
            slice::from_raw_parts(result.output_json, result.output_json_length).to_vec()
        })
    };
    let detail = (result.has_detail_code == 1).then(|| owned_field(&result.detail_code));
    let _ = sender.send(OwnedDispatchResult {
        outcome: result.outcome,
        output,
        detail,
    });
}

fn start_test_dispatch(
    store: *const BondryStoreHandle,
    token: &[u8],
    capability: &[u8],
    input: &[u8],
) -> Result<Receiver<OwnedDispatchResult>, Box<dyn std::error::Error>> {
    let (sender, receiver) = mpsc::channel::<OwnedDispatchResult>();
    let context = Box::into_raw(Box::new(sender)).cast::<c_void>();
    let status = unsafe {
        bondry_dispatch_token_v1(
            store,
            b"request-test".as_ptr(),
            12,
            b"rest".as_ptr(),
            4,
            token.as_ptr(),
            token.len(),
            capability.as_ptr(),
            capability.len(),
            input.as_ptr(),
            input.len(),
            Some(receive_dispatch),
            context,
        )
    };
    if status != BONDRY_STATUS_OK {
        // SAFETY: Immediate dispatch errors leave completion context caller-owned.
        unsafe {
            drop(Box::from_raw(
                context.cast::<mpsc::Sender<OwnedDispatchResult>>(),
            ))
        };
        return Err(std::io::Error::other(format!("dispatch failed with status {status}")).into());
    }
    Ok(receiver)
}

fn start_test_principal_dispatch(
    store: *const BondryStoreHandle,
    adapter: &[u8],
    principal: &[u8],
    principal_kind: u32,
    capability: &[u8],
    input: &[u8],
) -> Result<Receiver<OwnedDispatchResult>, Box<dyn std::error::Error>> {
    let (sender, receiver) = mpsc::channel::<OwnedDispatchResult>();
    let context = Box::into_raw(Box::new(sender)).cast::<c_void>();
    let status = unsafe {
        bondry_dispatch_principal_v1(
            store,
            b"request-platform".as_ptr(),
            16,
            adapter.as_ptr(),
            adapter.len(),
            principal.as_ptr(),
            principal.len(),
            principal_kind,
            capability.as_ptr(),
            capability.len(),
            input.as_ptr(),
            input.len(),
            Some(receive_dispatch),
            context,
        )
    };
    if status != BONDRY_STATUS_OK {
        unsafe {
            drop(Box::from_raw(
                context.cast::<mpsc::Sender<OwnedDispatchResult>>(),
            ))
        };
        return Err(std::io::Error::other(format!("dispatch failed with status {status}")).into());
    }
    Ok(receiver)
}

fn assert_immediate_dispatch_status(
    store: *const BondryStoreHandle,
    token: &[u8],
    input: &[u8],
    expected: i32,
) {
    let (sender, receiver) = mpsc::channel::<OwnedDispatchResult>();
    let context = Box::into_raw(Box::new(sender)).cast::<c_void>();
    let status = unsafe {
        bondry_dispatch_token_v1(
            store,
            b"request-invalid".as_ptr(),
            15,
            b"rest".as_ptr(),
            4,
            token.as_ptr(),
            token.len(),
            b"battery.status".as_ptr(),
            14,
            input.as_ptr(),
            input.len(),
            Some(receive_dispatch),
            context,
        )
    };
    assert_eq!(status, expected);
    assert!(receiver.recv_timeout(Duration::from_millis(20)).is_err());
    // SAFETY: Immediate dispatch errors leave completion context caller-owned.
    unsafe {
        drop(Box::from_raw(
            context.cast::<mpsc::Sender<OwnedDispatchResult>>(),
        ))
    };
}

fn assert_immediate_principal_dispatch_status(
    store: *const BondryStoreHandle,
    principal: &[u8],
    principal_kind: u32,
    input: &[u8],
    expected: i32,
) {
    let (sender, receiver) = mpsc::channel::<OwnedDispatchResult>();
    let context = Box::into_raw(Box::new(sender)).cast::<c_void>();
    let status = unsafe {
        bondry_dispatch_principal_v1(
            store,
            b"request-invalid".as_ptr(),
            15,
            b"shortcuts".as_ptr(),
            9,
            principal.as_ptr(),
            principal.len(),
            principal_kind,
            b"battery.status".as_ptr(),
            14,
            input.as_ptr(),
            input.len(),
            Some(receive_dispatch),
            context,
        )
    };
    assert_eq!(status, expected);
    assert!(receiver.recv_timeout(Duration::from_millis(20)).is_err());
    unsafe {
        drop(Box::from_raw(
            context.cast::<mpsc::Sender<OwnedDispatchResult>>(),
        ))
    };
}

fn create_test_credential(
    store: *const BondryStoreHandle,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
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
                ptr::null(),
                0,
                0,
                0,
                &mut issued,
            )
        },
        BONDRY_STATUS_OK
    );
    let token = utf8_field(&issued.secret)?.as_bytes().to_vec();
    assert_eq!(
        unsafe { bondry_issued_token_clear_v1(&mut issued) },
        BONDRY_STATUS_OK
    );
    Ok((client_id, token))
}

fn unsafe_query_audit(
    store: *const BondryStoreHandle,
    limit: u32,
) -> Result<Vec<BondryAuditEventV1>, Box<dyn std::error::Error>> {
    let mut count = 0;
    assert_eq!(
        unsafe { bondry_audit_recent_v1(store, limit, ptr::null_mut(), 0, &mut count) },
        BONDRY_STATUS_OK
    );
    let mut events = Vec::<BondryAuditEventV1>::with_capacity(count);
    assert_eq!(
        unsafe { bondry_audit_recent_v1(store, limit, events.as_mut_ptr(), count, &mut count) },
        BONDRY_STATUS_OK
    );
    // SAFETY: The ABI initialized exactly count records within the allocated capacity.
    unsafe { events.set_len(count) };
    Ok(events)
}

fn owned_field(bytes: &[u8]) -> String {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..length]).into_owned()
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
