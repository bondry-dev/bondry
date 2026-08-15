use std::{ffi::c_void, mem, ptr};

use crate::{
    BONDRY_STATUS_INTERNAL_FAILURE, BONDRY_STATUS_NULL_POINTER, BONDRY_STATUS_OK,
    BondryDispatchCompletionV1, BondryStoreHandle, bondry_capabilities_discover_json_v1,
    bondry_store_close_v1, bondry_store_retain_v1, capabilities::MAX_AUTOMATION_INPUT_LENGTH,
    capabilities::dispatch_principal_with_limit, catch_status,
};

/// ABI version of the protocol-neutral automation-service descriptor.
pub const BONDRY_AUTOMATION_SERVICE_ABI_VERSION_V1: u32 = 1;
/// The service may be called concurrently and synchronizes its own state.
pub const BONDRY_SERVICE_THREADING_CONCURRENT_V1: u32 = 1;

/// Retains one service context ownership unit.
pub type BondryServiceContextRetainV1 = unsafe extern "C" fn(context: *mut c_void) -> *mut c_void;
/// Releases one service context ownership unit.
pub type BondryServiceContextReleaseV1 = unsafe extern "C" fn(context: *mut c_void);
/// Serializes authorized capabilities; a null zero-capacity output returns the required length.
pub type BondryAutomationCapabilitiesV1 = unsafe extern "C" fn(
    context: *mut c_void,
    principal_id: *const u8,
    principal_id_length: usize,
    principal_kind: u32,
    adapter_id: *const u8,
    adapter_id_length: usize,
    output_json: *mut u8,
    capacity: usize,
    out_length: *mut usize,
) -> i32;
/// Dispatches one host-authenticated invocation and completes it exactly once after acceptance.
pub type BondryAutomationDispatchV1 = unsafe extern "C" fn(
    context: *mut c_void,
    invocation_id: *const u8,
    invocation_id_length: usize,
    adapter_id: *const u8,
    adapter_id_length: usize,
    principal_id: *const u8,
    principal_id_length: usize,
    principal_kind: u32,
    capability_id: *const u8,
    capability_id_length: usize,
    input_json: *const u8,
    input_json_length: usize,
    completion: BondryDispatchCompletionV1,
    completion_context: *mut c_void,
) -> i32;

/// Versioned protocol-neutral service view over one retained runtime handle.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryAutomationServiceV1 {
    /// Must equal `BONDRY_AUTOMATION_SERVICE_ABI_VERSION_V1`.
    pub abi_version: u32,
    /// Byte size of this descriptor.
    pub struct_size: usize,
    /// Must equal `BONDRY_SERVICE_THREADING_CONCURRENT_V1`.
    pub threading_model: u32,
    /// Owned runtime context.
    pub context: *mut c_void,
    /// Required context retain callback.
    pub retain: Option<BondryServiceContextRetainV1>,
    /// Required context release callback.
    pub release: Option<BondryServiceContextReleaseV1>,
    /// Required capability-discovery callback.
    pub capabilities: Option<BondryAutomationCapabilitiesV1>,
    /// Required asynchronous dispatch callback.
    pub dispatch: Option<BondryAutomationDispatchV1>,
}

impl BondryAutomationServiceV1 {
    const fn zeroed() -> Self {
        Self {
            abi_version: 0,
            struct_size: 0,
            threading_model: 0,
            context: ptr::null_mut(),
            retain: None,
            release: None,
            capabilities: None,
            dispatch: None,
        }
    }
}

/// Derives one owned protocol-neutral service descriptor from the existing runtime handle.
///
/// # Safety
///
/// `store` must remain live for this call. `out_service` must be writable. On success the caller
/// must invoke the descriptor's release callback exactly once.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_automation_service_v1(
    store: *const BondryStoreHandle,
    out_service: *mut BondryAutomationServiceV1,
) -> i32 {
    if out_service.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: The caller guarantees writable output memory.
    unsafe { out_service.write(BondryAutomationServiceV1::zeroed()) };
    catch_status(|| {
        if store.is_null() {
            return BONDRY_STATUS_NULL_POINTER;
        }
        let mut retained = ptr::null_mut();
        // SAFETY: The caller keeps the source handle live for this synchronous retain.
        let status = unsafe { bondry_store_retain_v1(store, &mut retained) };
        if status != BONDRY_STATUS_OK {
            return status;
        }
        if retained.is_null() {
            return BONDRY_STATUS_INTERNAL_FAILURE;
        }
        let descriptor = BondryAutomationServiceV1 {
            abi_version: BONDRY_AUTOMATION_SERVICE_ABI_VERSION_V1,
            struct_size: mem::size_of::<BondryAutomationServiceV1>(),
            threading_model: BONDRY_SERVICE_THREADING_CONCURRENT_V1,
            context: retained.cast::<c_void>(),
            retain: Some(retain_context),
            release: Some(release_context),
            capabilities: Some(capabilities),
            dispatch: Some(dispatch),
        };
        // SAFETY: Output was validated and receives the descriptor ownership unit.
        unsafe { out_service.write(descriptor) };
        BONDRY_STATUS_OK
    })
}

unsafe extern "C" fn retain_context(context: *mut c_void) -> *mut c_void {
    if context.is_null() {
        return ptr::null_mut();
    }
    let mut retained = ptr::null_mut::<BondryStoreHandle>();
    // SAFETY: Descriptor contexts are live retained runtime handles.
    let status = unsafe {
        bondry_store_retain_v1(
            context.cast::<BondryStoreHandle>(),
            &mut retained as *mut *mut BondryStoreHandle,
        )
    };
    if status == BONDRY_STATUS_OK {
        retained.cast::<c_void>()
    } else {
        ptr::null_mut()
    }
}

unsafe extern "C" fn release_context(context: *mut c_void) {
    if !context.is_null() {
        // SAFETY: Each descriptor ownership unit is released exactly once.
        let _ = unsafe { bondry_store_close_v1(context.cast::<BondryStoreHandle>()) };
    }
}

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn capabilities(
    context: *mut c_void,
    principal_id: *const u8,
    principal_id_length: usize,
    principal_kind: u32,
    adapter_id: *const u8,
    adapter_id_length: usize,
    output_json: *mut u8,
    capacity: usize,
    out_length: *mut usize,
) -> i32 {
    // SAFETY: This callback preserves the public function's complete pointer contract.
    unsafe {
        bondry_capabilities_discover_json_v1(
            context.cast::<BondryStoreHandle>(),
            principal_id,
            principal_id_length,
            principal_kind,
            adapter_id,
            adapter_id_length,
            output_json,
            capacity,
            out_length,
        )
    }
}

#[allow(clippy::too_many_arguments)]
unsafe extern "C" fn dispatch(
    context: *mut c_void,
    invocation_id: *const u8,
    invocation_id_length: usize,
    adapter_id: *const u8,
    adapter_id_length: usize,
    principal_id: *const u8,
    principal_id_length: usize,
    principal_kind: u32,
    capability_id: *const u8,
    capability_id_length: usize,
    input_json: *const u8,
    input_json_length: usize,
    completion: BondryDispatchCompletionV1,
    completion_context: *mut c_void,
) -> i32 {
    // SAFETY: This callback preserves the public function's complete pointer contract.
    unsafe {
        dispatch_principal_with_limit(
            context.cast::<BondryStoreHandle>(),
            invocation_id,
            invocation_id_length,
            adapter_id,
            adapter_id_length,
            principal_id,
            principal_id_length,
            principal_kind,
            capability_id,
            capability_id_length,
            input_json,
            input_json_length,
            Some(completion),
            completion_context,
            MAX_AUTOMATION_INPUT_LENGTH,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::ptr;

    use tempfile::TempDir;

    use super::{
        BONDRY_AUTOMATION_SERVICE_ABI_VERSION_V1, BondryAutomationServiceV1,
        bondry_automation_service_v1,
    };
    use crate::{BONDRY_STATUS_OK, BondryStoreHandle, bondry_store_close_v1, bondry_store_open_v1};

    #[test]
    fn descriptor_owns_and_retains_the_existing_runtime() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = TempDir::new()?;
        let path = directory.path().join("automation.db");
        let path = path.to_str().ok_or("non-UTF-8 test path")?.as_bytes();
        let key = [0x31; 32];
        let mut store = ptr::null_mut::<BondryStoreHandle>();
        assert_eq!(
            unsafe {
                bondry_store_open_v1(
                    path.as_ptr(),
                    path.len(),
                    key.as_ptr(),
                    key.len(),
                    &mut store,
                )
            },
            BONDRY_STATUS_OK
        );
        let mut descriptor = BondryAutomationServiceV1::zeroed();
        assert_eq!(
            unsafe { bondry_automation_service_v1(store, &mut descriptor) },
            BONDRY_STATUS_OK
        );
        assert_eq!(
            descriptor.abi_version,
            BONDRY_AUTOMATION_SERVICE_ABI_VERSION_V1
        );
        let retain = descriptor.retain.ok_or("missing retain")?;
        let release = descriptor.release.ok_or("missing release")?;
        let retained = unsafe { retain(descriptor.context) };
        assert!(!retained.is_null());
        unsafe {
            release(retained);
            release(descriptor.context);
        }
        assert_eq!(unsafe { bondry_store_close_v1(store) }, BONDRY_STATUS_OK);
        Ok(())
    }
}
