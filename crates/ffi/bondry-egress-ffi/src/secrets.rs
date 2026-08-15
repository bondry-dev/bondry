use std::{
    ffi::c_void,
    panic::{AssertUnwindSafe, catch_unwind},
    slice,
};

use bondry_secrets::{ResolvedSecret, SecretProvider, SecretProviderError, SecretRef, SecretValue};

use crate::{BondryContextReleaseV1, BondryContextRetainV1};

/// ABI version of the host secret-provider descriptor.
pub const BONDRY_SECRET_PROVIDER_ABI_VERSION_V1: u32 = 1;

const STATUS_OK: i32 = 0;
const STATUS_UNAVAILABLE: i32 = 15;
const STATUS_NOT_FOUND: i32 = 20;

/// Receives secret material synchronously while its borrowed buffers remain valid.
pub type BondrySecretResolutionV1 = unsafe extern "C" fn(
    completion_context: *mut c_void,
    current: *const u8,
    current_length: usize,
    previous: *const u8,
    previous_length: usize,
    has_previous: u8,
);
/// Resolves one non-secret reference and invokes completion exactly once before returning success.
pub type BondrySecretResolveV1 = unsafe extern "C" fn(
    provider_context: *mut c_void,
    secret_reference: *const u8,
    secret_reference_length: usize,
    completion: BondrySecretResolutionV1,
    completion_context: *mut c_void,
) -> i32;

/// Versioned host secret-provider callbacks.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondrySecretProviderV1 {
    /// Must equal `BONDRY_SECRET_PROVIDER_ABI_VERSION_V1`.
    pub abi_version: u32,
    /// Byte size of this descriptor.
    pub struct_size: usize,
    /// Caller-owned context retained during egress startup.
    pub context: *mut c_void,
    /// Required context retain callback.
    pub retain: Option<BondryContextRetainV1>,
    /// Required context release callback.
    pub release: Option<BondryContextReleaseV1>,
    /// Required synchronous resolution callback.
    pub resolve: Option<BondrySecretResolveV1>,
}

pub(crate) struct ForeignSecretProvider {
    context: *mut c_void,
    release: BondryContextReleaseV1,
    resolve: BondrySecretResolveV1,
}

// SAFETY: Descriptor registration requires callbacks and context to support arbitrary threads.
unsafe impl Send for ForeignSecretProvider {}
// SAFETY: Concurrent resolution must be safe by the host descriptor contract.
unsafe impl Sync for ForeignSecretProvider {}

impl ForeignSecretProvider {
    pub(crate) unsafe fn retain(descriptor: &BondrySecretProviderV1) -> Result<Self, ()> {
        if descriptor.abi_version != BONDRY_SECRET_PROVIDER_ABI_VERSION_V1
            || descriptor.struct_size != std::mem::size_of::<BondrySecretProviderV1>()
            || descriptor.context.is_null()
        {
            return Err(());
        }
        let (Some(retain), Some(release), Some(resolve)) =
            (descriptor.retain, descriptor.release, descriptor.resolve)
        else {
            return Err(());
        };
        // SAFETY: The caller keeps the original context live for this synchronous retain.
        let context = unsafe { retain(descriptor.context) };
        if context.is_null() {
            return Err(());
        }
        Ok(Self {
            context,
            release,
            resolve,
        })
    }
}

impl Drop for ForeignSecretProvider {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns exactly one retained foreign context.
        unsafe { (self.release)(self.context) };
    }
}

impl SecretProvider for ForeignSecretProvider {
    fn resolve(&self, reference: &SecretRef) -> Result<ResolvedSecret, SecretProviderError> {
        let mut completion = SecretCompletion::Pending;
        let reference = reference.as_str().as_bytes();
        // SAFETY: The reference remains readable and completion remains writable for this call.
        let status = unsafe {
            (self.resolve)(
                self.context,
                reference.as_ptr(),
                reference.len(),
                complete_secret,
                (&mut completion as *mut SecretCompletion).cast::<c_void>(),
            )
        };
        match status {
            STATUS_OK => match completion {
                SecretCompletion::Ready(result) => result,
                SecretCompletion::Pending => Err(SecretProviderError::InvalidMaterial),
            },
            STATUS_NOT_FOUND => Err(SecretProviderError::NotFound),
            STATUS_UNAVAILABLE => Err(SecretProviderError::Unavailable),
            _ => Err(SecretProviderError::InvalidMaterial),
        }
    }
}

enum SecretCompletion {
    Pending,
    Ready(Result<ResolvedSecret, SecretProviderError>),
}

unsafe extern "C" fn complete_secret(
    completion_context: *mut c_void,
    current: *const u8,
    current_length: usize,
    previous: *const u8,
    previous_length: usize,
    has_previous: u8,
) {
    if completion_context.is_null() {
        return;
    }
    // SAFETY: resolve receives this stack context only for its synchronous callback duration.
    let completion = unsafe { &mut *completion_context.cast::<SecretCompletion>() };
    if !matches!(completion, SecretCompletion::Pending) {
        *completion = SecretCompletion::Ready(Err(SecretProviderError::InvalidMaterial));
        return;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The provider keeps both buffers readable until this callback returns.
        unsafe {
            parse_secret(
                current,
                current_length,
                previous,
                previous_length,
                has_previous,
            )
        }
    }))
    .unwrap_or(Err(SecretProviderError::InvalidMaterial));
    *completion = SecretCompletion::Ready(result);
}

unsafe fn parse_secret(
    current: *const u8,
    current_length: usize,
    previous: *const u8,
    previous_length: usize,
    has_previous: u8,
) -> Result<ResolvedSecret, SecretProviderError> {
    let current = SecretValue::new(unsafe { borrowed_bytes(current, current_length) }?.to_vec())
        .map_err(|_| SecretProviderError::InvalidMaterial)?;
    match has_previous {
        0 if previous_length == 0 => Ok(ResolvedSecret::current(current)),
        1 => {
            let previous =
                SecretValue::new(unsafe { borrowed_bytes(previous, previous_length) }?.to_vec())
                    .map_err(|_| SecretProviderError::InvalidMaterial)?;
            Ok(ResolvedSecret::rotating(current, previous))
        }
        _ => Err(SecretProviderError::InvalidMaterial),
    }
}

unsafe fn borrowed_bytes<'a>(
    pointer: *const u8,
    length: usize,
) -> Result<&'a [u8], SecretProviderError> {
    if pointer.is_null() || length == 0 || length > isize::MAX as usize {
        return Err(SecretProviderError::InvalidMaterial);
    }
    // SAFETY: The provider contract guarantees readable memory for the declared byte length.
    Ok(unsafe { slice::from_raw_parts(pointer, length) })
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;

    use bondry_secrets::{SecretProvider, SecretProviderError, SecretRef};

    use super::{
        BONDRY_SECRET_PROVIDER_ABI_VERSION_V1, BondrySecretProviderV1, BondrySecretResolutionV1,
        ForeignSecretProvider, STATUS_OK, parse_secret,
    };

    unsafe extern "C" fn retain(context: *mut c_void) -> *mut c_void {
        context
    }

    unsafe extern "C" fn release(_context: *mut c_void) {}

    unsafe extern "C" fn omit_completion(
        _context: *mut c_void,
        _reference: *const u8,
        _reference_length: usize,
        _completion: BondrySecretResolutionV1,
        _completion_context: *mut c_void,
    ) -> i32 {
        STATUS_OK
    }

    #[test]
    fn rejects_malformed_rotation_shapes() {
        let current = b"current";
        assert!(matches!(
            unsafe { parse_secret(current.as_ptr(), current.len(), current.as_ptr(), 0, 1) },
            Err(SecretProviderError::InvalidMaterial)
        ));
        assert!(matches!(
            unsafe { parse_secret(current.as_ptr(), current.len(), current.as_ptr(), 1, 2) },
            Err(SecretProviderError::InvalidMaterial)
        ));
    }

    #[test]
    fn fails_closed_when_success_omits_synchronous_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut context = 1_u8;
        let descriptor = BondrySecretProviderV1 {
            abi_version: BONDRY_SECRET_PROVIDER_ABI_VERSION_V1,
            struct_size: size_of::<BondrySecretProviderV1>(),
            context: (&mut context as *mut u8).cast::<c_void>(),
            retain: Some(retain),
            release: Some(release),
            resolve: Some(omit_completion),
        };
        let provider = unsafe { ForeignSecretProvider::retain(&descriptor) }
            .map_err(|()| "descriptor rejected")?;
        let reference = SecretRef::new("keychain:test")?;
        assert!(matches!(
            provider.resolve(&reference),
            Err(SecretProviderError::InvalidMaterial)
        ));
        Ok(())
    }
}
