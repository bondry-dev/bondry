use std::{
    ffi::c_void,
    panic::{AssertUnwindSafe, catch_unwind},
    slice,
};

use bondry_secrets::{ResolvedSecret, SecretProvider, SecretProviderError, SecretRef, SecretValue};

use crate::{
    BONDRY_STATUS_NOT_FOUND, BONDRY_STATUS_OK, BONDRY_STATUS_UNAVAILABLE,
    BONDRY_WEBHOOK_SECRET_PROVIDER_ABI_VERSION_V1, BondryContextReleaseV1,
    BondryWebhookSecretProviderV1, BondryWebhookSecretResolveV1,
};

pub(crate) struct ForeignSecretProvider {
    context: *mut c_void,
    release: BondryContextReleaseV1,
    resolve: BondryWebhookSecretResolveV1,
}

// SAFETY: Registration requires descriptor callbacks to support arbitrary calling threads.
unsafe impl Send for ForeignSecretProvider {}
// SAFETY: The host descriptor promises synchronized concurrent resolution.
unsafe impl Sync for ForeignSecretProvider {}

impl ForeignSecretProvider {
    pub(crate) unsafe fn retain(descriptor: &BondryWebhookSecretProviderV1) -> Result<Self, ()> {
        if descriptor.abi_version != BONDRY_WEBHOOK_SECRET_PROVIDER_ABI_VERSION_V1
            || descriptor.struct_size != size_of::<BondryWebhookSecretProviderV1>()
            || descriptor.context.is_null()
        {
            return Err(());
        }
        let (Some(retain), Some(release), Some(resolve)) =
            (descriptor.retain, descriptor.release, descriptor.resolve)
        else {
            return Err(());
        };
        // SAFETY: The registration descriptor remains live during this synchronous retain.
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
        // SAFETY: This wrapper owns one retained context unit.
        unsafe { (self.release)(self.context) };
    }
}

impl SecretProvider for ForeignSecretProvider {
    fn resolve(&self, reference: &SecretRef) -> Result<ResolvedSecret, SecretProviderError> {
        let reference = reference.as_str().as_bytes();
        let mut completion = SecretCompletion::Pending;
        // SAFETY: Reference and completion remain valid for the required synchronous callback.
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
            BONDRY_STATUS_OK => match completion {
                SecretCompletion::Ready(result) => result,
                SecretCompletion::Pending => Err(SecretProviderError::InvalidMaterial),
            },
            BONDRY_STATUS_NOT_FOUND => Err(SecretProviderError::NotFound),
            BONDRY_STATUS_UNAVAILABLE => Err(SecretProviderError::Unavailable),
            _ => Err(SecretProviderError::InvalidMaterial),
        }
    }
}

enum SecretCompletion {
    Pending,
    Ready(Result<ResolvedSecret, SecretProviderError>),
}

unsafe extern "C" fn complete_secret(
    context: *mut c_void,
    current: *const u8,
    current_length: usize,
    previous: *const u8,
    previous_length: usize,
    has_previous: u8,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: The provider receives this stack context only for its synchronous callback.
    let completion = unsafe { &mut *context.cast::<SecretCompletion>() };
    if !matches!(completion, SecretCompletion::Pending) {
        *completion = SecretCompletion::Ready(Err(SecretProviderError::InvalidMaterial));
        return;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: Secret buffers remain borrowed for this callback.
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
    let current = SecretValue::new(unsafe { bytes(current, current_length) }?.to_vec())
        .map_err(|_| SecretProviderError::InvalidMaterial)?;
    match has_previous {
        0 if previous_length == 0 => Ok(ResolvedSecret::current(current)),
        1 => {
            let previous = SecretValue::new(unsafe { bytes(previous, previous_length) }?.to_vec())
                .map_err(|_| SecretProviderError::InvalidMaterial)?;
            Ok(ResolvedSecret::rotating(current, previous))
        }
        _ => Err(SecretProviderError::InvalidMaterial),
    }
}

unsafe fn bytes<'a>(pointer: *const u8, length: usize) -> Result<&'a [u8], SecretProviderError> {
    if pointer.is_null() || length == 0 || length > isize::MAX as usize {
        return Err(SecretProviderError::InvalidMaterial);
    }
    // SAFETY: The provider contract guarantees readable memory for this bounded length.
    Ok(unsafe { slice::from_raw_parts(pointer, length) })
}

#[cfg(test)]
mod tests {
    use std::ffi::c_void;

    use bondry_secrets::{SecretProvider, SecretProviderError, SecretRef};

    use super::ForeignSecretProvider;
    use crate::{
        BONDRY_STATUS_OK, BONDRY_WEBHOOK_SECRET_PROVIDER_ABI_VERSION_V1,
        BondryWebhookSecretProviderV1, BondryWebhookSecretResolutionV1,
    };

    unsafe extern "C" fn retain(context: *mut c_void) -> *mut c_void {
        context
    }

    unsafe extern "C" fn release(_context: *mut c_void) {}

    unsafe extern "C" fn omit_completion(
        _context: *mut c_void,
        _reference: *const u8,
        _reference_length: usize,
        _completion: BondryWebhookSecretResolutionV1,
        _completion_context: *mut c_void,
    ) -> i32 {
        BONDRY_STATUS_OK
    }

    #[test]
    fn rejects_a_provider_that_omits_synchronous_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut value = 1_u8;
        let descriptor = BondryWebhookSecretProviderV1 {
            abi_version: BONDRY_WEBHOOK_SECRET_PROVIDER_ABI_VERSION_V1,
            struct_size: size_of::<BondryWebhookSecretProviderV1>(),
            context: (&mut value as *mut u8).cast::<c_void>(),
            retain: Some(retain),
            release: Some(release),
            resolve: Some(omit_completion),
        };
        let provider = unsafe { ForeignSecretProvider::retain(&descriptor) }
            .map_err(|()| "descriptor rejected")?;
        assert!(matches!(
            provider.resolve(&SecretRef::new("keychain:test")?),
            Err(SecretProviderError::InvalidMaterial)
        ));
        Ok(())
    }
}
