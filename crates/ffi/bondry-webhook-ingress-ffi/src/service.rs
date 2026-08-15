use std::{ffi::c_void, ptr};

use bondry_core::{
    AuditError, AutomationService, CapabilityDescriptor, CapabilityDiscoveryError,
    CapabilityEffect, CapabilityId, DenialReason, DispatchError, DispatchFuture, HandlerError,
    HandlerErrorCode, Invocation,
};
use serde::Deserialize;
use tokio::sync::oneshot;

use crate::{
    BONDRY_AUTOMATION_SERVICE_ABI_VERSION_V1, BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1,
    BONDRY_DISPATCH_OUTCOME_AUDIT_UNAVAILABLE_V1, BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1,
    BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1, BONDRY_DISPATCH_OUTCOME_INVALID_INPUT_V1,
    BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1, BONDRY_SERVICE_THREADING_CONCURRENT_V1, BONDRY_STATUS_OK,
    BondryAutomationCapabilitiesV1, BondryAutomationDispatchV1, BondryAutomationServiceV1,
    BondryContextReleaseV1, BondryDispatchResultV1,
};

const MAX_CAPABILITIES_JSON: usize = 1_048_576;
const MAX_DISPATCH_INPUT_JSON: usize = 10 * 1_048_576;

pub(crate) struct ForeignAutomationService {
    context: *mut c_void,
    release: BondryContextReleaseV1,
    capabilities: BondryAutomationCapabilitiesV1,
    dispatch: BondryAutomationDispatchV1,
}

// SAFETY: Registration accepts only a descriptor promising concurrent callback safety.
unsafe impl Send for ForeignAutomationService {}
// SAFETY: The descriptor's threading model permits concurrent calls.
unsafe impl Sync for ForeignAutomationService {}

impl ForeignAutomationService {
    pub(crate) unsafe fn retain(descriptor: &BondryAutomationServiceV1) -> Result<Self, ()> {
        if descriptor.abi_version != BONDRY_AUTOMATION_SERVICE_ABI_VERSION_V1
            || descriptor.struct_size != size_of::<BondryAutomationServiceV1>()
            || descriptor.threading_model != BONDRY_SERVICE_THREADING_CONCURRENT_V1
            || descriptor.context.is_null()
        {
            return Err(());
        }
        let (Some(retain), Some(release), Some(capabilities), Some(dispatch)) = (
            descriptor.retain,
            descriptor.release,
            descriptor.capabilities,
            descriptor.dispatch,
        ) else {
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
            capabilities,
            dispatch,
        })
    }

    fn discover(
        &self,
        principal: &bondry_core::Principal,
        adapter: &bondry_core::AdapterId,
    ) -> Result<Vec<CapabilityDescriptor>, CapabilityDiscoveryError> {
        let principal_id = principal.id().as_str().as_bytes();
        let adapter_id = adapter.as_str().as_bytes();
        let principal_kind = encode_principal_kind(principal.kind());
        let mut length = 0;
        // SAFETY: Inputs and output length remain borrowed for this synchronous query.
        let status = unsafe {
            (self.capabilities)(
                self.context,
                principal_id.as_ptr(),
                principal_id.len(),
                principal_kind,
                adapter_id.as_ptr(),
                adapter_id.len(),
                ptr::null_mut(),
                0,
                &mut length,
            )
        };
        if status != BONDRY_STATUS_OK || length == 0 || length > MAX_CAPABILITIES_JSON {
            return Err(CapabilityDiscoveryError::PolicyUnavailable);
        }
        let mut output = vec![0; length];
        // SAFETY: Output allocation and all inputs remain valid for this synchronous call.
        let status = unsafe {
            (self.capabilities)(
                self.context,
                principal_id.as_ptr(),
                principal_id.len(),
                principal_kind,
                adapter_id.as_ptr(),
                adapter_id.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut length,
            )
        };
        if status != BONDRY_STATUS_OK || length > output.len() {
            return Err(CapabilityDiscoveryError::PolicyUnavailable);
        }
        output.truncate(length);
        decode_capabilities(&output).map_err(|()| CapabilityDiscoveryError::PolicyUnavailable)
    }
}

impl Drop for ForeignAutomationService {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns one retained descriptor context.
        unsafe { (self.release)(self.context) };
    }
}

impl AutomationService for ForeignAutomationService {
    fn capabilities(
        &self,
        principal: &bondry_core::Principal,
        adapter: &bondry_core::AdapterId,
    ) -> Result<Vec<CapabilityDescriptor>, CapabilityDiscoveryError> {
        self.discover(principal, adapter)
    }

    fn dispatch(&self, invocation: Invocation) -> DispatchFuture<'_> {
        let input = match serde_json::to_vec(invocation.input()) {
            Ok(input) if input.len() <= MAX_DISPATCH_INPUT_JSON => input,
            _ => return Box::pin(std::future::ready(Err(DispatchError::InvalidInput))),
        };
        let capability = invocation.capability().clone();
        let invocation_id = invocation.id().as_str().as_bytes();
        let adapter = invocation.adapter().as_str().as_bytes();
        let principal_id = invocation.principal().id().as_str().as_bytes();
        let capability_id = invocation.capability().as_str().as_bytes();
        let principal_kind = encode_principal_kind(invocation.principal().kind());
        let (sender, receiver) = oneshot::channel();
        let completion = Box::into_raw(Box::new(sender)).cast::<c_void>();
        // SAFETY: Borrowed invocation buffers remain valid for this call. Success transfers the
        // completion allocation to exactly one callback.
        let status = unsafe {
            (self.dispatch)(
                self.context,
                invocation_id.as_ptr(),
                invocation_id.len(),
                adapter.as_ptr(),
                adapter.len(),
                principal_id.as_ptr(),
                principal_id.len(),
                principal_kind,
                capability_id.as_ptr(),
                capability_id.len(),
                input.as_ptr(),
                input.len(),
                complete_dispatch,
                completion,
            )
        };
        if status != BONDRY_STATUS_OK {
            // SAFETY: Immediate descriptor failures do not consume or invoke the completion.
            drop(unsafe { Box::from_raw(completion.cast::<DispatchSender>()) });
            return Box::pin(std::future::ready(Err(policy_unavailable())));
        }
        Box::pin(async move {
            match receiver.await {
                Ok(Ok(result)) => decode_dispatch(result, capability),
                Ok(Err(())) | Err(_) => Err(DispatchError::Audit(AuditError::Unavailable)),
            }
        })
    }
}

type DispatchSender = oneshot::Sender<Result<OwnedDispatchResult, ()>>;

struct OwnedDispatchResult {
    outcome: u32,
    detail: Option<String>,
}

unsafe extern "C" fn complete_dispatch(
    context: *mut c_void,
    result: *const BondryDispatchResultV1,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: An accepted dispatch transfers exactly one sender allocation.
    let sender = unsafe { Box::from_raw(context.cast::<DispatchSender>()) };
    let result = unsafe { result.as_ref() }.ok_or(()).and_then(|result| {
        Ok(OwnedDispatchResult {
            outcome: result.outcome,
            detail: detail(result)?,
        })
    });
    let _ = sender.send(result);
}

fn decode_dispatch(
    result: OwnedDispatchResult,
    capability: bondry_core::CapabilityId,
) -> Result<serde_json::Value, DispatchError> {
    match result.outcome {
        BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1 => Ok(serde_json::Value::Null),
        BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1 => {
            Err(DispatchError::CapabilityNotFound(capability))
        }
        BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1 => {
            if result.detail.as_deref() == Some("policy_unavailable") {
                Err(policy_unavailable())
            } else {
                Err(DispatchError::AccessDenied(DenialReason::NotGranted))
            }
        }
        BONDRY_DISPATCH_OUTCOME_AUDIT_UNAVAILABLE_V1 => {
            Err(DispatchError::Audit(AuditError::Unavailable))
        }
        BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1 => {
            let detail = result
                .detail
                .ok_or(DispatchError::Audit(AuditError::Unavailable))?;
            let code = HandlerErrorCode::new(detail)
                .map_err(|_| DispatchError::Audit(AuditError::Unavailable))?;
            Err(DispatchError::Handler(HandlerError::new(code)))
        }
        BONDRY_DISPATCH_OUTCOME_INVALID_INPUT_V1 => Err(DispatchError::InvalidInput),
        _ => Err(DispatchError::Audit(AuditError::Unavailable)),
    }
}

fn detail(result: &BondryDispatchResultV1) -> Result<Option<String>, ()> {
    if result.has_detail_code == 0 {
        return Ok(None);
    }
    if result.has_detail_code != 1 {
        return Err(());
    }
    let end = result
        .detail_code
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(())?;
    std::str::from_utf8(&result.detail_code[..end])
        .map(str::to_owned)
        .map(Some)
        .map_err(|_| ())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SerializedCapability {
    id: String,
    summary: String,
    effect: SerializedCapabilityEffect,
    input_schema: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SerializedCapabilityEffect {
    ReadOnly,
    Mutating,
}

fn decode_capabilities(bytes: &[u8]) -> Result<Vec<CapabilityDescriptor>, ()> {
    let serialized: Vec<SerializedCapability> = serde_json::from_slice(bytes).map_err(|_| ())?;
    serialized
        .into_iter()
        .map(|capability| {
            let id = CapabilityId::new(capability.id).map_err(|_| ())?;
            let effect = match capability.effect {
                SerializedCapabilityEffect::ReadOnly => CapabilityEffect::ReadOnly,
                SerializedCapabilityEffect::Mutating => CapabilityEffect::Mutating,
            };
            CapabilityDescriptor::new(id, capability.summary, effect)
                .map_err(|_| ())?
                .with_input_schema(capability.input_schema)
                .map_err(|_| ())
        })
        .collect()
}

const fn encode_principal_kind(kind: bondry_core::PrincipalKind) -> u32 {
    match kind {
        bondry_core::PrincipalKind::User => crate::BONDRY_PRINCIPAL_KIND_USER_V1,
        bondry_core::PrincipalKind::Application => crate::BONDRY_PRINCIPAL_KIND_APPLICATION_V1,
        bondry_core::PrincipalKind::System => crate::BONDRY_PRINCIPAL_KIND_SYSTEM_V1,
    }
}

fn policy_unavailable() -> DispatchError {
    DispatchError::AccessDenied(DenialReason::PolicyUnavailable)
}
