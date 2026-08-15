use std::{
    collections::{HashMap, hash_map::Entry},
    ffi::c_void,
    future::{Future, ready},
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    ptr, slice,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use bondry_auth::AuthenticationError;
use bondry_core::{
    AdapterId, AuditSink, AutomationService, CapabilityDescriptor, CapabilityDiscoveryError,
    CapabilityEffect, CapabilityHandler, CapabilityId, CapabilityRegistry, DenialReason,
    DispatchError, DispatchFuture as ServiceDispatchFuture, Dispatcher, GrantStore, HandlerError,
    HandlerErrorCode, HandlerFuture, Invocation, InvocationContext, InvocationId, Principal,
    PrincipalId, PrincipalKind, StoredGrantPolicy,
};
use bondry_store_sqlcipher::SqlCipherStore;
use serde_json::Value;

use crate::{
    BONDRY_STATUS_ALREADY_EXISTS, BONDRY_STATUS_AUTHENTICATION_REJECTED,
    BONDRY_STATUS_INTERNAL_FAILURE, BONDRY_STATUS_INVALID_ARGUMENT, BONDRY_STATUS_INVALID_JSON,
    BONDRY_STATUS_INVALID_LENGTH, BONDRY_STATUS_NULL_POINTER, BONDRY_STATUS_OK,
    BONDRY_STATUS_PAYLOAD_TOO_LARGE, BONDRY_STATUS_UNAVAILABLE, BondryCapabilityV1,
    BondryDispatchResultV1, BondryInvocationV1, BondryStoreHandle, catch_status,
    records::{
        BONDRY_CAPABILITY_EFFECT_MUTATING_V1, BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1,
        BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1, BONDRY_DISPATCH_OUTCOME_AUDIT_UNAVAILABLE_V1,
        BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1, BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1,
        BONDRY_DISPATCH_OUTCOME_INVALID_INPUT_V1, BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1,
        BONDRY_HANDLER_RESULT_FAILED_V1, BONDRY_HANDLER_RESULT_SUCCEEDED_V1,
        BONDRY_PRINCIPAL_KIND_APPLICATION_V1, BONDRY_PRINCIPAL_KIND_SYSTEM_V1,
        BONDRY_PRINCIPAL_KIND_USER_V1, optional_terminated,
    },
    required_utf8, write_bytes, write_records,
};

const MAX_JSON_PAYLOAD_LENGTH: usize = 1_048_576;
pub(crate) const MAX_AUTOMATION_INPUT_LENGTH: usize = 10 * 1_048_576;

/// Completes one foreign capability invocation exactly once.
pub type BondryCapabilityCompletionV1 = unsafe extern "C" fn(
    completion_context: *mut c_void,
    outcome: u32,
    payload: *const u8,
    payload_length: usize,
);

/// Invokes a foreign capability handler.
pub type BondryCapabilityInvokeV1 = unsafe extern "C" fn(
    handler_context: *mut c_void,
    invocation: *const BondryInvocationV1,
    completion: BondryCapabilityCompletionV1,
    completion_context: *mut c_void,
);

/// Releases a foreign capability handler context.
pub type BondryCapabilityReleaseV1 = unsafe extern "C" fn(handler_context: *mut c_void);

/// Receives the final result of one accepted dispatch.
pub type BondryDispatchCompletionV1 =
    unsafe extern "C" fn(completion_context: *mut c_void, result: *const BondryDispatchResultV1);

#[derive(Clone)]
pub(crate) struct RegisteredCapability {
    descriptor: CapabilityDescriptor,
    handler: Arc<ForeignHandler>,
}

struct ForeignHandler {
    context: *mut c_void,
    invoke: BondryCapabilityInvokeV1,
    release: Option<BondryCapabilityReleaseV1>,
    invalid_result_code: HandlerErrorCode,
}

// SAFETY: Registration requires the context and callbacks to be safe on any calling thread.
unsafe impl Send for ForeignHandler {}
// SAFETY: The foreign host promises concurrent callback safety for the registered context.
unsafe impl Sync for ForeignHandler {}

impl Drop for ForeignHandler {
    fn drop(&mut self) {
        if let Some(release) = self.release {
            // SAFETY: Successful registration transferred exactly one context ownership unit.
            unsafe { release(self.context) };
        }
    }
}

impl CapabilityHandler for ForeignHandler {
    fn invoke(&self, context: InvocationContext, input: Value) -> HandlerFuture {
        let input = match serde_json::to_vec(&input) {
            Ok(input) => input,
            Err(_) => {
                return Box::pin(ready(Err(HandlerError::new(
                    self.invalid_result_code.clone(),
                ))));
            }
        };
        let completion = Arc::new(ForeignCompletionState {
            state: Mutex::new(ForeignCompletion::Pending(None)),
            invalid_result_code: self.invalid_result_code.clone(),
        });
        let completion_context = Arc::into_raw(completion.clone())
            .cast_mut()
            .cast::<c_void>();
        let invocation = BondryInvocationV1::new(&context, &input);
        // SAFETY: The callback and context were registered together. Invocation memory remains
        // readable until the callback returns, and completion_context transfers one Arc unit.
        unsafe {
            (self.invoke)(
                self.context,
                &invocation,
                complete_foreign_handler,
                completion_context,
            );
        }
        Box::pin(ForeignHandlerFuture { completion })
    }
}

struct SharedForeignHandler(Arc<ForeignHandler>);

impl CapabilityHandler for SharedForeignHandler {
    fn invoke(&self, context: InvocationContext, input: Value) -> HandlerFuture {
        self.0.invoke(context, input)
    }
}

pub(crate) struct ForeignAutomationService {
    store: Arc<SqlCipherStore>,
    capabilities: Arc<RwLock<HashMap<CapabilityId, RegisteredCapability>>>,
}

impl ForeignAutomationService {
    pub(crate) const fn new(
        store: Arc<SqlCipherStore>,
        capabilities: Arc<RwLock<HashMap<CapabilityId, RegisteredCapability>>>,
    ) -> Self {
        Self {
            store,
            capabilities,
        }
    }

    fn dispatcher(&self, capability: Option<&CapabilityId>) -> Result<Dispatcher, ()> {
        let capabilities = self.capabilities.read().map_err(|_| ())?;
        let selected = match capability {
            Some(capability) => capabilities.get(capability).into_iter().collect::<Vec<_>>(),
            None => capabilities.values().collect(),
        };
        let mut registry = CapabilityRegistry::new();
        for registered in selected {
            registry
                .register(
                    registered.descriptor.clone(),
                    SharedForeignHandler(registered.handler.clone()),
                )
                .map_err(|_| ())?;
        }
        let policy_store: Arc<dyn GrantStore> = self.store.clone();
        let audit: Arc<dyn AuditSink> = self.store.clone();
        Ok(Dispatcher::from_shared(
            registry,
            Arc::new(StoredGrantPolicy::from_shared(policy_store)),
            audit,
        ))
    }
}

impl AutomationService for ForeignAutomationService {
    fn capabilities(
        &self,
        principal: &Principal,
        adapter: &AdapterId,
    ) -> Result<Vec<CapabilityDescriptor>, CapabilityDiscoveryError> {
        self.dispatcher(None)
            .map_err(|()| CapabilityDiscoveryError::PolicyUnavailable)?
            .capabilities(principal, adapter)
    }

    fn dispatch(&self, invocation: Invocation) -> ServiceDispatchFuture<'_> {
        let dispatcher = self.dispatcher(Some(invocation.capability()));
        Box::pin(async move {
            match dispatcher {
                Ok(dispatcher) => dispatcher.dispatch(invocation).await,
                Err(()) => Err(DispatchError::AccessDenied(DenialReason::PolicyUnavailable)),
            }
        })
    }
}

enum ForeignCompletion {
    Pending(Option<Waker>),
    Ready(Result<Value, HandlerError>),
    Consumed,
}

struct ForeignCompletionState {
    state: Mutex<ForeignCompletion>,
    invalid_result_code: HandlerErrorCode,
}

impl ForeignCompletionState {
    fn invalid_result(&self) -> Result<Value, HandlerError> {
        Err(HandlerError::new(self.invalid_result_code.clone()))
    }

    fn complete(&self, result: Result<Value, HandlerError>) {
        let waker = {
            let mut state = lock(&self.state);
            match std::mem::replace(&mut *state, ForeignCompletion::Ready(result)) {
                ForeignCompletion::Pending(waker) => waker,
                previous => {
                    *state = previous;
                    None
                }
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

struct ForeignHandlerFuture {
    completion: Arc<ForeignCompletionState>,
}

impl Future for ForeignHandlerFuture {
    type Output = Result<Value, HandlerError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = lock(&self.completion.state);
        match &mut *state {
            ForeignCompletion::Pending(waker) => {
                *waker = Some(context.waker().clone());
                Poll::Pending
            }
            ForeignCompletion::Ready(_) => {
                let ForeignCompletion::Ready(result) =
                    std::mem::replace(&mut *state, ForeignCompletion::Consumed)
                else {
                    return Poll::Ready(self.completion.invalid_result());
                };
                Poll::Ready(result)
            }
            ForeignCompletion::Consumed => Poll::Ready(self.completion.invalid_result()),
        }
    }
}

impl Drop for ForeignHandlerFuture {
    fn drop(&mut self) {
        let mut state = lock(&self.completion.state);
        if let ForeignCompletion::Pending(waker) = &mut *state {
            *waker = None;
        }
    }
}

unsafe extern "C" fn complete_foreign_handler(
    completion_context: *mut c_void,
    outcome: u32,
    payload: *const u8,
    payload_length: usize,
) {
    if completion_context.is_null() {
        return;
    }
    // SAFETY: The handler owns exactly one Arc unit encoded in completion_context.
    let completion = unsafe {
        Arc::from_raw(
            completion_context
                .cast::<ForeignCompletionState>()
                .cast_const(),
        )
    };
    let parsed = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: The foreign completion contract requires a readable payload for this call.
        unsafe { parse_foreign_result(&completion, outcome, payload, payload_length) }
    }));
    completion.complete(match parsed {
        Ok(result) => result,
        Err(_) => completion.invalid_result(),
    });
}

unsafe fn parse_foreign_result(
    completion: &ForeignCompletionState,
    outcome: u32,
    payload: *const u8,
    payload_length: usize,
) -> Result<Value, HandlerError> {
    if payload.is_null()
        || payload_length > MAX_JSON_PAYLOAD_LENGTH
        || payload_length > isize::MAX as usize
    {
        return completion.invalid_result();
    }
    // SAFETY: The caller guarantees that payload is readable for payload_length bytes.
    let payload = unsafe { slice::from_raw_parts(payload, payload_length) };
    match outcome {
        BONDRY_HANDLER_RESULT_SUCCEEDED_V1 => serde_json::from_slice(payload)
            .map_err(|_| HandlerError::new(completion.invalid_result_code.clone())),
        BONDRY_HANDLER_RESULT_FAILED_V1 => std::str::from_utf8(payload)
            .ok()
            .and_then(|code| HandlerErrorCode::new(code).ok())
            .map_or_else(
                || completion.invalid_result(),
                |code| Err(HandlerError::new(code)),
            ),
        _ => completion.invalid_result(),
    }
}

struct DispatchCallback {
    callback: BondryDispatchCompletionV1,
    context: *mut c_void,
}

// SAFETY: Accepted dispatch callbacks may be invoked from any thread by contract.
unsafe impl Send for DispatchCallback {}

impl DispatchCallback {
    fn call(self, result: Result<Value, DispatchError>) {
        let (outcome, output, detail) = match result {
            Ok(value) => match serde_json::to_vec(&value) {
                Ok(output) => (BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1, Some(output), None),
                Err(_) => (
                    BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1,
                    None,
                    Some("invalid_handler_result".to_owned()),
                ),
            },
            Err(DispatchError::CapabilityNotFound(_)) => {
                (BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1, None, None)
            }
            Err(DispatchError::AccessDenied(DenialReason::NotGranted)) => (
                BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1,
                None,
                Some("not_granted".to_owned()),
            ),
            Err(DispatchError::AccessDenied(DenialReason::PolicyUnavailable)) => (
                BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1,
                None,
                Some("policy_unavailable".to_owned()),
            ),
            Err(DispatchError::InvalidInput) => {
                (BONDRY_DISPATCH_OUTCOME_INVALID_INPUT_V1, None, None)
            }
            Err(DispatchError::Audit(_)) => {
                (BONDRY_DISPATCH_OUTCOME_AUDIT_UNAVAILABLE_V1, None, None)
            }
            Err(DispatchError::Handler(error)) => (
                BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1,
                None,
                Some(error.code().as_str().to_owned()),
            ),
        };
        let (output_json, output_json_length) = output
            .as_ref()
            .map_or((ptr::null(), 0), |output| (output.as_ptr(), output.len()));
        let (detail_code, has_detail_code) = optional_terminated(detail.as_deref());
        let mut result = BondryDispatchResultV1::zeroed();
        result.outcome = outcome;
        result.output_json = output_json;
        result.output_json_length = output_json_length;
        result.detail_code = detail_code;
        result.has_detail_code = has_detail_code;
        // SAFETY: The callback and context remain caller-provided and valid until this one call.
        unsafe { (self.callback)(self.context, &result) };
    }
}

type DispatchFuture = Pin<Box<dyn Future<Output = Result<Value, DispatchError>> + Send>>;

struct DispatchState {
    future: Option<DispatchFuture>,
    callback: Option<DispatchCallback>,
}

struct DispatchTask {
    state: Mutex<DispatchState>,
    polling: AtomicBool,
    poll_requested: AtomicBool,
}

impl DispatchTask {
    fn new(future: DispatchFuture, callback: DispatchCallback) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(DispatchState {
                future: Some(future),
                callback: Some(callback),
            }),
            polling: AtomicBool::new(false),
            poll_requested: AtomicBool::new(false),
        })
    }

    fn request_poll(self: &Arc<Self>) {
        self.poll_requested.store(true, Ordering::Release);
        if self
            .polling
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.drive();
        }
    }

    fn drive(self: &Arc<Self>) {
        loop {
            self.poll_requested.store(false, Ordering::Release);
            let completed = {
                let mut state = lock(&self.state);
                let Some(future) = state.future.as_mut() else {
                    self.polling.store(false, Ordering::Release);
                    return;
                };
                let waker = Waker::from(self.clone());
                let mut context = Context::from_waker(&waker);
                match future.as_mut().poll(&mut context) {
                    Poll::Ready(result) => {
                        state.future = None;
                        state.callback.take().map(|callback| (callback, result))
                    }
                    Poll::Pending => None,
                }
            };
            if let Some((callback, result)) = completed {
                self.polling.store(false, Ordering::Release);
                callback.call(result);
                return;
            }
            if self.poll_requested.swap(false, Ordering::AcqRel) {
                continue;
            }
            self.polling.store(false, Ordering::Release);
            if !self.poll_requested.swap(false, Ordering::AcqRel) {
                return;
            }
            if self
                .polling
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return;
            }
        }
    }
}

impl Wake for DispatchTask {
    fn wake(self: Arc<Self>) {
        self.request_poll();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.request_poll();
    }
}

/// Registers a protocol-neutral capability implemented by a foreign callback.
///
/// # Safety
///
/// Input buffers must be readable for their declared lengths. On success, Bondry owns one
/// `handler_context` unit and eventually passes it once to `release`, when provided. The invoke,
/// completion, and release callbacks must not unwind and must be safe on any calling thread.
#[must_use]
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bondry_capability_register_v1(
    store: *const BondryStoreHandle,
    capability_id: *const u8,
    capability_id_length: usize,
    summary: *const u8,
    summary_length: usize,
    effect: u32,
    handler_context: *mut c_void,
    invoke: Option<BondryCapabilityInvokeV1>,
    release: Option<BondryCapabilityReleaseV1>,
) -> i32 {
    unsafe {
        register_capability(
            store,
            capability_id,
            capability_id_length,
            summary,
            summary_length,
            effect,
            None,
            handler_context,
            invoke,
            release,
        )
    }
}

/// Registers a protocol-neutral capability with a JSON Schema 2020-12 input contract.
///
/// # Safety
///
/// Input buffers must be readable for their declared lengths. Ownership and callback requirements
/// match `bondry_capability_register_v1`.
#[must_use]
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bondry_capability_register_with_schema_v1(
    store: *const BondryStoreHandle,
    capability_id: *const u8,
    capability_id_length: usize,
    summary: *const u8,
    summary_length: usize,
    effect: u32,
    input_schema_json: *const u8,
    input_schema_json_length: usize,
    handler_context: *mut c_void,
    invoke: Option<BondryCapabilityInvokeV1>,
    release: Option<BondryCapabilityReleaseV1>,
) -> i32 {
    unsafe {
        register_capability(
            store,
            capability_id,
            capability_id_length,
            summary,
            summary_length,
            effect,
            Some(RawBuffer::new(input_schema_json, input_schema_json_length)),
            handler_context,
            invoke,
            release,
        )
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn register_capability(
    store: *const BondryStoreHandle,
    capability_id: *const u8,
    capability_id_length: usize,
    summary: *const u8,
    summary_length: usize,
    effect: u32,
    input_schema_json: Option<RawBuffer>,
    handler_context: *mut c_void,
    invoke: Option<BondryCapabilityInvokeV1>,
    release: Option<BondryCapabilityReleaseV1>,
) -> i32 {
    catch_status(|| {
        let Ok(handle) = crate::auth::store_handle(store) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let Some(invoke) = invoke else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let descriptor = match unsafe {
            parse_descriptor(
                capability_id,
                capability_id_length,
                summary,
                summary_length,
                effect,
                input_schema_json,
            )
        } {
            Ok(descriptor) => descriptor,
            Err(status) => return status,
        };
        let invalid_result_code = match HandlerErrorCode::new("invalid_handler_result") {
            Ok(code) => code,
            Err(_) => return BONDRY_STATUS_INTERNAL_FAILURE,
        };
        let Ok(mut capabilities) = handle.capabilities.write() else {
            return BONDRY_STATUS_UNAVAILABLE;
        };
        match capabilities.entry(descriptor.id().clone()) {
            Entry::Occupied(_) => BONDRY_STATUS_ALREADY_EXISTS,
            Entry::Vacant(entry) => {
                entry.insert(RegisteredCapability {
                    descriptor,
                    handler: Arc::new(ForeignHandler {
                        context: handler_context,
                        invoke,
                        release,
                        invalid_result_code,
                    }),
                });
                BONDRY_STATUS_OK
            }
        }
    })
}

/// Unregisters a capability and reports whether state changed.
///
/// # Safety
///
/// The identifier must be readable for its declared length. `out_changed` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_capability_unregister_v1(
    store: *const BondryStoreHandle,
    capability_id: *const u8,
    capability_id_length: usize,
    out_changed: *mut u8,
) -> i32 {
    if out_changed.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    catch_status(|| {
        // SAFETY: out_changed is writable by contract.
        unsafe { out_changed.write(0) };
        let Ok(handle) = crate::auth::store_handle(store) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let capability = match unsafe { parse_capability_id(capability_id, capability_id_length) } {
            Ok(capability) => capability,
            Err(status) => return status,
        };
        let removed = {
            let Ok(mut capabilities) = handle.capabilities.write() else {
                return BONDRY_STATUS_UNAVAILABLE;
            };
            capabilities.remove(&capability)
        };
        // SAFETY: out_changed is writable and parsing no longer borrows input memory.
        unsafe { out_changed.write(u8::from(removed.is_some())) };
        drop(removed);
        BONDRY_STATUS_OK
    })
}

/// Lists registered capability descriptors in stable identifier order.
///
/// # Safety
///
/// A non-null output must be writable for `capacity` records. `out_count` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_capabilities_list_v1(
    store: *const BondryStoreHandle,
    output: *mut BondryCapabilityV1,
    capacity: usize,
    out_count: *mut usize,
) -> i32 {
    if out_count.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: out_count is writable by contract.
    unsafe { out_count.write(0) };
    catch_status(|| {
        let Ok(handle) = crate::auth::store_handle(store) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let descriptors = match registered_descriptors(handle) {
            Ok(descriptors) => descriptors,
            Err(status) => return status,
        };
        let records = descriptors
            .iter()
            .map(BondryCapabilityV1::from_descriptor)
            .collect::<Vec<_>>();
        write_records(&records, output, capacity, out_count)
    })
}

/// Serializes every registered capability descriptor in stable identifier order.
///
/// # Safety
///
/// A non-null output must be writable for `capacity` bytes. `out_length` must be writable.
#[must_use]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bondry_capabilities_json_v1(
    store: *const BondryStoreHandle,
    output_json: *mut u8,
    capacity: usize,
    out_length: *mut usize,
) -> i32 {
    if out_length.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: out_length was validated as writable by contract.
    unsafe { out_length.write(0) };
    catch_status(|| {
        let Ok(handle) = crate::auth::store_handle(store) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let descriptors = match registered_descriptors(handle) {
            Ok(descriptors) => descriptors,
            Err(status) => return status,
        };
        let encoded = match serde_json::to_vec(&descriptors) {
            Ok(encoded) => encoded,
            Err(_) => return BONDRY_STATUS_INTERNAL_FAILURE,
        };
        write_bytes(&encoded, output_json, capacity, out_length)
    })
}

/// Serializes capability descriptors authorized for one principal and adapter.
///
/// # Safety
///
/// Input buffers must be readable for their declared lengths. A non-null output must be writable
/// for `capacity` bytes. `out_length` must be writable.
#[must_use]
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bondry_capabilities_discover_json_v1(
    store: *const BondryStoreHandle,
    principal_id: *const u8,
    principal_id_length: usize,
    principal_kind: u32,
    adapter_id: *const u8,
    adapter_id_length: usize,
    output_json: *mut u8,
    capacity: usize,
    out_length: *mut usize,
) -> i32 {
    if out_length.is_null() {
        return BONDRY_STATUS_NULL_POINTER;
    }
    // SAFETY: out_length was validated as writable by contract.
    unsafe { out_length.write(0) };
    catch_status(|| {
        let Ok(handle) = crate::auth::store_handle(store) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let principal =
            match unsafe { parse_principal(principal_id, principal_id_length, principal_kind) } {
                Ok(principal) => principal,
                Err(status) => return status,
            };
        let adapter = match unsafe { required_utf8(adapter_id, adapter_id_length) }
            .and_then(|value| AdapterId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT))
        {
            Ok(adapter) => adapter,
            Err(status) => return status,
        };
        let service =
            ForeignAutomationService::new(handle.store.clone(), handle.capabilities.clone());
        let descriptors = match service.capabilities(&principal, &adapter) {
            Ok(descriptors) => descriptors,
            Err(CapabilityDiscoveryError::PolicyUnavailable) => {
                return BONDRY_STATUS_UNAVAILABLE;
            }
        };
        let encoded = match serde_json::to_vec(&descriptors) {
            Ok(encoded) => encoded,
            Err(_) => return BONDRY_STATUS_INTERNAL_FAILURE,
        };
        write_bytes(&encoded, output_json, capacity, out_length)
    })
}

/// Authenticates and asynchronously dispatches one protocol-neutral JSON invocation.
///
/// # Safety
///
/// Input buffers must be readable for their declared lengths. The completion callback and context
/// must remain valid until the callback is invoked. An accepted dispatch calls completion exactly
/// once, possibly before this function returns. Immediate errors do not call completion.
#[must_use]
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bondry_dispatch_token_v1(
    store: *const BondryStoreHandle,
    invocation_id: *const u8,
    invocation_id_length: usize,
    adapter_id: *const u8,
    adapter_id_length: usize,
    token: *const u8,
    token_length: usize,
    capability_id: *const u8,
    capability_id_length: usize,
    input_json: *const u8,
    input_json_length: usize,
    completion: Option<BondryDispatchCompletionV1>,
    completion_context: *mut c_void,
) -> i32 {
    catch_status(|| {
        let Ok(handle) = crate::auth::store_handle(store) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let Some(completion) = completion else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let dispatch = match unsafe {
            parse_dispatch(
                RawBuffer::new(invocation_id, invocation_id_length),
                RawBuffer::new(adapter_id, adapter_id_length),
                RawBuffer::new(capability_id, capability_id_length),
                RawBuffer::new(input_json, input_json_length),
                MAX_JSON_PAYLOAD_LENGTH,
            )
        } {
            Ok(dispatch) => dispatch,
            Err(status) => return status,
        };
        let token = match unsafe { required_utf8(token, token_length) } {
            Ok(token) => token,
            Err(status) => return status,
        };
        let principal = match handle.auth.authenticate(token) {
            Ok(principal) => principal,
            Err(AuthenticationError::Rejected) => return BONDRY_STATUS_AUTHENTICATION_REJECTED,
            Err(AuthenticationError::StorageUnavailable) => return BONDRY_STATUS_UNAVAILABLE,
        };
        let dispatch = match unsafe { dispatch.parse_input() } {
            Ok(dispatch) => dispatch,
            Err(status) => return status,
        };
        start_dispatch(handle, principal, dispatch, completion, completion_context)
    })
}

/// Asynchronously dispatches one protocol-neutral JSON invocation for a host-trusted principal.
///
/// # Safety
///
/// Input buffers must be readable for their declared lengths. The host must establish the
/// principal identity before calling this function. The completion callback and context must
/// remain valid until the callback is invoked. An accepted dispatch calls completion exactly
/// once, possibly before this function returns. Immediate errors do not call completion.
#[must_use]
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bondry_dispatch_principal_v1(
    store: *const BondryStoreHandle,
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
    completion: Option<BondryDispatchCompletionV1>,
    completion_context: *mut c_void,
) -> i32 {
    unsafe {
        dispatch_principal_with_limit(
            store,
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
            completion,
            completion_context,
            MAX_JSON_PAYLOAD_LENGTH,
        )
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) unsafe fn dispatch_principal_with_limit(
    store: *const BondryStoreHandle,
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
    completion: Option<BondryDispatchCompletionV1>,
    completion_context: *mut c_void,
    maximum_input_length: usize,
) -> i32 {
    catch_status(|| {
        let Ok(handle) = crate::auth::store_handle(store) else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let Some(completion) = completion else {
            return BONDRY_STATUS_NULL_POINTER;
        };
        let dispatch = match unsafe {
            parse_dispatch(
                RawBuffer::new(invocation_id, invocation_id_length),
                RawBuffer::new(adapter_id, adapter_id_length),
                RawBuffer::new(capability_id, capability_id_length),
                RawBuffer::new(input_json, input_json_length),
                maximum_input_length,
            )
        } {
            Ok(dispatch) => dispatch,
            Err(status) => return status,
        };
        let principal =
            match unsafe { parse_principal(principal_id, principal_id_length, principal_kind) } {
                Ok(principal) => principal,
                Err(status) => return status,
            };
        let dispatch = match unsafe { dispatch.parse_input() } {
            Ok(dispatch) => dispatch,
            Err(status) => return status,
        };
        start_dispatch(handle, principal, dispatch, completion, completion_context)
    })
}

struct ParsedDispatch {
    invocation_id: InvocationId,
    adapter: AdapterId,
    capability: CapabilityId,
    input: RawBuffer,
}

struct ReadyDispatch {
    invocation_id: InvocationId,
    adapter: AdapterId,
    capability: CapabilityId,
    input: Value,
}

#[derive(Clone, Copy)]
struct RawBuffer {
    bytes: *const u8,
    length: usize,
}

impl RawBuffer {
    const fn new(bytes: *const u8, length: usize) -> Self {
        Self { bytes, length }
    }
}

impl ParsedDispatch {
    unsafe fn parse_input(self) -> Result<ReadyDispatch, i32> {
        let input = unsafe { slice::from_raw_parts(self.input.bytes, self.input.length) };
        let input = serde_json::from_slice(input).map_err(|_| BONDRY_STATUS_INVALID_JSON)?;
        Ok(ReadyDispatch {
            invocation_id: self.invocation_id,
            adapter: self.adapter,
            capability: self.capability,
            input,
        })
    }
}

unsafe fn parse_dispatch(
    invocation: RawBuffer,
    adapter: RawBuffer,
    capability: RawBuffer,
    input: RawBuffer,
    maximum_input_length: usize,
) -> Result<ParsedDispatch, i32> {
    let invocation_id = unsafe { required_utf8(invocation.bytes, invocation.length) }
        .and_then(|value| InvocationId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT))?;
    let adapter = unsafe { required_utf8(adapter.bytes, adapter.length) }
        .and_then(|value| AdapterId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT))?;
    let capability = unsafe { parse_capability_id(capability.bytes, capability.length) }?;
    if input.bytes.is_null() {
        return Err(BONDRY_STATUS_NULL_POINTER);
    }
    if input.length > isize::MAX as usize {
        return Err(BONDRY_STATUS_INVALID_LENGTH);
    }
    if input.length > maximum_input_length {
        return Err(BONDRY_STATUS_PAYLOAD_TOO_LARGE);
    }
    Ok(ParsedDispatch {
        invocation_id,
        adapter,
        capability,
        input,
    })
}

fn start_dispatch(
    handle: &crate::StoreHandle,
    principal: Principal,
    dispatch: ReadyDispatch,
    completion: BondryDispatchCompletionV1,
    completion_context: *mut c_void,
) -> i32 {
    let registered = {
        let Ok(capabilities) = handle.capabilities.read() else {
            return BONDRY_STATUS_UNAVAILABLE;
        };
        capabilities.get(&dispatch.capability).cloned()
    };
    let mut registry = CapabilityRegistry::new();
    if let Some(registered) = registered {
        if registry
            .register(
                registered.descriptor,
                SharedForeignHandler(registered.handler),
            )
            .is_err()
        {
            return BONDRY_STATUS_INTERNAL_FAILURE;
        }
    }
    let store = handle.store.clone();
    let policy_store: Arc<dyn GrantStore> = store.clone();
    let audit: Arc<dyn AuditSink> = store;
    let dispatcher = Dispatcher::from_shared(
        registry,
        Arc::new(StoredGrantPolicy::from_shared(policy_store)),
        audit,
    );
    let invocation = Invocation::new(
        dispatch.invocation_id,
        dispatch.adapter,
        principal,
        dispatch.capability,
        dispatch.input,
    );
    let future = Box::pin(async move { dispatcher.dispatch(invocation).await });
    DispatchTask::new(
        future,
        DispatchCallback {
            callback: completion,
            context: completion_context,
        },
    )
    .request_poll();
    BONDRY_STATUS_OK
}

unsafe fn parse_descriptor(
    capability_id: *const u8,
    capability_id_length: usize,
    summary: *const u8,
    summary_length: usize,
    effect: u32,
    input_schema_json: Option<RawBuffer>,
) -> Result<CapabilityDescriptor, i32> {
    // SAFETY: The public entry point requires readable identifier input.
    let capability = unsafe { parse_capability_id(capability_id, capability_id_length) }?;
    // SAFETY: The public entry point requires readable summary input.
    let summary = unsafe { required_utf8(summary, summary_length) }?;
    let effect = match effect {
        BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1 => CapabilityEffect::ReadOnly,
        BONDRY_CAPABILITY_EFFECT_MUTATING_V1 => CapabilityEffect::Mutating,
        _ => return Err(BONDRY_STATUS_INVALID_ARGUMENT),
    };
    let descriptor = CapabilityDescriptor::new(capability, summary, effect)
        .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)?;
    let Some(input_schema_json) = input_schema_json else {
        return Ok(descriptor);
    };
    if input_schema_json.bytes.is_null() {
        return Err(BONDRY_STATUS_NULL_POINTER);
    }
    if input_schema_json.length > isize::MAX as usize {
        return Err(BONDRY_STATUS_INVALID_LENGTH);
    }
    if input_schema_json.length > MAX_JSON_PAYLOAD_LENGTH {
        return Err(BONDRY_STATUS_PAYLOAD_TOO_LARGE);
    }
    // SAFETY: The caller guarantees the schema buffer is readable for its declared length.
    let input_schema =
        unsafe { slice::from_raw_parts(input_schema_json.bytes, input_schema_json.length) };
    let input_schema =
        serde_json::from_slice(input_schema).map_err(|_| BONDRY_STATUS_INVALID_JSON)?;
    descriptor
        .with_input_schema(input_schema)
        .map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT)
}

fn registered_descriptors(handle: &crate::StoreHandle) -> Result<Vec<CapabilityDescriptor>, i32> {
    let capabilities = handle
        .capabilities
        .read()
        .map_err(|_| BONDRY_STATUS_UNAVAILABLE)?;
    let mut descriptors = capabilities
        .values()
        .map(|capability| capability.descriptor.clone())
        .collect::<Vec<_>>();
    descriptors.sort_unstable_by(|left, right| left.id().cmp(right.id()));
    Ok(descriptors)
}

unsafe fn parse_principal(
    principal_id: *const u8,
    principal_id_length: usize,
    principal_kind: u32,
) -> Result<Principal, i32> {
    let principal_id = unsafe { required_utf8(principal_id, principal_id_length) }
        .and_then(|value| PrincipalId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT))?;
    let kind = match principal_kind {
        BONDRY_PRINCIPAL_KIND_USER_V1 => PrincipalKind::User,
        BONDRY_PRINCIPAL_KIND_APPLICATION_V1 => PrincipalKind::Application,
        BONDRY_PRINCIPAL_KIND_SYSTEM_V1 => PrincipalKind::System,
        _ => return Err(BONDRY_STATUS_INVALID_ARGUMENT),
    };
    Ok(Principal::new(principal_id, kind))
}

unsafe fn parse_capability_id(bytes: *const u8, length: usize) -> Result<CapabilityId, i32> {
    // SAFETY: The caller guarantees the identifier buffer is readable.
    unsafe { required_utf8(bytes, length) }
        .and_then(|value| CapabilityId::new(value).map_err(|_| BONDRY_STATUS_INVALID_ARGUMENT))
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
