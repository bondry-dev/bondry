use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use bondry_core::{
    AdapterId, AuditError, AutomationService, CapabilityDescriptor, CapabilityDiscoveryError,
    CapabilityEffect, CapabilityId, DenialReason, DispatchError, DispatchFuture, Invocation,
    InvocationId, InvocationIdGenerationError, InvocationIdGenerator, Principal, PrincipalId,
    PrincipalKind,
};
use bondry_delivery_store::{
    DedupClaim, DedupClaimPolicy, DedupKey, DedupRecord, DedupResolution, DedupState, DedupStore,
    DedupStoreError, RouteId, StoreDurability, VerifierNamespace,
};
use bondry_webhook_verify::{
    IdentityGuarantee, PeerAddress, TrustedDeliveryIdentity, VerificationError, VerificationHeader,
    VerificationRequest, VerificationResult, WebhookVerifier,
};
use http::{HeaderName, Method, StatusCode, header};
use serde_json::{Value, json};

use crate::{
    AuthenticatedRequestLimiter, CapabilitySemantics, PayloadMapping, WebhookIngressContext,
    WebhookIngressLimits, WebhookIngressTime, WebhookRoute, WebhookRouteConfiguration,
    WebhookRouteError,
};

const DISPATCH_SUCCESS: u8 = 0;
const DISPATCH_PENDING: u8 = 1;
const DISPATCH_POLICY_UNAVAILABLE: u8 = 2;
const DISPATCH_AUDIT_UNAVAILABLE: u8 = 3;

struct TestVerifier {
    selected: Arc<[HeaderName]>,
    credentials: Arc<[HeaderName]>,
    guarantee: IdentityGuarantee,
    result: Result<VerificationResult, VerificationError>,
}

impl WebhookVerifier for TestVerifier {
    fn selected_headers(&self) -> &[HeaderName] {
        &self.selected
    }

    fn credential_headers(&self) -> &[HeaderName] {
        &self.credentials
    }

    fn identity_guarantee(&self) -> IdentityGuarantee {
        self.guarantee
    }

    fn verify(
        &self,
        _request: VerificationRequest<'_>,
        _now_unix_seconds: i64,
    ) -> Result<VerificationResult, VerificationError> {
        self.result.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CapturedInvocation {
    adapter: String,
    principal: String,
    capability: String,
    input: Value,
}

struct TestService {
    descriptor: CapabilityDescriptor,
    dispatch_mode: AtomicU8,
    invocations: Mutex<Vec<CapturedInvocation>>,
}

impl AutomationService for TestService {
    fn capabilities(
        &self,
        _principal: &Principal,
        _adapter: &AdapterId,
    ) -> Result<Vec<CapabilityDescriptor>, CapabilityDiscoveryError> {
        Ok(vec![self.descriptor.clone()])
    }

    fn dispatch(&self, invocation: Invocation) -> DispatchFuture<'_> {
        lock(&self.invocations).push(CapturedInvocation {
            adapter: invocation.adapter().as_str().to_owned(),
            principal: invocation.principal().id().as_str().to_owned(),
            capability: invocation.capability().as_str().to_owned(),
            input: invocation.input().clone(),
        });
        match self.dispatch_mode.load(Ordering::SeqCst) {
            DISPATCH_PENDING => Box::pin(std::future::pending()),
            DISPATCH_POLICY_UNAVAILABLE => Box::pin(async {
                Err(DispatchError::AccessDenied(DenialReason::PolicyUnavailable))
            }),
            DISPATCH_AUDIT_UNAVAILABLE => {
                Box::pin(async { Err(DispatchError::Audit(AuditError::Unavailable)) })
            }
            _ => Box::pin(async { Ok(json!({ "ignored": true })) }),
        }
    }
}

struct FixedInvocationIds;

impl InvocationIdGenerator for FixedInvocationIds {
    fn generate(&self) -> Result<InvocationId, InvocationIdGenerationError> {
        InvocationId::new("webhook_test").map_err(|_| InvocationIdGenerationError)
    }
}

struct MemoryDedupStore {
    durability: StoreDurability,
    records: Mutex<HashMap<DedupKey, DedupState>>,
    claim_error: Mutex<Option<DedupStoreError>>,
    policies: Mutex<Vec<DedupClaimPolicy>>,
}

impl MemoryDedupStore {
    fn new(durability: StoreDurability) -> Self {
        Self {
            durability,
            records: Mutex::new(HashMap::new()),
            claim_error: Mutex::new(None),
            policies: Mutex::new(Vec::new()),
        }
    }

    fn state(&self, key: &DedupKey) -> Option<DedupState> {
        lock(&self.records).get(key).copied()
    }

    fn fail_claim_with(&self, error: DedupStoreError) {
        *lock(&self.claim_error) = Some(error);
    }

    fn policies(&self) -> Vec<DedupClaimPolicy> {
        lock(&self.policies).clone()
    }
}

impl DedupStore for MemoryDedupStore {
    fn durability(&self) -> StoreDurability {
        self.durability
    }

    fn claim(
        &self,
        key: DedupKey,
        policy: DedupClaimPolicy,
        _updated_at_unix_ms: u64,
    ) -> Result<DedupClaim, DedupStoreError> {
        lock(&self.policies).push(policy);
        if let Some(error) = *lock(&self.claim_error) {
            return Err(error);
        }
        let mut records = lock(&self.records);
        if let Some(state) = records.get(&key) {
            return Ok(DedupClaim::Duplicate(*state));
        }
        records.insert(key, DedupState::InFlight);
        Ok(DedupClaim::Claimed)
    }

    fn complete(&self, key: &DedupKey, _updated_at_unix_ms: u64) -> Result<(), DedupStoreError> {
        transition(&self.records, key, DedupState::Completed)
    }

    fn mark_unknown(
        &self,
        key: &DedupKey,
        _updated_at_unix_ms: u64,
    ) -> Result<(), DedupStoreError> {
        transition(&self.records, key, DedupState::Unknown)
    }

    fn release_claim(&self, key: &DedupKey) -> Result<(), DedupStoreError> {
        let mut records = lock(&self.records);
        if records.get(key) != Some(&DedupState::InFlight) {
            return Err(DedupStoreError::InvalidTransition);
        }
        records.remove(key);
        Ok(())
    }

    fn record(&self, key: &DedupKey) -> Result<Option<DedupRecord>, DedupStoreError> {
        Ok(lock(&self.records)
            .get(key)
            .copied()
            .map(|state| DedupRecord::from_stored_parts(key.clone(), state, 0)))
    }

    fn recover_in_flight(&self, _updated_at_unix_ms: u64) -> Result<u64, DedupStoreError> {
        let mut records = lock(&self.records);
        let mut recovered = 0;
        for state in records.values_mut() {
            if *state == DedupState::InFlight {
                *state = DedupState::Unknown;
                recovered += 1;
            }
        }
        Ok(recovered)
    }

    fn resolve_unknown(
        &self,
        key: &DedupKey,
        resolution: DedupResolution,
        _updated_at_unix_ms: u64,
    ) -> Result<(), DedupStoreError> {
        let mut records = lock(&self.records);
        if records.get(key) != Some(&DedupState::Unknown) {
            return Err(DedupStoreError::InvalidTransition);
        }
        match resolution {
            DedupResolution::Completed => {
                records.insert(key.clone(), DedupState::Completed);
            }
            DedupResolution::RetryAllowed => {
                records.remove(key);
            }
        }
        Ok(())
    }

    fn visit_unknown(
        &self,
        visitor: &mut dyn FnMut(&DedupRecord) -> bool,
    ) -> Result<(), DedupStoreError> {
        let records = lock(&self.records)
            .iter()
            .filter(|(_, state)| **state == DedupState::Unknown)
            .map(|(key, state)| DedupRecord::from_stored_parts(key.clone(), *state, 0))
            .collect::<Vec<_>>();
        for record in &records {
            if !visitor(record) {
                break;
            }
        }
        Ok(())
    }

    fn clear_completed_before(&self, _updated_before_unix_ms: u64) -> Result<u64, DedupStoreError> {
        let mut records = lock(&self.records);
        let before = records.len();
        records.retain(|_, state| *state != DedupState::Completed);
        Ok((before - records.len()) as u64)
    }
}

#[test]
fn fixes_principal_adapter_and_capability_and_deduplicates_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = identity()?;
    let key = dedup_key(&identity)?;
    let verifier = Arc::new(verifier(
        IdentityGuarantee::Required,
        Ok(VerificationResult::with_identity(identity)),
    ));
    let service = Arc::new(service(CapabilityEffect::Mutating)?);
    let store = Arc::new(MemoryDedupStore::new(StoreDurability::Persistent));
    let context = context(service.clone(), store.clone());
    let route = WebhookRoute::new(
        configuration(CapabilitySemantics::NonIdempotentMutation)?,
        verifier,
        context,
    )?;
    let headers = request_headers();
    let body = br#"{"adapter":"rest","principal":"attacker","capability":"other","value":7}"#;
    let method = Method::POST;
    let request = request(&method, &headers, body);

    let first = block_on(route.handle(request, WebhookIngressTime::new(1_000, 1_000)));
    let duplicate = block_on(route.handle(request, WebhookIngressTime::new(1_001, 1_001)));

    assert_eq!(first.status(), StatusCode::NO_CONTENT);
    assert_eq!(duplicate.status(), StatusCode::NO_CONTENT);
    assert_eq!(store.state(&key), Some(DedupState::Completed));
    assert_eq!(
        store.policies(),
        [
            DedupClaimPolicy::RetainCompleted,
            DedupClaimPolicy::RetainCompleted,
        ]
    );
    let invocations = lock(&service.invocations);
    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0].adapter, "webhook");
    assert_eq!(invocations[0].principal, "trusted_sender");
    assert_eq!(invocations[0].capability, "device.actuate");
    assert_eq!(invocations[0].input, serde_json::from_slice::<Value>(body)?);
    assert!(route.selected_headers().contains(&header::CONTENT_TYPE));
    assert!(
        route
            .selected_headers()
            .contains(&HeaderName::from_static("x-signature"))
    );
    Ok(())
}

#[test]
fn cancellation_marks_claim_unknown_and_prevents_automatic_redispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = identity()?;
    let key = dedup_key(&identity)?;
    let verifier = Arc::new(verifier(
        IdentityGuarantee::Required,
        Ok(VerificationResult::with_identity(identity)),
    ));
    let service = Arc::new(service(CapabilityEffect::Mutating)?);
    service
        .dispatch_mode
        .store(DISPATCH_PENDING, Ordering::SeqCst);
    let store = Arc::new(MemoryDedupStore::new(StoreDurability::Persistent));
    let route = WebhookRoute::new(
        configuration(CapabilitySemantics::NonIdempotentMutation)?,
        verifier,
        context(service.clone(), store.clone()),
    )?;
    let headers = request_headers();
    let method = Method::POST;
    let mut delivery = Box::pin(route.handle(
        request(&method, &headers, br#"{"value":1}"#),
        WebhookIngressTime::new(2_000, 2_000),
    ));
    let waker = Waker::from(Arc::new(NoopWake));
    let mut task = Context::from_waker(&waker);
    assert!(matches!(delivery.as_mut().poll(&mut task), Poll::Pending));
    drop(delivery);
    assert_eq!(store.state(&key), Some(DedupState::Unknown));

    service
        .dispatch_mode
        .store(DISPATCH_SUCCESS, Ordering::SeqCst);
    let duplicate = block_on(route.handle(
        request(&method, &headers, br#"{"value":1}"#),
        WebhookIngressTime::new(2_001, 2_001),
    ));
    assert_eq!(duplicate.status(), StatusCode::NO_CONTENT);
    assert_eq!(lock(&service.invocations).len(), 1);
    Ok(())
}

#[test]
fn enforces_route_semantics_store_and_credential_mapping() -> Result<(), Box<dyn std::error::Error>>
{
    let service = Arc::new(service(CapabilityEffect::Mutating)?);
    let process_store = Arc::new(MemoryDedupStore::new(StoreDurability::ProcessLocal));
    let never = Arc::new(verifier(
        IdentityGuarantee::Never,
        Ok(VerificationResult::authenticated()),
    ));
    assert!(matches!(
        WebhookRoute::new(
            configuration(CapabilitySemantics::NonIdempotentMutation)?,
            never,
            context(service.clone(), process_store.clone()),
        ),
        Err(WebhookRouteError::TrustedIdentityRequired)
    ));

    let required = Arc::new(verifier(
        IdentityGuarantee::Required,
        Ok(VerificationResult::with_identity(identity()?)),
    ));
    assert!(matches!(
        WebhookRoute::new(
            configuration(CapabilitySemantics::NonIdempotentMutation)?,
            required.clone(),
            context(service.clone(), process_store),
        ),
        Err(WebhookRouteError::PersistentStoreRequired)
    ));
    let persistent = Arc::new(MemoryDedupStore::new(StoreDurability::Persistent));
    let mapping = PayloadMapping::envelope([HeaderName::from_static("x-signature")])?;
    assert!(matches!(
        WebhookRoute::new(
            configuration(CapabilitySemantics::NonIdempotentMutation)?.with_mapping(mapping),
            required,
            context(service.clone(), persistent.clone()),
        ),
        Err(WebhookRouteError::CredentialMetadataOverlap)
    ));
    assert!(matches!(
        WebhookRoute::new(
            configuration(CapabilitySemantics::ReadOnly)?,
            Arc::new(verifier(
                IdentityGuarantee::Never,
                Ok(VerificationResult::authenticated()),
            )),
            context(service, persistent),
        ),
        Err(WebhookRouteError::CapabilityEffectMismatch)
    ));
    Ok(())
}

#[test]
fn authenticates_before_media_type_and_json_rejection() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = Arc::new(verifier(
        IdentityGuarantee::Never,
        Err(VerificationError::Rejected),
    ));
    let service = Arc::new(service(CapabilityEffect::ReadOnly)?);
    let store = Arc::new(MemoryDedupStore::new(StoreDurability::ProcessLocal));
    let route = WebhookRoute::new(
        configuration(CapabilitySemantics::ReadOnly)?,
        verifier,
        context(service.clone(), store),
    )?;
    let method = Method::POST;
    let headers = [VerificationHeader::new(
        HeaderName::from_static("x-signature"),
        b"invalid",
    )];

    let response = block_on(route.handle(
        request(&method, &headers, b"not-json"),
        WebhookIngressTime::new(3_000, 3_000),
    ));

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.error_code(), Some("authentication_rejected"));
    assert!(lock(&service.invocations).is_empty());
    Ok(())
}

#[test]
fn rejects_wrong_method_and_verifier_identity_contract_violation()
-> Result<(), Box<dyn std::error::Error>> {
    let verifier = Arc::new(verifier(
        IdentityGuarantee::Required,
        Ok(VerificationResult::authenticated()),
    ));
    let service = Arc::new(service(CapabilityEffect::Mutating)?);
    let store = Arc::new(MemoryDedupStore::new(StoreDurability::Persistent));
    let route = WebhookRoute::new(
        configuration(CapabilitySemantics::NonIdempotentMutation)?,
        verifier,
        context(service.clone(), store),
    )?;
    let headers = request_headers();
    let get = Method::GET;
    let post = Method::POST;

    let wrong_method = block_on(route.handle(
        request(&get, &headers, br#"{"value":1}"#),
        WebhookIngressTime::new(3_100, 3_100),
    ));
    let contract_violation = block_on(route.handle(
        request(&post, &headers, br#"{"value":1}"#),
        WebhookIngressTime::new(3_101, 3_101),
    ));

    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(contract_violation.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        contract_violation.error_code(),
        Some("verification_unavailable")
    );
    assert!(lock(&service.invocations).is_empty());
    Ok(())
}

#[test]
fn bounds_json_allocation_before_claim_and_dispatch() -> Result<(), Box<dyn std::error::Error>> {
    let identity = identity()?;
    let key = dedup_key(&identity)?;
    let verifier = Arc::new(verifier(
        IdentityGuarantee::Required,
        Ok(VerificationResult::with_identity(identity)),
    ));
    let service = Arc::new(service(CapabilityEffect::Mutating)?);
    let store = Arc::new(MemoryDedupStore::new(StoreDurability::Persistent));
    let configuration = configuration(CapabilitySemantics::NonIdempotentMutation)?
        .with_limits(WebhookIngressLimits::new(1_024, 1_024)?);
    let route = WebhookRoute::new(
        configuration,
        verifier,
        context(service.clone(), store.clone()),
    )?;
    let method = Method::POST;
    let headers = request_headers();
    let dense = format!(
        "[{}]",
        std::iter::repeat_n("0", 32).collect::<Vec<_>>().join(",")
    );

    let response = block_on(route.handle(
        request(&method, &headers, dense.as_bytes()),
        WebhookIngressTime::new(4_000, 4_000),
    ));

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response.error_code(), Some("retained_capacity"));
    assert_eq!(store.state(&key), None);
    assert!(lock(&service.invocations).is_empty());
    Ok(())
}

#[test]
fn releases_known_pre_dispatch_failure_but_preserves_uncertain_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = identity()?;
    let key = dedup_key(&identity)?;
    let verifier = Arc::new(verifier(
        IdentityGuarantee::Required,
        Ok(VerificationResult::with_identity(identity)),
    ));
    let service = Arc::new(service(CapabilityEffect::Mutating)?);
    let store = Arc::new(MemoryDedupStore::new(StoreDurability::Persistent));
    let route = WebhookRoute::new(
        configuration(CapabilitySemantics::NonIdempotentMutation)?,
        verifier,
        context(service.clone(), store.clone()),
    )?;
    let method = Method::POST;
    let headers = request_headers();

    service
        .dispatch_mode
        .store(DISPATCH_POLICY_UNAVAILABLE, Ordering::SeqCst);
    let policy_failure = block_on(route.handle(
        request(&method, &headers, br#"{"value":1}"#),
        WebhookIngressTime::new(5_000, 5_000),
    ));
    assert_eq!(policy_failure.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(store.state(&key), None);

    service
        .dispatch_mode
        .store(DISPATCH_AUDIT_UNAVAILABLE, Ordering::SeqCst);
    let audit_failure = block_on(route.handle(
        request(&method, &headers, br#"{"value":1}"#),
        WebhookIngressTime::new(5_001, 5_001),
    ));
    assert_eq!(audit_failure.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(store.state(&key), Some(DedupState::Unknown));

    service
        .dispatch_mode
        .store(DISPATCH_SUCCESS, Ordering::SeqCst);
    let duplicate = block_on(route.handle(
        request(&method, &headers, br#"{"value":1}"#),
        WebhookIngressTime::new(5_002, 5_002),
    ));
    assert_eq!(duplicate.status(), StatusCode::NO_CONTENT);
    assert_eq!(lock(&service.invocations).len(), 2);
    Ok(())
}

#[test]
fn fails_closed_with_a_distinct_dedup_capacity_category() -> Result<(), Box<dyn std::error::Error>>
{
    let verifier = Arc::new(verifier(
        IdentityGuarantee::Required,
        Ok(VerificationResult::with_identity(identity()?)),
    ));
    let service = Arc::new(service(CapabilityEffect::Mutating)?);
    let store = Arc::new(MemoryDedupStore::new(StoreDurability::Persistent));
    store.fail_claim_with(DedupStoreError::CapacityExhausted);
    let route = WebhookRoute::new(
        configuration(CapabilitySemantics::NonIdempotentMutation)?,
        verifier,
        context(service.clone(), store),
    )?;
    let method = Method::POST;
    let headers = request_headers();

    let response = block_on(route.handle(
        request(&method, &headers, br#"{"value":1}"#),
        WebhookIngressTime::new(6_000, 6_000),
    ));

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.error_code(), Some("dedup_capacity"));
    assert!(lock(&service.invocations).is_empty());
    Ok(())
}

fn verifier(
    guarantee: IdentityGuarantee,
    result: Result<VerificationResult, VerificationError>,
) -> TestVerifier {
    let signature = HeaderName::from_static("x-signature");
    TestVerifier {
        selected: Arc::from([signature.clone()]),
        credentials: Arc::from([signature]),
        guarantee,
        result,
    }
}

fn service(effect: CapabilityEffect) -> Result<TestService, Box<dyn std::error::Error>> {
    Ok(TestService {
        descriptor: CapabilityDescriptor::new(
            CapabilityId::new("device.actuate")?,
            "Actuate device",
            effect,
        )?,
        dispatch_mode: AtomicU8::new(DISPATCH_SUCCESS),
        invocations: Mutex::new(Vec::new()),
    })
}

fn context(service: Arc<TestService>, store: Arc<MemoryDedupStore>) -> Arc<WebhookIngressContext> {
    let service: Arc<dyn AutomationService> = service;
    let store: Arc<dyn DedupStore> = store;
    Arc::new(WebhookIngressContext::with_dependencies(
        service,
        store,
        Arc::new(FixedInvocationIds),
        Arc::new(AuthenticatedRequestLimiter::default()),
    ))
}

fn configuration(
    semantics: CapabilitySemantics,
) -> Result<WebhookRouteConfiguration, Box<dyn std::error::Error>> {
    Ok(WebhookRouteConfiguration::new(
        RouteId::new("device_hook")?,
        Principal::new(
            PrincipalId::new("trusted_sender")?,
            PrincipalKind::Application,
        ),
        CapabilityId::new("device.actuate")?,
        semantics,
    ))
}

fn identity() -> Result<TrustedDeliveryIdentity, Box<dyn std::error::Error>> {
    Ok(TrustedDeliveryIdentity::from_normalized(
        VerifierNamespace::new("test:v1")?,
        b"delivery-1",
        None,
    )?)
}

fn dedup_key(identity: &TrustedDeliveryIdentity) -> Result<DedupKey, Box<dyn std::error::Error>> {
    Ok(DedupKey::new(
        RouteId::new("device_hook")?,
        identity.namespace().clone(),
        *identity.hash(),
    ))
}

fn request_headers<'a>() -> [VerificationHeader<'a>; 2] {
    [
        VerificationHeader::new(header::CONTENT_TYPE, b"application/json"),
        VerificationHeader::new(HeaderName::from_static("x-signature"), b"valid"),
    ]
}

fn request<'a>(
    method: &'a Method,
    headers: &'a [VerificationHeader<'a>],
    body: &'a [u8],
) -> VerificationRequest<'a> {
    VerificationRequest::new(
        method,
        "/hooks/device",
        headers,
        body,
        PeerAddress::v4([127, 0, 0, 1], 1234),
    )
}

fn transition(
    records: &Mutex<HashMap<DedupKey, DedupState>>,
    key: &DedupKey,
    next: DedupState,
) -> Result<(), DedupStoreError> {
    let mut records = lock(records);
    if records.get(key) != Some(&DedupState::InFlight) {
        return Err(DedupStoreError::InvalidTransition);
    }
    records.insert(key.clone(), next);
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        std::thread::yield_now();
    }
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}
