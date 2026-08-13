#![allow(missing_docs)]

use std::{
    collections::HashSet,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use bondry_core::{
    AdapterId, AuditError, AuditEvent, AuditOutcome, AuditSink, CapabilityDescriptor,
    CapabilityEffect, CapabilityGrant, CapabilityId, CapabilityRegistry, DenialReason,
    DenyAllPolicy, DispatchError, Dispatcher, GrantPolicy, GrantStore, GrantStoreError,
    HandlerError, HandlerErrorCode, Invocation, InvocationContext, InvocationId, Principal,
    PrincipalId, PrincipalKind, RegistrationError, StoredGrantPolicy,
};
use futures::executor::block_on;
use serde_json::{Value, json};

#[derive(Default)]
struct CollectingAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl CollectingAuditSink {
    fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().map_or_else(
            |poisoned| poisoned.into_inner().clone(),
            |events| events.clone(),
        )
    }
}

impl AuditSink for CollectingAuditSink {
    fn record(&self, event: AuditEvent) -> Result<(), AuditError> {
        let mut events = match self.events.lock() {
            Ok(events) => events,
            Err(poisoned) => poisoned.into_inner(),
        };
        events.push(event);
        Ok(())
    }
}

struct FailingAuditSink;

impl AuditSink for FailingAuditSink {
    fn record(&self, _event: AuditEvent) -> Result<(), AuditError> {
        Err(AuditError::Unavailable)
    }
}

#[derive(Default)]
struct MemoryGrantStore {
    grants: RwLock<HashSet<CapabilityGrant>>,
    unavailable: AtomicBool,
}

impl GrantStore for MemoryGrantStore {
    fn add_grant(&self, grant: CapabilityGrant) -> Result<bool, GrantStoreError> {
        self.grants
            .write()
            .map_err(|_| GrantStoreError::Unavailable)
            .map(|mut grants| grants.insert(grant))
    }

    fn remove_grant(&self, grant: &CapabilityGrant) -> Result<bool, GrantStoreError> {
        self.grants
            .write()
            .map_err(|_| GrantStoreError::Unavailable)
            .map(|mut grants| grants.remove(grant))
    }

    fn contains_grant(&self, grant: &CapabilityGrant) -> Result<bool, GrantStoreError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(GrantStoreError::Unavailable);
        }
        self.grants
            .read()
            .map_err(|_| GrantStoreError::Unavailable)
            .map(|grants| grants.contains(grant))
    }

    fn grants_for_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<CapabilityGrant>, GrantStoreError> {
        let mut grants = self
            .grants
            .read()
            .map_err(|_| GrantStoreError::Unavailable)?
            .iter()
            .filter(|grant| grant.principal() == principal)
            .cloned()
            .collect::<Vec<_>>();
        grants.sort_unstable_by(|left, right| {
            left.adapter()
                .cmp(right.adapter())
                .then_with(|| left.capability().cmp(right.capability()))
        });
        Ok(grants)
    }
}

fn capability_id() -> Result<CapabilityId, Box<dyn std::error::Error>> {
    Ok(CapabilityId::new("battery.snapshot")?)
}

fn descriptor() -> Result<CapabilityDescriptor, Box<dyn std::error::Error>> {
    Ok(CapabilityDescriptor::new(
        capability_id()?,
        "Read the current battery snapshot",
        CapabilityEffect::ReadOnly,
    )?)
}

#[test]
fn capability_summaries_reject_empty_oversized_and_control_text()
-> Result<(), Box<dyn std::error::Error>> {
    let id = capability_id()?;
    assert!(CapabilityDescriptor::new(id.clone(), "  ", CapabilityEffect::ReadOnly).is_err());
    assert!(
        CapabilityDescriptor::new(id.clone(), "x".repeat(257), CapabilityEffect::ReadOnly).is_err()
    );
    assert!(CapabilityDescriptor::new(id, "Read\nstate", CapabilityEffect::ReadOnly).is_err());
    Ok(())
}

fn adapter_id() -> Result<AdapterId, Box<dyn std::error::Error>> {
    Ok(AdapterId::new("mcp")?)
}

fn principal_id() -> Result<PrincipalId, Box<dyn std::error::Error>> {
    Ok(PrincipalId::new("client.test")?)
}

fn invocation(input: Value) -> Result<Invocation, Box<dyn std::error::Error>> {
    Ok(Invocation::new(
        InvocationId::new("request-1")?,
        adapter_id()?,
        Principal::new(principal_id()?, PrincipalKind::Application),
        capability_id()?,
        input,
    ))
}

#[test]
fn rejects_invalid_identifiers_during_deserialization() {
    let result = serde_json::from_str::<CapabilityId>("\"battery snapshot\"");
    assert!(result.is_err());
}

#[test]
fn rejects_duplicate_capability_registration() -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = CapabilityRegistry::new();
    registry.register(descriptor()?, |_, _| async { Ok(Value::Null) })?;
    let result = registry.register(descriptor()?, |_, _| async { Ok(Value::Null) });

    assert_eq!(result, Err(RegistrationError::Duplicate(capability_id()?)));
    Ok(())
}

#[test]
fn denies_by_default_without_executing_handler() -> Result<(), Box<dyn std::error::Error>> {
    let executions = Arc::new(AtomicUsize::new(0));
    let handler_executions = Arc::clone(&executions);
    let mut registry = CapabilityRegistry::new();
    registry.register(descriptor()?, move |_, _| {
        let executions = Arc::clone(&handler_executions);
        async move {
            executions.fetch_add(1, Ordering::Relaxed);
            Ok(Value::Null)
        }
    })?;
    let audit = Arc::new(CollectingAuditSink::default());
    let dispatcher = Dispatcher::from_shared(registry, Arc::new(DenyAllPolicy), audit.clone());

    let result =
        block_on(dispatcher.dispatch(invocation(json!({ "secret": "not-a-real-secret" }))?));

    assert_eq!(
        result,
        Err(DispatchError::AccessDenied(DenialReason::NotGranted))
    );
    assert_eq!(executions.load(Ordering::Relaxed), 0);
    let events = audit.events();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].outcome(),
        &AuditOutcome::Denied(DenialReason::NotGranted)
    );
    Ok(())
}

#[test]
fn executes_only_an_exact_grant() -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = CapabilityRegistry::new();
    registry.register(
        descriptor()?,
        |context: InvocationContext, input: Value| async move {
            Ok(json!({
                "adapter": context.adapter().as_str(),
                "input": input,
            }))
        },
    )?;
    let policy = GrantPolicy::new();
    assert!(policy.grant(principal_id()?, adapter_id()?, capability_id()?)?);
    let audit = Arc::new(CollectingAuditSink::default());
    let dispatcher = Dispatcher::from_shared(registry, Arc::new(policy), audit.clone());

    let output = block_on(dispatcher.dispatch(invocation(json!({ "includeHealth": true }))?))?;

    assert_eq!(
        output,
        json!({ "adapter": "mcp", "input": { "includeHealth": true } })
    );
    assert_eq!(
        audit
            .events()
            .iter()
            .map(AuditEvent::outcome)
            .collect::<Vec<_>>(),
        vec![&AuditOutcome::Started, &AuditOutcome::Succeeded]
    );
    Ok(())
}

#[test]
fn applies_policy_revocation_immediately() -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = CapabilityRegistry::new();
    registry.register(descriptor()?, |_, _| async { Ok(Value::Null) })?;
    let policy = Arc::new(GrantPolicy::new());
    assert!(policy.grant(principal_id()?, adapter_id()?, capability_id()?)?);
    let dispatcher = Dispatcher::from_shared(
        registry,
        policy.clone(),
        Arc::new(CollectingAuditSink::default()),
    );

    assert!(block_on(dispatcher.dispatch(invocation(Value::Null)?)).is_ok());
    assert!(policy.revoke(&principal_id()?, &adapter_id()?, &capability_id()?)?);
    assert_eq!(
        block_on(dispatcher.dispatch(invocation(Value::Null)?)),
        Err(DispatchError::AccessDenied(DenialReason::NotGranted))
    );
    Ok(())
}

#[test]
fn stored_policy_tracks_durable_grants_and_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let mut registry = CapabilityRegistry::new();
    registry.register(descriptor()?, |_, _| async { Ok(Value::Null) })?;
    let store = Arc::new(MemoryGrantStore::default());
    let grant = CapabilityGrant::new(principal_id()?, adapter_id()?, capability_id()?);
    assert!(store.add_grant(grant.clone())?);
    let policy_store: Arc<dyn GrantStore> = store.clone();
    let dispatcher = Dispatcher::from_shared(
        registry,
        Arc::new(StoredGrantPolicy::from_shared(policy_store)),
        Arc::new(CollectingAuditSink::default()),
    );

    assert!(block_on(dispatcher.dispatch(invocation(Value::Null)?)).is_ok());
    assert!(store.remove_grant(&grant)?);
    assert_eq!(
        block_on(dispatcher.dispatch(invocation(Value::Null)?)),
        Err(DispatchError::AccessDenied(DenialReason::NotGranted))
    );
    store.unavailable.store(true, Ordering::SeqCst);
    assert_eq!(
        block_on(dispatcher.dispatch(invocation(Value::Null)?)),
        Err(DispatchError::AccessDenied(DenialReason::PolicyUnavailable))
    );
    Ok(())
}

#[test]
fn rejects_a_grant_from_another_adapter() -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = CapabilityRegistry::new();
    registry.register(descriptor()?, |_, _| async { Ok(Value::Null) })?;
    let policy = GrantPolicy::new();
    assert!(policy.grant(principal_id()?, AdapterId::new("rest")?, capability_id()?)?);
    let dispatcher = Dispatcher::new(registry, policy, CollectingAuditSink::default());

    let result = block_on(dispatcher.dispatch(invocation(Value::Null)?));

    assert_eq!(
        result,
        Err(DispatchError::AccessDenied(DenialReason::NotGranted))
    );
    Ok(())
}

#[test]
fn prevents_execution_when_required_audit_is_unavailable() -> Result<(), Box<dyn std::error::Error>>
{
    let executions = Arc::new(AtomicUsize::new(0));
    let handler_executions = Arc::clone(&executions);
    let mut registry = CapabilityRegistry::new();
    registry.register(descriptor()?, move |_, _| {
        let executions = Arc::clone(&handler_executions);
        async move {
            executions.fetch_add(1, Ordering::Relaxed);
            Ok(Value::Null)
        }
    })?;
    let policy = GrantPolicy::new();
    assert!(policy.grant(principal_id()?, adapter_id()?, capability_id()?)?);
    let dispatcher = Dispatcher::new(registry, policy, FailingAuditSink);

    assert_eq!(
        block_on(dispatcher.dispatch(invocation(Value::Null)?)),
        Err(DispatchError::Audit(AuditError::Unavailable))
    );
    assert_eq!(executions.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn audits_handler_error_codes_without_payloads() -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = CapabilityRegistry::new();
    let error_code = HandlerErrorCode::new("battery.unavailable")?;
    let handler_error_code = error_code.clone();
    registry.register(descriptor()?, move |_, _| {
        let code = handler_error_code.clone();
        async move { Err(HandlerError::new(code)) }
    })?;
    let policy = GrantPolicy::new();
    assert!(policy.grant(principal_id()?, adapter_id()?, capability_id()?)?);
    let audit = Arc::new(CollectingAuditSink::default());
    let dispatcher = Dispatcher::from_shared(registry, Arc::new(policy), audit.clone());

    let result = block_on(dispatcher.dispatch(invocation(json!({ "private": "payload" }))?));

    assert_eq!(
        result,
        Err(DispatchError::Handler(HandlerError::new(
            error_code.clone()
        )))
    );
    assert_eq!(
        audit.events()[1].outcome(),
        &AuditOutcome::HandlerFailed(error_code)
    );
    Ok(())
}

#[test]
fn audits_unknown_capabilities() -> Result<(), Box<dyn std::error::Error>> {
    let audit = Arc::new(CollectingAuditSink::default());
    let dispatcher = Dispatcher::from_shared(
        CapabilityRegistry::new(),
        Arc::new(DenyAllPolicy),
        audit.clone(),
    );

    let result = block_on(dispatcher.dispatch(invocation(Value::Null)?));

    assert_eq!(
        result,
        Err(DispatchError::CapabilityNotFound(capability_id()?))
    );
    assert_eq!(
        audit.events()[0].outcome(),
        &AuditOutcome::CapabilityNotFound
    );
    Ok(())
}
