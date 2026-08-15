use std::{collections::HashSet, sync::Arc};

use bondry_core::{
    AdapterId, AutomationService, CapabilityEffect, CapabilityId, DenialReason, DispatchError,
    Invocation, InvocationIdGenerator, Principal, SystemInvocationIdGenerator,
};
use bondry_delivery_store::{
    DedupClaim, DedupKey, DedupState, DedupStore, DedupStoreError, RouteId, StoreDurability,
};
use bondry_webhook_verify::{
    IdentityGuarantee, VerificationError, VerificationRequest, WebhookVerifier,
};
use http::{HeaderName, Method, StatusCode, header};
use thiserror::Error;

use crate::{
    AuthenticatedRequestLimiter, WebhookIngressLimits, WebhookIngressResponse,
    limiter::AuthenticatedAdmission, payload,
};

const MAX_SELECTED_HEADERS: usize = 32;

/// Trusted capability behavior used to enforce replay-storage requirements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilitySemantics {
    /// The capability has no observable mutation.
    ReadOnly,
    /// Repeating the same mutation is explicitly safe.
    IdempotentMutation,
    /// Repeating the same mutation may cause harm.
    NonIdempotentMutation,
}

/// Mapping from a verified raw body into fixed capability input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PayloadMapping {
    /// Parse the body as the complete JSON capability input.
    JsonBody,
    /// Wrap parsed JSON and allowlisted non-credential metadata.
    Envelope {
        /// Non-credential selected headers copied as arrays of UTF-8 strings.
        metadata_headers: Arc<[HeaderName]>,
    },
}

impl PayloadMapping {
    /// Creates envelope mapping from unique normalized metadata headers.
    pub fn envelope(
        metadata_headers: impl IntoIterator<Item = HeaderName>,
    ) -> Result<Self, WebhookRouteError> {
        let metadata_headers = metadata_headers.into_iter().collect::<Vec<_>>();
        if metadata_headers.len() > MAX_SELECTED_HEADERS {
            return Err(WebhookRouteError::TooManySelectedHeaders);
        }
        let mut unique = HashSet::with_capacity(metadata_headers.len());
        if metadata_headers
            .iter()
            .any(|header| !unique.insert(header.clone()))
        {
            return Err(WebhookRouteError::DuplicateSelectedHeader);
        }
        Ok(Self::Envelope {
            metadata_headers: metadata_headers.into(),
        })
    }

    fn metadata_headers(&self) -> &[HeaderName] {
        match self {
            Self::JsonBody => &[],
            Self::Envelope { metadata_headers } => metadata_headers,
        }
    }
}

/// Immutable trusted configuration for one webhook route.
pub struct WebhookRouteConfiguration {
    id: RouteId,
    principal: Principal,
    capability: CapabilityId,
    semantics: CapabilitySemantics,
    mapping: PayloadMapping,
    success_status: StatusCode,
    limits: WebhookIngressLimits,
}

impl WebhookRouteConfiguration {
    /// Creates a fixed JSON-body route with a 204 success response.
    #[must_use]
    pub fn new(
        id: RouteId,
        principal: Principal,
        capability: CapabilityId,
        semantics: CapabilitySemantics,
    ) -> Self {
        Self {
            id,
            principal,
            capability,
            semantics,
            mapping: PayloadMapping::JsonBody,
            success_status: StatusCode::NO_CONTENT,
            limits: WebhookIngressLimits::default(),
        }
    }

    /// Replaces payload mapping.
    #[must_use]
    pub fn with_mapping(mut self, mapping: PayloadMapping) -> Self {
        self.mapping = mapping;
        self
    }

    /// Replaces the successful 2xx status.
    pub fn with_success_status(mut self, status: StatusCode) -> Result<Self, WebhookRouteError> {
        if !status.is_success() {
            return Err(WebhookRouteError::InvalidSuccessStatus);
        }
        self.success_status = status;
        Ok(self)
    }

    /// Replaces raw-body and retained-memory limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: WebhookIngressLimits) -> Self {
        self.limits = limits;
        self
    }
}

/// Shared server-owned dependencies used by all route generations.
pub struct WebhookIngressContext {
    service: Arc<dyn AutomationService>,
    store: Arc<dyn DedupStore>,
    invocation_ids: Arc<dyn InvocationIdGenerator>,
    limiter: Arc<AuthenticatedRequestLimiter>,
}

impl WebhookIngressContext {
    /// Creates shared ingress dependencies with the standard authenticated rate.
    #[must_use]
    pub fn new(service: Arc<dyn AutomationService>, store: Arc<dyn DedupStore>) -> Self {
        Self {
            service,
            store,
            invocation_ids: Arc::new(SystemInvocationIdGenerator),
            limiter: Arc::new(AuthenticatedRequestLimiter::default()),
        }
    }

    /// Creates shared ingress dependencies with explicit deterministic host services.
    #[must_use]
    pub fn with_dependencies(
        service: Arc<dyn AutomationService>,
        store: Arc<dyn DedupStore>,
        invocation_ids: Arc<dyn InvocationIdGenerator>,
        limiter: Arc<AuthenticatedRequestLimiter>,
    ) -> Self {
        Self {
            service,
            store,
            invocation_ids,
            limiter,
        }
    }
}

/// Explicit trusted wall and monotonic time for one delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebhookIngressTime {
    unix_milliseconds: u64,
    monotonic_milliseconds: u64,
}

impl WebhookIngressTime {
    /// Creates one request-time snapshot.
    #[must_use]
    pub const fn new(unix_milliseconds: u64, monotonic_milliseconds: u64) -> Self {
        Self {
            unix_milliseconds,
            monotonic_milliseconds,
        }
    }
}

/// One verified route-to-capability adapter.
pub struct WebhookRoute {
    configuration: WebhookRouteConfiguration,
    verifier: Arc<dyn WebhookVerifier>,
    context: Arc<WebhookIngressContext>,
    adapter: AdapterId,
    selected_headers: Arc<[HeaderName]>,
}

impl WebhookRoute {
    /// Validates one fixed route against its verifier, grant, capability, and store.
    pub fn new(
        configuration: WebhookRouteConfiguration,
        verifier: Arc<dyn WebhookVerifier>,
        context: Arc<WebhookIngressContext>,
    ) -> Result<Self, WebhookRouteError> {
        let adapter = AdapterId::new("webhook").map_err(|_| WebhookRouteError::InvalidAdapter)?;
        let capabilities = context
            .service
            .capabilities(&configuration.principal, &adapter)
            .map_err(|_| WebhookRouteError::PolicyUnavailable)?;
        let effect = capabilities
            .iter()
            .find(|descriptor| descriptor.id() == &configuration.capability)
            .map(|descriptor| descriptor.effect())
            .ok_or(WebhookRouteError::CapabilityUnavailable)?;
        validate_semantics(configuration.semantics, effect)?;
        if configuration.semantics == CapabilitySemantics::NonIdempotentMutation {
            if verifier.identity_guarantee() != IdentityGuarantee::Required {
                return Err(WebhookRouteError::TrustedIdentityRequired);
            }
            if context.store.durability() != StoreDurability::Persistent {
                return Err(WebhookRouteError::PersistentStoreRequired);
            }
        }
        let selected_headers = selected_headers(&configuration.mapping, verifier.as_ref())?;
        Ok(Self {
            configuration,
            verifier,
            context,
            adapter,
            selected_headers: selected_headers.into(),
        })
    }

    /// Returns the stable route identifier.
    #[must_use]
    pub const fn id(&self) -> &RouteId {
        &self.configuration.id
    }

    /// Returns the normalized headers required by verification and mapping.
    #[must_use]
    pub fn selected_headers(&self) -> &[HeaderName] {
        &self.selected_headers
    }

    /// Verifies, rate-limits, deduplicates, and dispatches one bounded delivery.
    pub async fn handle(
        &self,
        request: VerificationRequest<'_>,
        now: WebhookIngressTime,
    ) -> WebhookIngressResponse {
        if request.method() != Method::POST {
            return WebhookIngressResponse::error(
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
            );
        }
        let Ok(now_unix_seconds) = i64::try_from(now.unix_milliseconds / 1_000) else {
            return retryable("clock_unavailable");
        };
        let verified = match self.verifier.verify(request, now_unix_seconds) {
            Ok(verified) => verified,
            Err(VerificationError::Rejected) => {
                return WebhookIngressResponse::error(
                    StatusCode::UNAUTHORIZED,
                    "authentication_rejected",
                );
            }
            Err(VerificationError::Unavailable) => return retryable("verification_unavailable"),
        };
        if self.verifier.identity_guarantee() == IdentityGuarantee::Required
            && verified.identity().is_none()
        {
            return retryable("verification_unavailable");
        }
        if self.verifier.identity_guarantee() == IdentityGuarantee::Never
            && verified.identity().is_some()
        {
            return retryable("verification_unavailable");
        }
        match self.context.limiter.admit(
            self.configuration.principal.id(),
            now.monotonic_milliseconds,
        ) {
            AuthenticatedAdmission::Allowed => {}
            AuthenticatedAdmission::Limited { retry_after } => {
                return WebhookIngressResponse::retryable(
                    StatusCode::TOO_MANY_REQUESTS,
                    "rate_limited",
                    retry_after,
                );
            }
        }
        if !payload::has_json_content_type(request, &header::CONTENT_TYPE) {
            return WebhookIngressResponse::error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
            );
        }
        let input = match payload::map_payload(
            &self.configuration.mapping,
            request,
            self.configuration.limits,
        ) {
            Ok(input) => input,
            Err(response) => return response,
        };
        let mut claim = match verified.identity() {
            Some(identity) => {
                let key = DedupKey::new(
                    self.configuration.id.clone(),
                    identity.namespace().clone(),
                    *identity.hash(),
                );
                match self.context.store.claim(key.clone(), now.unix_milliseconds) {
                    Ok(DedupClaim::Claimed) => Some(DedupGuard::new(
                        Arc::clone(&self.context.store),
                        key,
                        now.unix_milliseconds,
                    )),
                    Ok(DedupClaim::Duplicate(DedupState::InFlight)) => {
                        return WebhookIngressResponse::retryable(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "delivery_in_flight",
                            1,
                        );
                    }
                    Ok(DedupClaim::Duplicate(DedupState::Completed | DedupState::Unknown)) => {
                        return WebhookIngressResponse::success(self.configuration.success_status);
                    }
                    Err(DedupStoreError::CapacityExhausted) => {
                        return retryable("dedup_capacity");
                    }
                    Err(
                        DedupStoreError::NotFound
                        | DedupStoreError::InvalidTransition
                        | DedupStoreError::Unavailable,
                    ) => return retryable("dedup_store_unavailable"),
                }
            }
            None => None,
        };
        let id = match self.context.invocation_ids.generate() {
            Ok(id) => id,
            Err(_) => {
                if claim.as_mut().is_some_and(|claim| !claim.release()) {
                    return retryable("dedup_store_unavailable");
                }
                return retryable("identifier_generation_unavailable");
            }
        };
        let invocation = Invocation::new(
            id,
            self.adapter.clone(),
            self.configuration.principal.clone(),
            self.configuration.capability.clone(),
            input,
        );
        let result = self.context.service.dispatch(invocation).await;
        let persistence_succeeded = match (&result, &mut claim) {
            (Err(DispatchError::Audit(_)), Some(claim)) => claim.mark_unknown(),
            (Err(DispatchError::AccessDenied(DenialReason::PolicyUnavailable)), Some(claim)) => {
                claim.release()
            }
            (_, Some(claim)) => claim.complete(),
            (_, None) => true,
        };
        if !persistence_succeeded {
            return retryable("dedup_store_unavailable");
        }
        match result {
            Ok(_) => WebhookIngressResponse::success(self.configuration.success_status),
            Err(DispatchError::CapabilityNotFound(_))
            | Err(DispatchError::AccessDenied(DenialReason::NotGranted)) => {
                WebhookIngressResponse::error(StatusCode::NOT_FOUND, "route_unavailable")
            }
            Err(DispatchError::InvalidInput) => {
                WebhookIngressResponse::error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_input")
            }
            Err(DispatchError::Handler(_)) => {
                WebhookIngressResponse::error(StatusCode::UNPROCESSABLE_ENTITY, "capability_failed")
            }
            Err(DispatchError::AccessDenied(DenialReason::PolicyUnavailable)) => {
                retryable("policy_unavailable")
            }
            Err(DispatchError::Audit(_)) => retryable("audit_unavailable"),
        }
    }
}

fn selected_headers(
    mapping: &PayloadMapping,
    verifier: &dyn WebhookVerifier,
) -> Result<Vec<HeaderName>, WebhookRouteError> {
    let mut metadata = HashSet::with_capacity(mapping.metadata_headers().len());
    if mapping
        .metadata_headers()
        .iter()
        .any(|name| !metadata.insert(name.clone()))
    {
        return Err(WebhookRouteError::DuplicateSelectedHeader);
    }
    let mut selected = Vec::new();
    let mut unique = HashSet::new();
    for name in verifier
        .selected_headers()
        .iter()
        .chain(std::iter::once(&header::CONTENT_TYPE))
        .chain(mapping.metadata_headers())
    {
        if unique.insert(name.clone()) {
            selected.push(name.clone());
        }
    }
    if selected.len() > MAX_SELECTED_HEADERS {
        return Err(WebhookRouteError::TooManySelectedHeaders);
    }
    if verifier
        .credential_headers()
        .iter()
        .any(|credential| !verifier.selected_headers().contains(credential))
    {
        return Err(WebhookRouteError::CredentialHeaderNotSelected);
    }
    if mapping.metadata_headers().iter().any(|metadata| {
        verifier
            .credential_headers()
            .iter()
            .any(|credential| credential == metadata)
    }) {
        return Err(WebhookRouteError::CredentialMetadataOverlap);
    }
    Ok(selected)
}

fn validate_semantics(
    semantics: CapabilitySemantics,
    effect: CapabilityEffect,
) -> Result<(), WebhookRouteError> {
    match (semantics, effect) {
        (CapabilitySemantics::ReadOnly, CapabilityEffect::ReadOnly)
        | (
            CapabilitySemantics::IdempotentMutation | CapabilitySemantics::NonIdempotentMutation,
            CapabilityEffect::Mutating,
        ) => Ok(()),
        _ => Err(WebhookRouteError::CapabilityEffectMismatch),
    }
}

fn retryable(error_code: &'static str) -> WebhookIngressResponse {
    WebhookIngressResponse::retryable(StatusCode::SERVICE_UNAVAILABLE, error_code, 1)
}

struct DedupGuard {
    store: Arc<dyn DedupStore>,
    key: Option<DedupKey>,
    updated_at_unix_ms: u64,
}

impl DedupGuard {
    fn new(store: Arc<dyn DedupStore>, key: DedupKey, updated_at_unix_ms: u64) -> Self {
        Self {
            store,
            key: Some(key),
            updated_at_unix_ms,
        }
    }

    fn complete(&mut self) -> bool {
        let Some(key) = self.key.as_ref() else {
            return true;
        };
        if self.store.complete(key, self.updated_at_unix_ms).is_err() {
            return false;
        }
        self.key = None;
        true
    }

    fn mark_unknown(&mut self) -> bool {
        let Some(key) = self.key.as_ref() else {
            return true;
        };
        if self
            .store
            .mark_unknown(key, self.updated_at_unix_ms)
            .is_err()
        {
            return false;
        }
        self.key = None;
        true
    }

    fn release(&mut self) -> bool {
        let Some(key) = self.key.as_ref() else {
            return true;
        };
        if self.store.release_claim(key).is_err() {
            return false;
        }
        self.key = None;
        true
    }
}

impl Drop for DedupGuard {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            let _ = self.store.mark_unknown(&key, self.updated_at_unix_ms);
        }
    }
}

/// A route configuration that could weaken fixed routing or replay protection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WebhookRouteError {
    /// The fixed webhook adapter identifier could not be constructed.
    #[error("the webhook adapter identifier is invalid")]
    InvalidAdapter,
    /// Capability or grant discovery was unavailable.
    #[error("route policy is unavailable")]
    PolicyUnavailable,
    /// The fixed capability is absent or not granted to the fixed principal.
    #[error("the fixed capability or webhook grant is unavailable")]
    CapabilityUnavailable,
    /// Configured semantics disagree with the registered capability effect.
    #[error("configured capability semantics do not match its effect")]
    CapabilityEffectMismatch,
    /// A non-idempotent mutation requires an identity on every verified request.
    #[error("a trusted delivery identity is required")]
    TrustedIdentityRequired,
    /// A non-idempotent mutation requires restart-surviving replay state.
    #[error("a persistent deduplication store is required")]
    PersistentStoreRequired,
    /// More than 32 unique headers would cross the server seam.
    #[error("too many selected webhook headers")]
    TooManySelectedHeaders,
    /// Metadata mapping contains the same header more than once.
    #[error("duplicate selected webhook header")]
    DuplicateSelectedHeader,
    /// A credential-bearing header was not selected by its verifier.
    #[error("a credential header is absent from verifier selection")]
    CredentialHeaderNotSelected,
    /// Credential material cannot be copied into capability input.
    #[error("a credential header overlaps payload metadata")]
    CredentialMetadataOverlap,
    /// Successful webhook responses must use a 2xx status.
    #[error("webhook success status must be 2xx")]
    InvalidSuccessStatus,
}
