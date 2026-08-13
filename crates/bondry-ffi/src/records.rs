use std::{
    ptr, slice,
    sync::atomic::{Ordering, compiler_fence},
};

use bondry_auth::{Client, IssuedToken, TokenMetadata};
use bondry_core::{
    AuditOutcome, CapabilityDescriptor, CapabilityEffect, CapabilityGrant, InvocationContext,
    Principal,
};
use bondry_store_sqlcipher::StoredAuditEvent;

pub const BONDRY_IDENTIFIER_CAPACITY_V1: usize = 129;
pub const BONDRY_LABEL_CAPACITY_V1: usize = 129;
pub const BONDRY_TOKEN_CAPACITY_V1: usize = 100;
pub const BONDRY_AUDIT_DETAIL_CAPACITY_V1: usize = 129;
pub const BONDRY_CAPABILITY_SUMMARY_CAPACITY_V1: usize = 257;

pub const BONDRY_AUDIT_OUTCOME_CAPABILITY_NOT_FOUND_V1: u32 = 1;
pub const BONDRY_AUDIT_OUTCOME_DENIED_V1: u32 = 2;
pub const BONDRY_AUDIT_OUTCOME_STARTED_V1: u32 = 3;
pub const BONDRY_AUDIT_OUTCOME_SUCCEEDED_V1: u32 = 4;
pub const BONDRY_AUDIT_OUTCOME_HANDLER_FAILED_V1: u32 = 5;
pub const BONDRY_AUDIT_OUTCOME_INVALID_INPUT_V1: u32 = 6;

pub const BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1: u32 = 1;
pub const BONDRY_CAPABILITY_EFFECT_MUTATING_V1: u32 = 2;

pub const BONDRY_HANDLER_RESULT_SUCCEEDED_V1: u32 = 1;
pub const BONDRY_HANDLER_RESULT_FAILED_V1: u32 = 2;

pub const BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1: u32 = 1;
pub const BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1: u32 = 2;
pub const BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1: u32 = 3;
pub const BONDRY_DISPATCH_OUTCOME_AUDIT_UNAVAILABLE_V1: u32 = 4;
pub const BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1: u32 = 5;
pub const BONDRY_DISPATCH_OUTCOME_INVALID_INPUT_V1: u32 = 6;

/// A fixed-capacity client record written into caller-owned memory.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryClientV1 {
    /// UTF-8 client identifier, terminated with zero.
    pub id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    /// UTF-8 display name, terminated with zero.
    pub name: [u8; BONDRY_LABEL_CAPACITY_V1],
    /// One when authentication is enabled; otherwise zero.
    pub enabled: u8,
    /// Unix timestamp in seconds.
    pub created_at_unix_seconds: i64,
}

/// Non-secret token metadata written into caller-owned memory.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryTokenMetadataV1 {
    /// UTF-8 token identifier, terminated with zero.
    pub id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    /// UTF-8 owning client identifier, terminated with zero.
    pub client_id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    /// UTF-8 administrative label, terminated with zero when present.
    pub label: [u8; BONDRY_LABEL_CAPACITY_V1],
    /// One when a label is present; otherwise zero.
    pub has_label: u8,
    /// Unix timestamp in seconds.
    pub created_at_unix_seconds: i64,
    /// Optional Unix expiration timestamp in seconds.
    pub expires_at_unix_seconds: i64,
    /// One when the expiration field is present; otherwise zero.
    pub has_expiration: u8,
    /// Optional Unix revocation timestamp in seconds.
    pub revoked_at_unix_seconds: i64,
    /// One when the revocation field is present; otherwise zero.
    pub has_revocation: u8,
}

/// A newly issued token and its one-time secret.
#[repr(C)]
pub struct BondryIssuedTokenV1 {
    /// Non-secret administrative metadata.
    pub metadata: BondryTokenMetadataV1,
    /// UTF-8 bearer token, terminated with zero.
    pub secret: [u8; BONDRY_TOKEN_CAPACITY_V1],
}

/// An authenticated principal returned without retaining a credential.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryPrincipalV1 {
    /// UTF-8 principal identifier, terminated with zero.
    pub id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    /// Stable principal-kind value.
    pub kind: u32,
}

/// An exact authorization grant written into caller-owned memory.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryGrantV1 {
    /// UTF-8 principal identifier, terminated with zero.
    pub principal_id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    /// UTF-8 adapter identifier, terminated with zero.
    pub adapter_id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    /// UTF-8 capability identifier, terminated with zero.
    pub capability_id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
}

/// Protocol-neutral audit metadata written into caller-owned memory.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryAuditEventV1 {
    /// Monotonically increasing database sequence.
    pub sequence: i64,
    /// Unix timestamp in milliseconds.
    pub occurred_at_unix_milliseconds: i64,
    /// UTF-8 invocation identifier, terminated with zero.
    pub invocation_id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    /// UTF-8 principal identifier, terminated with zero.
    pub principal_id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    /// UTF-8 adapter identifier, terminated with zero.
    pub adapter_id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    /// UTF-8 capability identifier, terminated with zero.
    pub capability_id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    /// Stable audit-outcome value.
    pub outcome: u32,
    /// Optional UTF-8 denial or handler error code, terminated with zero.
    pub detail_code: [u8; BONDRY_AUDIT_DETAIL_CAPACITY_V1],
    /// One when a detail code is present; otherwise zero.
    pub has_detail_code: u8,
}

/// Protocol-neutral capability metadata written into caller-owned memory.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct BondryCapabilityV1 {
    /// UTF-8 capability identifier, terminated with zero.
    pub id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    /// UTF-8 human-readable summary, terminated with zero.
    pub summary: [u8; BONDRY_CAPABILITY_SUMMARY_CAPACITY_V1],
    /// Stable capability-effect value.
    pub effect: u32,
}

/// Invocation data borrowed by a registered foreign handler.
#[repr(C)]
pub struct BondryInvocationV1 {
    /// UTF-8 invocation identifier, terminated with zero.
    pub invocation_id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    /// UTF-8 authenticated principal identifier, terminated with zero.
    pub principal_id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    /// Stable principal-kind value.
    pub principal_kind: u32,
    /// UTF-8 adapter identifier, terminated with zero.
    pub adapter_id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    /// UTF-8 capability identifier, terminated with zero.
    pub capability_id: [u8; BONDRY_IDENTIFIER_CAPACITY_V1],
    /// Serialized JSON input borrowed for the handler callback duration.
    pub input_json: *const u8,
    /// Length of the serialized JSON input.
    pub input_json_length: usize,
}

/// The result borrowed by a dispatch completion callback.
#[repr(C)]
pub struct BondryDispatchResultV1 {
    /// Stable dispatch-outcome value.
    pub outcome: u32,
    /// Serialized JSON output for a successful dispatch.
    pub output_json: *const u8,
    /// Length of the serialized JSON output.
    pub output_json_length: usize,
    /// Optional UTF-8 denial or handler error code, terminated with zero.
    pub detail_code: [u8; BONDRY_AUDIT_DETAIL_CAPACITY_V1],
    /// One when a detail code is present; otherwise zero.
    pub has_detail_code: u8,
}

impl BondryClientV1 {
    pub(crate) fn from_client(client: &Client) -> Self {
        let mut record = Self::zeroed();
        record.id = terminated(client.id().as_str());
        record.name = terminated(client.name().as_str());
        record.enabled = u8::from(client.is_enabled());
        record.created_at_unix_seconds = client.created_at_unix_seconds();
        record
    }

    fn zeroed() -> Self {
        // SAFETY: Every field accepts an all-zero bit pattern.
        unsafe { std::mem::zeroed() }
    }
}

impl BondryTokenMetadataV1 {
    pub(crate) fn from_metadata(metadata: &TokenMetadata) -> Self {
        let (label, has_label) = optional_terminated(metadata.label().map(|value| value.as_str()));
        let (expires_at_unix_seconds, has_expiration) =
            optional_i64(metadata.expires_at_unix_seconds());
        let (revoked_at_unix_seconds, has_revocation) =
            optional_i64(metadata.revoked_at_unix_seconds());
        let mut record = Self::zeroed();
        record.id = terminated(metadata.id().as_str());
        record.client_id = terminated(metadata.client().as_str());
        record.label = label;
        record.has_label = has_label;
        record.created_at_unix_seconds = metadata.created_at_unix_seconds();
        record.expires_at_unix_seconds = expires_at_unix_seconds;
        record.has_expiration = has_expiration;
        record.revoked_at_unix_seconds = revoked_at_unix_seconds;
        record.has_revocation = has_revocation;
        record
    }

    fn zeroed() -> Self {
        // SAFETY: Every field accepts an all-zero bit pattern.
        unsafe { std::mem::zeroed() }
    }
}

impl BondryIssuedTokenV1 {
    pub(crate) fn from_issued(issued: &IssuedToken) -> Self {
        let mut record = Self::zeroed();
        record.metadata = BondryTokenMetadataV1::from_metadata(issued.metadata());
        record.secret = terminated(issued.secret().expose());
        record
    }

    fn zeroed() -> Self {
        // SAFETY: Every field accepts an all-zero bit pattern.
        unsafe { std::mem::zeroed() }
    }
}

impl BondryPrincipalV1 {
    pub(crate) fn from_principal(principal: &Principal) -> Self {
        let mut record = Self::zeroed();
        record.id = terminated(principal.id().as_str());
        record.kind = match principal.kind() {
            bondry_core::PrincipalKind::User => 1,
            bondry_core::PrincipalKind::Application => 2,
            bondry_core::PrincipalKind::System => 3,
        };
        record
    }

    fn zeroed() -> Self {
        // SAFETY: Every field accepts an all-zero bit pattern.
        unsafe { std::mem::zeroed() }
    }
}

impl BondryGrantV1 {
    pub(crate) fn from_grant(grant: &CapabilityGrant) -> Self {
        Self {
            principal_id: terminated(grant.principal().as_str()),
            adapter_id: terminated(grant.adapter().as_str()),
            capability_id: terminated(grant.capability().as_str()),
        }
    }
}

impl BondryAuditEventV1 {
    pub(crate) fn try_from_stored(event: &StoredAuditEvent) -> Option<Self> {
        let milliseconds = event
            .event()
            .occurred_at()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_millis()).ok())?;
        let (outcome, detail) = match event.event().outcome() {
            AuditOutcome::CapabilityNotFound => {
                (BONDRY_AUDIT_OUTCOME_CAPABILITY_NOT_FOUND_V1, None)
            }
            AuditOutcome::Denied(bondry_core::DenialReason::NotGranted) => {
                (BONDRY_AUDIT_OUTCOME_DENIED_V1, Some("not_granted"))
            }
            AuditOutcome::Denied(bondry_core::DenialReason::PolicyUnavailable) => {
                (BONDRY_AUDIT_OUTCOME_DENIED_V1, Some("policy_unavailable"))
            }
            AuditOutcome::Started => (BONDRY_AUDIT_OUTCOME_STARTED_V1, None),
            AuditOutcome::InvalidInput => (BONDRY_AUDIT_OUTCOME_INVALID_INPUT_V1, None),
            AuditOutcome::Succeeded => (BONDRY_AUDIT_OUTCOME_SUCCEEDED_V1, None),
            AuditOutcome::HandlerFailed(code) => {
                (BONDRY_AUDIT_OUTCOME_HANDLER_FAILED_V1, Some(code.as_str()))
            }
        };
        let (detail_code, has_detail_code) = optional_terminated(detail);
        let mut record = Self::zeroed();
        record.sequence = event.sequence();
        record.occurred_at_unix_milliseconds = milliseconds;
        record.invocation_id = terminated(event.event().invocation().as_str());
        record.principal_id = terminated(event.event().principal().as_str());
        record.adapter_id = terminated(event.event().adapter().as_str());
        record.capability_id = terminated(event.event().capability().as_str());
        record.outcome = outcome;
        record.detail_code = detail_code;
        record.has_detail_code = has_detail_code;
        Some(record)
    }

    fn zeroed() -> Self {
        // SAFETY: Every field accepts an all-zero bit pattern.
        unsafe { std::mem::zeroed() }
    }
}

impl BondryCapabilityV1 {
    pub(crate) fn from_descriptor(descriptor: &CapabilityDescriptor) -> Self {
        let mut record = Self::zeroed();
        record.id = terminated(descriptor.id().as_str());
        record.summary = terminated(descriptor.summary());
        record.effect = match descriptor.effect() {
            CapabilityEffect::ReadOnly => BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1,
            CapabilityEffect::Mutating => BONDRY_CAPABILITY_EFFECT_MUTATING_V1,
        };
        record
    }

    fn zeroed() -> Self {
        // SAFETY: Every field accepts an all-zero bit pattern.
        unsafe { std::mem::zeroed() }
    }
}

impl BondryInvocationV1 {
    pub(crate) fn new(context: &InvocationContext, input_json: &[u8]) -> Self {
        let mut record = Self::zeroed();
        record.invocation_id = terminated(context.id().as_str());
        record.principal_id = terminated(context.principal().id().as_str());
        record.principal_kind = match context.principal().kind() {
            bondry_core::PrincipalKind::User => 1,
            bondry_core::PrincipalKind::Application => 2,
            bondry_core::PrincipalKind::System => 3,
        };
        record.adapter_id = terminated(context.adapter().as_str());
        record.capability_id = terminated(context.capability().as_str());
        record.input_json = input_json.as_ptr();
        record.input_json_length = input_json.len();
        record
    }

    fn zeroed() -> Self {
        // SAFETY: Every field accepts an all-zero bit pattern.
        unsafe { std::mem::zeroed() }
    }
}

impl BondryDispatchResultV1 {
    pub(crate) fn zeroed() -> Self {
        // SAFETY: Every field accepts an all-zero bit pattern.
        unsafe { std::mem::zeroed() }
    }
}

pub(crate) unsafe fn clear_issued_token(token: *mut BondryIssuedTokenV1) {
    // SAFETY: The caller guarantees the complete record is writable.
    let bytes = unsafe {
        slice::from_raw_parts_mut(
            token.cast::<u8>(),
            std::mem::size_of::<BondryIssuedTokenV1>(),
        )
    };
    for byte in bytes {
        // SAFETY: Each byte belongs to the writable record above.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

pub(crate) fn terminated<const N: usize>(value: &str) -> [u8; N] {
    let bytes = value.as_bytes();
    debug_assert!(bytes.len() < N);
    let mut destination = [0_u8; N];
    destination[..bytes.len()].copy_from_slice(bytes);
    destination
}

pub(crate) fn optional_terminated<const N: usize>(value: Option<&str>) -> ([u8; N], u8) {
    value.map_or(([0_u8; N], 0), |value| (terminated(value), 1))
}

fn optional_i64(value: Option<i64>) -> (i64, u8) {
    value.map_or((0, 0), |value| (value, 1))
}
