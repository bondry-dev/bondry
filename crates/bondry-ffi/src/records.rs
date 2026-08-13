use std::{
    ptr, slice,
    sync::atomic::{Ordering, compiler_fence},
};

use bondry_auth::{Client, IssuedToken, TokenMetadata};
use bondry_core::{AuditOutcome, Principal};
use bondry_store_sqlcipher::StoredAuditEvent;

pub const BONDRY_IDENTIFIER_CAPACITY_V1: usize = 129;
pub const BONDRY_LABEL_CAPACITY_V1: usize = 129;
pub const BONDRY_TOKEN_CAPACITY_V1: usize = 100;
pub const BONDRY_AUDIT_DETAIL_CAPACITY_V1: usize = 129;

pub const BONDRY_AUDIT_OUTCOME_CAPABILITY_NOT_FOUND_V1: u32 = 1;
pub const BONDRY_AUDIT_OUTCOME_DENIED_V1: u32 = 2;
pub const BONDRY_AUDIT_OUTCOME_STARTED_V1: u32 = 3;
pub const BONDRY_AUDIT_OUTCOME_SUCCEEDED_V1: u32 = 4;
pub const BONDRY_AUDIT_OUTCOME_HANDLER_FAILED_V1: u32 = 5;

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

impl BondryClientV1 {
    pub(crate) fn from_client(client: &Client) -> Self {
        Self {
            id: terminated(client.id().as_str()),
            name: terminated(client.name().as_str()),
            enabled: u8::from(client.is_enabled()),
            created_at_unix_seconds: client.created_at_unix_seconds(),
        }
    }
}

impl BondryTokenMetadataV1 {
    pub(crate) fn from_metadata(metadata: &TokenMetadata) -> Self {
        let (label, has_label) = optional_terminated(metadata.label().map(|value| value.as_str()));
        let (expires_at_unix_seconds, has_expiration) =
            optional_i64(metadata.expires_at_unix_seconds());
        let (revoked_at_unix_seconds, has_revocation) =
            optional_i64(metadata.revoked_at_unix_seconds());
        Self {
            id: terminated(metadata.id().as_str()),
            client_id: terminated(metadata.client().as_str()),
            label,
            has_label,
            created_at_unix_seconds: metadata.created_at_unix_seconds(),
            expires_at_unix_seconds,
            has_expiration,
            revoked_at_unix_seconds,
            has_revocation,
        }
    }
}

impl BondryIssuedTokenV1 {
    pub(crate) fn from_issued(issued: &IssuedToken) -> Self {
        Self {
            metadata: BondryTokenMetadataV1::from_metadata(issued.metadata()),
            secret: terminated(issued.secret().expose()),
        }
    }
}

impl BondryPrincipalV1 {
    pub(crate) fn from_principal(principal: &Principal) -> Self {
        Self {
            id: terminated(principal.id().as_str()),
            kind: match principal.kind() {
                bondry_core::PrincipalKind::User => 1,
                bondry_core::PrincipalKind::Application => 2,
                bondry_core::PrincipalKind::System => 3,
            },
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
            AuditOutcome::Succeeded => (BONDRY_AUDIT_OUTCOME_SUCCEEDED_V1, None),
            AuditOutcome::HandlerFailed(code) => {
                (BONDRY_AUDIT_OUTCOME_HANDLER_FAILED_V1, Some(code.as_str()))
            }
        };
        let (detail_code, has_detail_code) = optional_terminated(detail);
        Some(Self {
            sequence: event.sequence(),
            occurred_at_unix_milliseconds: milliseconds,
            invocation_id: terminated(event.event().invocation().as_str()),
            principal_id: terminated(event.event().principal().as_str()),
            adapter_id: terminated(event.event().adapter().as_str()),
            capability_id: terminated(event.event().capability().as_str()),
            outcome,
            detail_code,
            has_detail_code,
        })
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

fn terminated<const N: usize>(value: &str) -> [u8; N] {
    let bytes = value.as_bytes();
    debug_assert!(bytes.len() < N);
    let mut destination = [0_u8; N];
    destination[..bytes.len()].copy_from_slice(bytes);
    destination
}

fn optional_terminated<const N: usize>(value: Option<&str>) -> ([u8; N], u8) {
    value.map_or(([0_u8; N], 0), |value| (terminated(value), 1))
}

fn optional_i64(value: Option<i64>) -> (i64, u8) {
    value.map_or((0, 0), |value| (value, 1))
}
