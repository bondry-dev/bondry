use http::HeaderName;
use thiserror::Error;

use crate::{IdentityGuarantee, TrustedDeliveryIdentity, VerificationRequest};

/// Safe output produced only after route-specific credential verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationResult {
    identity: Option<TrustedDeliveryIdentity>,
}

impl VerificationResult {
    /// Creates a verified result without a replay identity.
    #[must_use]
    pub const fn authenticated() -> Self {
        Self { identity: None }
    }

    /// Creates a verified result with verifier-trusted replay identity.
    #[must_use]
    pub const fn with_identity(identity: TrustedDeliveryIdentity) -> Self {
        Self {
            identity: Some(identity),
        }
    }

    /// Returns the verifier-trusted delivery identity when present.
    #[must_use]
    pub const fn identity(&self) -> Option<&TrustedDeliveryIdentity> {
        self.identity.as_ref()
    }
}

/// Route-specific bounded credential verification.
pub trait WebhookVerifier: Send + Sync {
    /// Returns every header the raw-body server must select.
    fn selected_headers(&self) -> &[HeaderName];

    /// Returns the selected headers that contain credentials and must never enter payload mapping.
    fn credential_headers(&self) -> &[HeaderName];

    /// Declares whether successful verification guarantees a trusted delivery identity.
    fn identity_guarantee(&self) -> IdentityGuarantee;

    /// Verifies exact request bytes against trusted time and configured secret material.
    fn verify(
        &self,
        request: VerificationRequest<'_>,
        now_unix_seconds: i64,
    ) -> Result<VerificationResult, VerificationError>;
}

/// Stable verification failure categories that reveal no credential detail.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VerificationError {
    /// Credentials, signature material, freshness, or provider contract was rejected.
    #[error("webhook verification rejected the request")]
    Rejected,
    /// Trusted secret, clock, or verifier state was unavailable.
    #[error("webhook verification is unavailable")]
    Unavailable,
}
