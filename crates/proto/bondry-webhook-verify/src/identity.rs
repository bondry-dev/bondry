use std::time::Duration;

use bondry_delivery_store::{TrustedDeliveryIdHash, VerifierNamespace};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MIN_FRESHNESS_TOLERANCE: Duration = Duration::from_secs(30);
const MAX_FRESHNESS_TOLERANCE: Duration = Duration::from_secs(15 * 60);

/// Whether every successfully verified request carries a trusted delivery identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityGuarantee {
    /// The verifier never produces a trusted identity.
    Never,
    /// Some valid requests produce an identity.
    Optional,
    /// Every valid request produces an identity.
    Required,
}

/// Signed freshness evidence that independently rejects old deliveries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedFreshness {
    signed_at_unix_seconds: i64,
    tolerance: Duration,
}

impl VerifiedFreshness {
    /// Creates bounded verifier-confirmed timestamp evidence.
    pub fn new(
        signed_at_unix_seconds: i64,
        tolerance: Duration,
    ) -> Result<Self, VerifiedFreshnessError> {
        if !(MIN_FRESHNESS_TOLERANCE..=MAX_FRESHNESS_TOLERANCE).contains(&tolerance) {
            return Err(VerifiedFreshnessError);
        }
        Ok(Self {
            signed_at_unix_seconds,
            tolerance,
        })
    }

    /// Returns the signed Unix timestamp.
    #[must_use]
    pub const fn signed_at_unix_seconds(self) -> i64 {
        self.signed_at_unix_seconds
    }

    /// Returns the accepted past and future skew.
    #[must_use]
    pub const fn tolerance(self) -> Duration {
        self.tolerance
    }
}

/// A signature timestamp tolerance outside 30 seconds through 15 minutes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("verified freshness tolerance is outside the accepted range")]
pub struct VerifiedFreshnessError;

/// A verifier-produced identity safe to use as a replay-protection key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedDeliveryIdentity {
    namespace: VerifierNamespace,
    hash: TrustedDeliveryIdHash,
    freshness: Option<VerifiedFreshness>,
}

impl TrustedDeliveryIdentity {
    /// Hashes one verifier-normalized non-empty identifier into its persistence form.
    pub fn from_normalized(
        namespace: VerifierNamespace,
        normalized_identifier: &[u8],
        freshness: Option<VerifiedFreshness>,
    ) -> Result<Self, TrustedDeliveryIdentityError> {
        if normalized_identifier.is_empty() {
            return Err(TrustedDeliveryIdentityError);
        }
        let hash = Sha256::digest(normalized_identifier).into();
        Ok(Self {
            namespace,
            hash: TrustedDeliveryIdHash::from_bytes(hash),
            freshness,
        })
    }

    /// Returns the verifier or sender namespace.
    #[must_use]
    pub const fn namespace(&self) -> &VerifierNamespace {
        &self.namespace
    }

    /// Returns the normalized identifier hash.
    #[must_use]
    pub const fn hash(&self) -> &TrustedDeliveryIdHash {
        &self.hash
    }

    /// Returns independently verified freshness when present.
    #[must_use]
    pub const fn freshness(&self) -> Option<VerifiedFreshness> {
        self.freshness
    }
}

/// A trusted delivery identifier cannot be empty before hashing.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("a trusted delivery identifier cannot be empty")]
pub struct TrustedDeliveryIdentityError;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bondry_delivery_store::VerifierNamespace;

    use super::{TrustedDeliveryIdentity, VerifiedFreshness, VerifiedFreshnessError};

    #[test]
    fn hashes_normalized_identifiers_without_retaining_them()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = TrustedDeliveryIdentity::from_normalized(
            VerifierNamespace::new("provider:v1")?,
            b"sensitive-delivery-id",
            Some(VerifiedFreshness::new(42, Duration::from_secs(300))?),
        )?;

        let rendered = format!("{identity:?}");
        assert!(!rendered.contains("sensitive-delivery-id"));
        assert_eq!(
            identity
                .freshness()
                .map(|value| value.signed_at_unix_seconds()),
            Some(42)
        );
        assert!(VerifiedFreshness::new(42, Duration::from_secs(29)).is_err());
        Ok(())
    }

    #[test]
    fn accepts_only_the_contract_freshness_range() {
        assert!(VerifiedFreshness::new(0, Duration::from_secs(30)).is_ok());
        assert!(VerifiedFreshness::new(0, Duration::from_secs(15 * 60)).is_ok());
        assert_eq!(
            VerifiedFreshness::new(0, Duration::from_secs(15 * 60 + 1)),
            Err(VerifiedFreshnessError)
        );
    }
}
