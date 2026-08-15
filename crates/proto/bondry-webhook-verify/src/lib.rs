#![doc = "Sans-I/O inbound webhook verification contracts for Bondry."]

mod identity;
mod provider;
mod request;
mod verifier;

pub use identity::{
    IdentityGuarantee, TrustedDeliveryIdentity, TrustedDeliveryIdentityError, VerifiedFreshness,
    VerifiedFreshnessError,
};
pub use provider::{
    BONDRY_HMAC_NAMESPACE, BearerSecretVerifier, BondryHmacSha256Verifier, GITHUB_HMAC_NAMESPACE,
    GITHUB_SIGNATURE_HEADER, GitHubHmacSha256Verifier, PROVIDER_SIGNATURE_TIMESTAMP_TOLERANCE,
    ProviderVerifierConfigurationError, STRIPE_HMAC_NAMESPACE, STRIPE_SIGNATURE_HEADER,
    StripeHmacSha256Verifier,
};
pub use request::{PeerAddress, VerificationHeader, VerificationRequest};
pub use verifier::{VerificationError, VerificationResult, WebhookVerifier};
