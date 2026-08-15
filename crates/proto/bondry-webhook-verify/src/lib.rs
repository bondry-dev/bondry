#![doc = "Sans-I/O inbound webhook verification contracts for Bondry."]

mod identity;
mod request;
mod verifier;

pub use identity::{
    IdentityGuarantee, TrustedDeliveryIdentity, TrustedDeliveryIdentityError, VerifiedFreshness,
    VerifiedFreshnessError,
};
pub use request::{PeerAddress, VerificationHeader, VerificationRequest};
pub use verifier::{VerificationError, VerificationResult, WebhookVerifier};
