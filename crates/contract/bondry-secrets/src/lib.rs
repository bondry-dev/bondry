#![doc = "Host-owned secret resolution and shared HMAC primitives for Bondry."]

mod canonical;
mod provider;
mod secret;
mod signature;

pub use canonical::{WebhookSigningInput, canonical_webhook_bytes};
pub use provider::{ResolvedSecret, SecretProvider, SecretProviderError};
pub use secret::{MAX_SECRET_BYTES, SecretRef, SecretRefError, SecretValue, SecretValueError};
pub use signature::{
    HmacSignature, HmacSignatureError, constant_time_eq, sign_webhook, verify_webhook,
};
