#![doc = "Host-owned secret resolution and shared HMAC primitives for Bondry."]

mod canonical;
mod provider;
mod secret;
mod signature;

pub use canonical::{
    BONDRY_WEBHOOK_DELIVERY_ID_HEADER, BONDRY_WEBHOOK_SIGNATURE_HEADER,
    BONDRY_WEBHOOK_TIMESTAMP_HEADER, WebhookSigningInput, canonical_webhook_bytes,
};
pub use provider::{ResolvedSecret, SecretProvider, SecretProviderError};
pub use secret::{
    MAX_SECRET_BYTES, MAX_SECRET_REF_BYTES, SecretRef, SecretRefError, SecretValue,
    SecretValueError,
};
pub use signature::{
    HmacSignature, HmacSignatureError, constant_time_eq, sign_webhook, verify_webhook,
};
