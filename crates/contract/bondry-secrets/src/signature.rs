use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;

use crate::{ResolvedSecret, SecretValue, WebhookSigningInput};

const HMAC_SHA256_BYTES: usize = 32;
const HMAC_SHA256_HEX_BYTES: usize = HMAC_SHA256_BYTES * 2;

type HmacSha256 = Hmac<Sha256>;

/// A fixed-size HMAC-SHA-256 signature.
#[derive(Clone, Eq, PartialEq)]
pub struct HmacSignature([u8; HMAC_SHA256_BYTES]);

impl HmacSignature {
    /// Parses a 64-character hexadecimal signature.
    pub fn from_hex(value: &str) -> Result<Self, HmacSignatureError> {
        if value.len() != HMAC_SHA256_HEX_BYTES {
            return Err(HmacSignatureError::InvalidEncoding);
        }
        let mut signature = [0_u8; HMAC_SHA256_BYTES];
        for (destination, pair) in signature.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            let high = decode_nibble(pair[0]).ok_or(HmacSignatureError::InvalidEncoding)?;
            let low = decode_nibble(pair[1]).ok_or(HmacSignatureError::InvalidEncoding)?;
            *destination = (high << 4) | low;
        }
        Ok(Self(signature))
    }

    /// Returns lowercase hexadecimal suitable for the signature header.
    #[must_use]
    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(HMAC_SHA256_HEX_BYTES);
        for byte in self.0 {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    /// Returns the raw signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HMAC_SHA256_BYTES] {
        &self.0
    }
}

impl fmt::Debug for HmacSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HmacSignature([REDACTED])")
    }
}

/// An invalid HMAC signature representation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HmacSignatureError {
    /// The input is not exactly 32 bytes of hexadecimal.
    #[error("invalid HMAC-SHA-256 signature encoding")]
    InvalidEncoding,
}

/// Compares equal-length public encodings without data-dependent early exit.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

/// Signs a Bondry webhook with the provider's current secret.
#[must_use]
pub fn sign_webhook(secret: &SecretValue, input: WebhookSigningInput<'_>) -> HmacSignature {
    sign(secret, input)
}

/// Verifies against both rotation-overlap values without an early return.
#[must_use]
pub fn verify_webhook(
    secrets: &ResolvedSecret,
    input: WebhookSigningInput<'_>,
    candidate: &HmacSignature,
) -> bool {
    let current = sign(secrets.current_value(), input);
    let mut matched = current.0.ct_eq(&candidate.0);
    if let Some(previous) = secrets.previous_value() {
        let previous = sign(previous, input);
        matched |= previous.0.ct_eq(&candidate.0);
    } else {
        matched |= Choice::from(0);
    }
    bool::from(matched)
}

fn sign(secret: &SecretValue, input: WebhookSigningInput<'_>) -> HmacSignature {
    let mut mac = HmacSha256::new_from_slice(secret.expose())
        .unwrap_or_else(|_| unreachable!("HMAC accepts every key length admitted by SecretValue"));
    update_webhook_mac(&mut mac, input);
    HmacSignature(mac.finalize().into_bytes().into())
}

fn update_webhook_mac(mac: &mut HmacSha256, input: WebhookSigningInput<'_>) {
    let timestamp = input.timestamp_unix_seconds.to_string();
    let delivery_id_length = input.delivery_id.len().to_string();
    let body_length = input.body.len().to_string();
    for component in [
        b"bondry-webhook-v1\n".as_slice(),
        timestamp.as_bytes(),
        b"\n",
        delivery_id_length.as_bytes(),
        b"\n",
        input.delivery_id,
        b"\n",
        body_length.as_bytes(),
        b"\n",
        input.body,
    ] {
        mac.update(component);
    }
}

fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::Deserialize;

    use super::{HmacSignature, constant_time_eq, sign_webhook, verify_webhook};
    use crate::{ResolvedSecret, SecretValue, WebhookSigningInput, canonical_webhook_bytes};

    #[derive(Deserialize)]
    struct FixtureBundle {
        vectors: Vec<Fixture>,
    }

    #[derive(Deserialize)]
    struct Fixture {
        secret_base64: String,
        timestamp_unix_seconds: i64,
        delivery_id: String,
        body_base64: String,
        canonical_base64: String,
        signature_hex: String,
    }

    #[test]
    fn reproduces_shared_signing_fixtures() {
        let fixtures: FixtureBundle = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../fixtures/signing-v1/webhook-hmac.json"
        )))
        .unwrap_or_else(|error| unreachable!("valid signing fixtures: {error}"));

        for fixture in fixtures.vectors {
            let secret = SecretValue::new(
                STANDARD
                    .decode(fixture.secret_base64)
                    .unwrap_or_else(|error| unreachable!("valid secret fixture: {error}")),
            )
            .unwrap_or_else(|error| unreachable!("bounded secret fixture: {error}"));
            let body = STANDARD
                .decode(fixture.body_base64)
                .unwrap_or_else(|error| unreachable!("valid body fixture: {error}"));
            let input = WebhookSigningInput {
                timestamp_unix_seconds: fixture.timestamp_unix_seconds,
                delivery_id: fixture.delivery_id.as_bytes(),
                body: &body,
            };
            assert_eq!(
                STANDARD.encode(canonical_webhook_bytes(input)),
                fixture.canonical_base64
            );
            assert_eq!(sign_webhook(&secret, input).to_hex(), fixture.signature_hex);
        }
    }

    #[test]
    fn accepts_both_rotation_values() {
        let current = SecretValue::new(b"current".to_vec())
            .unwrap_or_else(|error| unreachable!("valid secret: {error}"));
        let previous = SecretValue::new(b"previous".to_vec())
            .unwrap_or_else(|error| unreachable!("valid secret: {error}"));
        let input = WebhookSigningInput {
            timestamp_unix_seconds: 1,
            delivery_id: b"delivery",
            body: b"body",
        };
        let old_signature = sign_webhook(&previous, input);
        let secrets = ResolvedSecret::rotating(current, previous);
        assert!(verify_webhook(&secrets, input, &old_signature));
    }

    #[test]
    fn rejects_tampering_and_invalid_encodings() {
        let secret = SecretValue::new(b"secret".to_vec())
            .unwrap_or_else(|error| unreachable!("valid secret: {error}"));
        let signature = sign_webhook(
            &secret,
            WebhookSigningInput {
                timestamp_unix_seconds: 1,
                delivery_id: b"delivery",
                body: b"body",
            },
        );
        assert!(!verify_webhook(
            &ResolvedSecret::current(secret),
            WebhookSigningInput {
                timestamp_unix_seconds: 1,
                delivery_id: b"delivery",
                body: b"tampered",
            },
            &signature
        ));
        assert!(HmacSignature::from_hex("invalid").is_err());
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"size"));
        assert!(!constant_time_eq(b"short", b"longer"));
        assert_eq!(format!("{signature:?}"), "HmacSignature([REDACTED])");
    }
}
