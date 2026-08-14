const WEBHOOK_CANONICAL_PREFIX: &[u8] = b"bondry-webhook-v1\n";

/// Exact inputs covered by the Bondry webhook HMAC form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebhookSigningInput<'a> {
    /// Signature timestamp in Unix seconds.
    pub timestamp_unix_seconds: i64,
    /// Stable delivery identifier sent with the request.
    pub delivery_id: &'a [u8],
    /// Exact request body bytes.
    pub body: &'a [u8],
}

/// Encodes the versioned, length-delimited Bondry webhook HMAC form.
#[must_use]
pub fn canonical_webhook_bytes(input: WebhookSigningInput<'_>) -> Vec<u8> {
    let timestamp = input.timestamp_unix_seconds.to_string();
    let delivery_id_length = input.delivery_id.len().to_string();
    let body_length = input.body.len().to_string();
    let mut result = Vec::with_capacity(
        WEBHOOK_CANONICAL_PREFIX.len()
            + timestamp.len()
            + delivery_id_length.len()
            + input.delivery_id.len()
            + body_length.len()
            + input.body.len()
            + 4,
    );
    result.extend_from_slice(WEBHOOK_CANONICAL_PREFIX);
    result.extend_from_slice(timestamp.as_bytes());
    result.push(b'\n');
    result.extend_from_slice(delivery_id_length.as_bytes());
    result.push(b'\n');
    result.extend_from_slice(input.delivery_id);
    result.push(b'\n');
    result.extend_from_slice(body_length.as_bytes());
    result.push(b'\n');
    result.extend_from_slice(input.body);
    result
}

#[cfg(test)]
mod tests {
    use super::{WebhookSigningInput, canonical_webhook_bytes};

    #[test]
    fn length_delimits_untrusted_fields() {
        let first = canonical_webhook_bytes(WebhookSigningInput {
            timestamp_unix_seconds: 1,
            delivery_id: b"a\n1",
            body: b"b",
        });
        let second = canonical_webhook_bytes(WebhookSigningInput {
            timestamp_unix_seconds: 1,
            delivery_id: b"a",
            body: b"1\nb",
        });
        assert_ne!(first, second);
    }
}
