use http::{HeaderName, StatusCode};
use serde_json::{Map, Value};

use crate::{PayloadMapping, WebhookIngressLimits, WebhookIngressResponse};
use bondry_webhook_verify::VerificationRequest;

const VALUE_ALLOCATION_CHARGE: usize = 128;

pub(crate) fn map_payload(
    mapping: &PayloadMapping,
    request: VerificationRequest<'_>,
    limits: WebhookIngressLimits,
) -> Result<Value, WebhookIngressResponse> {
    if request.body().len() > limits.body_bytes() {
        return Err(WebhookIngressResponse::error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
        ));
    }
    let retained_charge = retained_charge(mapping, request).ok_or_else(capacity_response)?;
    if retained_charge > limits.retained_bytes() {
        return Err(capacity_response());
    }
    let body = serde_json::from_slice(request.body())
        .map_err(|_| WebhookIngressResponse::error(StatusCode::BAD_REQUEST, "invalid_json"))?;
    match mapping {
        PayloadMapping::JsonBody => Ok(body),
        PayloadMapping::Envelope { metadata_headers } => {
            let mut metadata = Map::new();
            for name in metadata_headers.iter() {
                let values = request
                    .header_values(name)
                    .map(|value| {
                        std::str::from_utf8(value)
                            .map(str::to_owned)
                            .map(Value::String)
                            .map_err(|_| {
                                WebhookIngressResponse::error(
                                    StatusCode::BAD_REQUEST,
                                    "invalid_metadata",
                                )
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if !values.is_empty() {
                    metadata.insert(name.as_str().to_owned(), Value::Array(values));
                }
            }
            Ok(serde_json::json!({ "body": body, "metadata": metadata }))
        }
    }
}

fn retained_charge(mapping: &PayloadMapping, request: VerificationRequest<'_>) -> Option<usize> {
    let body_bytes = request.body().len().checked_mul(2)?;
    let json_values = count_json_values(request.body())?;
    let json_charge = json_values.checked_mul(VALUE_ALLOCATION_CHARGE)?;
    let metadata_charge = metadata_charge(mapping, request)?;
    body_bytes
        .checked_add(json_charge)?
        .checked_add(metadata_charge)
}

fn count_json_values(input: &[u8]) -> Option<usize> {
    let mut count = 0_usize;
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b' ' | b'\t' | b'\r' | b'\n' | b'}' | b']' | b',' | b':' => index += 1,
            b'{' | b'[' => {
                count = count.checked_add(1)?;
                index += 1;
            }
            b'"' => {
                count = count.checked_add(1)?;
                index = string_end(input, index + 1)?;
            }
            _ => {
                count = count.checked_add(1)?;
                index += 1;
                while index < input.len()
                    && !matches!(
                        input[index],
                        b' ' | b'\t' | b'\r' | b'\n' | b'}' | b']' | b',' | b':'
                    )
                {
                    index += 1;
                }
            }
        }
    }
    Some(count)
}

fn string_end(input: &[u8], mut index: usize) -> Option<usize> {
    while index < input.len() {
        match input[index] {
            b'"' => return index.checked_add(1),
            b'\\' => index = index.checked_add(2)?,
            _ => index += 1,
        }
    }
    None
}

fn metadata_charge(mapping: &PayloadMapping, request: VerificationRequest<'_>) -> Option<usize> {
    let PayloadMapping::Envelope { metadata_headers } = mapping else {
        return Some(0);
    };
    let mut charge = VALUE_ALLOCATION_CHARGE.checked_mul(2)?;
    for name in metadata_headers.iter() {
        let mut present = false;
        for value in request.header_values(name) {
            present = true;
            charge = charge
                .checked_add(value.len())?
                .checked_add(VALUE_ALLOCATION_CHARGE)?;
        }
        if present {
            charge = charge
                .checked_add(name.as_str().len())?
                .checked_add(VALUE_ALLOCATION_CHARGE)?;
        }
    }
    Some(charge)
}

fn capacity_response() -> WebhookIngressResponse {
    WebhookIngressResponse::error(StatusCode::PAYLOAD_TOO_LARGE, "retained_capacity")
}

pub(crate) fn has_json_content_type(
    request: VerificationRequest<'_>,
    content_type: &HeaderName,
) -> bool {
    let mut values = request.header_values(content_type);
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    std::str::from_utf8(value).is_ok_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
    })
}

#[cfg(test)]
mod tests {
    use http::Method;

    use super::{count_json_values, retained_charge};
    use crate::PayloadMapping;
    use bondry_webhook_verify::{PeerAddress, VerificationRequest};

    #[test]
    fn preflight_counts_structure_without_treating_string_punctuation_as_values() {
        assert_eq!(
            count_json_values(br#"{"a":"[,:]","b":[1,true,null]}"#),
            Some(8)
        );
    }

    #[test]
    fn retained_charge_grows_with_json_node_density() {
        let method = Method::POST;
        let sparse = VerificationRequest::new(
            &method,
            "/hook",
            &[],
            br#""0000000000""#,
            PeerAddress::v4([127, 0, 0, 1], 1),
        );
        let dense = VerificationRequest::new(
            &method,
            "/hook",
            &[],
            br#"[0,0,0,0,0]"#,
            PeerAddress::v4([127, 0, 0, 1], 1),
        );

        assert!(
            retained_charge(&PayloadMapping::JsonBody, dense)
                > retained_charge(&PayloadMapping::JsonBody, sparse)
        );
    }
}
