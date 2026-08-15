use std::{fmt, slice, sync::Arc};

use bondry_delivery_store::{DeliveryFailure, DeliveryId};
use bondry_egress::{
    AttemptContext, AttemptDisposition, DeliveryKind, DeliveryOperation, EventPayload,
    KindOperationError, KindTransition, OperationMode, RetryableFailure, TransportCompletion,
};
use bondry_secrets::{
    BONDRY_WEBHOOK_DELIVERY_ID_HEADER, BONDRY_WEBHOOK_SIGNATURE_HEADER,
    BONDRY_WEBHOOK_TIMESTAMP_HEADER, ResolvedSecret, SecretRef, WebhookSigningInput, sign_webhook,
};
use bondry_transport::{
    EndpointPolicy, HttpRequest, NetworkEndpoint, NetworkScheme, TransportError,
};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{SecretUrlTemplate, WebhookLimits};

/// Authentication for a fixed webhook endpoint.
#[derive(Clone, Eq, PartialEq)]
pub enum WebhookAuthentication {
    /// No credential is attached.
    None,
    /// A current host-owned secret is sent as an RFC 6750 bearer token.
    Bearer(SecretRef),
    /// A current host-owned secret signs timestamp, delivery ID, and exact body bytes.
    Hmac(SecretRef),
}

impl fmt::Debug for WebhookAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::None => "WebhookAuthentication::None",
            Self::Bearer(_) => "WebhookAuthentication::Bearer([REFERENCE])",
            Self::Hmac(_) => "WebhookAuthentication::Hmac([REFERENCE])",
        })
    }
}

/// Immutable sans-I/O configuration for outbound webhook delivery.
pub struct WebhookDeliveryKind {
    configuration: Arc<WebhookConfiguration>,
}

impl WebhookDeliveryKind {
    /// Configures a non-secret fixed endpoint with none, bearer, or HMAC authentication.
    pub fn new(
        endpoint: NetworkEndpoint,
        authentication: WebhookAuthentication,
        policy: EndpointPolicy,
        limits: WebhookLimits,
    ) -> Result<Self, WebhookConfigurationError> {
        if !matches!(
            endpoint.scheme(),
            NetworkScheme::Http | NetworkScheme::Https
        ) {
            return Err(WebhookConfigurationError::UnsupportedScheme);
        }
        let summary = Arc::from(redacted_origin(&endpoint));
        Ok(Self {
            configuration: Arc::new(WebhookConfiguration {
                target: WebhookTarget::Fixed(endpoint),
                authentication,
                policy,
                limits,
                summary,
            }),
        })
    }

    /// Configures the exclusive URL-template authentication shape.
    #[must_use]
    pub fn with_url_template(
        template: SecretUrlTemplate,
        policy: EndpointPolicy,
        limits: WebhookLimits,
    ) -> Self {
        let summary = Arc::from(template.redacted());
        Self {
            configuration: Arc::new(WebhookConfiguration {
                target: WebhookTarget::Template(template),
                authentication: WebhookAuthentication::None,
                policy,
                limits,
                summary,
            }),
        }
    }
}

/// A webhook route configuration that cannot produce an HTTP POST.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WebhookConfigurationError {
    /// Webhook routes support only HTTP and HTTPS endpoints.
    #[error("webhook endpoint must use HTTP or HTTPS")]
    UnsupportedScheme,
}

impl fmt::Debug for WebhookDeliveryKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookDeliveryKind")
            .field("target", &self.configuration.summary)
            .field("authentication", &self.configuration.authentication)
            .field("policy", &self.configuration.policy)
            .field("limits", &self.configuration.limits)
            .finish()
    }
}

impl DeliveryKind for WebhookDeliveryKind {
    fn name(&self) -> &'static str {
        "webhook"
    }

    fn target_summary(&self) -> &str {
        &self.configuration.summary
    }

    fn supports_call(&self) -> bool {
        false
    }

    fn max_payload_bytes(&self) -> usize {
        self.configuration.limits.body_bytes()
    }

    fn operation(
        &self,
        mode: OperationMode,
        delivery: DeliveryId,
        payload: EventPayload,
    ) -> Result<Box<dyn DeliveryOperation>, KindOperationError> {
        if mode != OperationMode::Emit {
            return Err(KindOperationError::UnsupportedOperation);
        }
        if payload.len() > self.configuration.limits.body_bytes() {
            return Err(KindOperationError::InvalidEvent);
        }
        Ok(Box::new(WebhookOperation {
            configuration: Arc::clone(&self.configuration),
            delivery,
            payload,
            state: OperationState::Ready,
        }))
    }
}

struct WebhookConfiguration {
    target: WebhookTarget,
    authentication: WebhookAuthentication,
    policy: EndpointPolicy,
    limits: WebhookLimits,
    summary: Arc<str>,
}

impl WebhookConfiguration {
    fn secret_reference(&self) -> Option<&SecretRef> {
        match (&self.target, &self.authentication) {
            (WebhookTarget::Template(template), WebhookAuthentication::None) => {
                Some(template.secret_reference())
            }
            (WebhookTarget::Fixed(_), WebhookAuthentication::Bearer(reference))
            | (WebhookTarget::Fixed(_), WebhookAuthentication::Hmac(reference)) => Some(reference),
            (WebhookTarget::Fixed(_), WebhookAuthentication::None) => None,
            (WebhookTarget::Template(_), _) => None,
        }
    }
}

enum WebhookTarget {
    Fixed(NetworkEndpoint),
    Template(SecretUrlTemplate),
}

struct WebhookOperation {
    configuration: Arc<WebhookConfiguration>,
    delivery: DeliveryId,
    payload: EventPayload,
    state: OperationState,
}

impl DeliveryOperation for WebhookOperation {
    fn secret_references(&self) -> &[SecretRef] {
        self.configuration
            .secret_reference()
            .map_or(&[], slice::from_ref)
    }

    fn start(&mut self, context: AttemptContext, secrets: Vec<ResolvedSecret>) -> KindTransition {
        if self.state != OperationState::Ready {
            self.state = OperationState::Complete;
            return KindTransition::Complete(AttemptDisposition::Failed(DeliveryFailure::Internal));
        }
        match self.compose_request(context, &secrets) {
            Ok(request) => {
                self.state = OperationState::AwaitingHttp;
                KindTransition::Http(Box::new(request))
            }
            Err(disposition) => {
                self.state = OperationState::Complete;
                KindTransition::Complete(disposition)
            }
        }
    }

    fn resume(
        &mut self,
        _context: AttemptContext,
        completion: TransportCompletion,
    ) -> KindTransition {
        if self.state != OperationState::AwaitingHttp {
            return KindTransition::Complete(AttemptDisposition::Failed(DeliveryFailure::Internal));
        }
        self.state = OperationState::Complete;
        match completion {
            TransportCompletion::Http(Ok(response)) => {
                KindTransition::Complete(classify_status(response.status()))
            }
            TransportCompletion::Http(Err(error)) => {
                KindTransition::Complete(classify_transport(error))
            }
        }
    }
}

impl WebhookOperation {
    fn compose_request(
        &self,
        context: AttemptContext,
        secrets: &[ResolvedSecret],
    ) -> Result<HttpRequest, AttemptDisposition> {
        let expected_secrets = usize::from(self.configuration.secret_reference().is_some());
        if secrets.len() != expected_secrets {
            return Err(AttemptDisposition::Failed(
                DeliveryFailure::SecretUnavailable,
            ));
        }
        let secret = secrets.first();
        let endpoint = match &self.configuration.target {
            WebhookTarget::Fixed(endpoint) => endpoint.clone(),
            WebhookTarget::Template(template) => template
                .expand(secret.ok_or(AttemptDisposition::Failed(
                    DeliveryFailure::SecretUnavailable,
                ))?)
                .map_err(|_| AttemptDisposition::Failed(DeliveryFailure::SecretUnavailable))?,
        };
        let mut headers = HeaderMap::with_capacity(4);
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            BONDRY_WEBHOOK_DELIVERY_ID_HEADER,
            HeaderValue::from_str(self.delivery.as_str())
                .map_err(|_| AttemptDisposition::Failed(DeliveryFailure::Internal))?,
        );
        match &self.configuration.authentication {
            WebhookAuthentication::None => {}
            WebhookAuthentication::Bearer(_) => {
                let mut value = bearer_header(secret.ok_or(AttemptDisposition::Failed(
                    DeliveryFailure::SecretUnavailable,
                ))?)?;
                value.set_sensitive(true);
                headers.insert(header::AUTHORIZATION, value);
            }
            WebhookAuthentication::Hmac(_) => {
                let timestamp = i64::try_from(context.unix_ms() / 1_000)
                    .map_err(|_| AttemptDisposition::Failed(DeliveryFailure::Internal))?;
                let signing_input = WebhookSigningInput {
                    timestamp_unix_seconds: timestamp,
                    delivery_id: self.delivery.as_str().as_bytes(),
                    body: self.payload.as_bytes(),
                };
                let signature = sign_webhook(
                    secret
                        .ok_or(AttemptDisposition::Failed(
                            DeliveryFailure::SecretUnavailable,
                        ))?
                        .current_value(),
                    signing_input,
                );
                headers.insert(
                    BONDRY_WEBHOOK_TIMESTAMP_HEADER,
                    HeaderValue::from_str(&timestamp.to_string())
                        .map_err(|_| AttemptDisposition::Failed(DeliveryFailure::Internal))?,
                );
                let mut value = HeaderValue::from_str(&signature.to_hex())
                    .map_err(|_| AttemptDisposition::Failed(DeliveryFailure::Internal))?;
                value.set_sensitive(true);
                headers.insert(BONDRY_WEBHOOK_SIGNATURE_HEADER, value);
            }
        }
        HttpRequest::new(
            Method::POST,
            endpoint,
            headers,
            self.payload.as_bytes().clone(),
            context.deadline(),
            self.configuration.policy.clone(),
            self.configuration.limits.response(),
        )
        .map_err(classify_request_error)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OperationState {
    Ready,
    AwaitingHttp,
    Complete,
}

fn bearer_header(secret: &ResolvedSecret) -> Result<HeaderValue, AttemptDisposition> {
    let token = secret.current_value().expose();
    let padding = token
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(token.len());
    if padding == 0
        || !token[..padding].iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        || !token[padding..].iter().all(|byte| *byte == b'=')
    {
        return Err(AttemptDisposition::Failed(
            DeliveryFailure::SecretUnavailable,
        ));
    }
    let mut encoded = Zeroizing::new(Vec::with_capacity(7 + token.len()));
    encoded.extend_from_slice(b"Bearer ");
    encoded.extend_from_slice(token);
    HeaderValue::from_bytes(&encoded)
        .map_err(|_| AttemptDisposition::Failed(DeliveryFailure::SecretUnavailable))
}

fn classify_status(status: StatusCode) -> AttemptDisposition {
    if status.is_success() {
        AttemptDisposition::Delivered(None)
    } else if status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_EARLY
        || status == StatusCode::TOO_MANY_REQUESTS
        || status.is_server_error()
    {
        AttemptDisposition::Retryable(RetryableFailure::ReceiverRejected)
    } else {
        AttemptDisposition::Failed(DeliveryFailure::ReceiverRejected)
    }
}

fn classify_request_error(error: TransportError) -> AttemptDisposition {
    match error {
        TransportError::RequestTooLarge
        | TransportError::InvalidLimits
        | TransportError::UnsupportedEndpoint
        | TransportError::InvalidMessage => AttemptDisposition::Failed(DeliveryFailure::Internal),
        TransportError::Policy(_) | TransportError::TlsFailed => {
            AttemptDisposition::Failed(DeliveryFailure::EndpointPolicy)
        }
        TransportError::ResponseTooLarge
        | TransportError::DeadlineExceeded
        | TransportError::ConnectionFailed
        | TransportError::InvalidResponse => AttemptDisposition::Failed(DeliveryFailure::Internal),
    }
}

fn classify_transport(error: TransportError) -> AttemptDisposition {
    match error {
        TransportError::DeadlineExceeded => {
            AttemptDisposition::Retryable(RetryableFailure::DeadlineExceeded)
        }
        TransportError::ConnectionFailed | TransportError::InvalidResponse => {
            AttemptDisposition::Retryable(RetryableFailure::TransportUnavailable)
        }
        TransportError::Policy(_) | TransportError::TlsFailed => {
            AttemptDisposition::Failed(DeliveryFailure::EndpointPolicy)
        }
        TransportError::ResponseTooLarge => {
            AttemptDisposition::Failed(DeliveryFailure::ReceiverRejected)
        }
        TransportError::RequestTooLarge
        | TransportError::InvalidLimits
        | TransportError::UnsupportedEndpoint
        | TransportError::InvalidMessage => AttemptDisposition::Failed(DeliveryFailure::Internal),
    }
}

fn redacted_origin(endpoint: &NetworkEndpoint) -> String {
    let scheme = endpoint.uri().scheme_str().unwrap_or_default();
    let authority = endpoint
        .uri()
        .authority()
        .map_or("", http::uri::Authority::as_str);
    format!("{scheme}://{authority}")
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use bondry_egress::{
        AttemptContext, AttemptDisposition, DeliveryKind, KindTransition, OperationMode,
        PayloadContract, PayloadField, PayloadFieldName, PayloadFieldType, PayloadLimit,
        TransportCompletion,
    };
    use bondry_secrets::{
        BONDRY_WEBHOOK_DELIVERY_ID_HEADER, BONDRY_WEBHOOK_SIGNATURE_HEADER,
        BONDRY_WEBHOOK_TIMESTAMP_HEADER, ResolvedSecret, SecretRef, SecretValue,
    };
    use bondry_transport::{Deadline, EndpointPolicy, NetworkEndpoint, TransportError};
    use bytes::Bytes;
    use http::{Method, StatusCode, header};

    use super::{
        WebhookAuthentication, WebhookConfigurationError, WebhookDeliveryKind, classify_status,
        classify_transport,
    };
    use crate::{SECRET_URL_PLACEHOLDER, SecretUrlTemplate, UrlTemplateLimits, WebhookLimits};

    fn endpoint(value: &str) -> Result<NetworkEndpoint, Box<dyn std::error::Error>> {
        Ok(NetworkEndpoint::new(value.parse()?)?)
    }

    fn payload(
        bytes: &'static [u8],
    ) -> Result<bondry_egress::EventPayload, Box<dyn std::error::Error>> {
        let contract = PayloadContract::new(
            [PayloadField::new(
                PayloadFieldName::new("temperature")?,
                PayloadFieldType::Number,
                true,
            )],
            PayloadLimit::default(),
        )?;
        Ok(contract.validate(Bytes::from_static(bytes))?)
    }

    fn context(unix_ms: u64) -> AttemptContext {
        AttemptContext::new(unix_ms, Deadline::at(Instant::now()))
    }

    #[test]
    fn composes_fixture_compatible_hmac_over_exact_body() -> Result<(), Box<dyn std::error::Error>>
    {
        let kind = WebhookDeliveryKind::new(
            endpoint("https://example.com/private?opaque=value")?,
            WebhookAuthentication::Hmac(SecretRef::new("keychain:hmac")?),
            EndpointPolicy::default(),
            WebhookLimits::default(),
        )?;
        let delivery =
            bondry_delivery_store::DeliveryId::new("delivery_01J5B6JY0MM6R6Y7G6X4ZZWQ5A")?;
        let body = br#"{"temperature":21.5}"#;
        let mut operation =
            kind.operation(OperationMode::Emit, delivery.clone(), payload(body)?)?;
        assert_eq!(operation.secret_references()[0].as_str(), "keychain:hmac");
        let secret =
            ResolvedSecret::current(SecretValue::new(b"correct horse battery staple".to_vec())?);
        let KindTransition::Http(request) =
            operation.start(context(1_723_723_200_000), vec![secret])
        else {
            return Err(std::io::Error::other("HTTP request was not produced").into());
        };
        let parts = request.into_parts();
        assert_eq!(parts.method, Method::POST);
        assert_eq!(parts.body, Bytes::from_static(body));
        assert_eq!(parts.headers[header::CONTENT_TYPE], "application/json");
        assert_eq!(
            parts.headers[BONDRY_WEBHOOK_DELIVERY_ID_HEADER],
            delivery.as_str()
        );
        assert_eq!(parts.headers[BONDRY_WEBHOOK_TIMESTAMP_HEADER], "1723723200");
        assert_eq!(
            parts.headers[BONDRY_WEBHOOK_SIGNATURE_HEADER],
            "7dcbe7102d99ec9cbd3b0fb55bff43db320fa4deb0ee453f2b41d7b587a4304e"
        );
        Ok(())
    }

    #[test]
    fn expands_url_secret_only_when_attempt_starts() -> Result<(), Box<dyn std::error::Error>> {
        let template = SecretUrlTemplate::new(
            format!("https://example.com/topic/{SECRET_URL_PLACEHOLDER}"),
            SecretRef::new("keychain:topic")?,
            UrlTemplateLimits::default(),
        )?;
        let kind = WebhookDeliveryKind::with_url_template(
            template,
            EndpointPolicy::default(),
            WebhookLimits::default(),
        );
        assert!(kind.target_summary().contains(SECRET_URL_PLACEHOLDER));
        assert!(!format!("{kind:?}").contains("private/topic"));
        let mut operation = kind.operation(
            OperationMode::Emit,
            bondry_delivery_store::DeliveryId::new("url_delivery")?,
            payload(br#"{"temperature":1}"#)?,
        )?;
        let secret = ResolvedSecret::current(SecretValue::new(b"private/topic".to_vec())?);
        let KindTransition::Http(request) = operation.start(context(0), vec![secret]) else {
            return Err(std::io::Error::other("HTTP request was not produced").into());
        };
        assert_eq!(
            request.endpoint().path_and_query(),
            "/topic/private%2Ftopic"
        );
        assert!(!format!("{request:?}").contains("private%2Ftopic"));
        Ok(())
    }

    #[test]
    fn rejects_invalid_bearer_material_without_building_a_request()
    -> Result<(), Box<dyn std::error::Error>> {
        let kind = WebhookDeliveryKind::new(
            endpoint("https://example.com/hook")?,
            WebhookAuthentication::Bearer(SecretRef::new("keychain:bearer")?),
            EndpointPolicy::default(),
            WebhookLimits::default(),
        )?;
        let mut operation = kind.operation(
            OperationMode::Emit,
            bondry_delivery_store::DeliveryId::new("bearer_delivery")?,
            payload(br#"{"temperature":1}"#)?,
        )?;
        let secret = ResolvedSecret::current(SecretValue::new(b"line\nbreak".to_vec())?);
        assert!(matches!(
            operation.start(context(0), vec![secret]),
            KindTransition::Complete(AttemptDisposition::Failed(
                bondry_delivery_store::DeliveryFailure::SecretUnavailable
            ))
        ));
        Ok(())
    }

    #[test]
    fn emits_an_exact_sensitive_bearer_header() -> Result<(), Box<dyn std::error::Error>> {
        let kind = WebhookDeliveryKind::new(
            endpoint("https://example.com/hook")?,
            WebhookAuthentication::Bearer(SecretRef::new("keychain:bearer")?),
            EndpointPolicy::default(),
            WebhookLimits::default(),
        )?;
        let mut operation = kind.operation(
            OperationMode::Emit,
            bondry_delivery_store::DeliveryId::new("bearer_valid")?,
            payload(br#"{"temperature":1}"#)?,
        )?;
        let secret = ResolvedSecret::current(SecretValue::new(b"token+/==".to_vec())?);
        let KindTransition::Http(request) = operation.start(context(0), vec![secret]) else {
            return Err(std::io::Error::other("HTTP request was not produced").into());
        };
        let authorization = &request.into_parts().headers[header::AUTHORIZATION];
        assert_eq!(authorization, "Bearer token+/==");
        assert!(authorization.is_sensitive());

        let no_auth = WebhookDeliveryKind::new(
            endpoint("https://example.com/hook")?,
            WebhookAuthentication::None,
            EndpointPolicy::default(),
            WebhookLimits::default(),
        )?;
        let mut operation = no_auth.operation(
            OperationMode::Emit,
            bondry_delivery_store::DeliveryId::new("unexpected_secret")?,
            payload(br#"{"temperature":1}"#)?,
        )?;
        let extra = ResolvedSecret::current(SecretValue::new(b"extra".to_vec())?);
        assert!(matches!(
            operation.start(context(0), vec![extra]),
            KindTransition::Complete(AttemptDisposition::Failed(
                bondry_delivery_store::DeliveryFailure::SecretUnavailable
            ))
        ));
        Ok(())
    }

    #[test]
    fn classifies_only_explicitly_transient_failures_for_retry() {
        assert_eq!(
            classify_status(StatusCode::NO_CONTENT),
            AttemptDisposition::Delivered(None)
        );
        assert!(matches!(
            classify_status(StatusCode::TOO_MANY_REQUESTS),
            AttemptDisposition::Retryable(_)
        ));
        assert!(matches!(
            classify_status(StatusCode::BAD_REQUEST),
            AttemptDisposition::Failed(_)
        ));
        assert!(matches!(
            classify_transport(TransportError::ConnectionFailed),
            AttemptDisposition::Retryable(_)
        ));
        assert!(matches!(
            classify_transport(TransportError::TlsFailed),
            AttemptDisposition::Failed(bondry_delivery_store::DeliveryFailure::EndpointPolicy)
        ));
    }

    #[test]
    fn rejects_call_and_repeated_state_machine_drives() -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            WebhookDeliveryKind::new(
                endpoint("wss://example.com/hook")?,
                WebhookAuthentication::None,
                EndpointPolicy::default(),
                WebhookLimits::default(),
            ),
            Err(WebhookConfigurationError::UnsupportedScheme)
        ));
        let kind = WebhookDeliveryKind::new(
            endpoint("https://example.com/hook")?,
            WebhookAuthentication::None,
            EndpointPolicy::default(),
            WebhookLimits::default(),
        )?;
        assert_eq!(
            kind.operation(
                OperationMode::Call,
                bondry_delivery_store::DeliveryId::new("call")?,
                payload(br#"{"temperature":1}"#)?,
            )
            .err(),
            Some(bondry_egress::KindOperationError::UnsupportedOperation)
        );
        let mut operation = kind.operation(
            OperationMode::Emit,
            bondry_delivery_store::DeliveryId::new("emit")?,
            payload(br#"{"temperature":1}"#)?,
        )?;
        assert!(matches!(
            operation.start(context(0), Vec::new()),
            KindTransition::Http(_)
        ));
        assert!(matches!(
            operation.resume(
                context(0),
                TransportCompletion::Http(Err(TransportError::ConnectionFailed)),
            ),
            KindTransition::Complete(AttemptDisposition::Retryable(_))
        ));
        assert!(matches!(
            operation.resume(
                context(0),
                TransportCompletion::Http(Err(TransportError::ConnectionFailed)),
            ),
            KindTransition::Complete(AttemptDisposition::Failed(
                bondry_delivery_store::DeliveryFailure::Internal
            ))
        ));

        let mut invalid_sequence = kind.operation(
            OperationMode::Emit,
            bondry_delivery_store::DeliveryId::new("invalid_sequence")?,
            payload(br#"{"temperature":1}"#)?,
        )?;
        assert!(matches!(
            invalid_sequence.start(context(0), Vec::new()),
            KindTransition::Http(_)
        ));
        assert!(matches!(
            invalid_sequence.start(context(0), Vec::new()),
            KindTransition::Complete(AttemptDisposition::Failed(
                bondry_delivery_store::DeliveryFailure::Internal
            ))
        ));
        assert!(matches!(
            invalid_sequence.resume(
                context(0),
                TransportCompletion::Http(Err(TransportError::ConnectionFailed)),
            ),
            KindTransition::Complete(AttemptDisposition::Failed(
                bondry_delivery_store::DeliveryFailure::Internal
            ))
        ));
        Ok(())
    }
}
