use std::{sync::Arc, time::Duration};

use bondry_delivery_store::{MAX_DELIVERY_ID_BYTES, VerifierNamespace};
use bondry_secrets::{
    BONDRY_WEBHOOK_DELIVERY_ID_HEADER, BONDRY_WEBHOOK_SIGNATURE_HEADER,
    BONDRY_WEBHOOK_TIMESTAMP_HEADER, HmacSignature, ResolvedSecret, SecretProvider,
    SecretProviderError, SecretRef, WebhookSigningInput, constant_time_eq, verify_hmac_sha256,
    verify_webhook,
};
use http::{HeaderName, header};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    IdentityGuarantee, TrustedDeliveryIdentity, VerificationError, VerificationRequest,
    VerificationResult, VerifiedFreshness, VerifiedFreshnessError, WebhookVerifier,
};

/// Default signed timestamp tolerance used by provider verifiers.
pub const PROVIDER_SIGNATURE_TIMESTAMP_TOLERANCE: Duration = Duration::from_secs(5 * 60);
/// Namespace for Bondry's length-delimited webhook signature form.
pub const BONDRY_HMAC_NAMESPACE: &str = "bondry:hmac-sha256:v1";
/// Namespace for GitHub's exact-body HMAC-SHA-256 form.
pub const GITHUB_HMAC_NAMESPACE: &str = "github:hmac-sha256:v1";
/// GitHub's current HMAC-SHA-256 signature header.
pub const GITHUB_SIGNATURE_HEADER: &str = "x-hub-signature-256";
/// Namespace for Stripe's timestamp-dot-body HMAC-SHA-256 form.
pub const STRIPE_HMAC_NAMESPACE: &str = "stripe:hmac-sha256:v1";
/// Stripe's timestamped signature header.
pub const STRIPE_SIGNATURE_HEADER: &str = "stripe-signature";

struct SecretSource {
    reference: SecretRef,
    provider: Arc<dyn SecretProvider>,
}

impl SecretSource {
    const fn new(reference: SecretRef, provider: Arc<dyn SecretProvider>) -> Self {
        Self {
            reference,
            provider,
        }
    }

    fn resolve(&self) -> Result<ResolvedSecret, VerificationError> {
        self.provider
            .resolve(&self.reference)
            .map_err(map_secret_error)
    }
}

/// Bearer verification backed by a host-owned rotating secret.
pub struct BearerSecretVerifier {
    source: SecretSource,
    authorization: [HeaderName; 1],
}

impl BearerSecretVerifier {
    /// Creates a verifier that resolves the configured secret for every request.
    #[must_use]
    pub fn new(reference: SecretRef, provider: Arc<dyn SecretProvider>) -> Self {
        Self {
            source: SecretSource::new(reference, provider),
            authorization: [header::AUTHORIZATION],
        }
    }
}

impl WebhookVerifier for BearerSecretVerifier {
    fn selected_headers(&self) -> &[HeaderName] {
        &self.authorization
    }

    fn credential_headers(&self) -> &[HeaderName] {
        &self.authorization
    }

    fn identity_guarantee(&self) -> IdentityGuarantee {
        IdentityGuarantee::Never
    }

    fn verify(
        &self,
        request: VerificationRequest<'_>,
        _now_unix_seconds: i64,
    ) -> Result<VerificationResult, VerificationError> {
        let authorization = exactly_one_header(request, &header::AUTHORIZATION)?;
        let separator = authorization
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or(VerificationError::Rejected)?;
        let (scheme, token_with_space) = authorization.split_at(separator);
        let token = token_with_space
            .get(1..)
            .ok_or(VerificationError::Rejected)?;
        if !scheme.eq_ignore_ascii_case(b"Bearer")
            || token.is_empty()
            || token.iter().any(u8::is_ascii_whitespace)
        {
            return Err(VerificationError::Rejected);
        }
        let secrets = self.source.resolve()?;
        if !matches_secret(&secrets, token) {
            return Err(VerificationError::Rejected);
        }
        Ok(VerificationResult::authenticated())
    }
}

/// Verifier for Bondry's shared length-delimited HMAC form.
pub struct BondryHmacSha256Verifier {
    source: SecretSource,
    namespace: VerifierNamespace,
    tolerance: Duration,
    selected: [HeaderName; 3],
    credentials: [HeaderName; 1],
}

impl BondryHmacSha256Verifier {
    /// Creates a verifier with the default five-minute timestamp tolerance.
    pub fn new(
        reference: SecretRef,
        provider: Arc<dyn SecretProvider>,
    ) -> Result<Self, ProviderVerifierConfigurationError> {
        Self::with_tolerance(reference, provider, PROVIDER_SIGNATURE_TIMESTAMP_TOLERANCE)
    }

    /// Creates a verifier with an explicit accepted timestamp tolerance.
    pub fn with_tolerance(
        reference: SecretRef,
        provider: Arc<dyn SecretProvider>,
        tolerance: Duration,
    ) -> Result<Self, ProviderVerifierConfigurationError> {
        validate_tolerance(tolerance)?;
        Ok(Self {
            source: SecretSource::new(reference, provider),
            namespace: namespace(BONDRY_HMAC_NAMESPACE)?,
            tolerance,
            selected: [
                HeaderName::from_static(BONDRY_WEBHOOK_DELIVERY_ID_HEADER),
                HeaderName::from_static(BONDRY_WEBHOOK_TIMESTAMP_HEADER),
                HeaderName::from_static(BONDRY_WEBHOOK_SIGNATURE_HEADER),
            ],
            credentials: [HeaderName::from_static(BONDRY_WEBHOOK_SIGNATURE_HEADER)],
        })
    }
}

impl WebhookVerifier for BondryHmacSha256Verifier {
    fn selected_headers(&self) -> &[HeaderName] {
        &self.selected
    }

    fn credential_headers(&self) -> &[HeaderName] {
        &self.credentials
    }

    fn identity_guarantee(&self) -> IdentityGuarantee {
        IdentityGuarantee::Required
    }

    fn verify(
        &self,
        request: VerificationRequest<'_>,
        now_unix_seconds: i64,
    ) -> Result<VerificationResult, VerificationError> {
        let delivery_id = exactly_one_header(request, &self.selected[0])?;
        if delivery_id.is_empty() || delivery_id.len() > MAX_DELIVERY_ID_BYTES {
            return Err(VerificationError::Rejected);
        }
        let timestamp = parse_canonical_timestamp(exactly_one_header(request, &self.selected[1])?)?;
        verify_freshness(now_unix_seconds, timestamp, self.tolerance)?;
        let signature = parse_signature(exactly_one_header(request, &self.selected[2])?)?;
        let input = WebhookSigningInput {
            timestamp_unix_seconds: timestamp,
            delivery_id,
            body: request.body(),
        };
        if !verify_webhook(&self.source.resolve()?, input, &signature) {
            return Err(VerificationError::Rejected);
        }
        let freshness = VerifiedFreshness::new(timestamp, self.tolerance)
            .map_err(|_| VerificationError::Unavailable)?;
        let identity = TrustedDeliveryIdentity::from_normalized(
            self.namespace.clone(),
            delivery_id,
            Some(freshness),
        )
        .map_err(|_| VerificationError::Rejected)?;
        Ok(VerificationResult::with_identity(identity))
    }
}

/// Verifier for GitHub's `sha256=` exact-body signature format.
pub struct GitHubHmacSha256Verifier {
    source: SecretSource,
    namespace: VerifierNamespace,
    signature: [HeaderName; 1],
}

impl GitHubHmacSha256Verifier {
    /// Creates a verifier for one GitHub webhook secret.
    pub fn new(
        reference: SecretRef,
        provider: Arc<dyn SecretProvider>,
    ) -> Result<Self, ProviderVerifierConfigurationError> {
        Ok(Self {
            source: SecretSource::new(reference, provider),
            namespace: namespace(GITHUB_HMAC_NAMESPACE)?,
            signature: [HeaderName::from_static(GITHUB_SIGNATURE_HEADER)],
        })
    }
}

impl WebhookVerifier for GitHubHmacSha256Verifier {
    fn selected_headers(&self) -> &[HeaderName] {
        &self.signature
    }

    fn credential_headers(&self) -> &[HeaderName] {
        &self.signature
    }

    fn identity_guarantee(&self) -> IdentityGuarantee {
        IdentityGuarantee::Required
    }

    fn verify(
        &self,
        request: VerificationRequest<'_>,
        _now_unix_seconds: i64,
    ) -> Result<VerificationResult, VerificationError> {
        let value = exactly_one_header(request, &self.signature[0])?;
        let encoded = value
            .strip_prefix(b"sha256=")
            .ok_or(VerificationError::Rejected)?;
        let candidate = parse_signature(encoded)?;
        if !verify_hmac_sha256(&self.source.resolve()?, &[request.body()], &[candidate]) {
            return Err(VerificationError::Rejected);
        }
        Ok(VerificationResult::with_identity(body_identity(
            self.namespace.clone(),
            request.body(),
            None,
        )?))
    }
}

/// Verifier for Stripe's timestamp-dot-body `v1` signature format.
pub struct StripeHmacSha256Verifier {
    source: SecretSource,
    namespace: VerifierNamespace,
    tolerance: Duration,
    signature: [HeaderName; 1],
}

impl StripeHmacSha256Verifier {
    /// Creates a verifier with Stripe's standard five-minute timestamp tolerance.
    pub fn new(
        reference: SecretRef,
        provider: Arc<dyn SecretProvider>,
    ) -> Result<Self, ProviderVerifierConfigurationError> {
        Self::with_tolerance(reference, provider, PROVIDER_SIGNATURE_TIMESTAMP_TOLERANCE)
    }

    /// Creates a verifier with an explicit nonzero timestamp tolerance.
    pub fn with_tolerance(
        reference: SecretRef,
        provider: Arc<dyn SecretProvider>,
        tolerance: Duration,
    ) -> Result<Self, ProviderVerifierConfigurationError> {
        validate_tolerance(tolerance)?;
        Ok(Self {
            source: SecretSource::new(reference, provider),
            namespace: namespace(STRIPE_HMAC_NAMESPACE)?,
            tolerance,
            signature: [HeaderName::from_static(STRIPE_SIGNATURE_HEADER)],
        })
    }
}

impl WebhookVerifier for StripeHmacSha256Verifier {
    fn selected_headers(&self) -> &[HeaderName] {
        &self.signature
    }

    fn credential_headers(&self) -> &[HeaderName] {
        &self.signature
    }

    fn identity_guarantee(&self) -> IdentityGuarantee {
        IdentityGuarantee::Required
    }

    fn verify(
        &self,
        request: VerificationRequest<'_>,
        now_unix_seconds: i64,
    ) -> Result<VerificationResult, VerificationError> {
        let header = exactly_one_header(request, &self.signature[0])?;
        let parsed = parse_stripe_header(header)?;
        verify_freshness(now_unix_seconds, parsed.timestamp, self.tolerance)?;
        if !verify_hmac_sha256(
            &self.source.resolve()?,
            &[parsed.timestamp_bytes, b".", request.body()],
            &parsed.signatures,
        ) {
            return Err(VerificationError::Rejected);
        }
        let freshness = VerifiedFreshness::new(parsed.timestamp, self.tolerance)
            .map_err(|_| VerificationError::Unavailable)?;
        Ok(VerificationResult::with_identity(body_identity(
            self.namespace.clone(),
            request.body(),
            Some(freshness),
        )?))
    }
}

struct StripeHeader<'a> {
    timestamp: i64,
    timestamp_bytes: &'a [u8],
    signatures: Vec<HmacSignature>,
}

fn parse_stripe_header(value: &[u8]) -> Result<StripeHeader<'_>, VerificationError> {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for component in value.split(|byte| *byte == b',') {
        let separator = component
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(VerificationError::Rejected)?;
        let (key, value_with_separator) = component.split_at(separator);
        let component_value = value_with_separator
            .get(1..)
            .ok_or(VerificationError::Rejected)?;
        match key {
            b"t" => {
                if timestamp.is_some() || component_value.contains(&b'=') {
                    return Err(VerificationError::Rejected);
                }
                timestamp = Some((parse_canonical_timestamp(component_value)?, component_value));
            }
            b"v1" => {
                if component_value.contains(&b'=') {
                    return Err(VerificationError::Rejected);
                }
                signatures.push(parse_signature(component_value)?);
            }
            _ => {}
        }
    }
    let (timestamp, timestamp_bytes) = timestamp.ok_or(VerificationError::Rejected)?;
    if signatures.is_empty() {
        return Err(VerificationError::Rejected);
    }
    Ok(StripeHeader {
        timestamp,
        timestamp_bytes,
        signatures,
    })
}

fn body_identity(
    namespace: VerifierNamespace,
    body: &[u8],
    freshness: Option<VerifiedFreshness>,
) -> Result<TrustedDeliveryIdentity, VerificationError> {
    let body_hash = Sha256::digest(body);
    TrustedDeliveryIdentity::from_normalized(namespace, &body_hash, freshness)
        .map_err(|_| VerificationError::Unavailable)
}

fn exactly_one_header<'a>(
    request: VerificationRequest<'a>,
    name: &HeaderName,
) -> Result<&'a [u8], VerificationError> {
    let mut found = None;
    for header in request.headers() {
        if header.name() == name {
            if found.is_some() {
                return Err(VerificationError::Rejected);
            }
            found = Some(header.value());
        }
    }
    found.ok_or(VerificationError::Rejected)
}

fn parse_signature(value: &[u8]) -> Result<HmacSignature, VerificationError> {
    let value = std::str::from_utf8(value).map_err(|_| VerificationError::Rejected)?;
    HmacSignature::from_hex(value).map_err(|_| VerificationError::Rejected)
}

fn parse_canonical_timestamp(value: &[u8]) -> Result<i64, VerificationError> {
    let value = std::str::from_utf8(value).map_err(|_| VerificationError::Rejected)?;
    let timestamp = value
        .parse::<i64>()
        .map_err(|_| VerificationError::Rejected)?;
    if timestamp < 0 || timestamp.to_string() != value {
        return Err(VerificationError::Rejected);
    }
    Ok(timestamp)
}

fn verify_freshness(
    now_unix_seconds: i64,
    signed_at_unix_seconds: i64,
    tolerance: Duration,
) -> Result<(), VerificationError> {
    if now_unix_seconds < 0
        || now_unix_seconds.abs_diff(signed_at_unix_seconds) > tolerance.as_secs()
    {
        return Err(VerificationError::Rejected);
    }
    Ok(())
}

fn matches_secret(secrets: &ResolvedSecret, candidate: &[u8]) -> bool {
    let mut matched = constant_time_eq(secrets.current_value().expose(), candidate);
    if let Some(previous) = secrets.previous_value() {
        matched |= constant_time_eq(previous.expose(), candidate);
    }
    matched
}

fn namespace(value: &'static str) -> Result<VerifierNamespace, ProviderVerifierConfigurationError> {
    VerifierNamespace::new(value).map_err(|_| ProviderVerifierConfigurationError::InvalidNamespace)
}

fn validate_tolerance(tolerance: Duration) -> Result<(), ProviderVerifierConfigurationError> {
    VerifiedFreshness::new(0, tolerance)
        .map(|_| ())
        .map_err(ProviderVerifierConfigurationError::InvalidTimestampTolerance)
}

fn map_secret_error(_error: SecretProviderError) -> VerificationError {
    VerificationError::Unavailable
}

/// A provider verifier configuration that cannot preserve identity or freshness guarantees.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProviderVerifierConfigurationError {
    /// An internal versioned provider namespace violates the persistence contract.
    #[error("provider verifier namespace is invalid")]
    InvalidNamespace,
    /// The timestamp tolerance is outside 30 seconds through 15 minutes.
    #[error(transparent)]
    InvalidTimestampTolerance(VerifiedFreshnessError),
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use bondry_secrets::{
        ResolvedSecret, SecretProvider, SecretProviderError, SecretRef, SecretValue,
    };
    use http::{HeaderName, Method, header};
    use serde::Deserialize;

    use super::{
        BONDRY_HMAC_NAMESPACE, BearerSecretVerifier, BondryHmacSha256Verifier,
        GITHUB_HMAC_NAMESPACE, GITHUB_SIGNATURE_HEADER, GitHubHmacSha256Verifier,
        STRIPE_HMAC_NAMESPACE, STRIPE_SIGNATURE_HEADER, StripeHmacSha256Verifier,
    };
    use crate::{
        IdentityGuarantee, PeerAddress, VerificationError, VerificationHeader, VerificationRequest,
        WebhookVerifier,
    };

    struct TestSecretProvider {
        current: Vec<u8>,
        previous: Option<Vec<u8>>,
    }

    impl SecretProvider for TestSecretProvider {
        fn resolve(&self, _reference: &SecretRef) -> Result<ResolvedSecret, SecretProviderError> {
            let current = SecretValue::new(self.current.clone())
                .map_err(|_| SecretProviderError::InvalidMaterial)?;
            match &self.previous {
                Some(previous) => Ok(ResolvedSecret::rotating(
                    current,
                    SecretValue::new(previous.clone())
                        .map_err(|_| SecretProviderError::InvalidMaterial)?,
                )),
                None => Ok(ResolvedSecret::current(current)),
            }
        }
    }

    #[derive(Deserialize)]
    struct ProviderFixtures {
        #[serde(rename = "version")]
        _version: u32,
        github: GitHubFixture,
        stripe: StripeFixture,
    }

    #[derive(Deserialize)]
    struct GitHubFixture {
        #[serde(rename = "source")]
        _source: String,
        secret_base64: String,
        body_base64: String,
        signature_header: String,
    }

    #[derive(Deserialize)]
    struct StripeFixture {
        #[serde(rename = "source")]
        _source: String,
        secret_base64: String,
        timestamp_unix_seconds: i64,
        body_base64: String,
        canonical_base64: String,
        signature_header: String,
    }

    #[derive(Deserialize)]
    struct BondryFixtures {
        vectors: Vec<BondryFixture>,
    }

    #[derive(Deserialize)]
    struct BondryFixture {
        secret_base64: String,
        timestamp_unix_seconds: i64,
        delivery_id: String,
        body_base64: String,
        signature_hex: String,
    }

    #[test]
    fn verifies_bearer_rotation_without_claiming_replay_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let verifier = BearerSecretVerifier::new(
            secret_reference()?,
            Arc::new(TestSecretProvider {
                current: b"current-token".to_vec(),
                previous: Some(b"previous-token".to_vec()),
            }),
        );
        let method = Method::POST;
        let authorization =
            VerificationHeader::new(header::AUTHORIZATION, b"bearer previous-token");
        let headers = [authorization];
        let verified = verifier.verify(request(&method, &headers, b"{}"), 0)?;

        assert_eq!(verifier.identity_guarantee(), IdentityGuarantee::Never);
        assert!(verified.identity().is_none());
        assert_eq!(verifier.credential_headers(), [header::AUTHORIZATION]);
        Ok(())
    }

    #[test]
    fn reproduces_github_official_fixture_and_rejects_tampering()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = provider_fixtures()?;
        let secret = STANDARD.decode(&fixtures.github.secret_base64)?;
        let body = STANDARD.decode(&fixtures.github.body_base64)?;
        let verifier = GitHubHmacSha256Verifier::new(
            secret_reference()?,
            Arc::new(TestSecretProvider {
                current: secret,
                previous: None,
            }),
        )?;
        let method = Method::POST;
        let headers = [VerificationHeader::new(
            HeaderName::from_static(GITHUB_SIGNATURE_HEADER),
            fixtures.github.signature_header.as_bytes(),
        )];

        let verified = verifier.verify(request(&method, &headers, &body), 0)?;
        assert_eq!(
            verified
                .identity()
                .map(|identity| identity.namespace().as_str()),
            Some(GITHUB_HMAC_NAMESPACE)
        );
        assert_eq!(
            verifier.verify(request(&method, &headers, b"tampered"), 0),
            Err(VerificationError::Rejected)
        );
        let duplicates = [headers[0].clone(), headers[0].clone()];
        assert_eq!(
            verifier.verify(request(&method, &duplicates, &body), 0),
            Err(VerificationError::Rejected)
        );
        Ok(())
    }

    #[test]
    fn reproduces_stripe_fixture_rotation_and_bidirectional_freshness()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixtures = provider_fixtures()?;
        let secret = STANDARD.decode(&fixtures.stripe.secret_base64)?;
        let body = STANDARD.decode(&fixtures.stripe.body_base64)?;
        let timestamp = fixtures.stripe.timestamp_unix_seconds;
        let canonical = STANDARD.decode(&fixtures.stripe.canonical_base64)?;
        let mut expected_canonical = timestamp.to_string().into_bytes();
        expected_canonical.push(b'.');
        expected_canonical.extend_from_slice(&body);
        assert_eq!(canonical, expected_canonical);
        let verifier = StripeHmacSha256Verifier::new(
            secret_reference()?,
            Arc::new(TestSecretProvider {
                current: b"not-the-active-secret".to_vec(),
                previous: Some(secret),
            }),
        )?;
        let method = Method::POST;
        let multiple_signatures = fixtures
            .stripe
            .signature_header
            .replace("v1=", &format!("v1={},v1=", "0".repeat(64)));
        let headers = [VerificationHeader::new(
            HeaderName::from_static(STRIPE_SIGNATURE_HEADER),
            multiple_signatures.as_bytes(),
        )];

        let verified = verifier.verify(request(&method, &headers, &body), timestamp)?;
        assert_eq!(
            verified
                .identity()
                .map(|identity| identity.namespace().as_str()),
            Some(STRIPE_HMAC_NAMESPACE)
        );
        assert_eq!(
            verifier.verify(request(&method, &headers, &body), timestamp + 301),
            Err(VerificationError::Rejected)
        );
        assert_eq!(
            verifier.verify(request(&method, &headers, &body), timestamp - 301),
            Err(VerificationError::Rejected)
        );
        Ok(())
    }

    #[test]
    fn closes_the_shared_bondry_sign_and_verify_fixture_loop()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixtures: BondryFixtures = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../fixtures/signing-v1/webhook-hmac.json"
        )))?;
        let method = Method::POST;
        for fixture in fixtures.vectors {
            let verifier = BondryHmacSha256Verifier::new(
                secret_reference()?,
                Arc::new(TestSecretProvider {
                    current: STANDARD.decode(fixture.secret_base64)?,
                    previous: None,
                }),
            )?;
            let body = STANDARD.decode(fixture.body_base64)?;
            let timestamp = fixture.timestamp_unix_seconds.to_string();
            let headers = [
                VerificationHeader::new(
                    HeaderName::from_static("x-bondry-delivery-id"),
                    fixture.delivery_id.as_bytes(),
                ),
                VerificationHeader::new(
                    HeaderName::from_static("x-bondry-timestamp"),
                    timestamp.as_bytes(),
                ),
                VerificationHeader::new(
                    HeaderName::from_static("x-bondry-signature"),
                    fixture.signature_hex.as_bytes(),
                ),
            ];

            let verified = verifier.verify(
                request(&method, &headers, &body),
                fixture.timestamp_unix_seconds,
            )?;
            assert_eq!(
                verified
                    .identity()
                    .map(|identity| identity.namespace().as_str()),
                Some(BONDRY_HMAC_NAMESPACE)
            );
            assert!(
                verified
                    .identity()
                    .and_then(|identity| identity.freshness())
                    .is_some()
            );
        }
        Ok(())
    }

    fn provider_fixtures() -> Result<ProviderFixtures, Box<dyn std::error::Error>> {
        Ok(serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../fixtures/signing-v1/provider-hmac.json"
        )))?)
    }

    fn secret_reference() -> Result<SecretRef, Box<dyn std::error::Error>> {
        Ok(SecretRef::new("test:webhook")?)
    }

    fn request<'a>(
        method: &'a Method,
        headers: &'a [VerificationHeader<'a>],
        body: &'a [u8],
    ) -> VerificationRequest<'a> {
        VerificationRequest::new(
            method,
            "/hook",
            headers,
            body,
            PeerAddress::v4([127, 0, 0, 1], 443),
        )
    }
}
