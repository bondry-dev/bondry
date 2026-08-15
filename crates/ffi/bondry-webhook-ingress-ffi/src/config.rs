use std::{str::FromStr, sync::Arc, time::Duration};

use bondry_core::{CapabilityId, Principal, PrincipalId, PrincipalKind};
use bondry_delivery_store::RouteId;
use bondry_secrets::{SecretProvider, SecretRef};
use bondry_webhook_ingress::{
    CapabilitySemantics, PayloadMapping, WebhookIngressContext, WebhookIngressLimits, WebhookRoute,
    WebhookRouteConfiguration, WebhookRouteError,
};
use bondry_webhook_verify::{
    BearerSecretVerifier, BondryHmacSha256Verifier, GitHubHmacSha256Verifier,
    StripeHmacSha256Verifier, WebhookVerifier,
};
use http::{HeaderName, StatusCode, uri::PathAndQuery};
use serde::Deserialize;
use serde_json::Value;

use crate::{service::ForeignAutomationService, store::ForeignDedupStore};

const CONFIGURATION_VERSION: u32 = 1;
const DEFAULT_SELECTED_HEADER_BYTES: usize = 2 * 1_024;
const DEFAULT_SELECTED_HEADERS_BYTES: usize = 32 * 1_024;
const DEFAULT_PRE_AUTHENTICATION_PEER_RATE: u32 = 60;
const DEFAULT_PRE_AUTHENTICATION_ROUTE_RATE: u32 = 120;
const MAX_METADATA_HEADER_NAME_BYTES: usize = 128;

pub(crate) struct BuiltRoute {
    pub(crate) route: WebhookRoute,
    pub(crate) path: Box<[u8]>,
    pub(crate) raw_limits: RawLimits,
}

#[derive(Clone, Copy)]
pub(crate) struct RawLimits {
    pub(crate) selected_header_bytes: usize,
    pub(crate) selected_headers_bytes: usize,
    pub(crate) peer_rate: u32,
    pub(crate) route_rate: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigurationError {
    InvalidJson,
    Invalid,
    PolicyUnavailable,
}

pub(crate) fn build_route(
    bytes: &[u8],
    service: Arc<ForeignAutomationService>,
    store: Arc<ForeignDedupStore>,
    secrets: Arc<dyn SecretProvider>,
) -> Result<BuiltRoute, ConfigurationError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| ConfigurationError::InvalidJson)?;
    let input: RouteInput =
        serde_json::from_value(value).map_err(|_| ConfigurationError::Invalid)?;
    if input.version != CONFIGURATION_VERSION {
        return Err(ConfigurationError::Invalid);
    }
    validate_path(&input.path)?;
    let principal = Principal::new(
        PrincipalId::new(input.principal.id).map_err(|_| ConfigurationError::Invalid)?,
        input.principal.kind.into(),
    );
    let capability =
        CapabilityId::new(input.capability_id).map_err(|_| ConfigurationError::Invalid)?;
    let semantics = input.semantics.into();
    let limits = WebhookIngressLimits::new(input.limits.body_bytes, input.limits.retained_bytes)
        .and_then(|limits| limits.with_selected_headers(input.limits.selected_headers))
        .map_err(|_| ConfigurationError::Invalid)?;
    let raw_limits = input.limits.raw()?;
    let mapping = input.mapping.build()?;
    let verifier = input.verifier.build(secrets)?;
    let mut configuration = WebhookRouteConfiguration::new(
        RouteId::new(input.route_id).map_err(|_| ConfigurationError::Invalid)?,
        principal,
        capability,
        semantics,
    )
    .with_mapping(mapping)
    .with_limits(limits);
    let success =
        StatusCode::from_u16(input.success_status).map_err(|_| ConfigurationError::Invalid)?;
    configuration = configuration
        .with_success_status(success)
        .map_err(|_| ConfigurationError::Invalid)?;
    let context = Arc::new(WebhookIngressContext::new(service, store));
    let route = WebhookRoute::new(configuration, verifier, context).map_err(map_route_error)?;
    Ok(BuiltRoute {
        route,
        path: input.path.into_bytes().into_boxed_slice(),
        raw_limits,
    })
}

fn validate_path(path: &str) -> Result<(), ConfigurationError> {
    let parsed = PathAndQuery::from_str(path).map_err(|_| ConfigurationError::Invalid)?;
    if path.len() <= 1 || parsed.query().is_some() || parsed.path() != path {
        return Err(ConfigurationError::Invalid);
    }
    Ok(())
}

fn map_route_error(error: WebhookRouteError) -> ConfigurationError {
    match error {
        WebhookRouteError::PolicyUnavailable | WebhookRouteError::CapabilityUnavailable => {
            ConfigurationError::PolicyUnavailable
        }
        _ => ConfigurationError::Invalid,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RouteInput {
    version: u32,
    route_id: String,
    path: String,
    principal: PrincipalInput,
    capability_id: String,
    semantics: SemanticsInput,
    verifier: VerifierInput,
    #[serde(default)]
    mapping: MappingInput,
    #[serde(default = "default_success_status")]
    success_status: u16,
    #[serde(default)]
    limits: LimitsInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PrincipalInput {
    id: String,
    kind: PrincipalKindInput,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PrincipalKindInput {
    User,
    Application,
    System,
}

impl From<PrincipalKindInput> for PrincipalKind {
    fn from(value: PrincipalKindInput) -> Self {
        match value {
            PrincipalKindInput::User => Self::User,
            PrincipalKindInput::Application => Self::Application,
            PrincipalKindInput::System => Self::System,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SemanticsInput {
    ReadOnly,
    IdempotentMutation,
    NonIdempotentMutation,
}

impl From<SemanticsInput> for CapabilitySemantics {
    fn from(value: SemanticsInput) -> Self {
        match value {
            SemanticsInput::ReadOnly => Self::ReadOnly,
            SemanticsInput::IdempotentMutation => Self::IdempotentMutation,
            SemanticsInput::NonIdempotentMutation => Self::NonIdempotentMutation,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "type")]
enum VerifierInput {
    #[serde(rename = "bearer")]
    Bearer {
        #[serde(rename = "secretRef")]
        secret_ref: String,
    },
    #[serde(rename = "bondry_hmac_sha256")]
    BondryHmacSha256 {
        #[serde(rename = "secretRef")]
        secret_ref: String,
        #[serde(default = "default_tolerance")]
        #[serde(rename = "toleranceSeconds")]
        tolerance_seconds: u64,
    },
    #[serde(rename = "github_hmac_sha256")]
    GitHubHmacSha256 {
        #[serde(rename = "secretRef")]
        secret_ref: String,
    },
    #[serde(rename = "stripe_hmac_sha256")]
    StripeHmacSha256 {
        #[serde(rename = "secretRef")]
        secret_ref: String,
        #[serde(default = "default_tolerance")]
        #[serde(rename = "toleranceSeconds")]
        tolerance_seconds: u64,
    },
}

impl VerifierInput {
    fn build(
        self,
        provider: Arc<dyn SecretProvider>,
    ) -> Result<Arc<dyn WebhookVerifier>, ConfigurationError> {
        match self {
            Self::Bearer { secret_ref } => Ok(Arc::new(BearerSecretVerifier::new(
                secret(secret_ref)?,
                provider,
            ))),
            Self::BondryHmacSha256 {
                secret_ref,
                tolerance_seconds,
            } => BondryHmacSha256Verifier::with_tolerance(
                secret(secret_ref)?,
                provider,
                Duration::from_secs(tolerance_seconds),
            )
            .map(|verifier| Arc::new(verifier) as Arc<dyn WebhookVerifier>)
            .map_err(|_| ConfigurationError::Invalid),
            Self::GitHubHmacSha256 { secret_ref } => {
                GitHubHmacSha256Verifier::new(secret(secret_ref)?, provider)
                    .map(|verifier| Arc::new(verifier) as Arc<dyn WebhookVerifier>)
                    .map_err(|_| ConfigurationError::Invalid)
            }
            Self::StripeHmacSha256 {
                secret_ref,
                tolerance_seconds,
            } => StripeHmacSha256Verifier::with_tolerance(
                secret(secret_ref)?,
                provider,
                Duration::from_secs(tolerance_seconds),
            )
            .map(|verifier| Arc::new(verifier) as Arc<dyn WebhookVerifier>)
            .map_err(|_| ConfigurationError::Invalid),
        }
    }
}

fn secret(value: String) -> Result<SecretRef, ConfigurationError> {
    SecretRef::new(value).map_err(|_| ConfigurationError::Invalid)
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "type")]
enum MappingInput {
    #[default]
    #[serde(rename = "json_body")]
    JsonBody,
    #[serde(rename = "envelope")]
    Envelope {
        #[serde(rename = "metadataHeaders")]
        metadata_headers: Vec<String>,
    },
}

impl MappingInput {
    fn build(self) -> Result<PayloadMapping, ConfigurationError> {
        match self {
            Self::JsonBody => Ok(PayloadMapping::JsonBody),
            Self::Envelope { metadata_headers } => PayloadMapping::envelope(
                metadata_headers
                    .into_iter()
                    .map(|name| {
                        if name.is_empty() || name.len() > MAX_METADATA_HEADER_NAME_BYTES {
                            return Err(());
                        }
                        HeaderName::from_bytes(name.as_bytes()).map_err(|_| ())
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| ConfigurationError::Invalid)?,
            )
            .map_err(|_| ConfigurationError::Invalid),
        }
    }
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
struct LimitsInput {
    body_bytes: usize,
    retained_bytes: usize,
    selected_headers: usize,
    selected_header_bytes: usize,
    selected_headers_bytes: usize,
    pre_authentication_requests_per_peer_minute: u32,
    pre_authentication_requests_per_route_minute: u32,
}

impl LimitsInput {
    fn raw(&self) -> Result<RawLimits, ConfigurationError> {
        if self.selected_header_bytes == 0 || self.selected_header_bytes > 8 * 1_024 {
            return Err(ConfigurationError::Invalid);
        }
        if self.selected_headers_bytes == 0 || self.selected_headers_bytes > 64 * 1_024 {
            return Err(ConfigurationError::Invalid);
        }
        if self.pre_authentication_requests_per_peer_minute == 0
            || self.pre_authentication_requests_per_peer_minute > 600
            || self.pre_authentication_requests_per_route_minute == 0
            || self.pre_authentication_requests_per_route_minute > 1_200
        {
            return Err(ConfigurationError::Invalid);
        }
        Ok(RawLimits {
            selected_header_bytes: self.selected_header_bytes,
            selected_headers_bytes: self.selected_headers_bytes,
            peer_rate: self.pre_authentication_requests_per_peer_minute,
            route_rate: self.pre_authentication_requests_per_route_minute,
        })
    }
}

impl Default for LimitsInput {
    fn default() -> Self {
        Self {
            body_bytes: bondry_webhook_ingress::DEFAULT_WEBHOOK_BODY_BYTES,
            retained_bytes: bondry_webhook_ingress::DEFAULT_WEBHOOK_RETAINED_BYTES,
            selected_headers: bondry_webhook_ingress::DEFAULT_WEBHOOK_SELECTED_HEADERS,
            selected_header_bytes: DEFAULT_SELECTED_HEADER_BYTES,
            selected_headers_bytes: DEFAULT_SELECTED_HEADERS_BYTES,
            pre_authentication_requests_per_peer_minute: DEFAULT_PRE_AUTHENTICATION_PEER_RATE,
            pre_authentication_requests_per_route_minute: DEFAULT_PRE_AUTHENTICATION_ROUTE_RATE,
        }
    }
}

const fn default_success_status() -> u16 {
    204
}

const fn default_tolerance() -> u64 {
    300
}
