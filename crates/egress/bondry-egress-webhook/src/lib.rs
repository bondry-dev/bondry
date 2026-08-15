#![doc = "Sans-I/O webhook composition and response classification for Bondry egress."]

mod limits;
mod template;
mod webhook;

pub use limits::{
    DEFAULT_EXPANDED_URL_BYTES, DEFAULT_URL_TEMPLATE_BYTES, DEFAULT_WEBHOOK_BODY_BYTES,
    MAX_EXPANDED_URL_BYTES, MAX_URL_TEMPLATE_BYTES, MAX_WEBHOOK_BODY_BYTES, MIN_WEBHOOK_BODY_BYTES,
    UrlTemplateLimits, WebhookLimitError, WebhookLimits,
};
pub use template::{SECRET_URL_PLACEHOLDER, SecretUrlTemplate, UrlTemplateError};
pub use webhook::{WebhookAuthentication, WebhookConfigurationError, WebhookDeliveryKind};

pub use bondry_secrets::{
    BONDRY_WEBHOOK_DELIVERY_ID_HEADER, BONDRY_WEBHOOK_SIGNATURE_HEADER,
    BONDRY_WEBHOOK_TIMESTAMP_HEADER,
};
