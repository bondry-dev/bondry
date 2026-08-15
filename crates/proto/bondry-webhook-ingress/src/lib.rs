#![doc = "Sans-I/O verified webhook routing to fixed Bondry capabilities."]

mod limiter;
mod limits;
mod payload;
mod response;
mod route;
#[cfg(test)]
mod tests;

pub use limiter::{AuthenticatedRequestLimitError, AuthenticatedRequestLimiter};
pub use limits::{
    DEFAULT_WEBHOOK_BODY_BYTES, DEFAULT_WEBHOOK_RETAINED_BYTES, DEFAULT_WEBHOOK_SELECTED_HEADERS,
    MAX_WEBHOOK_BODY_BYTES, MAX_WEBHOOK_RETAINED_BYTES, MAX_WEBHOOK_SELECTED_HEADERS,
    MIN_WEBHOOK_BODY_BYTES, WebhookIngressLimitError, WebhookIngressLimits,
};
pub use response::WebhookIngressResponse;
pub use route::{
    CapabilitySemantics, PayloadMapping, WebhookDispatch, WebhookIngressContext,
    WebhookIngressTime, WebhookRoute, WebhookRouteConfiguration, WebhookRouteError,
};
