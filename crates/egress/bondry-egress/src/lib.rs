#![doc = "Sans-I/O route and delivery lifecycle core for Bondry egress."]

mod delivery;
mod kind;
mod limits;
mod payload;
mod route;
mod time;

pub use delivery::{
    DeliveryAction, DeliveryEvent, DeliveryLifecycle, DeliveryLifecycleError,
    DeliveryPersistenceAction, DeliveryTransition, RetryableFailure,
};
pub use kind::{
    AttemptContext, AttemptDisposition, DeliveryKind, DeliveryOperation, KindOperationError,
    KindTransition, OperationMode, TransportCompletion,
};
pub use limits::{
    DEFAULT_EVENT_PAYLOAD_BYTES, DEFAULT_GLOBAL_ADMISSION_CAPACITY,
    DEFAULT_GLOBAL_ADMISSION_REFILL_PER_SECOND, DEFAULT_REQUEST_TIMEOUT, DEFAULT_RETRY_ATTEMPTS,
    DEFAULT_ROUTE_ADMISSION_CAPACITY, DEFAULT_ROUTE_ADMISSION_REFILL_PER_SECOND,
    DEFAULT_ROUTE_REGISTRY_LIMIT, GlobalAdmissionLimit, LimitError, MAX_EVENT_PAYLOAD_BYTES,
    MAX_JSON_NESTING_DEPTH, MAX_PAYLOAD_FIELD_NAME_BYTES, MAX_PAYLOAD_FIELDS, PayloadLimit,
    RequestTimeout, RetryPolicy, RouteAdmissionLimit, RouteRegistryLimit,
};
pub use payload::{
    EventPayload, PayloadContract, PayloadError, PayloadField, PayloadFieldName, PayloadFieldType,
};
pub use route::{
    AdmissionError, AdmittedDelivery, AdmittedDeliveryParts, Route, RouteRegistry,
    RouteRegistryError, RouteSummary,
};
pub use time::{EgressInstant, TransitionTime};

pub use bondry_delivery_store::{DeliveryId, RouteId};
