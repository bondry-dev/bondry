#![doc = "Bounded current-thread scheduling and persistence for Bondry egress."]

mod limits;
mod memory_log;

pub use limits::{
    DEFAULT_CALL_IN_FLIGHT, DEFAULT_DRAIN_TIMEOUT, DEFAULT_GLOBAL_IN_FLIGHT,
    DEFAULT_GLOBAL_PENDING_BYTES, DEFAULT_GLOBAL_PENDING_DELIVERIES, DEFAULT_IN_MEMORY_LOG_ENTRIES,
    DEFAULT_ROUTE_IN_FLIGHT, DEFAULT_ROUTE_PENDING_BYTES, DEFAULT_ROUTE_PENDING_DELIVERIES,
    EgressRuntimeLimitError, EgressRuntimeLimits, MAX_IN_MEMORY_LOG_ENTRIES,
    MIN_IN_MEMORY_LOG_ENTRIES,
};
pub use memory_log::{
    InMemoryDeliveryLog, InMemoryDeliveryLogLimit, InMemoryDeliveryLogLimitError,
};
