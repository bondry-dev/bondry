#![doc = "Versioned C ABI for composing verified webhooks with a Bondry local server."]

mod abi;
mod config;
mod handler;
mod secrets;
mod service;
mod store;

pub use abi::*;
pub use handler::{bondry_webhook_ingress_handler_release_v1, bondry_webhook_ingress_handler_v1};

/// The first inbound webhook composition ABI version.
pub const BONDRY_WEBHOOK_INGRESS_ABI_VERSION_V1: u32 = 1;

/// Returns the inbound webhook ABI version implemented by the linked library.
#[must_use]
#[unsafe(no_mangle)]
pub extern "C" fn bondry_webhook_ingress_abi_version_v1() -> u32 {
    BONDRY_WEBHOOK_INGRESS_ABI_VERSION_V1
}
