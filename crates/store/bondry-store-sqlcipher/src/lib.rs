#![doc = "Optional encrypted SQLCipher persistence for Bondry state."]

mod audit;
mod auth;
mod database;
mod dedup;
mod delivery;
mod grants;
mod key;
mod usage;

pub use audit::{AuditQueryLimit, AuditQueryLimitError, StoredAuditEvent};
pub use database::{SqlCipherStore, SqlCipherStoreError};
pub use dedup::SqlCipherDedupStore;
pub use delivery::SqlCipherDeliveryLog;
pub use key::{DatabaseKey, DatabaseKeyError};

#[cfg(test)]
mod tests;
