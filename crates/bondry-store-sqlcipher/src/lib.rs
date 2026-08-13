#![doc = "Optional encrypted SQLCipher persistence for Bondry authentication and audit events."]

mod audit;
mod auth;
mod database;
mod key;

pub use audit::{AuditQueryLimit, AuditQueryLimitError, StoredAuditEvent};
pub use database::{SqlCipherStore, SqlCipherStoreError};
pub use key::{DatabaseKey, DatabaseKeyError};

#[cfg(test)]
mod tests;
