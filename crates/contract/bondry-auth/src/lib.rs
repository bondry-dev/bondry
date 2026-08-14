#![doc = "Client identity and local access-token lifecycle for Bondry."]

mod client;
mod manager;
mod store;
mod token;

pub use client::{Client, ClientName, ClientNameError};
pub use manager::{AuthManager, AuthenticationError, ClientManagementError, TokenLifecycleError};
pub use store::{AuthStore, AuthenticationRecord, RotationOutcome, StoreError, TokenReplacement};
pub use token::{
    IssuedToken, SecretToken, TokenDigest, TokenId, TokenIdError, TokenLabel, TokenLabelError,
    TokenMetadata, TokenRecord,
};
