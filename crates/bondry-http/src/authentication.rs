use std::{net::SocketAddr, sync::Arc};

use bondry_auth::{AuthManager, AuthenticationError as TokenAuthenticationError};
use bondry_core::Principal;
use http::{HeaderMap, Method, Uri, header};
use thiserror::Error;

/// Non-body request metadata available to an HTTP authenticator.
#[derive(Clone, Copy)]
pub struct AuthenticationRequest<'a> {
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    peer: SocketAddr,
}

impl<'a> AuthenticationRequest<'a> {
    pub(crate) const fn new(
        method: &'a Method,
        uri: &'a Uri,
        headers: &'a HeaderMap,
        peer: SocketAddr,
    ) -> Self {
        Self {
            method,
            uri,
            headers,
            peer,
        }
    }

    /// Returns the HTTP method.
    #[must_use]
    pub const fn method(self) -> &'a Method {
        self.method
    }

    /// Returns the request URI.
    #[must_use]
    pub const fn uri(self) -> &'a Uri {
        self.uri
    }

    /// Returns the request headers.
    #[must_use]
    pub const fn headers(self) -> &'a HeaderMap {
        self.headers
    }

    /// Returns the connected peer address.
    #[must_use]
    pub const fn peer(self) -> SocketAddr {
        self.peer
    }
}

/// Authenticates HTTP request metadata into a non-secret principal.
pub trait HttpAuthenticator: Send + Sync {
    /// Authenticates one request without exposing credential rejection details.
    fn authenticate(
        &self,
        request: AuthenticationRequest<'_>,
    ) -> Result<Principal, AuthenticationError>;

    /// Removes every credential-bearing header before adapter dispatch.
    fn redact_credentials(&self, headers: &mut HeaderMap) {
        redact_common_credentials(headers);
    }

    /// Returns the challenge value for a rejected request.
    fn challenge(&self) -> Option<&'static str> {
        None
    }
}

/// Verifies one bearer token into a non-secret principal.
pub trait BearerTokenVerifier: Send + Sync {
    /// Verifies a token without retaining it or revealing rejection details.
    fn verify(&self, token: &str) -> Result<Principal, AuthenticationError>;
}

impl BearerTokenVerifier for AuthManager {
    fn verify(&self, token: &str) -> Result<Principal, AuthenticationError> {
        match self.authenticate(token) {
            Ok(principal) => Ok(principal),
            Err(TokenAuthenticationError::Rejected) => Err(AuthenticationError::Rejected),
            Err(TokenAuthenticationError::StorageUnavailable) => {
                Err(AuthenticationError::Unavailable)
            }
        }
    }
}

/// Bearer authentication backed by a pluggable token verifier.
pub struct BearerAuthenticator {
    verifier: Arc<dyn BearerTokenVerifier>,
}

impl BearerAuthenticator {
    /// Creates a bearer authenticator.
    #[must_use]
    pub const fn new(verifier: Arc<dyn BearerTokenVerifier>) -> Self {
        Self { verifier }
    }
}

impl HttpAuthenticator for BearerAuthenticator {
    fn authenticate(
        &self,
        request: AuthenticationRequest<'_>,
    ) -> Result<Principal, AuthenticationError> {
        let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
        let value = values.next().ok_or(AuthenticationError::Rejected)?;
        if values.next().is_some() {
            return Err(AuthenticationError::Rejected);
        }
        let value = value.to_str().map_err(|_| AuthenticationError::Rejected)?;
        let (scheme, token) = value.split_once(' ').ok_or(AuthenticationError::Rejected)?;
        if !scheme.eq_ignore_ascii_case("Bearer")
            || token.is_empty()
            || token.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(AuthenticationError::Rejected);
        }
        self.verifier.verify(token)
    }

    fn challenge(&self) -> Option<&'static str> {
        Some("Bearer")
    }
}

/// Authentication policy for one local HTTP server.
#[derive(Clone)]
pub enum Authentication {
    /// Every request must pass the configured authenticator.
    Required(Arc<dyn HttpAuthenticator>),
    /// Requests use one explicit principal without credentials.
    Disabled(Principal),
}

impl Authentication {
    /// Requires a custom HTTP authenticator.
    #[must_use]
    pub const fn required(authenticator: Arc<dyn HttpAuthenticator>) -> Self {
        Self::Required(authenticator)
    }

    /// Requires Bondry bearer tokens.
    #[must_use]
    pub fn bearer(manager: Arc<AuthManager>) -> Self {
        Self::Required(Arc::new(BearerAuthenticator::new(manager)))
    }

    /// Disables credentials and assigns every request the supplied principal.
    #[must_use]
    pub const fn disabled(principal: Principal) -> Self {
        Self::Disabled(principal)
    }

    pub(crate) fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled(_))
    }

    pub(crate) fn authenticate(
        &self,
        request: AuthenticationRequest<'_>,
    ) -> Result<Principal, AuthenticationError> {
        match self {
            Self::Required(authenticator) => authenticator.authenticate(request),
            Self::Disabled(principal) => Ok(principal.clone()),
        }
    }

    pub(crate) fn redact_credentials(&self, headers: &mut HeaderMap) {
        match self {
            Self::Required(authenticator) => authenticator.redact_credentials(headers),
            Self::Disabled(_) => redact_common_credentials(headers),
        }
    }

    pub(crate) fn challenge(&self) -> Option<&'static str> {
        match self {
            Self::Required(authenticator) => authenticator.challenge(),
            Self::Disabled(_) => None,
        }
    }
}

fn redact_common_credentials(headers: &mut HeaderMap) {
    headers.remove(header::AUTHORIZATION);
    headers.remove(header::PROXY_AUTHORIZATION);
    headers.remove(header::COOKIE);
}

/// A safe HTTP authentication failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthenticationError {
    /// Credentials were absent, malformed, or rejected.
    #[error("authentication was rejected")]
    Rejected,
    /// Authentication state could not be checked safely.
    #[error("authentication is unavailable")]
    Unavailable,
}
