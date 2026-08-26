use std::{sync::Arc, time::Duration};

use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    sign::{CertifiedKey, SingleCertAndKey},
};
use thiserror::Error;
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

/// Maximum aggregate DER size accepted for one server certificate chain.
pub const MAX_TLS_CERTIFICATE_CHAIN_BYTES: usize = 256 * 1_024;
/// Maximum PKCS#8 DER size accepted for one server private key.
pub const MAX_TLS_PRIVATE_KEY_BYTES: usize = 64 * 1_024;
const MAX_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// TLS 1.3 identity and handshake policy for one network listener.
#[derive(Clone)]
pub struct TlsServerConfiguration {
    pub(crate) acceptor: TlsAcceptor,
    pub(crate) handshake_timeout: Duration,
}

impl TlsServerConfiguration {
    /// Builds a TLS 1.3 configuration from a leaf-first DER chain and PKCS#8 private key.
    pub fn new(
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_pkcs8_der: Vec<u8>,
        handshake_timeout: Duration,
    ) -> Result<Self, TlsServerConfigurationError> {
        let private_key_pkcs8_der = Zeroizing::new(private_key_pkcs8_der);
        validate_material(
            &certificate_chain_der,
            private_key_pkcs8_der.as_slice(),
            handshake_timeout,
        )?;

        let certificates = certificate_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_pkcs8_der.as_slice()));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&private_key)
            .map_err(|_| TlsServerConfigurationError::InvalidIdentity)?;
        let certified_key = CertifiedKey::new(certificates, signing_key);
        certified_key
            .keys_match()
            .map_err(|_| TlsServerConfigurationError::InvalidIdentity)?;

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| TlsServerConfigurationError::TlsUnavailable)?;
        let configuration = builder
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key)));
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(configuration)),
            handshake_timeout,
        })
    }

    /// Returns the maximum duration allowed for a TLS handshake.
    #[must_use]
    pub const fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }
}

fn validate_material(
    certificate_chain_der: &[Vec<u8>],
    private_key_pkcs8_der: &[u8],
    handshake_timeout: Duration,
) -> Result<(), TlsServerConfigurationError> {
    if certificate_chain_der.is_empty()
        || certificate_chain_der.iter().any(Vec::is_empty)
        || certificate_chain_der
            .iter()
            .try_fold(0_usize, |total, certificate| {
                total.checked_add(certificate.len())
            })
            .is_none_or(|total| total > MAX_TLS_CERTIFICATE_CHAIN_BYTES)
    {
        return Err(TlsServerConfigurationError::InvalidCertificateChain);
    }
    if private_key_pkcs8_der.is_empty() || private_key_pkcs8_der.len() > MAX_TLS_PRIVATE_KEY_BYTES {
        return Err(TlsServerConfigurationError::InvalidPrivateKey);
    }
    if handshake_timeout.is_zero() || handshake_timeout > MAX_TLS_HANDSHAKE_TIMEOUT {
        return Err(TlsServerConfigurationError::InvalidHandshakeTimeout);
    }
    Ok(())
}

/// A rejected TLS server identity or handshake policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TlsServerConfigurationError {
    /// The certificate chain is empty, contains an empty certificate, or exceeds 256 KiB.
    #[error("TLS certificate chain is invalid or too large")]
    InvalidCertificateChain,
    /// The PKCS#8 private key is empty or exceeds 64 KiB.
    #[error("TLS private key is invalid or too large")]
    InvalidPrivateKey,
    /// The certificate and private key could not form a usable server identity.
    #[error("TLS server identity is invalid")]
    InvalidIdentity,
    /// The handshake timeout must be greater than zero and no longer than one minute.
    #[error("TLS handshake timeout is invalid")]
    InvalidHandshakeTimeout,
    /// A TLS 1.3 server configuration could not be created.
    #[error("TLS 1.3 server configuration is unavailable")]
    TlsUnavailable,
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_TLS_CERTIFICATE_CHAIN_BYTES, MAX_TLS_PRIVATE_KEY_BYTES, TlsServerConfiguration,
        TlsServerConfigurationError,
    };
    use std::time::Duration;

    #[test]
    fn rejects_unbounded_or_empty_material_before_parsing() {
        assert_eq!(
            TlsServerConfiguration::new(Vec::new(), vec![1], Duration::from_secs(5)).err(),
            Some(TlsServerConfigurationError::InvalidCertificateChain)
        );
        assert_eq!(
            TlsServerConfiguration::new(
                vec![vec![1; MAX_TLS_CERTIFICATE_CHAIN_BYTES + 1]],
                vec![1],
                Duration::from_secs(5),
            )
            .err(),
            Some(TlsServerConfigurationError::InvalidCertificateChain)
        );
        assert_eq!(
            TlsServerConfiguration::new(
                vec![vec![1]],
                vec![1; MAX_TLS_PRIVATE_KEY_BYTES + 1],
                Duration::from_secs(5),
            )
            .err(),
            Some(TlsServerConfigurationError::InvalidPrivateKey)
        );
        assert_eq!(
            TlsServerConfiguration::new(vec![vec![1]], vec![1], Duration::ZERO).err(),
            Some(TlsServerConfigurationError::InvalidHandshakeTimeout)
        );
    }
}
