use std::{fmt, sync::Arc};

use bondry_secrets::{ResolvedSecret, SecretRef};
use bondry_transport::{NetworkEndpoint, NetworkScheme};
use http::Uri;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::UrlTemplateLimits;

/// The single secret placeholder accepted in a redacted URL template.
pub const SECRET_URL_PLACEHOLDER: &str = "{secret}";
const PARSE_SENTINEL: &str = "bondry-secret-placeholder-8c09e98d";

/// A structurally constrained URL carrying one host-owned secret reference.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretUrlTemplate {
    redacted: Arc<str>,
    reference: SecretRef,
    parsed: NetworkEndpoint,
    limits: UrlTemplateLimits,
}

impl SecretUrlTemplate {
    /// Parses a template whose only secret is one complete placeholder path segment or query value.
    pub fn new(
        redacted: impl Into<Arc<str>>,
        reference: SecretRef,
        limits: UrlTemplateLimits,
    ) -> Result<Self, UrlTemplateError> {
        let redacted = redacted.into();
        if redacted.is_empty() || redacted.len() > limits.template_bytes() {
            return Err(UrlTemplateError::TemplateLength);
        }
        if redacted.contains('#') {
            return Err(UrlTemplateError::FragmentForbidden);
        }
        if redacted.contains(PARSE_SENTINEL) {
            return Err(UrlTemplateError::AmbiguousTemplate);
        }
        if redacted.match_indices(SECRET_URL_PLACEHOLDER).count() != 1 {
            return Err(UrlTemplateError::PlaceholderCount);
        }
        let parseable = redacted.replacen(SECRET_URL_PLACEHOLDER, PARSE_SENTINEL, 1);
        let uri = parseable
            .parse::<Uri>()
            .map_err(|_| UrlTemplateError::InvalidEndpoint)?;
        if !placeholder_is_complete(&uri) {
            return Err(UrlTemplateError::PlaceholderPosition);
        }
        let parsed = NetworkEndpoint::new(uri).map_err(|_| UrlTemplateError::InvalidEndpoint)?;
        if !matches!(parsed.scheme(), NetworkScheme::Http | NetworkScheme::Https) {
            return Err(UrlTemplateError::InvalidEndpoint);
        }
        Ok(Self {
            redacted,
            reference,
            parsed,
            limits,
        })
    }

    /// Returns the unresolved host-owned secret reference.
    #[must_use]
    pub const fn secret_reference(&self) -> &SecretRef {
        &self.reference
    }

    /// Returns the redacted template without resolved material.
    #[must_use]
    pub fn redacted(&self) -> &str {
        &self.redacted
    }

    /// Expands current secret bytes as one percent-encoded URL component.
    pub fn expand(&self, secret: &ResolvedSecret) -> Result<NetworkEndpoint, UrlTemplateError> {
        let encoded = Zeroizing::new(percent_encode(secret.current_value().expose()));
        let expanded = Zeroizing::new(self.redacted.replacen(
            SECRET_URL_PLACEHOLDER,
            encoded.as_str(),
            1,
        ));
        if expanded.len() > self.limits.expanded_bytes() {
            return Err(UrlTemplateError::ExpandedLength);
        }
        let uri = expanded
            .parse::<Uri>()
            .map_err(|_| UrlTemplateError::InvalidExpansion)?;
        let endpoint = NetworkEndpoint::new(uri).map_err(|_| UrlTemplateError::InvalidExpansion)?;
        if !same_origin(&self.parsed, &endpoint) {
            return Err(UrlTemplateError::OriginChanged);
        }
        Ok(endpoint)
    }
}

impl fmt::Debug for SecretUrlTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SecretUrlTemplate")
            .field(&self.redacted)
            .finish()
    }
}

impl fmt::Display for SecretUrlTemplate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.redacted)
    }
}

/// A URL template that cannot preserve the configured security boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum UrlTemplateError {
    /// The redacted template is empty or exceeds its configured cap.
    #[error("URL template length is invalid")]
    TemplateLength,
    /// Exactly one secret placeholder is required.
    #[error("URL template must contain exactly one secret placeholder")]
    PlaceholderCount,
    /// The placeholder collides with the internal parse sentinel.
    #[error("URL template is ambiguous")]
    AmbiguousTemplate,
    /// URI fragments are forbidden.
    #[error("URL template fragments are forbidden")]
    FragmentForbidden,
    /// The redacted template is not a supported absolute endpoint.
    #[error("URL template endpoint is invalid")]
    InvalidEndpoint,
    /// The placeholder is not one complete path segment or query value.
    #[error("URL template placeholder position is invalid")]
    PlaceholderPosition,
    /// The expanded endpoint exceeds its configured cap.
    #[error("expanded URL exceeds the configured limit")]
    ExpandedLength,
    /// Percent-encoded substitution did not produce a valid endpoint.
    #[error("expanded URL is invalid")]
    InvalidExpansion,
    /// Expansion changed the exact configured origin.
    #[error("expanded URL changed the configured origin")]
    OriginChanged,
}

fn placeholder_is_complete(uri: &Uri) -> bool {
    let path_matches = uri
        .path()
        .split('/')
        .filter(|segment| *segment == PARSE_SENTINEL)
        .count();
    let query_matches = uri.query().map_or(0, |query| {
        query
            .split('&')
            .filter(|pair| {
                pair.split_once('=')
                    .is_some_and(|(_, value)| value == PARSE_SENTINEL)
            })
            .count()
    });
    path_matches + query_matches == 1
}

fn same_origin(configured: &NetworkEndpoint, expanded: &NetworkEndpoint) -> bool {
    configured.uri().scheme_str() == expanded.uri().scheme_str()
        && configured
            .uri()
            .authority()
            .map(http::uri::Authority::as_str)
            == expanded.uri().authority().map(http::uri::Authority::as_str)
}

fn percent_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(3));
    for byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(*byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(*byte & 0x0f)]));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use bondry_secrets::{ResolvedSecret, SecretRef, SecretValue};

    use super::{SECRET_URL_PLACEHOLDER, SecretUrlTemplate, UrlTemplateError};
    use crate::UrlTemplateLimits;

    fn secret() -> Result<ResolvedSecret, Box<dyn std::error::Error>> {
        Ok(ResolvedSecret::current(SecretValue::new(
            b"a/b?c#d &\0".to_vec(),
        )?))
    }

    #[test]
    fn expands_one_component_and_preserves_origin() -> Result<(), Box<dyn std::error::Error>> {
        let template = SecretUrlTemplate::new(
            format!("https://example.com/topic/{SECRET_URL_PLACEHOLDER}?mode=publish"),
            SecretRef::new("keychain:ntfy-topic")?,
            UrlTemplateLimits::default(),
        )?;
        let endpoint = template.expand(&secret()?)?;
        assert_eq!(
            endpoint.path_and_query(),
            "/topic/a%2Fb%3Fc%23d%20%26%00?mode=publish"
        );
        assert_eq!(endpoint.host(), "example.com");
        assert!(!format!("{template:?}").contains("a/b"));
        assert_eq!(template.to_string(), template.redacted());
        Ok(())
    }

    #[test]
    fn accepts_a_complete_query_value() -> Result<(), Box<dyn std::error::Error>> {
        let template = SecretUrlTemplate::new(
            format!("https://example.com/hook?id={SECRET_URL_PLACEHOLDER}"),
            SecretRef::new("keychain:webhook-id")?,
            UrlTemplateLimits::default(),
        )?;
        assert_eq!(
            template.expand(&secret()?)?.path_and_query(),
            "/hook?id=a%2Fb%3Fc%23d%20%26%00"
        );
        Ok(())
    }

    #[test]
    fn rejects_missing_multiple_or_partial_placeholders() -> Result<(), Box<dyn std::error::Error>>
    {
        let reference = SecretRef::new("keychain:secret")?;
        let limits = UrlTemplateLimits::default();
        assert_eq!(
            SecretUrlTemplate::new("https://example.com/static", reference.clone(), limits),
            Err(UrlTemplateError::PlaceholderCount)
        );
        assert_eq!(
            SecretUrlTemplate::new(
                format!("https://example.com/{SECRET_URL_PLACEHOLDER}/{SECRET_URL_PLACEHOLDER}"),
                reference.clone(),
                limits,
            ),
            Err(UrlTemplateError::PlaceholderCount)
        );
        for invalid in [
            format!("https://{SECRET_URL_PLACEHOLDER}.example.com/hook"),
            format!("https://example.com/prefix-{SECRET_URL_PLACEHOLDER}"),
            format!("https://example.com/?{SECRET_URL_PLACEHOLDER}=value"),
            format!("wss://example.com/{SECRET_URL_PLACEHOLDER}"),
        ] {
            assert!(SecretUrlTemplate::new(invalid, reference.clone(), limits).is_err());
        }
        assert_eq!(
            SecretUrlTemplate::new(
                format!("https://example.com/{SECRET_URL_PLACEHOLDER}#fragment"),
                reference,
                limits,
            ),
            Err(UrlTemplateError::FragmentForbidden)
        );
        Ok(())
    }

    #[test]
    fn enforces_template_and_expansion_bounds() -> Result<(), Box<dyn std::error::Error>> {
        let reference = SecretRef::new("keychain:secret")?;
        let limits = UrlTemplateLimits::new(64, 40)?;
        assert_eq!(
            SecretUrlTemplate::new(
                format!(
                    "https://example.com/{}/{SECRET_URL_PLACEHOLDER}",
                    "a".repeat(64)
                ),
                reference.clone(),
                limits,
            ),
            Err(UrlTemplateError::TemplateLength)
        );
        let template = SecretUrlTemplate::new(
            format!("https://example.com/{SECRET_URL_PLACEHOLDER}"),
            reference,
            limits,
        )?;
        assert_eq!(
            template.expand(&secret()?),
            Err(UrlTemplateError::ExpandedLength)
        );
        Ok(())
    }
}
