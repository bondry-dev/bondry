use std::{fmt, sync::Arc};

use thiserror::Error;

/// Fixed maximum route identifier length from the limits contract.
pub const MAX_ROUTE_ID_BYTES: usize = 128;
/// Maximum delivery identifier length from the limits contract.
pub const MAX_DELIVERY_ID_BYTES: usize = 128;
/// Fixed maximum verifier namespace length from the limits contract.
pub const MAX_VERIFIER_NAMESPACE_BYTES: usize = 128;

fn validate(value: &str, maximum: usize) -> Result<(), PersistenceIdentifierError> {
    if value.is_empty() {
        return Err(PersistenceIdentifierError::Empty);
    }
    if value.len() > maximum {
        return Err(PersistenceIdentifierError::TooLong { maximum });
    }
    if let Some((index, character)) = value
        .char_indices()
        .find(|(_, character)| !is_allowed(*character))
    {
        return Err(PersistenceIdentifierError::InvalidCharacter { index, character });
    }
    Ok(())
}

fn is_allowed(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | ':' | '_' | '-')
}

macro_rules! persistence_identifier {
    ($name:ident, $maximum:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Arc<str>);

        impl $name {
            /// Creates a bounded portable identifier.
            pub fn new(value: impl Into<Arc<str>>) -> Result<Self, PersistenceIdentifierError> {
                let value = value.into();
                validate(&value, $maximum)?;
                Ok(Self(value))
            }

            /// Returns the validated identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

persistence_identifier!(
    RouteId,
    MAX_ROUTE_ID_BYTES,
    "A stable identifier for an egress or ingress route."
);
persistence_identifier!(
    DeliveryId,
    MAX_DELIVERY_ID_BYTES,
    "A unique identifier assigned to an accepted delivery."
);
persistence_identifier!(
    VerifierNamespace,
    MAX_VERIFIER_NAMESPACE_BYTES,
    "A stable namespace separating trusted delivery identifiers."
);

/// A malformed persistence identifier.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PersistenceIdentifierError {
    /// The identifier is empty.
    #[error("a persistence identifier cannot be empty")]
    Empty,
    /// The encoded identifier exceeds its contract bound.
    #[error("a persistence identifier cannot exceed {maximum} bytes")]
    TooLong {
        /// The maximum encoded byte length.
        maximum: usize,
    },
    /// The identifier contains a character outside the portable set.
    #[error("a persistence identifier contains invalid character '{character}' at byte {index}")]
    InvalidCharacter {
        /// The byte offset of the invalid character.
        index: usize,
        /// The invalid character.
        character: char,
    },
}

#[cfg(test)]
mod tests {
    use super::{
        DeliveryId, MAX_DELIVERY_ID_BYTES, PersistenceIdentifierError, RouteId, VerifierNamespace,
    };

    #[test]
    fn accepts_portable_identifiers() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(RouteId::new("power.watchdog")?.as_str(), "power.watchdog");
        assert_eq!(
            DeliveryId::new("delivery_01-AB")?.as_str(),
            "delivery_01-AB"
        );
        assert_eq!(VerifierNamespace::new("github:v1")?.as_str(), "github:v1");
        Ok(())
    }

    #[test]
    fn rejects_empty_oversized_and_nonportable_identifiers() {
        assert_eq!(DeliveryId::new(""), Err(PersistenceIdentifierError::Empty));
        assert_eq!(
            DeliveryId::new("a".repeat(MAX_DELIVERY_ID_BYTES + 1)),
            Err(PersistenceIdentifierError::TooLong {
                maximum: MAX_DELIVERY_ID_BYTES,
            })
        );
        assert!(matches!(
            RouteId::new("unsafe/path"),
            Err(PersistenceIdentifierError::InvalidCharacter { .. })
        ));
    }
}
