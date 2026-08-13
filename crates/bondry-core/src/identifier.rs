use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

const MAX_IDENTIFIER_LENGTH: usize = 128;

/// An error produced when a Bondry identifier is invalid.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IdentifierError {
    /// The identifier is empty.
    #[error("an identifier cannot be empty")]
    Empty,
    /// The identifier exceeds the maximum encoded length.
    #[error("an identifier cannot exceed {MAX_IDENTIFIER_LENGTH} bytes")]
    TooLong,
    /// The identifier contains a character outside the portable identifier set.
    #[error("an identifier contains invalid character '{character}' at byte {index}")]
    InvalidCharacter {
        /// The byte offset of the invalid character.
        index: usize,
        /// The invalid character.
        character: char,
    },
}

fn validate(value: &str) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty);
    }
    if value.len() > MAX_IDENTIFIER_LENGTH {
        return Err(IdentifierError::TooLong);
    }
    if let Some((index, character)) = value
        .char_indices()
        .find(|(_, character)| !is_allowed(*character))
    {
        return Err(IdentifierError::InvalidCharacter { index, character });
    }
    Ok(())
}

fn is_allowed(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | ':' | '_' | '-')
}

macro_rules! identifier {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Creates a validated identifier.
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                let value = value.into();
                validate(&value)?;
                Ok(Self(value))
            }

            /// Returns the identifier as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = IdentifierError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

identifier!(
    AdapterId,
    "A stable identifier for the adapter through which an invocation arrived."
);
identifier!(CapabilityId, "A stable identifier for a capability.");
identifier!(
    HandlerErrorCode,
    "A stable, non-sensitive code describing a handler failure."
);
identifier!(InvocationId, "A unique identifier for an invocation.");
identifier!(
    PrincipalId,
    "A stable identifier for an authenticated principal."
);
