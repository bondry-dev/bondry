use std::{borrow::Borrow, collections::BTreeMap, fmt, sync::Arc};

use bytes::Bytes;
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use thiserror::Error;

use crate::{
    MAX_JSON_NESTING_DEPTH, MAX_PAYLOAD_FIELD_NAME_BYTES, MAX_PAYLOAD_FIELDS, PayloadLimit,
};

/// A bounded portable top-level JSON field name.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct PayloadFieldName(Arc<str>);

impl PayloadFieldName {
    /// Creates a field name accepted by route contracts.
    pub fn new(value: impl Into<Arc<str>>) -> Result<Self, PayloadError> {
        let value = value.into();
        if value.is_empty() {
            return Err(PayloadError::EmptyFieldName);
        }
        if value.len() > MAX_PAYLOAD_FIELD_NAME_BYTES {
            return Err(PayloadError::FieldNameTooLong);
        }
        if !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | ':' | '_' | '-')
        }) {
            return Err(PayloadError::InvalidFieldName);
        }
        Ok(Self(value))
    }

    /// Returns the validated field name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PayloadFieldName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PayloadFieldName")
            .field(&self.0)
            .finish()
    }
}

impl Borrow<str> for PayloadFieldName {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

/// The JSON value shape declared for one top-level field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadFieldType {
    /// Any bounded JSON value.
    Any,
    /// JSON null.
    Null,
    /// A JSON boolean.
    Boolean,
    /// A JSON number.
    Number,
    /// A JSON string.
    String,
    /// A JSON array.
    Array,
    /// A JSON object.
    Object,
}

/// One declared top-level payload field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadField {
    name: PayloadFieldName,
    field_type: PayloadFieldType,
    required: bool,
}

impl PayloadField {
    /// Declares a field, its JSON shape, and whether it is required.
    #[must_use]
    pub const fn new(name: PayloadFieldName, field_type: PayloadFieldType, required: bool) -> Self {
        Self {
            name,
            field_type,
            required,
        }
    }

    /// Returns the declared name.
    #[must_use]
    pub const fn name(&self) -> &PayloadFieldName {
        &self.name
    }

    /// Returns the declared JSON shape.
    #[must_use]
    pub const fn field_type(&self) -> PayloadFieldType {
        self.field_type
    }

    /// Returns whether the field must be present.
    #[must_use]
    pub const fn is_required(&self) -> bool {
        self.required
    }
}

/// A closed, bounded top-level JSON payload contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadContract {
    fields: BTreeMap<PayloadFieldName, PayloadField>,
    limit: PayloadLimit,
}

impl PayloadContract {
    /// Creates a contract and rejects duplicate or unbounded declarations.
    pub fn new(
        fields: impl IntoIterator<Item = PayloadField>,
        limit: PayloadLimit,
    ) -> Result<Self, PayloadError> {
        let mut declared = BTreeMap::new();
        for field in fields {
            if declared.len() >= MAX_PAYLOAD_FIELDS {
                return Err(PayloadError::TooManyFields);
            }
            if declared.insert(field.name.clone(), field).is_some() {
                return Err(PayloadError::DuplicateContractField);
            }
        }
        Ok(Self {
            fields: declared,
            limit,
        })
    }

    /// Returns the route's encoded event bound.
    #[must_use]
    pub const fn limit(&self) -> PayloadLimit {
        self.limit
    }

    /// Validates exact JSON bytes without retaining a parsed duplicate.
    pub fn validate(&self, bytes: Bytes) -> Result<EventPayload, PayloadError> {
        if bytes.len() > self.limit.get() {
            return Err(PayloadError::TooLarge);
        }
        let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
        let actual = PayloadDocumentSeed
            .deserialize(&mut deserializer)
            .and_then(|fields| {
                deserializer.end()?;
                Ok(fields)
            })
            .map_err(|_| PayloadError::InvalidJson)?;
        let mut present = BTreeMap::new();
        for (name, field_type) in actual {
            let Some(declared) = self.fields.get(name.as_str()) else {
                return Err(PayloadError::UndeclaredField);
            };
            if declared.field_type != PayloadFieldType::Any && declared.field_type != field_type {
                return Err(PayloadError::FieldTypeMismatch);
            }
            present.insert(name, ());
        }
        if self
            .fields
            .values()
            .any(|field| field.required && !present.contains_key(field.name.as_str()))
        {
            return Err(PayloadError::MissingRequiredField);
        }
        Ok(EventPayload(bytes))
    }
}

/// Validated exact event bytes retained for delivery.
#[derive(Clone, Eq, PartialEq)]
pub struct EventPayload(Bytes);

impl EventPayload {
    /// Returns exact validated bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &Bytes {
        &self.0
    }

    /// Returns retained payload bytes for queue accounting.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the validated JSON object has zero encoded bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for EventPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventPayload")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// A payload or declared payload contract that cannot be accepted safely.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PayloadError {
    /// A declared field name is empty.
    #[error("payload field name cannot be empty")]
    EmptyFieldName,
    /// A declared field name exceeds its fixed bound.
    #[error("payload field name exceeds the maximum length")]
    FieldNameTooLong,
    /// A declared field name is not portable ASCII.
    #[error("payload field name contains an invalid character")]
    InvalidFieldName,
    /// A contract contains more than 64 fields.
    #[error("payload contract declares too many fields")]
    TooManyFields,
    /// A contract declares the same field twice.
    #[error("payload contract contains a duplicate field")]
    DuplicateContractField,
    /// Exact event bytes exceed the route bound.
    #[error("event payload exceeds the route limit")]
    TooLarge,
    /// Event bytes are malformed, ambiguous, too deep, or not a JSON object.
    #[error("event payload is not an accepted JSON object")]
    InvalidJson,
    /// The event contains a top-level field outside the declared set.
    #[error("event payload contains an undeclared field")]
    UndeclaredField,
    /// A required top-level field is absent.
    #[error("event payload is missing a required field")]
    MissingRequiredField,
    /// A field's JSON shape differs from its declaration.
    #[error("event payload field has the wrong JSON type")]
    FieldTypeMismatch,
}

struct PayloadDocumentSeed;

impl<'de> DeserializeSeed<'de> for PayloadDocumentSeed {
    type Value = Vec<(String, PayloadFieldType)>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(PayloadDocumentVisitor)
    }
}

struct PayloadDocumentVisitor;

impl<'de> Visitor<'de> for PayloadDocumentVisitor {
    type Value = Vec<(String, PayloadFieldType)>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON object without duplicate keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = BTreeMap::new();
        while let Some(name) = map.next_key::<String>()? {
            if fields.len() >= MAX_PAYLOAD_FIELDS {
                return Err(de::Error::custom("too many top-level JSON fields"));
            }
            if fields.contains_key(&name) {
                return Err(de::Error::custom("duplicate JSON field"));
            }
            let field_type = map.next_value_seed(PayloadValueSeed { depth: 2 })?;
            fields.insert(name, field_type);
        }
        Ok(fields.into_iter().collect())
    }
}

struct PayloadValueSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for PayloadValueSeed {
    type Value = PayloadFieldType;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PayloadValueVisitor { depth: self.depth })
    }
}

struct PayloadValueVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for PayloadValueVisitor {
    type Value = PayloadFieldType;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(PayloadFieldType::Boolean)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(PayloadFieldType::Number)
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(PayloadFieldType::Number)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(PayloadFieldType::Number)
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(PayloadFieldType::String)
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(PayloadFieldType::String)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(PayloadFieldType::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(PayloadFieldType::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        self.check_depth::<A::Error>()?;
        while sequence
            .next_element_seed(PayloadValueSeed {
                depth: self.depth + 1,
            })?
            .is_some()
        {}
        Ok(PayloadFieldType::Array)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        self.check_depth::<A::Error>()?;
        let mut names = BTreeMap::new();
        while let Some(name) = map.next_key::<String>()? {
            if names.insert(name, ()).is_some() {
                return Err(de::Error::custom("duplicate JSON field"));
            }
            let _ = map.next_value_seed(PayloadValueSeed {
                depth: self.depth + 1,
            })?;
        }
        Ok(PayloadFieldType::Object)
    }
}

impl PayloadValueVisitor {
    fn check_depth<E: de::Error>(&self) -> Result<(), E> {
        if self.depth > MAX_JSON_NESTING_DEPTH {
            Err(E::custom("JSON nesting depth exceeded"))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{
        EventPayload, PayloadContract, PayloadError, PayloadField, PayloadFieldName,
        PayloadFieldType,
    };
    use crate::{MAX_PAYLOAD_FIELDS, PayloadLimit};

    fn contract() -> Result<PayloadContract, PayloadError> {
        PayloadContract::new(
            [
                PayloadField::new(
                    PayloadFieldName::new("event")?,
                    PayloadFieldType::String,
                    true,
                ),
                PayloadField::new(
                    PayloadFieldName::new("metadata")?,
                    PayloadFieldType::Object,
                    false,
                ),
            ],
            PayloadLimit::default(),
        )
    }

    #[test]
    fn accepts_exact_declared_fields_without_retaining_a_parsed_copy()
    -> Result<(), Box<dyn std::error::Error>> {
        let payload = contract()?.validate(Bytes::from_static(
            br#"{"event":"power_lost","metadata":{"battery":42}}"#,
        ))?;
        assert_eq!(payload.len(), payload.as_bytes().len());
        assert_eq!(
            format!("{payload:?}"),
            format!("EventPayload {{ bytes: {} }}", payload.len())
        );
        Ok(())
    }

    #[test]
    fn rejects_undeclared_missing_wrong_type_and_duplicate_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let contract = contract()?;
        assert_eq!(
            contract.validate(Bytes::from_static(br#"{"event":"lost","secret":true}"#)),
            Err(PayloadError::UndeclaredField)
        );
        assert_eq!(
            contract.validate(Bytes::from_static(br#"{"metadata":{}}"#)),
            Err(PayloadError::MissingRequiredField)
        );
        assert_eq!(
            contract.validate(Bytes::from_static(br#"{"event":42}"#)),
            Err(PayloadError::FieldTypeMismatch)
        );
        assert_eq!(
            contract.validate(Bytes::from_static(br#"{"event":"a","event":"b"}"#)),
            Err(PayloadError::InvalidJson)
        );
        assert_eq!(
            contract.validate(Bytes::from_static(
                br#"{"event":"a","metadata":{"x":1,"x":2}}"#
            )),
            Err(PayloadError::InvalidJson)
        );
        Ok(())
    }

    #[test]
    fn rejects_excessive_depth_and_contract_size() -> Result<(), Box<dyn std::error::Error>> {
        let nested = format!(
            "{{\"event\":\"a\",\"metadata\":{}{}}}",
            "[".repeat(32),
            "]".repeat(32)
        );
        assert_eq!(
            contract()?.validate(Bytes::from(nested)),
            Err(PayloadError::InvalidJson)
        );
        let fields = (0..=MAX_PAYLOAD_FIELDS)
            .map(|index| {
                Ok(PayloadField::new(
                    PayloadFieldName::new(format!("field_{index}"))?,
                    PayloadFieldType::Any,
                    false,
                ))
            })
            .collect::<Result<Vec<_>, PayloadError>>()?;
        assert_eq!(
            PayloadContract::new(fields, PayloadLimit::default()),
            Err(PayloadError::TooManyFields)
        );

        let object = format!(
            "{{{}}}",
            (0..=MAX_PAYLOAD_FIELDS)
                .map(|index| format!("\"field_{index}\":null"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let empty = PayloadContract::new([], PayloadLimit::default())?;
        assert_eq!(
            empty.validate(Bytes::from(object)),
            Err(PayloadError::InvalidJson)
        );
        Ok(())
    }

    #[test]
    fn redacts_payload_bytes_from_debug() {
        let payload = EventPayload(Bytes::from_static(br#"{"private":"marker"}"#));
        assert!(!format!("{payload:?}").contains("marker"));
    }
}
