use std::time::{Duration, UNIX_EPOCH};

use bondry_core::{
    AdapterId, AuditError, AuditEvent, AuditOutcome, AuditSink, CapabilityId, DenialReason,
    HandlerErrorCode, InvocationId, PrincipalId,
};
use rusqlite::{Row, params};
use thiserror::Error;

use crate::{SqlCipherStore, SqlCipherStoreError};

const MAX_AUDIT_QUERY_LIMIT: u32 = 1_000;

/// A bounded number of audit events to return from one query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditQueryLimit(u32);

impl AuditQueryLimit {
    /// Creates a nonzero query limit of at most 1,000 events.
    pub const fn new(value: u32) -> Result<Self, AuditQueryLimitError> {
        if value == 0 || value > MAX_AUDIT_QUERY_LIMIT {
            return Err(AuditQueryLimitError);
        }
        Ok(Self(value))
    }

    const fn as_i64(self) -> i64 {
        self.0 as i64
    }
}

/// An audit query limit outside the supported range.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("audit query limit must be between 1 and {MAX_AUDIT_QUERY_LIMIT}")]
pub struct AuditQueryLimitError;

/// A persisted audit event with its monotonically increasing database sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredAuditEvent {
    sequence: i64,
    event: AuditEvent,
}

impl StoredAuditEvent {
    /// Returns the database sequence assigned to the event.
    #[must_use]
    pub const fn sequence(&self) -> i64 {
        self.sequence
    }

    /// Returns the protocol-neutral event.
    #[must_use]
    pub const fn event(&self) -> &AuditEvent {
        &self.event
    }
}

impl SqlCipherStore {
    /// Returns the newest audit events in descending sequence order.
    pub fn recent_audit_events(
        &self,
        limit: AuditQueryLimit,
    ) -> Result<Vec<StoredAuditEvent>, SqlCipherStoreError> {
        self.query_audit_events(
            "SELECT
                 sequence, occurred_at_ms, invocation_id, principal_id, adapter_id,
                 capability_id, outcome_kind, detail_code
             FROM audit_events
             ORDER BY sequence DESC
             LIMIT ?1",
            rusqlite::params![limit.as_i64()],
        )
    }

    /// Returns the newest audit events for one principal in descending sequence order.
    pub fn audit_events_for_principal(
        &self,
        principal: &PrincipalId,
        limit: AuditQueryLimit,
    ) -> Result<Vec<StoredAuditEvent>, SqlCipherStoreError> {
        self.query_audit_events(
            "SELECT
                 sequence, occurred_at_ms, invocation_id, principal_id, adapter_id,
                 capability_id, outcome_kind, detail_code
             FROM audit_events
             WHERE principal_id = ?1
             ORDER BY sequence DESC
             LIMIT ?2",
            rusqlite::params![principal.as_str(), limit.as_i64()],
        )
    }

    fn query_audit_events<P>(
        &self,
        sql: &str,
        parameters: P,
    ) -> Result<Vec<StoredAuditEvent>, SqlCipherStoreError>
    where
        P: rusqlite::Params,
    {
        let connection = self.connection()?;
        let mut statement = connection.prepare_cached(sql)?;
        let rows = statement.query_map(parameters, RawAuditEvent::read)?;
        let mut events = Vec::new();
        for row in rows {
            events.push(row?.validate()?);
        }
        Ok(events)
    }
}

impl AuditSink for SqlCipherStore {
    fn record(&self, event: AuditEvent) -> Result<(), AuditError> {
        let occurred_at_ms = event
            .occurred_at()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_millis()).ok())
            .ok_or(AuditError::Unavailable)?;
        let (outcome_kind, detail_code) = encode_outcome(event.outcome());
        let connection = self
            .connection
            .lock()
            .map_err(|_| AuditError::Unavailable)?;
        let mut statement = connection
            .prepare_cached(
                "INSERT INTO audit_events (
                     occurred_at_ms, invocation_id, principal_id, adapter_id,
                     capability_id, outcome_kind, detail_code
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .map_err(|_| AuditError::Unavailable)?;
        statement
            .execute(params![
                occurred_at_ms,
                event.invocation().as_str(),
                event.principal().as_str(),
                event.adapter().as_str(),
                event.capability().as_str(),
                outcome_kind,
                detail_code,
            ])
            .map(|_| ())
            .map_err(|_| AuditError::Unavailable)
    }
}

fn encode_outcome(outcome: &AuditOutcome) -> (&'static str, Option<&str>) {
    match outcome {
        AuditOutcome::CapabilityNotFound => ("capability_not_found", None),
        AuditOutcome::Denied(DenialReason::NotGranted) => ("denied", Some("not_granted")),
        AuditOutcome::Denied(DenialReason::PolicyUnavailable) => {
            ("denied", Some("policy_unavailable"))
        }
        AuditOutcome::Started => ("started", None),
        AuditOutcome::InvalidInput => ("invalid_input", None),
        AuditOutcome::Succeeded => ("succeeded", None),
        AuditOutcome::HandlerFailed(code) => ("handler_failed", Some(code.as_str())),
    }
}

struct RawAuditEvent {
    sequence: i64,
    occurred_at_ms: i64,
    invocation: String,
    principal: String,
    adapter: String,
    capability: String,
    outcome_kind: String,
    detail_code: Option<String>,
}

impl RawAuditEvent {
    fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            sequence: row.get(0)?,
            occurred_at_ms: row.get(1)?,
            invocation: row.get(2)?,
            principal: row.get(3)?,
            adapter: row.get(4)?,
            capability: row.get(5)?,
            outcome_kind: row.get(6)?,
            detail_code: row.get(7)?,
        })
    }

    fn validate(self) -> Result<StoredAuditEvent, SqlCipherStoreError> {
        let milliseconds =
            u64::try_from(self.occurred_at_ms).map_err(|_| SqlCipherStoreError::InvalidData)?;
        let outcome = decode_outcome(&self.outcome_kind, self.detail_code.as_deref())?;
        Ok(StoredAuditEvent {
            sequence: self.sequence,
            event: AuditEvent::from_parts(
                UNIX_EPOCH + Duration::from_millis(milliseconds),
                InvocationId::new(self.invocation).map_err(|_| SqlCipherStoreError::InvalidData)?,
                PrincipalId::new(self.principal).map_err(|_| SqlCipherStoreError::InvalidData)?,
                AdapterId::new(self.adapter).map_err(|_| SqlCipherStoreError::InvalidData)?,
                CapabilityId::new(self.capability).map_err(|_| SqlCipherStoreError::InvalidData)?,
                outcome,
            ),
        })
    }
}

fn decode_outcome(
    outcome_kind: &str,
    detail_code: Option<&str>,
) -> Result<AuditOutcome, SqlCipherStoreError> {
    match (outcome_kind, detail_code) {
        ("capability_not_found", None) => Ok(AuditOutcome::CapabilityNotFound),
        ("denied", Some("not_granted")) => Ok(AuditOutcome::Denied(DenialReason::NotGranted)),
        ("denied", Some("policy_unavailable")) => {
            Ok(AuditOutcome::Denied(DenialReason::PolicyUnavailable))
        }
        ("started", None) => Ok(AuditOutcome::Started),
        ("invalid_input", None) => Ok(AuditOutcome::InvalidInput),
        ("succeeded", None) => Ok(AuditOutcome::Succeeded),
        ("handler_failed", Some(code)) => Ok(AuditOutcome::HandlerFailed(
            HandlerErrorCode::new(code).map_err(|_| SqlCipherStoreError::InvalidData)?,
        )),
        _ => Err(SqlCipherStoreError::InvalidData),
    }
}
