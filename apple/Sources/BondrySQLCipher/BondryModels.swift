import CBondry
import Foundation

public struct BondryClient: Equatable, Identifiable, Sendable {
  public let id: String
  public let name: String
  public let isEnabled: Bool
  public let createdAt: Date

  init(record: BondryClientV1) throws {
    id = try decodeCString(record.id)
    name = try decodeCString(record.name)
    isEnabled = try decodeBoolean(record.enabled)
    createdAt = Date(timeIntervalSince1970: TimeInterval(record.created_at_unix_seconds))
  }
}

public struct BondryTokenMetadata: Equatable, Identifiable, Sendable {
  public let id: String
  public let clientID: String
  public let label: String?
  public let createdAt: Date
  public let expiresAt: Date?
  public let revokedAt: Date?

  init(record: BondryTokenMetadataV1) throws {
    id = try decodeCString(record.id)
    clientID = try decodeCString(record.client_id)
    label = try decodeOptionalCString(record.label, presence: record.has_label)
    createdAt = Date(timeIntervalSince1970: TimeInterval(record.created_at_unix_seconds))
    expiresAt = try decodeOptionalDate(
      record.expires_at_unix_seconds,
      presence: record.has_expiration
    )
    revokedAt = try decodeOptionalDate(
      record.revoked_at_unix_seconds,
      presence: record.has_revocation
    )
  }
}

public enum BondryPrincipalKind: Equatable, Sendable {
  case user
  case application
  case system
}

public struct BondryPrincipal: Equatable, Identifiable, Sendable {
  public let id: String
  public let kind: BondryPrincipalKind

  init(record: BondryPrincipalV1) throws {
    id = try decodeCString(record.id)
    kind =
      switch record.kind {
      case BONDRY_PRINCIPAL_KIND_USER_V1:
        .user
      case BONDRY_PRINCIPAL_KIND_APPLICATION_V1:
        .application
      case BONDRY_PRINCIPAL_KIND_SYSTEM_V1:
        .system
      default:
        throw BondryEncryptedStoreError.invalidData
      }
  }
}

public struct BondryCapabilityGrant: Equatable, Hashable, Sendable {
  public let principalID: String
  public let adapterID: String
  public let capabilityID: String

  public init(principalID: String, adapterID: String, capabilityID: String) {
    self.principalID = principalID
    self.adapterID = adapterID
    self.capabilityID = capabilityID
  }

  init(record: BondryGrantV1) throws {
    principalID = try decodeCString(record.principal_id)
    adapterID = try decodeCString(record.adapter_id)
    capabilityID = try decodeCString(record.capability_id)
  }
}

public enum BondryAuditOutcome: Equatable, Sendable {
  case capabilityNotFound
  case denied(code: String)
  case started
  case succeeded
  case handlerFailed(code: String)
}

public struct BondryAuditEvent: Equatable, Identifiable, Sendable {
  public var id: Int64 { sequence }

  public let sequence: Int64
  public let occurredAt: Date
  public let invocationID: String
  public let principalID: String
  public let adapterID: String
  public let capabilityID: String
  public let outcome: BondryAuditOutcome

  init(record: BondryAuditEventV1) throws {
    sequence = record.sequence
    occurredAt = Date(
      timeIntervalSince1970: TimeInterval(record.occurred_at_unix_milliseconds) / 1_000
    )
    invocationID = try decodeCString(record.invocation_id)
    principalID = try decodeCString(record.principal_id)
    adapterID = try decodeCString(record.adapter_id)
    capabilityID = try decodeCString(record.capability_id)
    let detail = try decodeOptionalCString(
      record.detail_code,
      presence: record.has_detail_code
    )
    outcome = try decodeOutcome(record.outcome, detail: detail)
  }
}

func decodeCString<Value>(_ value: Value) throws -> String {
  try withUnsafeBytes(of: value) { bytes in
    guard let end = bytes.firstIndex(of: 0), end > 0,
      let string = String(bytes: bytes[..<end], encoding: .utf8)
    else {
      throw BondryEncryptedStoreError.invalidData
    }
    return string
  }
}

private func decodeBoolean(_ value: UInt8) throws -> Bool {
  switch value {
  case 0: false
  case 1: true
  default: throw BondryEncryptedStoreError.invalidData
  }
}

private func decodeOptionalCString<Value>(_ value: Value, presence: UInt8) throws -> String? {
  switch presence {
  case 0: return nil
  case 1: return try decodeCString(value)
  default: throw BondryEncryptedStoreError.invalidData
  }
}

private func decodeOptionalDate(_ seconds: Int64, presence: UInt8) throws -> Date? {
  switch presence {
  case 0: return nil
  case 1: return Date(timeIntervalSince1970: TimeInterval(seconds))
  default: throw BondryEncryptedStoreError.invalidData
  }
}

private func decodeOutcome(_ value: UInt32, detail: String?) throws -> BondryAuditOutcome {
  switch (value, detail) {
  case (BONDRY_AUDIT_OUTCOME_CAPABILITY_NOT_FOUND_V1, nil):
    .capabilityNotFound
  case (BONDRY_AUDIT_OUTCOME_DENIED_V1, .some(let code)):
    .denied(code: code)
  case (BONDRY_AUDIT_OUTCOME_STARTED_V1, nil):
    .started
  case (BONDRY_AUDIT_OUTCOME_SUCCEEDED_V1, nil):
    .succeeded
  case (BONDRY_AUDIT_OUTCOME_HANDLER_FAILED_V1, .some(let code)):
    .handlerFailed(code: code)
  default:
    throw BondryEncryptedStoreError.invalidData
  }
}
