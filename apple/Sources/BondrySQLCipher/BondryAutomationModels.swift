import CBondry
import Foundation

public enum BondryCapabilityEffect: Equatable, Sendable {
  case readOnly
  case mutating
}

public struct BondryCapability: Equatable, Identifiable, Sendable {
  public let id: String
  public let summary: String
  public let effect: BondryCapabilityEffect

  public init(id: String, summary: String, effect: BondryCapabilityEffect) {
    self.id = id
    self.summary = summary
    self.effect = effect
  }

  init(record: BondryCapabilityV1) throws {
    id = try decodeCString(record.id)
    summary = try decodeCString(record.summary)
    effect =
      switch record.effect {
      case BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1:
        .readOnly
      case BONDRY_CAPABILITY_EFFECT_MUTATING_V1:
        .mutating
      default:
        throw BondryEncryptedStoreError.invalidData
      }
  }
}

public struct BondryCapabilityInvocation: Sendable {
  public let id: String
  public let principal: BondryPrincipal
  public let adapterID: String
  public let capabilityID: String
  public let inputJSON: Data

  init(record: BondryInvocationV1) throws {
    id = try decodeCString(record.invocation_id)
    principal = try BondryPrincipal(
      id: decodeCString(record.principal_id),
      cKind: record.principal_kind
    )
    adapterID = try decodeCString(record.adapter_id)
    capabilityID = try decodeCString(record.capability_id)
    guard let input = record.input_json, record.input_json_length > 0 else {
      throw BondryEncryptedStoreError.invalidData
    }
    inputJSON = Data(bytes: input, count: record.input_json_length)
  }
}

public enum BondryCapabilityHandlerError: Error, Equatable, Sendable {
  case failed(code: String)
}

public enum BondryAccessDenialReason: Equatable, Sendable {
  case notGranted
  case policyUnavailable
}

public enum BondryDispatchError: Error, Equatable, Sendable {
  case capabilityNotFound
  case accessDenied(BondryAccessDenialReason)
  case auditUnavailable
  case handlerFailed(code: String)
}

public typealias BondryCapabilityHandler =
  @Sendable (BondryCapabilityInvocation) async throws -> Data
