import CBondryRuntime
import Foundation

public enum BondryCapabilityEffect: Equatable, Sendable {
  case readOnly
  case mutating
}

public struct BondryCapabilityInputSchema: Equatable, Sendable {
  public static let permissive = BondryCapabilityInputSchema(validatedJSON: Data([0x7B, 0x7D]))

  public let jsonRepresentation: Data

  public init(jsonRepresentation: Data) throws {
    guard jsonRepresentation.count <= 65_536 else {
      throw BondryCapabilityInputSchemaError.tooLarge
    }
    let value: Any
    do {
      value = try JSONSerialization.jsonObject(with: jsonRepresentation)
    } catch {
      throw BondryCapabilityInputSchemaError.invalidJSON
    }
    guard value is [String: Any] else {
      throw BondryCapabilityInputSchemaError.notObject
    }
    do {
      self.jsonRepresentation = try JSONSerialization.data(
        withJSONObject: value,
        options: [.sortedKeys, .withoutEscapingSlashes]
      )
    } catch {
      throw BondryCapabilityInputSchemaError.invalidJSON
    }
  }

  private init(validatedJSON: Data) {
    jsonRepresentation = validatedJSON
  }
}

public enum BondryCapabilityInputSchemaError: Error, Equatable, Sendable {
  case invalidJSON
  case notObject
  case tooLarge
}

public struct BondryCapability: Equatable, Identifiable, Sendable {
  public let id: String
  public let summary: String
  public let effect: BondryCapabilityEffect
  public let inputSchema: BondryCapabilityInputSchema

  public init(
    id: String,
    summary: String,
    effect: BondryCapabilityEffect,
    inputSchema: BondryCapabilityInputSchema = .permissive
  ) {
    self.id = id
    self.summary = summary
    self.effect = effect
    self.inputSchema = inputSchema
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
      throw BondryRuntimeError.invalidData
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
  case invalidInput
  case auditUnavailable
  case handlerFailed(code: String)
}

public typealias BondryCapabilityHandler =
  @Sendable (BondryCapabilityInvocation) async throws -> Data
