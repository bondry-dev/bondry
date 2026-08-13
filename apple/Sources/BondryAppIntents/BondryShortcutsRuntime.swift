import AppIntents
import BondrySQLCipher
import Foundation

public struct BondryShortcutsRuntime: Sendable {
  public static let adapterID = "shortcuts"

  private let store: BondryEncryptedStore
  public let principal: BondryPrincipal

  public init(store: BondryEncryptedStore, principal: BondryPrincipal) {
    self.store = store
    self.principal = principal
  }

  public func register(with manager: AppDependencyManager = .shared) {
    manager.add(dependency: self)
  }

  public func authorizedCapabilities() throws -> [BondryCapability] {
    do {
      let identifiers = Set(
        try store.grants(for: principal.id)
          .filter { $0.principalID == principal.id && $0.adapterID == Self.adapterID }
          .map(\.capabilityID)
      )
      return try store.capabilities().filter { identifiers.contains($0.id) }
    } catch {
      throw BondryShortcutsError.serviceUnavailable
    }
  }

  public func invoke(
    capabilityID: String,
    inputJSON: Data,
    invocationID: String = UUID().uuidString
  ) async throws -> Data {
    do {
      return try await store.dispatchPlatformInvocation(
        invocationID: invocationID,
        adapterID: Self.adapterID,
        principal: principal,
        capabilityID: capabilityID,
        inputJSON: inputJSON
      )
    } catch BondryDispatchError.capabilityNotFound {
      throw BondryShortcutsError.capabilityUnavailable
    } catch BondryDispatchError.accessDenied {
      throw BondryShortcutsError.notAuthorized
    } catch BondryDispatchError.invalidInput {
      throw BondryShortcutsError.invalidInput
    } catch BondryDispatchError.auditUnavailable {
      throw BondryShortcutsError.serviceUnavailable
    } catch BondryDispatchError.handlerFailed {
      throw BondryShortcutsError.executionFailed
    } catch let error as BondryEncryptedStoreError where error == .invalidJSON {
      throw BondryShortcutsError.invalidInput
    } catch {
      throw BondryShortcutsError.serviceUnavailable
    }
  }
}

public enum BondryShortcutsError: Error, Equatable, LocalizedError, Sendable {
  case invalidInput
  case capabilityUnavailable
  case notAuthorized
  case executionFailed
  case serviceUnavailable
  case invalidOutput

  public var errorDescription: String? {
    switch self {
    case .invalidInput: "The input is not valid JSON."
    case .capabilityUnavailable: "This automation capability is unavailable."
    case .notAuthorized: "This automation capability is not authorized for Shortcuts."
    case .executionFailed: "The automation capability could not complete."
    case .serviceUnavailable: "The automation service is unavailable."
    case .invalidOutput: "The automation capability returned invalid output."
    }
  }
}
