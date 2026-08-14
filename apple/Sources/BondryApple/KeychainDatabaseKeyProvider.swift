import Foundation
import Security

public struct KeychainDatabaseKeyProvider: Sendable {
  public let configuration: KeychainDatabaseKeyConfiguration

  private let keychain: any KeychainClient
  private let randomBytes: any RandomByteGenerator

  public init(configuration: KeychainDatabaseKeyConfiguration) {
    self.init(
      configuration: configuration,
      keychain: SecurityKeychainClient(),
      randomBytes: SecurityRandomByteGenerator()
    )
  }

  public func load() throws -> DatabaseKeyMaterial? {
    let locator = KeychainItemLocator(configuration: configuration)

    switch keychain.copyData(for: locator) {
    case .found(let data):
      return try DatabaseKeyMaterial(rawRepresentation: data)
    case .missing:
      return nil
    case .failure(let status):
      throw Self.keychainError(for: status)
    case .unexpectedResult:
      throw KeychainDatabaseKeyError.unexpectedKeychainResult
    }
  }

  public func loadOrCreate() throws -> DatabaseKeyMaterial {
    if let existing = try load() {
      return existing
    }

    let generated = try DatabaseKeyMaterial(
      rawRepresentation: randomBytes.generate(count: DatabaseKeyMaterial.byteCount)
    )
    let locator = KeychainItemLocator(configuration: configuration)
    let status = keychain.add(data: generated.rawRepresentation, for: locator)

    switch status {
    case errSecSuccess:
      return generated
    case errSecDuplicateItem:
      guard let winner = try load() else {
        throw KeychainDatabaseKeyError.creationRaceCouldNotBeResolved
      }
      return winner
    default:
      throw Self.keychainError(for: status)
    }
  }

  private static func keychainError(for status: OSStatus) -> KeychainDatabaseKeyError {
    if status == errSecMissingEntitlement {
      return .missingKeychainEntitlement
    }
    return .keychainOperationFailed(status)
  }

  init(
    configuration: KeychainDatabaseKeyConfiguration,
    keychain: any KeychainClient,
    randomBytes: any RandomByteGenerator
  ) {
    self.configuration = configuration
    self.keychain = keychain
    self.randomBytes = randomBytes
  }
}

enum KeychainReadResult: Equatable, Sendable {
  case found(Data)
  case missing
  case failure(OSStatus)
  case unexpectedResult
}

struct KeychainItemLocator: Equatable, Hashable, Sendable {
  let service: String
  let account: String
  let accessGroup: String?

  init(configuration: KeychainDatabaseKeyConfiguration) {
    service = configuration.service
    account = configuration.account
    accessGroup = configuration.accessGroup
  }

  init(service: String, account: String, accessGroup: String?) {
    self.service = service
    self.account = account
    self.accessGroup = accessGroup
  }
}

protocol KeychainClient: Sendable {
  func copyData(for locator: KeychainItemLocator) -> KeychainReadResult
  func add(data: Data, for locator: KeychainItemLocator) -> OSStatus
  func update(data: Data, for locator: KeychainItemLocator) -> OSStatus
}

protocol RandomByteGenerator: Sendable {
  func generate(count: Int) throws -> Data
}

struct SecurityRandomByteGenerator: RandomByteGenerator {
  func generate(count: Int) throws -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    let status = bytes.withUnsafeMutableBytes { buffer in
      guard let baseAddress = buffer.baseAddress else {
        return errSecParam
      }
      return SecRandomCopyBytes(kSecRandomDefault, buffer.count, baseAddress)
    }

    guard status == errSecSuccess else {
      throw KeychainDatabaseKeyError.randomGenerationFailed(status)
    }

    return Data(bytes)
  }
}
