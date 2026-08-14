import Foundation
import Security

public struct KeychainSecretProvider: Sendable {
  public let configuration: KeychainSecretProviderConfiguration

  private let state: KeychainSecretProviderState

  public init(configuration: KeychainSecretProviderConfiguration) {
    self.configuration = configuration
    state = KeychainSecretProviderState(keychain: SecurityKeychainClient())
  }

  public func resolve(_ reference: BondrySecretReference) throws -> BondryResolvedSecret {
    try state.withLock {
      try load(reference)
    }
  }

  public func store(_ secret: Data, for reference: BondrySecretReference) throws {
    let material = try BondryResolvedSecret(current: secret)
    try state.withLock {
      try write(material, for: reference)
    }
  }

  public func rotate(to secret: Data, for reference: BondrySecretReference) throws {
    try state.withLock {
      let existing = try load(reference)
      let rotated = try BondryResolvedSecret(current: secret, previous: existing.current)
      try update(rotated, for: reference)
    }
  }

  public func retirePrevious(for reference: BondrySecretReference) throws {
    try state.withLock {
      let existing = try load(reference)
      try update(BondryResolvedSecret(current: existing.current), for: reference)
    }
  }

  private func load(_ reference: BondrySecretReference) throws -> BondryResolvedSecret {
    switch state.keychain.copyData(for: locator(for: reference)) {
    case .found(let data):
      return try SecretEnvelope.decode(data)
    case .missing:
      throw BondrySecretProviderError.secretNotFound
    case .failure(let status):
      throw Self.error(for: status)
    case .unexpectedResult:
      throw BondrySecretProviderError.corruptStoredSecret
    }
  }

  private func write(
    _ material: BondryResolvedSecret,
    for reference: BondrySecretReference
  ) throws {
    let locator = locator(for: reference)
    let data = SecretEnvelope.encode(material)
    let status = state.keychain.add(data: data, for: locator)
    if status == errSecSuccess {
      return
    }
    if status == errSecDuplicateItem {
      try update(material, for: reference)
      return
    }
    throw Self.error(for: status)
  }

  private func update(
    _ material: BondryResolvedSecret,
    for reference: BondrySecretReference
  ) throws {
    let status = state.keychain.update(
      data: SecretEnvelope.encode(material),
      for: locator(for: reference)
    )
    if status == errSecSuccess {
      return
    }
    if status == errSecItemNotFound {
      throw BondrySecretProviderError.updateRaceCouldNotBeResolved
    }
    throw Self.error(for: status)
  }

  private func locator(for reference: BondrySecretReference) -> KeychainItemLocator {
    KeychainItemLocator(
      service: configuration.service,
      account: reference.rawValue,
      accessGroup: configuration.accessGroup
    )
  }

  private static func error(for status: OSStatus) -> BondrySecretProviderError {
    if status == errSecMissingEntitlement {
      return .missingKeychainEntitlement
    }
    return .keychainOperationFailed(status)
  }

  init(
    configuration: KeychainSecretProviderConfiguration,
    keychain: any KeychainClient
  ) {
    self.configuration = configuration
    state = KeychainSecretProviderState(keychain: keychain)
  }
}

private final class KeychainSecretProviderState: @unchecked Sendable {
  let keychain: any KeychainClient
  private let lock = NSLock()

  init(keychain: any KeychainClient) {
    self.keychain = keychain
  }

  func withLock<T>(_ operation: () throws -> T) rethrows -> T {
    lock.lock()
    defer { lock.unlock() }
    return try operation()
  }
}

private enum SecretEnvelope {
  private static let version: UInt8 = 1

  static func encode(_ material: BondryResolvedSecret) -> Data {
    var result = Data([version])
    appendLength(material.current.count, to: &result)
    result.append(material.current)
    appendLength(material.previous?.count ?? 0, to: &result)
    if let previous = material.previous {
      result.append(previous)
    }
    return result
  }

  static func decode(_ data: Data) throws -> BondryResolvedSecret {
    var cursor = data.startIndex
    guard readByte(from: data, cursor: &cursor) == version,
      let currentLength = readLength(from: data, cursor: &cursor),
      let current = readData(length: currentLength, from: data, cursor: &cursor),
      let previousLength = readLength(from: data, cursor: &cursor)
    else {
      throw BondrySecretProviderError.corruptStoredSecret
    }
    let previous: Data?
    if previousLength == 0 {
      previous = nil
    } else {
      guard let value = readData(length: previousLength, from: data, cursor: &cursor) else {
        throw BondrySecretProviderError.corruptStoredSecret
      }
      previous = value
    }
    guard cursor == data.endIndex else {
      throw BondrySecretProviderError.corruptStoredSecret
    }
    do {
      return try BondryResolvedSecret(current: current, previous: previous)
    } catch {
      throw BondrySecretProviderError.corruptStoredSecret
    }
  }

  private static func appendLength(_ length: Int, to data: inout Data) {
    let value = UInt32(length).bigEndian
    withUnsafeBytes(of: value) { data.append(contentsOf: $0) }
  }

  private static func readByte(from data: Data, cursor: inout Data.Index) -> UInt8? {
    guard cursor < data.endIndex else {
      return nil
    }
    defer { cursor = data.index(after: cursor) }
    return data[cursor]
  }

  private static func readLength(from data: Data, cursor: inout Data.Index) -> Int? {
    guard let bytes = readData(length: MemoryLayout<UInt32>.size, from: data, cursor: &cursor)
    else {
      return nil
    }
    let value = bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    return Int(value)
  }

  private static func readData(
    length: Int,
    from data: Data,
    cursor: inout Data.Index
  ) -> Data? {
    guard length >= 0,
      let end = data.index(cursor, offsetBy: length, limitedBy: data.endIndex)
    else {
      return nil
    }
    defer { cursor = end }
    return data[cursor..<end]
  }
}
