import Foundation
import Security
import XCTest

@testable import BondryApple

final class KeychainSecretProviderTests: XCTestCase {
  private let configuration = try! KeychainSecretProviderConfiguration(
    service: "dev.bondry.secrets"
  )
  private let reference = try! BondrySecretReference("webhook/primary")

  func testStoresAndResolvesCurrentSecret() throws {
    let keychain = SecretTestKeychainClient()
    let provider = makeProvider(keychain)

    try provider.store(Data("current".utf8), for: reference)

    XCTAssertEqual(
      try provider.resolve(reference),
      try BondryResolvedSecret(current: Data("current".utf8))
    )
  }

  func testRotationPreservesOnePreviousValue() throws {
    let keychain = SecretTestKeychainClient()
    let provider = makeProvider(keychain)
    try provider.store(Data("first".utf8), for: reference)

    try provider.rotate(to: Data("second".utf8), for: reference)

    XCTAssertEqual(
      try provider.resolve(reference),
      try BondryResolvedSecret(
        current: Data("second".utf8),
        previous: Data("first".utf8)
      )
    )
  }

  func testRetiringPreviousValueEndsOverlap() throws {
    let keychain = SecretTestKeychainClient()
    let provider = makeProvider(keychain)
    try provider.store(Data("first".utf8), for: reference)
    try provider.rotate(to: Data("second".utf8), for: reference)

    try provider.retirePrevious(for: reference)

    XCTAssertEqual(
      try provider.resolve(reference),
      try BondryResolvedSecret(current: Data("second".utf8))
    )
  }

  func testMissingAndCorruptItemsFailClosed() {
    let keychain = SecretTestKeychainClient()
    let provider = makeProvider(keychain)

    XCTAssertThrowsError(try provider.resolve(reference)) { error in
      XCTAssertEqual(error as? BondrySecretProviderError, .secretNotFound)
    }

    keychain.set(Data([0xff]), for: locator())
    XCTAssertThrowsError(try provider.resolve(reference)) { error in
      XCTAssertEqual(error as? BondrySecretProviderError, .corruptStoredSecret)
    }
  }

  func testSecretBoundsAreEnforcedBeforeKeychainWrites() {
    let keychain = SecretTestKeychainClient()
    let provider = makeProvider(keychain)

    XCTAssertThrowsError(try provider.store(Data(), for: reference))
    XCTAssertThrowsError(
      try provider.store(
        Data(repeating: 0, count: BondryResolvedSecret.maximumByteCount + 1),
        for: reference
      )
    )
    XCTAssertEqual(keychain.addCount, 0)
  }

  func testKeychainFailuresAreNonSensitive() {
    let keychain = SecretTestKeychainClient(readResult: .failure(errSecMissingEntitlement))
    let provider = makeProvider(keychain)

    XCTAssertThrowsError(try provider.resolve(reference)) { error in
      XCTAssertEqual(error as? BondrySecretProviderError, .missingKeychainEntitlement)
    }
  }

  private func makeProvider(_ keychain: SecretTestKeychainClient) -> KeychainSecretProvider {
    KeychainSecretProvider(configuration: configuration, keychain: keychain)
  }

  private func locator() -> KeychainItemLocator {
    KeychainItemLocator(
      service: configuration.service,
      account: reference.rawValue,
      accessGroup: configuration.accessGroup
    )
  }
}

private final class SecretTestKeychainClient: KeychainClient, @unchecked Sendable {
  private let lock = NSLock()
  private var items: [KeychainItemLocator: Data] = [:]
  private let readResult: KeychainReadResult?
  private var storedAddCount = 0

  init(readResult: KeychainReadResult? = nil) {
    self.readResult = readResult
  }

  var addCount: Int {
    withLock { storedAddCount }
  }

  func copyData(for locator: KeychainItemLocator) -> KeychainReadResult {
    withLock {
      readResult ?? items[locator].map(KeychainReadResult.found) ?? .missing
    }
  }

  func add(data: Data, for locator: KeychainItemLocator) -> OSStatus {
    withLock {
      storedAddCount += 1
      guard items[locator] == nil else {
        return errSecDuplicateItem
      }
      items[locator] = data
      return errSecSuccess
    }
  }

  func update(data: Data, for locator: KeychainItemLocator) -> OSStatus {
    withLock {
      guard items[locator] != nil else {
        return errSecItemNotFound
      }
      items[locator] = data
      return errSecSuccess
    }
  }

  func set(_ data: Data, for locator: KeychainItemLocator) {
    withLock {
      items[locator] = data
    }
  }

  private func withLock<T>(_ operation: () -> T) -> T {
    lock.lock()
    defer { lock.unlock() }
    return operation()
  }
}
