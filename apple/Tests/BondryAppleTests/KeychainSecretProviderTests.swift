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

    assertSecret(
      try provider.resolve(reference),
      try BondryResolvedSecret(current: Data("current".utf8))
    )
  }

  func testRotationPreservesOnePreviousValue() throws {
    let keychain = SecretTestKeychainClient()
    let provider = makeProvider(keychain)
    try provider.store(Data("first".utf8), for: reference)

    try provider.rotate(to: Data("second".utf8), for: reference)

    assertSecret(
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

    assertSecret(
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

  func testReferenceBoundUsesUTF8Bytes() throws {
    XCTAssertNoThrow(try BondrySecretReference(String(repeating: "a", count: 1_024)))
    XCTAssertThrowsError(
      try BondrySecretReference(String(repeating: "é", count: 513))
    ) { error in
      XCTAssertEqual(error as? BondrySecretProviderError, .invalidReferenceLength(1_026))
    }
  }

  func testProviderInstancesSerializeRotationForSameLocator() throws {
    let keychain = BlockingReadSecretKeychainClient()
    let first = makeProvider(keychain)
    let second = makeProvider(keychain)
    let reference = reference
    try first.store(Data("first".utf8), for: reference)
    keychain.blockNextRead()

    let group = DispatchGroup()
    let errors = ConcurrentErrorCollector()

    group.enter()
    DispatchQueue.global().async {
      defer { group.leave() }
      do {
        try first.rotate(to: Data("second".utf8), for: reference)
      } catch {
        errors.append(error)
      }
    }
    XCTAssertEqual(keychain.readEntered.wait(timeout: .now() + 2), .success)

    let secondStarted = DispatchSemaphore(value: 0)
    group.enter()
    DispatchQueue.global().async {
      defer { group.leave() }
      secondStarted.signal()
      do {
        try second.rotate(to: Data("third".utf8), for: reference)
      } catch {
        errors.append(error)
      }
    }
    XCTAssertEqual(secondStarted.wait(timeout: .now() + 2), .success)
    Thread.sleep(forTimeInterval: 0.05)
    XCTAssertEqual(keychain.readCount, 1)

    keychain.releaseRead.signal()
    XCTAssertEqual(group.wait(timeout: .now() + 2), .success)
    XCTAssertTrue(errors.values.isEmpty)
    assertSecret(
      try first.resolve(reference),
      try BondryResolvedSecret(
        current: Data("third".utf8),
        previous: Data("second".utf8)
      )
    )
  }

  func testKeychainFailuresAreNonSensitive() {
    let keychain = SecretTestKeychainClient(readResult: .failure(errSecMissingEntitlement))
    let provider = makeProvider(keychain)

    XCTAssertThrowsError(try provider.resolve(reference)) { error in
      XCTAssertEqual(error as? BondrySecretProviderError, .missingKeychainEntitlement)
    }
  }

  func testResolvedSecretsAreRedactedFromDebugAndReflection() throws {
    let secret = try BondryResolvedSecret(current: Data("visible-in-test".utf8))

    XCTAssertFalse(String(reflecting: secret).contains("visible-in-test"))
    XCTAssertFalse(String(reflecting: secret.current).contains("visible-in-test"))
    XCTAssertEqual(String(reflecting: secret), "BondryResolvedSecret([REDACTED])")
  }

  private func makeProvider(_ keychain: any KeychainClient) -> KeychainSecretProvider {
    KeychainSecretProvider(configuration: configuration, keychain: keychain)
  }

  private func locator() -> KeychainItemLocator {
    KeychainItemLocator(
      service: configuration.service,
      account: reference.rawValue,
      accessGroup: configuration.accessGroup
    )
  }

  private func assertSecret(
    _ actual: BondryResolvedSecret,
    _ expected: BondryResolvedSecret,
    file: StaticString = #filePath,
    line: UInt = #line
  ) {
    XCTAssertEqual(actual.current.copiedData, expected.current.copiedData, file: file, line: line)
    XCTAssertEqual(
      actual.previous?.copiedData,
      expected.previous?.copiedData,
      file: file,
      line: line
    )
  }
}

private final class ConcurrentErrorCollector: @unchecked Sendable {
  private let lock = NSLock()
  private var storedValues: [any Error] = []

  var values: [any Error] {
    lock.lock()
    defer { lock.unlock() }
    return storedValues
  }

  func append(_ error: any Error) {
    lock.lock()
    storedValues.append(error)
    lock.unlock()
  }
}

private final class BlockingReadSecretKeychainClient: KeychainClient, @unchecked Sendable {
  let readEntered = DispatchSemaphore(value: 0)
  let releaseRead = DispatchSemaphore(value: 0)

  private let lock = NSLock()
  private var items: [KeychainItemLocator: Data] = [:]
  private var shouldBlockRead = false
  private var storedReadCount = 0

  var readCount: Int {
    withLock { storedReadCount }
  }

  func blockNextRead() {
    withLock { shouldBlockRead = true }
  }

  func copyData(for locator: KeychainItemLocator) -> KeychainReadResult {
    let block = withLock {
      storedReadCount += 1
      defer { shouldBlockRead = false }
      return shouldBlockRead
    }
    if block {
      readEntered.signal()
      releaseRead.wait()
    }
    return withLock {
      items[locator].map(KeychainReadResult.found) ?? .missing
    }
  }

  func add(data: Data, for locator: KeychainItemLocator) -> OSStatus {
    withLock {
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

  private func withLock<T>(_ operation: () -> T) -> T {
    lock.lock()
    defer { lock.unlock() }
    return operation()
  }
}

extension BondrySecretBytes {
  fileprivate var copiedData: Data {
    withUnsafeBytes { Data($0) }
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
