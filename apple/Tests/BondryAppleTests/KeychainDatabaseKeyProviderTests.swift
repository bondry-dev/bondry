import Foundation
import Security
import XCTest

@testable import BondryApple

final class KeychainDatabaseKeyProviderTests: XCTestCase {
  private let configuration = try! KeychainDatabaseKeyConfiguration(
    service: "dev.bondry.database",
    account: "primary"
  )

  func testLoadReturnsNilWhenItemIsMissing() throws {
    let keychain = TestKeychainClient()
    let provider = makeProvider(keychain: keychain)

    XCTAssertNil(try provider.load())
  }

  func testLoadReturnsExistingKey() throws {
    let data = keyData(0x11)
    let keychain = TestKeychainClient(initialData: data, configuration: configuration)
    let provider = makeProvider(keychain: keychain)

    XCTAssertEqual(try provider.load()?.rawRepresentation, data)
  }

  func testLoadRejectsInvalidStoredKeyWithoutReplacingIt() {
    let invalidData = Data(repeating: 0x11, count: 31)
    let keychain = TestKeychainClient(initialData: invalidData, configuration: configuration)
    let provider = makeProvider(keychain: keychain)

    XCTAssertThrowsError(try provider.loadOrCreate()) { error in
      XCTAssertEqual(error as? KeychainDatabaseKeyError, .invalidKeyLength(31))
    }
    XCTAssertEqual(keychain.addCount, 0)
    XCTAssertEqual(keychain.data(for: configuration), invalidData)
  }

  func testLoadMapsKeychainFailure() {
    let keychain = TestKeychainClient(readOverride: .failure(errSecInteractionNotAllowed))
    let provider = makeProvider(keychain: keychain)

    XCTAssertThrowsError(try provider.load()) { error in
      XCTAssertEqual(
        error as? KeychainDatabaseKeyError,
        .keychainOperationFailed(errSecInteractionNotAllowed)
      )
    }
  }

  func testMissingEntitlementHasDedicatedError() {
    let keychain = TestKeychainClient(readOverride: .failure(errSecMissingEntitlement))
    let provider = makeProvider(keychain: keychain)

    XCTAssertThrowsError(try provider.load()) { error in
      XCTAssertEqual(error as? KeychainDatabaseKeyError, .missingKeychainEntitlement)
    }
  }

  func testLoadRejectsUnexpectedResult() {
    let keychain = TestKeychainClient(readOverride: .unexpectedResult)
    let provider = makeProvider(keychain: keychain)

    XCTAssertThrowsError(try provider.load()) { error in
      XCTAssertEqual(error as? KeychainDatabaseKeyError, .unexpectedKeychainResult)
    }
  }

  func testLoadOrCreatePersistsGeneratedKey() throws {
    let generated = keyData(0x22)
    let keychain = TestKeychainClient()
    let provider = makeProvider(keychain: keychain, generated: generated)

    let key = try provider.loadOrCreate()

    XCTAssertEqual(key.rawRepresentation, generated)
    XCTAssertEqual(keychain.data(for: configuration), generated)
    XCTAssertEqual(keychain.addCount, 1)
  }

  func testLoadOrCreateDoesNotGenerateWhenKeyExists() throws {
    let existing = keyData(0x33)
    let random = CountingRandomByteGenerator()
    let keychain = TestKeychainClient(initialData: existing, configuration: configuration)
    let provider = KeychainDatabaseKeyProvider(
      configuration: configuration,
      keychain: keychain,
      randomBytes: random
    )

    XCTAssertEqual(try provider.loadOrCreate().rawRepresentation, existing)
    XCTAssertEqual(random.callCount, 0)
    XCTAssertEqual(keychain.addCount, 0)
  }

  func testDuplicateCreationReturnsWinningKey() throws {
    let generated = keyData(0x44)
    let winner = keyData(0x55)
    let keychain = TestKeychainClient(addBehavior: .duplicate(winner: winner))
    let provider = makeProvider(keychain: keychain, generated: generated)

    XCTAssertEqual(try provider.loadOrCreate().rawRepresentation, winner)
    XCTAssertEqual(keychain.data(for: configuration), winner)
  }

  func testDuplicateCreationFailsWhenWinnerCannotBeLoaded() {
    let keychain = TestKeychainClient(addBehavior: .duplicate(winner: nil))
    let provider = makeProvider(keychain: keychain)

    XCTAssertThrowsError(try provider.loadOrCreate()) { error in
      XCTAssertEqual(
        error as? KeychainDatabaseKeyError,
        .creationRaceCouldNotBeResolved
      )
    }
  }

  func testAddFailureIsReported() {
    let keychain = TestKeychainClient(addBehavior: .status(errSecAuthFailed))
    let provider = makeProvider(keychain: keychain)

    XCTAssertThrowsError(try provider.loadOrCreate()) { error in
      XCTAssertEqual(
        error as? KeychainDatabaseKeyError,
        .keychainOperationFailed(errSecAuthFailed)
      )
    }
  }

  func testAddMapsMissingEntitlement() {
    let keychain = TestKeychainClient(addBehavior: .status(errSecMissingEntitlement))
    let provider = makeProvider(keychain: keychain)

    XCTAssertThrowsError(try provider.loadOrCreate()) { error in
      XCTAssertEqual(error as? KeychainDatabaseKeyError, .missingKeychainEntitlement)
    }
  }

  func testRandomFailureDoesNotWriteToKeychain() {
    let keychain = TestKeychainClient()
    let provider = KeychainDatabaseKeyProvider(
      configuration: configuration,
      keychain: keychain,
      randomBytes: FailingRandomByteGenerator(status: errSecInternalComponent)
    )

    XCTAssertThrowsError(try provider.loadOrCreate()) { error in
      XCTAssertEqual(
        error as? KeychainDatabaseKeyError,
        .randomGenerationFailed(errSecInternalComponent)
      )
    }
    XCTAssertEqual(keychain.addCount, 0)
  }

  func testConcurrentCreationConvergesOnOneKey() {
    let keychain = TestKeychainClient()
    let random = CountingRandomByteGenerator()
    let provider = KeychainDatabaseKeyProvider(
      configuration: configuration,
      keychain: keychain,
      randomBytes: random
    )
    let results = LockedResults()

    DispatchQueue.concurrentPerform(iterations: 32) { _ in
      do {
        results.append(.success(try provider.loadOrCreate().rawRepresentation))
      } catch {
        results.append(.failure(error))
      }
    }

    let values = results.values
    XCTAssertEqual(values.count, 32)
    XCTAssertTrue(values.allSatisfy { $0 == values.first })
    XCTAssertEqual(values.first, keychain.data(for: configuration))
    XCTAssertTrue(results.errors.isEmpty)
  }

  private func makeProvider(
    keychain: TestKeychainClient,
    generated: Data? = nil
  ) -> KeychainDatabaseKeyProvider {
    KeychainDatabaseKeyProvider(
      configuration: configuration,
      keychain: keychain,
      randomBytes: FixedRandomByteGenerator(data: generated ?? keyData(0xAA))
    )
  }

  private func keyData(_ byte: UInt8) -> Data {
    Data(repeating: byte, count: DatabaseKeyMaterial.byteCount)
  }
}

private final class TestKeychainClient: KeychainClient, @unchecked Sendable {
  enum AddBehavior: Sendable {
    case normal
    case status(OSStatus)
    case duplicate(winner: Data?)
  }

  private let lock = NSLock()
  private var items: [KeychainItemLocator: Data] = [:]
  private let readOverride: KeychainReadResult?
  private let addBehavior: AddBehavior
  private var storedAddCount = 0

  init(
    initialData: Data? = nil,
    configuration: KeychainDatabaseKeyConfiguration? = nil,
    readOverride: KeychainReadResult? = nil,
    addBehavior: AddBehavior = .normal
  ) {
    if let initialData, let configuration {
      items[KeychainItemLocator(configuration: configuration)] = initialData
    }
    self.readOverride = readOverride
    self.addBehavior = addBehavior
  }

  var addCount: Int {
    withLock { storedAddCount }
  }

  func copyData(for locator: KeychainItemLocator) -> KeychainReadResult {
    withLock {
      if let readOverride {
        return readOverride
      }
      return items[locator].map(KeychainReadResult.found) ?? .missing
    }
  }

  func add(data: Data, for locator: KeychainItemLocator) -> OSStatus {
    withLock {
      storedAddCount += 1

      switch addBehavior {
      case .normal:
        guard items[locator] == nil else {
          return errSecDuplicateItem
        }
        items[locator] = data
        return errSecSuccess
      case .status(let status):
        return status
      case .duplicate(let winner):
        items[locator] = winner
        return errSecDuplicateItem
      }
    }
  }

  func data(for configuration: KeychainDatabaseKeyConfiguration) -> Data? {
    withLock { items[KeychainItemLocator(configuration: configuration)] }
  }

  private func withLock<T>(_ body: () -> T) -> T {
    lock.lock()
    defer { lock.unlock() }
    return body()
  }
}

private struct FixedRandomByteGenerator: RandomByteGenerator {
  let data: Data

  func generate(count: Int) throws -> Data {
    data
  }
}

private struct FailingRandomByteGenerator: RandomByteGenerator {
  let status: OSStatus

  func generate(count: Int) throws -> Data {
    throw KeychainDatabaseKeyError.randomGenerationFailed(status)
  }
}

private final class CountingRandomByteGenerator: RandomByteGenerator, @unchecked Sendable {
  private let lock = NSLock()
  private var storedCallCount = 0

  var callCount: Int {
    withLock { storedCallCount }
  }

  func generate(count: Int) throws -> Data {
    withLock {
      storedCallCount += 1
      return Data(repeating: UInt8(truncatingIfNeeded: storedCallCount), count: count)
    }
  }

  private func withLock<T>(_ body: () -> T) -> T {
    lock.lock()
    defer { lock.unlock() }
    return body()
  }
}

private final class LockedResults: @unchecked Sendable {
  private let lock = NSLock()
  private var storedValues: [Data] = []
  private var storedErrors: [Error] = []

  var values: [Data] {
    withLock { storedValues }
  }

  var errors: [Error] {
    withLock { storedErrors }
  }

  func append(_ result: Result<Data, Error>) {
    withLock {
      switch result {
      case .success(let data):
        storedValues.append(data)
      case .failure(let error):
        storedErrors.append(error)
      }
    }
  }

  private func withLock<T>(_ body: () -> T) -> T {
    lock.lock()
    defer { lock.unlock() }
    return body()
  }
}
