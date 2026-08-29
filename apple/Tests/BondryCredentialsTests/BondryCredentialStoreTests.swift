import BondryCredentials
import CBondryCredentials
import CBondryCredentialsTestSupport
import Foundation
import XCTest

final class BondryCredentialStoreTests: XCTestCase {
  override func setUp() {
    super.setUp()
    bondry_credentials_test_reset()
  }

  func testValidatesCredentialIdentifiers() throws {
    XCTAssertEqual(try BondryCredentialID("database-key").rawValue, "database-key")
    XCTAssertThrowsError(try BondryCredentialID(""))
    XCTAssertThrowsError(try BondryCredentialID("../secret"))
    XCTAssertThrowsError(
      try BondryCredentialID(
        String(repeating: "a", count: BondryCredentialID.maximumByteCount + 1)
      )
    )
  }

  func testValidatesABIAndDirectoryURL() throws {
    bondry_credentials_test_set_abi_version(2)
    XCTAssertThrowsError(
      try BondryCredentialStore.openUnixFileStore(at: URL(fileURLWithPath: "/tmp"))
    ) {
      XCTAssertEqual(
        $0 as? BondryCredentialStoreError,
        .incompatibleABI(expected: 1, actual: 2)
      )
    }

    bondry_credentials_test_reset()
    XCTAssertThrowsError(
      try BondryCredentialStore.openUnixFileStore(at: URL(string: "https://example.com")!)
    ) {
      XCTAssertEqual($0 as? BondryCredentialStoreError, .invalidDirectoryURL)
    }
  }

  func testOwnsAndClosesNativeHandle() throws {
    var store: BondryCredentialStore? = try BondryCredentialStore.openUnixFileStore(
      at: URL(fileURLWithPath: "/tmp")
    )
    XCTAssertNotNil(store)
    XCTAssertEqual(bondry_credentials_test_open_count(), 1)
    XCTAssertEqual(bondry_credentials_test_close_count(), 0)

    store = nil

    XCTAssertEqual(bondry_credentials_test_close_count(), 1)
  }

  func testMapsCapabilities() throws {
    let store = try BondryCredentialStore.openUnixFileStore(at: URL(fileURLWithPath: "/tmp"))
    XCTAssertEqual(
      try store.capabilities(),
      BondryCredentialStoreCapabilities(
        protection: .accessControlled,
        access: .readWrite,
        supportsUnattendedAccess: true
      )
    )

    bondry_credentials_test_set_capabilities(99, 2, 1)
    XCTAssertThrowsError(try store.capabilities()) {
      XCTAssertEqual($0 as? BondryCredentialStoreError, .invalidCapabilities)
    }
  }

  func testStoresLoadsAndDeletesCredentialBytes() throws {
    let store = try BondryCredentialStore.openUnixFileStore(at: URL(fileURLWithPath: "/tmp"))
    let id = try BondryCredentialID("tls-identity")
    let value = Data("private material".utf8)

    XCTAssertNil(try store.load(id))
    try store.store(value, for: id)
    XCTAssertEqual(try store.load(id), value)
    XCTAssertTrue(try store.delete(id))
    XCTAssertFalse(try store.delete(id))
    XCTAssertNil(try store.load(id))
  }

  func testRetriesWhenCredentialGrowsBetweenLoadCalls() throws {
    let store = try BondryCredentialStore.openUnixFileStore(at: URL(fileURLWithPath: "/tmp"))
    let id = try BondryCredentialID("database-key")
    try store.store(Data([1, 2, 3]), for: id)
    bondry_credentials_test_grow_next_load(4)

    XCTAssertEqual(try store.load(id), Data([1, 2, 3, 4]))
  }

  func testRejectsInvalidCredentialLengthsBeforeCallingNativeStore() throws {
    let store = try BondryCredentialStore.openUnixFileStore(at: URL(fileURLWithPath: "/tmp"))
    let id = try BondryCredentialID("database-key")

    XCTAssertThrowsError(try store.store(Data(), for: id)) {
      XCTAssertEqual($0 as? BondryCredentialStoreError, .invalidLength)
    }
    XCTAssertThrowsError(
      try store.store(
        Data(repeating: 0, count: BondryCredentialStore.maximumCredentialByteCount + 1),
        for: id
      )
    ) {
      XCTAssertEqual($0 as? BondryCredentialStoreError, .invalidLength)
    }
  }

  func testMapsNativeOpenErrors() {
    bondry_credentials_test_set_open_status(BONDRY_CREDENTIAL_STATUS_UNSAFE_STORAGE)
    XCTAssertThrowsError(
      try BondryCredentialStore.openUnixFileStore(at: URL(fileURLWithPath: "/tmp"))
    ) {
      XCTAssertEqual($0 as? BondryCredentialStoreError, .unsafeStorage)
    }
  }
}
