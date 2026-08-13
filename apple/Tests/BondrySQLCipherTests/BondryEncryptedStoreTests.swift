import BondryApple
import BondrySQLCipher
import CBondry
import CBondryTestSupport
import Foundation
import XCTest

final class BondryEncryptedStoreTests: XCTestCase {
  override func setUp() {
    super.setUp()
    bondry_test_reset()
  }

  func testOpenPassesPathAndKeyAndOwnsHandle() throws {
    let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0xA5, count: 32))
    let url = URL(fileURLWithPath: "/tmp/bondry-store-test.db")
    var store: BondryEncryptedStore? = try BondryEncryptedStore.open(at: url, key: key)

    XCTAssertNotNil(store)
    XCTAssertEqual(bondry_test_open_count(), 1)
    XCTAssertEqual(bondry_test_path_length(), url.path.utf8.count)
    XCTAssertEqual(bondry_test_key_length(), 32)
    XCTAssertEqual(bondry_test_key_byte(0), 0xA5)
    XCTAssertEqual(bondry_test_key_byte(31), 0xA5)
    XCTAssertNoThrow(try store?.checkHealth())
    XCTAssertEqual(bondry_test_close_count(), 0)

    store = nil
    XCTAssertEqual(bondry_test_close_count(), 1)
  }

  func testRejectsIncompatibleABIWithoutOpening() throws {
    bondry_test_set_abi_version(BONDRY_ABI_VERSION_V1 + 1)
    let key = try makeKey()

    XCTAssertThrowsError(
      try BondryEncryptedStore.open(at: fileURL(), key: key)
    ) { error in
      XCTAssertEqual(
        error as? BondryEncryptedStoreError,
        .incompatibleABI(expected: BONDRY_ABI_VERSION_V1, actual: BONDRY_ABI_VERSION_V1 + 1)
      )
    }
    XCTAssertEqual(bondry_test_open_count(), 0)
  }

  func testRejectsNonFileURLWithoutOpening() throws {
    let url = try XCTUnwrap(URL(string: "https://example.com/database"))

    XCTAssertThrowsError(try BondryEncryptedStore.open(at: url, key: makeKey())) { error in
      XCTAssertEqual(error as? BondryEncryptedStoreError, .invalidFileURL)
    }
    XCTAssertEqual(bondry_test_open_count(), 0)
  }

  func testRejectsSuccessfulOpenWithoutHandle() throws {
    bondry_test_set_null_handle(1)

    XCTAssertThrowsError(
      try BondryEncryptedStore.open(at: fileURL(), key: makeKey())
    ) { error in
      XCTAssertEqual(error as? BondryEncryptedStoreError, .invalidHandle)
    }
  }

  func testMapsEveryOpenFailure() throws {
    let cases: [(BondryStatus, BondryEncryptedStoreError)] = [
      (BONDRY_STATUS_NULL_POINTER, .nullPointer),
      (BONDRY_STATUS_INVALID_LENGTH, .invalidLength),
      (BONDRY_STATUS_INVALID_UTF8, .invalidUTF8),
      (BONDRY_STATUS_INVALID_PATH, .invalidPath),
      (BONDRY_STATUS_INVALID_ARGUMENT, .invalidArgument),
      (BONDRY_STATUS_BUFFER_TOO_SMALL, .bufferTooSmall),
      (BONDRY_STATUS_INVALID_JSON, .invalidJSON),
      (BONDRY_STATUS_PAYLOAD_TOO_LARGE, .payloadTooLarge),
      (BONDRY_STATUS_FILE_SYSTEM, .fileSystem),
      (BONDRY_STATUS_DATABASE, .database),
      (BONDRY_STATUS_UNSUPPORTED_SCHEMA, .unsupportedSchema),
      (BONDRY_STATUS_INVALID_DATABASE_KEY, .invalidDatabaseKey),
      (BONDRY_STATUS_INVALID_DATA, .invalidData),
      (BONDRY_STATUS_UNAVAILABLE, .unavailable),
      (BONDRY_STATUS_NOT_FOUND, .notFound),
      (BONDRY_STATUS_CLIENT_DISABLED, .clientDisabled),
      (BONDRY_STATUS_TOKEN_INACTIVE, .tokenInactive),
      (BONDRY_STATUS_AUTHENTICATION_REJECTED, .authenticationRejected),
      (BONDRY_STATUS_INVALID_TOKEN_LIFETIME, .invalidTokenLifetime),
      (BONDRY_STATUS_ENTROPY_UNAVAILABLE, .entropyUnavailable),
      (BONDRY_STATUS_TIME_UNAVAILABLE, .timeUnavailable),
      (BONDRY_STATUS_GENERATION_EXHAUSTED, .generationExhausted),
      (BONDRY_STATUS_ALREADY_EXISTS, .alreadyExists),
      (BONDRY_STATUS_SERVER_BIND, .serverBind),
      (BONDRY_STATUS_SERVER_START, .serverStart),
      (BONDRY_STATUS_SERVER_STOP, .serverStop),
      (BONDRY_STATUS_INTERNAL_FAILURE, .internalFailure(BONDRY_STATUS_INTERNAL_FAILURE)),
      (99, .internalFailure(99)),
    ]

    for (status, expected) in cases {
      bondry_test_set_open_status(status)
      XCTAssertThrowsError(
        try BondryEncryptedStore.open(at: fileURL(), key: makeKey())
      ) { error in
        XCTAssertEqual(error as? BondryEncryptedStoreError, expected)
      }
    }
  }

  func testMapsHealthCheckFailure() throws {
    let store = try BondryEncryptedStore.open(at: fileURL(), key: makeKey())
    bondry_test_set_check_status(BONDRY_STATUS_UNAVAILABLE)

    XCTAssertThrowsError(try store.checkHealth()) { error in
      XCTAssertEqual(error as? BondryEncryptedStoreError, .unavailable)
    }
  }

  private func makeKey() throws -> DatabaseKeyMaterial {
    try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x55, count: 32))
  }

  private func fileURL() -> URL {
    URL(fileURLWithPath: "/tmp/bondry-store-test.db")
  }
}
