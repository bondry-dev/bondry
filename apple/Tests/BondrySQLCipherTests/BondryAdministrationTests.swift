import BondryApple
import BondrySQLCipher
import CBondry
import CBondryTestSupport
import Foundation
import XCTest

final class BondryAdministrationTests: XCTestCase {
  override func setUp() {
    super.setUp()
    bondry_test_reset()
  }

  func testCreatesListsAndUpdatesClients() throws {
    let store = try makeStore()
    let created = try store.createClient(named: "My Integration")

    XCTAssertEqual(created.id, "client_created")
    XCTAssertEqual(created.name, "Created Client")
    XCTAssertTrue(created.isEnabled)
    XCTAssertEqual(created.createdAt, Date(timeIntervalSince1970: 100))
    XCTAssertEqual(bondry_test_create_client_count(), 1)
    XCTAssertEqual(capturedIdentifier(), "My Integration")

    let clients = try store.clients()
    XCTAssertEqual(clients.map(\.id), ["client_a", "client_b"])
    XCTAssertTrue(clients[0].isEnabled)
    XCTAssertFalse(clients[1].isEnabled)

    bondry_test_set_client_list_growth(1)
    XCTAssertEqual(try store.clients().map(\.id), ["client_a", "client_b", "client_c"])

    try store.setClient("client_a", enabled: false)
    XCTAssertEqual(bondry_test_set_client_enabled_count(), 1)
    XCTAssertEqual(capturedIdentifier(), "client_a")
    XCTAssertEqual(bondry_test_enabled(), 0)
  }

  func testManagesOneTimeTokensAndClearsTheirStorage() throws {
    let store = try makeStore()
    var issued: BondryIssuedToken? = try store.issueToken(
      for: "client_test",
      label: "Primary",
      expiresInSeconds: 3_600
    )
    let secret = try XCTUnwrap(issued).copySecret()

    XCTAssertEqual(issued?.metadata.id, "token_issued")
    XCTAssertEqual(issued?.metadata.clientID, "client_test")
    XCTAssertEqual(issued?.metadata.label, "Primary")
    XCTAssertEqual(issued?.metadata.createdAt, Date(timeIntervalSince1970: 200))
    XCTAssertEqual(issued?.metadata.expiresAt, Date(timeIntervalSince1970: 300))
    XCTAssertNil(issued?.metadata.revokedAt)
    XCTAssertEqual(secret, "bondry_v1.token_issued.secret")
    XCTAssertFalse(try XCTUnwrap(issued).debugDescription.contains(secret))
    XCTAssertEqual(capturedIdentifier(), "client_test")
    XCTAssertEqual(capturedLabel(), "Primary")
    XCTAssertEqual(bondry_test_expiration_seconds(), 3_600)
    XCTAssertEqual(bondry_test_has_expiration(), 1)

    let secretBytes = try XCTUnwrap(issued).withUnsafeSecretBytes { Array($0) }
    XCTAssertEqual(String(decoding: secretBytes, as: UTF8.self), secret)

    let principal = try store.authenticate(token: try XCTUnwrap(issued))
    XCTAssertEqual(principal.id, "client_authenticated")
    XCTAssertEqual(principal.kind, .application)
    XCTAssertEqual(capturedIdentifier(), secret)

    let tokens = try store.tokens(for: "client_test")
    XCTAssertEqual(tokens.map(\.id), ["token_active", "token_revoked"])
    XCTAssertEqual(tokens[0].label, "Primary")
    XCTAssertNil(tokens[0].revokedAt)
    XCTAssertNil(tokens[1].expiresAt)
    XCTAssertEqual(tokens[1].revokedAt, Date(timeIntervalSince1970: 250))

    var replacement: BondryIssuedToken? = try store.rotateToken("token_issued")
    XCTAssertEqual(replacement?.metadata.id, "token_replacement")
    XCTAssertEqual(replacement?.copySecret(), "bondry_v1.token_replacement.secret")
    XCTAssertEqual(capturedIdentifier(), "token_issued")
    XCTAssertEqual(bondry_test_label_length(), 0)
    XCTAssertEqual(bondry_test_has_expiration(), 0)
    XCTAssertTrue(try store.revokeToken("token_replacement"))
    XCTAssertEqual(capturedIdentifier(), "token_replacement")

    XCTAssertEqual(bondry_test_issued_token_clear_count(), 0)
    issued = nil
    replacement = nil
    XCTAssertEqual(bondry_test_issued_token_clear_count(), 2)
  }

  func testMapsRecentAndPrincipalAuditEvents() throws {
    let store = try makeStore()
    let recent = try store.recentAuditEvents(limit: 20)

    XCTAssertEqual(recent.count, 5)
    XCTAssertEqual(recent[0].id, 5)
    XCTAssertEqual(recent[0].occurredAt, Date(timeIntervalSince1970: 400))
    XCTAssertEqual(recent[0].invocationID, "request_test")
    XCTAssertEqual(recent[0].principalID, "client_test")
    XCTAssertEqual(recent[0].adapterID, "rest")
    XCTAssertEqual(recent[0].capabilityID, "battery.read")
    XCTAssertEqual(
      recent.map(\.outcome),
      [
        .capabilityNotFound,
        .denied(code: "not_granted"),
        .started,
        .succeeded,
        .handlerFailed(code: "busy"),
      ])

    let filtered = try store.auditEvents(for: "client_test", limit: 10)
    XCTAssertEqual(filtered, recent)
    XCTAssertEqual(capturedIdentifier(), "client_test")
    XCTAssertEqual(bondry_test_principal_audit_count(), 2)
  }

  func testRejectsZeroExpirationBeforeCrossingTheABI() throws {
    let store = try makeStore()

    XCTAssertThrowsError(
      try store.issueToken(for: "client_test", expiresInSeconds: 0)
    ) { error in
      XCTAssertEqual(error as? BondryEncryptedStoreError, .invalidTokenLifetime)
    }
    XCTAssertEqual(bondry_test_issue_token_count(), 0)
  }

  func testImportedIssuedTokenLayoutExposesTheSecretOffset() {
    XCTAssertEqual(
      MemoryLayout<BondryIssuedTokenV1>.offset(of: \.secret),
      MemoryLayout<BondryTokenMetadataV1>.stride
    )
  }

  func testMapsAdministrationFailures() throws {
    let store = try makeStore()
    bondry_test_set_administration_status(BONDRY_STATUS_AUTHENTICATION_REJECTED)

    XCTAssertThrowsError(try store.authenticate(token: "credential")) { error in
      XCTAssertEqual(error as? BondryEncryptedStoreError, .authenticationRejected)
    }
    XCTAssertThrowsError(try store.clients()) { error in
      XCTAssertEqual(error as? BondryEncryptedStoreError, .authenticationRejected)
    }

    bondry_test_set_administration_status(BONDRY_STATUS_UNAVAILABLE)
    XCTAssertThrowsError(try store.issueToken(for: "client_test")) { error in
      XCTAssertEqual(error as? BondryEncryptedStoreError, .unavailable)
    }
    XCTAssertEqual(bondry_test_issued_token_clear_count(), 1)
  }

  private func makeStore() throws -> BondryEncryptedStore {
    let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x55, count: 32))
    return try BondryEncryptedStore.open(
      at: URL(fileURLWithPath: "/tmp/bondry-administration-test.db"),
      key: key
    )
  }

  private func capturedIdentifier() -> String {
    let bytes = (0..<bondry_test_identifier_length()).map(bondry_test_identifier_byte)
    return String(decoding: bytes, as: UTF8.self)
  }

  private func capturedLabel() -> String {
    let bytes = (0..<bondry_test_label_length()).map(bondry_test_label_byte)
    return String(decoding: bytes, as: UTF8.self)
  }
}
