import Bondry
import BondryApple
import CBondryRuntime
import CBondryTestSupport
import Foundation
import XCTest

final class BondryAdministrationTests: XCTestCase {
  override func setUp() {
    super.setUp()
    bondry_test_reset()
  }

  func testCreatesListsAndUpdatesClients() throws {
    let runtime = try makeRuntime()
    let created = try runtime.createClient(named: "My Integration")

    XCTAssertEqual(created.id, "client_created")
    XCTAssertEqual(created.name, "Created Client")
    XCTAssertTrue(created.isEnabled)
    XCTAssertEqual(created.createdAt, Date(timeIntervalSince1970: 100))
    XCTAssertEqual(bondry_test_create_client_count(), 1)
    XCTAssertEqual(capturedIdentifier(), "My Integration")

    let clients = try runtime.clients()
    XCTAssertEqual(clients.map(\.id), ["client_a", "client_b"])
    XCTAssertTrue(clients[0].isEnabled)
    XCTAssertFalse(clients[1].isEnabled)

    bondry_test_set_client_list_growth(1)
    XCTAssertEqual(try runtime.clients().map(\.id), ["client_a", "client_b", "client_c"])

    try runtime.setClient("client_a", enabled: false)
    XCTAssertEqual(bondry_test_set_client_enabled_count(), 1)
    XCTAssertEqual(capturedIdentifier(), "client_a")
    XCTAssertEqual(bondry_test_enabled(), 0)
  }

  func testManagesOneTimeTokensAndClearsTheirStorage() throws {
    let runtime = try makeRuntime()
    var issued: BondryIssuedToken? = try runtime.issueToken(
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

    let principal = try runtime.authenticate(token: try XCTUnwrap(issued))
    XCTAssertEqual(principal.id, "client_authenticated")
    XCTAssertEqual(principal.kind, .application)
    XCTAssertEqual(capturedIdentifier(), secret)

    let tokens = try runtime.tokens(for: "client_test")
    XCTAssertEqual(tokens.map(\.id), ["token_active", "token_revoked"])
    XCTAssertEqual(tokens[0].label, "Primary")
    XCTAssertNil(tokens[0].revokedAt)
    XCTAssertNil(tokens[1].expiresAt)
    XCTAssertEqual(tokens[1].revokedAt, Date(timeIntervalSince1970: 250))

    var replacement: BondryIssuedToken? = try runtime.rotateToken("token_issued")
    XCTAssertEqual(replacement?.metadata.id, "token_replacement")
    XCTAssertEqual(replacement?.copySecret(), "bondry_v1.token_replacement.secret")
    XCTAssertEqual(capturedIdentifier(), "token_issued")
    XCTAssertEqual(bondry_test_label_length(), 0)
    XCTAssertEqual(bondry_test_has_expiration(), 0)
    XCTAssertTrue(try runtime.revokeToken("token_replacement"))
    XCTAssertEqual(capturedIdentifier(), "token_replacement")

    XCTAssertEqual(bondry_test_issued_token_clear_count(), 0)
    issued = nil
    replacement = nil
    XCTAssertEqual(bondry_test_issued_token_clear_count(), 2)
  }

  func testMapsRecentAndPrincipalAuditEvents() throws {
    let runtime = try makeRuntime()
    let recent = try runtime.recentAuditEvents(limit: 20)

    XCTAssertEqual(recent.count, 6)
    XCTAssertEqual(recent[0].id, 6)
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
        .invalidInput,
        .succeeded,
        .handlerFailed(code: "busy"),
      ])

    let filtered = try runtime.auditEvents(for: "client_test", limit: 10)
    XCTAssertEqual(filtered, recent)
    XCTAssertEqual(capturedIdentifier(), "client_test")
    XCTAssertEqual(bondry_test_principal_audit_count(), 2)
  }

  func testManagesExactCapabilityGrants() throws {
    let runtime = try makeRuntime()

    XCTAssertTrue(
      try runtime.addGrant(
        principalID: "client_test",
        adapterID: "rest",
        capabilityID: "battery.status"
      )
    )
    XCTAssertEqual(bondry_test_add_grant_count(), 1)
    XCTAssertEqual(capturedIdentifier(), "client_test")
    XCTAssertEqual(capturedAdapter(), "rest")
    XCTAssertEqual(capturedCapability(), "battery.status")

    XCTAssertEqual(
      try runtime.grants(for: "client_test"),
      [
        BondryCapabilityGrant(
          principalID: "client_test",
          adapterID: "mcp",
          capabilityID: "battery.health"
        ),
        BondryCapabilityGrant(
          principalID: "client_test",
          adapterID: "rest",
          capabilityID: "battery.status"
        ),
      ]
    )

    XCTAssertTrue(
      try runtime.removeGrant(
        principalID: "client_test",
        adapterID: "rest",
        capabilityID: "battery.status"
      )
    )
    XCTAssertEqual(bondry_test_remove_grant_count(), 1)
  }

  func testRejectsZeroExpirationBeforeCrossingTheABI() throws {
    let runtime = try makeRuntime()

    XCTAssertThrowsError(
      try runtime.issueToken(for: "client_test", expiresInSeconds: 0)
    ) { error in
      XCTAssertEqual(error as? BondryRuntimeError, .invalidTokenLifetime)
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
    let runtime = try makeRuntime()
    bondry_test_set_administration_status(BONDRY_STATUS_AUTHENTICATION_REJECTED)

    XCTAssertThrowsError(try runtime.authenticate(token: "credential")) { error in
      XCTAssertEqual(error as? BondryRuntimeError, .authenticationRejected)
    }
    XCTAssertThrowsError(try runtime.clients()) { error in
      XCTAssertEqual(error as? BondryRuntimeError, .authenticationRejected)
    }

    bondry_test_set_administration_status(BONDRY_STATUS_UNAVAILABLE)
    XCTAssertThrowsError(try runtime.issueToken(for: "client_test")) { error in
      XCTAssertEqual(error as? BondryRuntimeError, .unavailable)
    }
    XCTAssertEqual(bondry_test_issued_token_clear_count(), 1)
  }

  private func makeRuntime() throws -> BondryRuntime {
    let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x55, count: 32))
    return try BondryRuntime.open(
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

  private func capturedAdapter() -> String {
    let bytes = (0..<bondry_test_adapter_length()).map(bondry_test_adapter_byte)
    return String(decoding: bytes, as: UTF8.self)
  }

  private func capturedCapability() -> String {
    let bytes = (0..<bondry_test_capability_length()).map(bondry_test_capability_byte)
    return String(decoding: bytes, as: UTF8.self)
  }
}
