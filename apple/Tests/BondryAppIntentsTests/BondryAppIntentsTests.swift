import AppIntents
import BondryApple
import BondrySQLCipher
import CBondry
import CBondryTestSupport
import Foundation
import XCTest
@testable import BondryAppIntents

final class BondryAppIntentsTests: XCTestCase {
  private var stores: [BondryEncryptedStore] = []

  override func setUp() {
    super.setUp()
    bondry_test_reset()
  }

  override func tearDown() {
    stores.removeAll()
    super.tearDown()
  }

  func testDiscoversOnlyRegisteredCapabilitiesGrantedToShortcuts() throws {
    let store = try makeStore()
    try store.registerCapability(capability()) { _ in Data("null".utf8) }
    let runtime = makeRuntime(store: store)

    XCTAssertEqual(try runtime.authorizedCapabilities(), [])
    bondry_test_set_shortcuts_grant(2)
    XCTAssertEqual(try runtime.authorizedCapabilities(), [])
    bondry_test_set_shortcuts_grant(1)
    XCTAssertEqual(try runtime.authorizedCapabilities(), [capability()])
  }

  func testEntityQueryPreservesRequestedIdentifierOrder() async throws {
    let store = try makeStore()
    try store.registerCapability(capability()) { _ in Data("null".utf8) }
    bondry_test_set_shortcuts_grant(1)
    let query = BondryCapabilityQuery(runtime: makeRuntime(store: store))

    let suggested = try await query.suggestedEntities()
    let selected = try await query.entities(for: ["missing", "battery.read"])
    XCTAssertEqual(
      suggested,
      [BondryCapabilityEntity(id: "battery.read", summary: "Read battery state")]
    )
    XCTAssertEqual(
      selected,
      [BondryCapabilityEntity(id: "battery.read", summary: "Read battery state")]
    )
  }

  func testInvokesThroughShortcutsAdapterAndTrustedPrincipal() async throws {
    let store = try makeStore()
    try store.registerCapability(capability()) { _ in Data(#"{"level":85}"#.utf8) }
    let runtime = makeRuntime(store: store)

    let output = try await runtime.invoke(
      capabilityID: "battery.read",
      inputJSON: Data("{}".utf8),
      invocationID: "shortcut_request"
    )

    XCTAssertEqual(output, Data(#"{"level":85}"#.utf8))
    XCTAssertEqual(capturedIdentifier(), "shortcuts.local-user")
    XCTAssertEqual(capturedAdapter(), BondryShortcutsRuntime.adapterID)
    XCTAssertEqual(bondry_test_principal_kind(), BONDRY_PRINCIPAL_KIND_SYSTEM_V1)
  }

  func testMapsDispatchFailuresToSafeShortcutErrors() async throws {
    let runtime = makeRuntime(store: try makeStore())
    let cases: [(UInt32, BondryShortcutsError)] = [
      (BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1, .capabilityUnavailable),
      (BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1, .notAuthorized),
      (BONDRY_DISPATCH_OUTCOME_INVALID_INPUT_V1, .invalidInput),
      (BONDRY_DISPATCH_OUTCOME_AUDIT_UNAVAILABLE_V1, .serviceUnavailable),
      (BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1, .executionFailed),
    ]

    for (outcome, expected) in cases {
      bondry_test_set_dispatch_outcome(outcome)
      await assertShortcutError(expected) {
        try await runtime.invoke(capabilityID: "battery.read", inputJSON: Data("{}".utf8))
      }
    }
  }

  func testGenericIntentRequiresAuthenticationAndValidatesJSON() async throws {
    XCTAssertEqual(BondryRunCapabilityIntent.authenticationPolicy, .requiresAuthentication)
    let intent = BondryRunCapabilityIntent(
      capability: BondryCapabilityEntity(id: "battery.read", summary: "Read battery state"),
      inputJSON: "not-json"
    )

    do {
      _ = try await intent.perform()
      XCTFail("Expected invalid input")
    } catch {
      XCTAssertEqual(error as? BondryShortcutsError, .invalidInput)
    }
  }

  func testGenericIntentReturnsJSONOutput() async throws {
    let store = try makeStore()
    try store.registerCapability(capability()) { _ in Data(#"{"level":85}"#.utf8) }
    let intent = BondryRunCapabilityIntent(
      capability: BondryCapabilityEntity(id: "battery.read", summary: "Read battery state"),
      inputJSON: "42",
      runtime: makeRuntime(store: store)
    )

    XCTAssertEqual(intent.capability.id, "battery.read")
    XCTAssertEqual(intent.inputJSON, "42")

    let result = try await intent.perform()

    XCTAssertEqual(result.value, #"{"level":85}"#)
  }

  func testMapsDiscoveryFailuresToServiceUnavailable() throws {
    let runtime = makeRuntime(store: try makeStore())
    bondry_test_set_administration_status(BONDRY_STATUS_UNAVAILABLE)

    XCTAssertThrowsError(try runtime.authorizedCapabilities()) { error in
      XCTAssertEqual(error as? BondryShortcutsError, .serviceUnavailable)
    }
  }

  private func capability() -> BondryCapability {
    BondryCapability(id: "battery.read", summary: "Read battery state", effect: .readOnly)
  }

  private func makeRuntime(store: BondryEncryptedStore) -> BondryShortcutsRuntime {
    BondryShortcutsRuntime(
      store: store,
      principal: BondryPrincipal(id: "shortcuts.local-user", kind: .system)
    )
  }

  private func makeStore() throws -> BondryEncryptedStore {
    let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x55, count: 32))
    let store = try BondryEncryptedStore.open(
      at: URL(fileURLWithPath: "/tmp/bondry-app-intents-test.db"),
      key: key
    )
    stores.append(store)
    return store
  }

  private func assertShortcutError(
    _ expected: BondryShortcutsError,
    operation: () async throws -> Data
  ) async {
    do {
      _ = try await operation()
      XCTFail("Expected invocation to fail")
    } catch {
      XCTAssertEqual(error as? BondryShortcutsError, expected)
    }
  }

  private func capturedIdentifier() -> String {
    String(
      decoding: (0..<bondry_test_identifier_length()).map(bondry_test_identifier_byte),
      as: UTF8.self
    )
  }

  private func capturedAdapter() -> String {
    String(
      decoding: (0..<bondry_test_adapter_length()).map(bondry_test_adapter_byte),
      as: UTF8.self
    )
  }
}
