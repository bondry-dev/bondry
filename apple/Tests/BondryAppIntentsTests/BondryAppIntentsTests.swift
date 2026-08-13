import AppIntents
import Bondry
import BondryApple
import CBondryRuntime
import CBondryTestSupport
import Foundation
import XCTest

@testable import BondryAppIntents

final class BondryAppIntentsTests: XCTestCase {
  private var runtimes: [BondryRuntime] = []

  override func setUp() {
    super.setUp()
    bondry_test_reset()
  }

  override func tearDown() {
    runtimes.removeAll()
    super.tearDown()
  }

  func testDiscoversOnlyRegisteredCapabilitiesGrantedToShortcuts() throws {
    let runtime = try makeRuntime()
    try runtime.registerCapability(capability()) { _ in Data("null".utf8) }
    let shortcutsRuntime = makeShortcutsRuntime(runtime: runtime)

    XCTAssertEqual(try shortcutsRuntime.authorizedCapabilities(), [])
    bondry_test_set_shortcuts_grant(2)
    XCTAssertEqual(try shortcutsRuntime.authorizedCapabilities(), [])
    bondry_test_set_shortcuts_grant(1)
    XCTAssertEqual(try shortcutsRuntime.authorizedCapabilities(), [capability()])
    XCTAssertEqual(capturedIdentifier(), "shortcuts.local-user")
    XCTAssertEqual(capturedAdapter(), BondryShortcutsRuntime.adapterID)
    XCTAssertEqual(bondry_test_principal_kind(), BONDRY_PRINCIPAL_KIND_SYSTEM_V1)
  }

  func testEntityQueryPreservesRequestedIdentifierOrder() async throws {
    let runtime = try makeRuntime()
    try runtime.registerCapability(capability()) { _ in Data("null".utf8) }
    bondry_test_set_shortcuts_grant(1)
    let query = BondryCapabilityQuery(runtime: makeShortcutsRuntime(runtime: runtime))

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
    let runtime = try makeRuntime()
    try runtime.registerCapability(capability()) { _ in Data(#"{"level":85}"#.utf8) }
    let shortcutsRuntime = makeShortcutsRuntime(runtime: runtime)

    let output = try await shortcutsRuntime.invoke(
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
    let shortcutsRuntime = makeShortcutsRuntime(runtime: try makeRuntime())
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
        try await shortcutsRuntime.invoke(capabilityID: "battery.read", inputJSON: Data("{}".utf8))
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
    let runtime = try makeRuntime()
    try runtime.registerCapability(capability()) { _ in Data(#"{"level":85}"#.utf8) }
    let intent = BondryRunCapabilityIntent(
      capability: BondryCapabilityEntity(id: "battery.read", summary: "Read battery state"),
      inputJSON: "42",
      runtime: makeShortcutsRuntime(runtime: runtime)
    )

    XCTAssertEqual(intent.capability.id, "battery.read")
    XCTAssertEqual(intent.inputJSON, "42")

    let result = try await intent.perform()

    XCTAssertEqual(result.value, #"{"level":85}"#)
  }

  func testMapsDiscoveryFailuresToServiceUnavailable() throws {
    let shortcutsRuntime = makeShortcutsRuntime(runtime: try makeRuntime())
    bondry_test_set_administration_status(BONDRY_STATUS_UNAVAILABLE)

    XCTAssertThrowsError(try shortcutsRuntime.authorizedCapabilities()) { error in
      XCTAssertEqual(error as? BondryShortcutsError, .serviceUnavailable)
    }
  }

  private func capability() -> BondryCapability {
    BondryCapability(id: "battery.read", summary: "Read battery state", effect: .readOnly)
  }

  private func makeShortcutsRuntime(runtime: BondryRuntime) -> BondryShortcutsRuntime {
    BondryShortcutsRuntime(
      runtime: runtime,
      principal: BondryPrincipal(id: "shortcuts.local-user", kind: .system)
    )
  }

  private func makeRuntime() throws -> BondryRuntime {
    let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x55, count: 32))
    let runtime = try BondryRuntime.open(
      at: URL(fileURLWithPath: "/tmp/bondry-app-intents-test.db"),
      key: key
    )
    runtimes.append(runtime)
    return runtime
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
