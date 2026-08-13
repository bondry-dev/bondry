import Bondry
import BondryApple
import CBondryRuntime
import CBondryTestSupport
import Foundation
import XCTest

final class BondryCapabilitiesTests: XCTestCase {
  override func setUp() {
    super.setUp()
    bondry_test_reset()
  }

  func testRegistersListsAndUnregistersCapabilities() throws {
    let runtime = try makeRuntime()
    let capability = BondryCapability(
      id: "battery.read",
      summary: "Read battery state",
      effect: .readOnly
    )

    try runtime.registerCapability(capability) { _ in
      Data("null".utf8)
    }

    XCTAssertEqual(bondry_test_register_capability_count(), 1)
    XCTAssertEqual(capturedCapability(), capability.id)
    XCTAssertEqual(capturedSummary(), capability.summary)
    XCTAssertEqual(bondry_test_capability_effect(), BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1)
    XCTAssertEqual(try runtime.capabilities(), [capability])
    XCTAssertTrue(try runtime.unregisterCapability(capability.id))
    XCTAssertEqual(bondry_test_unregister_capability_count(), 1)
    XCTAssertEqual(bondry_test_release_capability_count(), 1)
    XCTAssertEqual(try runtime.capabilities(), [])
  }

  func testRegistersCanonicalInputSchema() throws {
    let runtime = try makeRuntime()
    let schema = try BondryCapabilityInputSchema(
      jsonRepresentation: Data(#"{ "required": ["level"], "type": "object" }"#.utf8)
    )
    let capability = BondryCapability(
      id: "battery.configure",
      summary: "Change battery settings",
      effect: .mutating,
      inputSchema: schema
    )

    try runtime.registerCapability(capability) { _ in Data("null".utf8) }

    XCTAssertEqual(
      capturedSchema(),
      Data(#"{"required":["level"],"type":"object"}"#.utf8)
    )
  }

  func testRejectsInvalidCapabilityInputSchemas() throws {
    XCTAssertThrowsError(
      try BondryCapabilityInputSchema(jsonRepresentation: Data("not-json".utf8))
    ) { error in
      XCTAssertEqual(error as? BondryCapabilityInputSchemaError, .invalidJSON)
    }
    XCTAssertThrowsError(
      try BondryCapabilityInputSchema(jsonRepresentation: Data("[]".utf8))
    ) { error in
      XCTAssertEqual(error as? BondryCapabilityInputSchemaError, .notObject)
    }
    XCTAssertThrowsError(
      try BondryCapabilityInputSchema(jsonRepresentation: Data(repeating: 0x20, count: 65_537))
    ) { error in
      XCTAssertEqual(error as? BondryCapabilityInputSchemaError, .tooLarge)
    }
  }

  func testDispatchesIssuedTokensToAsyncHandlers() async throws {
    let runtime = try makeRuntime()
    let token = try runtime.issueToken(for: "client_test")
    let recorder = InvocationRecorder()
    try runtime.registerCapability(capability()) { invocation in
      await recorder.record(invocation)
      await Task.yield()
      return Data(#"{"level":85}"#.utf8)
    }

    let input = Data(#"{"detail":true}"#.utf8)
    let output = try await runtime.dispatch(
      invocationID: "request_swift",
      adapterID: "rest",
      token: token,
      capabilityID: "battery.read",
      inputJSON: input
    )

    XCTAssertEqual(output, Data(#"{"level":85}"#.utf8))
    XCTAssertEqual(bondry_test_dispatch_count(), 1)
    XCTAssertEqual(capturedIdentifier(), token.copySecret())
    XCTAssertEqual(capturedAdapter(), "rest")
    XCTAssertEqual(capturedCapability(), "battery.read")
    XCTAssertEqual(capturedInput(), input)
    let recordedInvocation = await recorder.invocation
    let invocation = try XCTUnwrap(recordedInvocation)
    XCTAssertEqual(invocation.id, "request_test")
    XCTAssertEqual(invocation.principal.id, "client_test")
    XCTAssertEqual(invocation.principal.kind, .application)
    XCTAssertEqual(invocation.adapterID, "rest")
    XCTAssertEqual(invocation.capabilityID, "battery.read")
    XCTAssertEqual(invocation.inputJSON, input)
  }

  func testMapsExplicitAndPrivateHandlerFailuresSafely() async throws {
    let runtime = try makeRuntime()
    try runtime.registerCapability(capability()) { _ in
      throw BondryCapabilityHandlerError.failed(code: "busy")
    }

    await assertDispatchError(.handlerFailed(code: "busy")) {
      try await runtime.dispatch(
        invocationID: "request_failure",
        adapterID: "rest",
        token: "credential",
        capabilityID: "battery.read",
        inputJSON: Data("null".utf8)
      )
    }

    XCTAssertTrue(try runtime.unregisterCapability("battery.read"))
    try runtime.registerCapability(capability()) { _ in
      throw PrivateHandlerFailure()
    }
    await assertDispatchError(.handlerFailed(code: "handler_failed")) {
      try await runtime.dispatch(
        invocationID: "request_private_failure",
        adapterID: "rest",
        token: "credential",
        capabilityID: "battery.read",
        inputJSON: Data("null".utf8)
      )
    }
  }

  func testDispatchesTrustedPlatformPrincipalWithoutCredentials() async throws {
    let runtime = try makeRuntime()
    let recorder = InvocationRecorder()
    try runtime.registerCapability(capability()) { invocation in
      await recorder.record(invocation)
      return Data(#"{"level":85}"#.utf8)
    }
    let principal = BondryPrincipal(id: "shortcuts.local-user", kind: .system)
    let input = Data(#"{"detail":true}"#.utf8)

    let output = try await runtime.dispatchPlatformInvocation(
      invocationID: "request_shortcuts",
      adapterID: "shortcuts",
      principal: principal,
      capabilityID: "battery.read",
      inputJSON: input
    )

    XCTAssertEqual(output, Data(#"{"level":85}"#.utf8))
    XCTAssertEqual(bondry_test_dispatch_count(), 1)
    XCTAssertEqual(capturedIdentifier(), principal.id)
    XCTAssertEqual(capturedAdapter(), "shortcuts")
    XCTAssertEqual(capturedCapability(), "battery.read")
    XCTAssertEqual(capturedInput(), input)
    XCTAssertEqual(bondry_test_principal_kind(), BONDRY_PRINCIPAL_KIND_SYSTEM_V1)
    let recordedInvocation = await recorder.invocation
    let invocation = try XCTUnwrap(recordedInvocation)
    XCTAssertEqual(invocation.id, "request_shortcuts")
    XCTAssertEqual(invocation.principal, principal)
    XCTAssertEqual(invocation.adapterID, "shortcuts")
    XCTAssertEqual(invocation.capabilityID, "battery.read")
    XCTAssertEqual(invocation.inputJSON, input)
  }

  func testMapsImmediatePlatformDispatchFailure() async throws {
    let runtime = try makeRuntime()
    bondry_test_set_administration_status(BONDRY_STATUS_INVALID_ARGUMENT)

    do {
      _ = try await runtime.dispatchPlatformInvocation(
        adapterID: "shortcuts",
        principal: BondryPrincipal(id: "shortcuts.local-user", kind: .system),
        capabilityID: "battery.read",
        inputJSON: Data("{}".utf8)
      )
      XCTFail("Expected dispatch to fail")
    } catch {
      XCTAssertEqual(error as? BondryRuntimeError, .invalidArgument)
    }
  }

  func testMapsSynchronousDispatchOutcomes() async throws {
    let runtime = try makeRuntime()
    let cases: [(UInt32, BondryDispatchError)] = [
      (BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1, .capabilityNotFound),
      (BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1, .accessDenied(.notGranted)),
      (BONDRY_DISPATCH_OUTCOME_INVALID_INPUT_V1, .invalidInput),
      (BONDRY_DISPATCH_OUTCOME_AUDIT_UNAVAILABLE_V1, .auditUnavailable),
      (BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1, .handlerFailed(code: "busy")),
    ]

    for (outcome, expected) in cases {
      bondry_test_set_dispatch_outcome(outcome)
      await assertDispatchError(expected) {
        try await runtime.dispatch(
          invocationID: "request_outcome",
          adapterID: "rest",
          token: "credential",
          capabilityID: "battery.read",
          inputJSON: Data("{}".utf8)
        )
      }
    }
  }

  func testMapsImmediateDispatchAndRegistrationFailures() async throws {
    let runtime = try makeRuntime()
    bondry_test_set_administration_status(BONDRY_STATUS_INVALID_JSON)

    do {
      _ = try await runtime.dispatch(
        invocationID: "request_invalid",
        adapterID: "rest",
        token: "credential",
        capabilityID: "battery.read",
        inputJSON: Data("invalid".utf8)
      )
      XCTFail("Expected dispatch to fail")
    } catch {
      XCTAssertEqual(error as? BondryRuntimeError, .invalidJSON)
    }
    XCTAssertThrowsError(
      try runtime.registerCapability(capability()) { _ in Data("null".utf8) }
    ) { error in
      XCTAssertEqual(error as? BondryRuntimeError, .invalidJSON)
    }
  }

  func testCancelledCallerDoesNotStartDispatch() async throws {
    let runtime = try makeRuntime()
    let gate = StartGate()
    let task = Task {
      await gate.wait()
      return try await runtime.dispatch(
        invocationID: "request_cancelled",
        adapterID: "rest",
        token: "credential",
        capabilityID: "battery.read",
        inputJSON: Data("{}".utf8)
      )
    }
    await gate.waitUntilBlocked()
    task.cancel()
    await gate.open()

    do {
      _ = try await task.value
      XCTFail("Expected cancellation")
    } catch is CancellationError {
    } catch {
      XCTFail("Unexpected error: \(error)")
    }
    XCTAssertEqual(bondry_test_dispatch_count(), 0)
  }

  func testAcceptedDispatchFinishesAfterCallerCancellation() async throws {
    let runtime = try makeRuntime()
    let gate = StartGate()
    try runtime.registerCapability(capability()) { _ in
      await gate.wait()
      return Data("null".utf8)
    }
    let task = Task {
      try await runtime.dispatch(
        invocationID: "request_accepted",
        adapterID: "rest",
        token: "credential",
        capabilityID: "battery.read",
        inputJSON: Data("{}".utf8)
      )
    }
    await gate.waitUntilBlocked()
    task.cancel()
    await gate.open()

    let output = try await task.value
    XCTAssertEqual(output, Data("null".utf8))
    XCTAssertTrue(task.isCancelled)
    XCTAssertEqual(bondry_test_dispatch_count(), 1)
  }

  private func capability() -> BondryCapability {
    BondryCapability(
      id: "battery.read",
      summary: "Read battery state",
      effect: .readOnly
    )
  }

  private func makeRuntime() throws -> BondryRuntime {
    let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x55, count: 32))
    return try BondryRuntime.open(
      at: URL(fileURLWithPath: "/tmp/bondry-capability-test.db"),
      key: key
    )
  }

  private func assertDispatchError(
    _ expected: BondryDispatchError,
    operation: () async throws -> Data
  ) async {
    do {
      _ = try await operation()
      XCTFail("Expected dispatch to fail")
    } catch {
      XCTAssertEqual(error as? BondryDispatchError, expected)
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

  private func capturedCapability() -> String {
    String(
      decoding: (0..<bondry_test_capability_length()).map(bondry_test_capability_byte),
      as: UTF8.self
    )
  }

  private func capturedSummary() -> String {
    String(
      decoding: (0..<bondry_test_summary_length()).map(bondry_test_summary_byte),
      as: UTF8.self
    )
  }

  private func capturedSchema() -> Data {
    Data((0..<bondry_test_schema_length()).map(bondry_test_schema_byte))
  }

  private func capturedInput() -> Data {
    Data((0..<bondry_test_input_length()).map(bondry_test_input_byte))
  }
}

private actor InvocationRecorder {
  var invocation: BondryCapabilityInvocation?

  func record(_ invocation: BondryCapabilityInvocation) {
    self.invocation = invocation
  }
}

private struct PrivateHandlerFailure: Error {}

private actor StartGate {
  private var continuation: CheckedContinuation<Void, Never>?
  private var isBlocked = false

  func wait() async {
    await withCheckedContinuation { continuation in
      self.continuation = continuation
      isBlocked = true
    }
  }

  func waitUntilBlocked() async {
    while !isBlocked {
      await Task.yield()
    }
  }

  func open() {
    continuation?.resume()
    continuation = nil
  }
}
