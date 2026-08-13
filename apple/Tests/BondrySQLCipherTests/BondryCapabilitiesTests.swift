import BondryApple
import BondrySQLCipher
import CBondry
import CBondryTestSupport
import Foundation
import XCTest

final class BondryCapabilitiesTests: XCTestCase {
  override func setUp() {
    super.setUp()
    bondry_test_reset()
  }

  func testRegistersListsAndUnregistersCapabilities() throws {
    let store = try makeStore()
    let capability = BondryCapability(
      id: "battery.read",
      summary: "Read battery state",
      effect: .readOnly
    )

    try store.registerCapability(capability) { _ in
      Data("null".utf8)
    }

    XCTAssertEqual(bondry_test_register_capability_count(), 1)
    XCTAssertEqual(capturedCapability(), capability.id)
    XCTAssertEqual(capturedSummary(), capability.summary)
    XCTAssertEqual(bondry_test_capability_effect(), BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1)
    XCTAssertEqual(try store.capabilities(), [capability])
    XCTAssertTrue(try store.unregisterCapability(capability.id))
    XCTAssertEqual(bondry_test_unregister_capability_count(), 1)
    XCTAssertEqual(bondry_test_release_capability_count(), 1)
    XCTAssertEqual(try store.capabilities(), [])
  }

  func testDispatchesIssuedTokensToAsyncHandlers() async throws {
    let store = try makeStore()
    let token = try store.issueToken(for: "client_test")
    let recorder = InvocationRecorder()
    try store.registerCapability(capability()) { invocation in
      await recorder.record(invocation)
      await Task.yield()
      return Data(#"{"level":85}"#.utf8)
    }

    let input = Data(#"{"detail":true}"#.utf8)
    let output = try await store.dispatch(
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
    let store = try makeStore()
    try store.registerCapability(capability()) { _ in
      throw BondryCapabilityHandlerError.failed(code: "busy")
    }

    await assertDispatchError(.handlerFailed(code: "busy")) {
      try await store.dispatch(
        invocationID: "request_failure",
        adapterID: "rest",
        token: "credential",
        capabilityID: "battery.read",
        inputJSON: Data("null".utf8)
      )
    }

    XCTAssertTrue(try store.unregisterCapability("battery.read"))
    try store.registerCapability(capability()) { _ in
      throw PrivateHandlerFailure()
    }
    await assertDispatchError(.handlerFailed(code: "handler_failed")) {
      try await store.dispatch(
        invocationID: "request_private_failure",
        adapterID: "rest",
        token: "credential",
        capabilityID: "battery.read",
        inputJSON: Data("null".utf8)
      )
    }
  }

  func testMapsSynchronousDispatchOutcomes() async throws {
    let store = try makeStore()
    let cases: [(UInt32, BondryDispatchError)] = [
      (BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1, .capabilityNotFound),
      (BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1, .accessDenied(.notGranted)),
      (BONDRY_DISPATCH_OUTCOME_AUDIT_UNAVAILABLE_V1, .auditUnavailable),
      (BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1, .handlerFailed(code: "busy")),
    ]

    for (outcome, expected) in cases {
      bondry_test_set_dispatch_outcome(outcome)
      await assertDispatchError(expected) {
        try await store.dispatch(
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
    let store = try makeStore()
    bondry_test_set_administration_status(BONDRY_STATUS_INVALID_JSON)

    do {
      _ = try await store.dispatch(
        invocationID: "request_invalid",
        adapterID: "rest",
        token: "credential",
        capabilityID: "battery.read",
        inputJSON: Data("invalid".utf8)
      )
      XCTFail("Expected dispatch to fail")
    } catch {
      XCTAssertEqual(error as? BondryEncryptedStoreError, .invalidJSON)
    }
    XCTAssertThrowsError(
      try store.registerCapability(capability()) { _ in Data("null".utf8) }
    ) { error in
      XCTAssertEqual(error as? BondryEncryptedStoreError, .invalidJSON)
    }
  }

  func testCancelledCallerDoesNotStartDispatch() async throws {
    let store = try makeStore()
    let gate = StartGate()
    let task = Task {
      await gate.wait()
      return try await store.dispatch(
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
    let store = try makeStore()
    let gate = StartGate()
    try store.registerCapability(capability()) { _ in
      await gate.wait()
      return Data("null".utf8)
    }
    let task = Task {
      try await store.dispatch(
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

  private func makeStore() throws -> BondryEncryptedStore {
    let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x55, count: 32))
    return try BondryEncryptedStore.open(
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
