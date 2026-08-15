import Bondry
import BondryApple
import BondryEgress
import CBondryEgress
import CBondryTestSupport
import Foundation
import XCTest

final class BondryEgressTests: XCTestCase {
  override func setUp() {
    super.setUp()
    bondry_test_reset()
  }

  func testStartEncodesConfigurationAndOwnsHostServicesUntilStop() throws {
    let runtime = try makeRuntime()
    let egress = try runtime.startEgress(secretProvider: makeSecretProvider())

    XCTAssertTrue(egress.isRunning)
    XCTAssertEqual(bondry_test_egress_start_count(), 1)
    let configuration = try XCTUnwrap(
      try JSONSerialization.jsonObject(with: capturedEgressConfiguration()) as? [String: Any]
    )
    XCTAssertEqual(configuration["version"] as? Int, 1)
    let limits = try XCTUnwrap(configuration["runtime"] as? [String: Any])
    XCTAssertEqual(limits["global_pending_deliveries"] as? Int, 1_024)
    XCTAssertEqual(limits["global_pending_bytes"] as? Int, 8 * 1_024 * 1_024)

    try egress.stop()

    XCTAssertFalse(egress.isRunning)
    XCTAssertEqual(bondry_test_egress_stop_count(), 1)
    XCTAssertThrowsError(try egress.routes()) { error in
      XCTAssertEqual(error as? BondryEgressError, .stopped)
    }
  }

  func testRejectsIncompatibleABIWithoutStarting() throws {
    bondry_test_set_egress_abi_version(BONDRY_EGRESS_ABI_VERSION_V1 + 1)
    let runtime = try makeRuntime()

    XCTAssertThrowsError(
      try runtime.startEgress(secretProvider: makeSecretProvider())
    ) { error in
      XCTAssertEqual(
        error as? BondryEgressError,
        .incompatibleABI(
          expected: BONDRY_EGRESS_ABI_VERSION_V1,
          actual: BONDRY_EGRESS_ABI_VERSION_V1 + 1
        )
      )
    }
    XCTAssertEqual(bondry_test_egress_start_count(), 0)
  }

  func testRegistersRedactedURLTemplateAndExposesDeliveryLifecycle() throws {
    let runtime = try makeRuntime()
    let egress = try runtime.startEgress(secretProvider: makeSecretProvider())
    defer { try? egress.stop() }
    let secret = try BondrySecretReference("keychain:ntfy-topic")
    let route = BondryWebhookRoute(
      id: "alerts",
      payload: BondryPayloadContract(
        fields: [BondryPayloadField(name: "message", type: .string, required: true)]
      ),
      authentication: .urlTemplate("https://ntfy.sh/{secret}", secret: secret)
    )

    try egress.register(route)

    XCTAssertEqual(bondry_test_egress_register_count(), 1)
    let encodedRoute = capturedEgressRoute()
    let root = try XCTUnwrap(
      try JSONSerialization.jsonObject(with: encodedRoute) as? [String: Any]
    )
    let kind = try XCTUnwrap(root["kind"] as? [String: Any])
    let authentication = try XCTUnwrap(kind["authentication"] as? [String: Any])
    XCTAssertEqual(authentication["type"] as? String, "url_template")
    XCTAssertEqual(authentication["template"] as? String, "https://ntfy.sh/{secret}")
    XCTAssertEqual(authentication["secret_ref"] as? String, secret.rawValue)
    XCTAssertNil(authentication["secret_reference"])
    XCTAssertFalse(String(decoding: encodedRoute, as: UTF8.self).contains("expanded-topic"))

    XCTAssertNoThrow(try egress.disable(routeID: "alerts"))
    XCTAssertNoThrow(try egress.enable(routeID: "alerts"))
    let routes = try egress.routes()
    XCTAssertEqual(routes.count, 1)
    XCTAssertEqual(routes.first?.id, "alerts")
    XCTAssertEqual(routes.first?.enabled, true)
    XCTAssertEqual(routes.first?.kind, "webhook")
    XCTAssertEqual(routes.first?.target, "https://example.com/hook")

    try egress.emit(
      routeID: "alerts",
      deliveryID: "delivery-1",
      payload: ["message": "hello"]
    )

    XCTAssertEqual(bondry_test_egress_emit_count(), 1)
    XCTAssertNil(try egress.deliveryStatus(for: "unknown"))
    let status = try XCTUnwrap(try egress.deliveryStatus(for: "delivery-1"))
    XCTAssertEqual(status.routeID, "alerts")
    XCTAssertEqual(status.deliveryID, "delivery-1")
    XCTAssertEqual(status.attempts, 1)
    XCTAssertEqual(status.state, .terminal(.delivered))
    XCTAssertEqual(status.resultCategory, .succeeded)
  }

  func testDeinitializationStopsEgress() throws {
    let runtime = try makeRuntime()
    var egress: BondryEgress? = try runtime.startEgress(secretProvider: makeSecretProvider())

    XCTAssertNotNil(egress)
    egress = nil

    XCTAssertEqual(bondry_test_egress_stop_count(), 1)
  }

  func testDiscoversRegistersAndCallsMCPRoute() async throws {
    let runtime = try makeRuntime()
    let egress = try runtime.startEgress(secretProvider: makeSecretProvider())
    defer { try? egress.stop() }
    let endpoint = try XCTUnwrap(URL(string: "https://example.com/mcp"))

    let discovery = try await egress.discoverMCP(
      BondryMCPDiscoveryConfiguration(authentication: .none(endpoint: endpoint))
    )
    XCTAssertEqual(discovery.protocolVersion, .v20260728)
    XCTAssertEqual(discovery.tools.count, 1)
    XCTAssertEqual(discovery.tools[0].name, "battery:status")
    XCTAssertEqual(
      discovery.tools[0].inputSchema,
      .object(["type": .string("object")])
    )

    let route = BondryMCPRoute(
      id: "mcp-alerts",
      payload: BondryPayloadContract(
        fields: [BondryPayloadField(name: "detail", type: .boolean)]
      ),
      authentication: .none(endpoint: endpoint),
      protocolVersion: discovery.protocolVersion,
      tool: discovery.tools[0]
    )
    try egress.register(route)
    let root = try XCTUnwrap(
      try JSONSerialization.jsonObject(with: capturedEgressRoute()) as? [String: Any]
    )
    let kind = try XCTUnwrap(root["kind"] as? [String: Any])
    XCTAssertEqual(kind["type"] as? String, "mcp")
    XCTAssertEqual(kind["endpoint"] as? String, endpoint.absoluteString)
    XCTAssertEqual(kind["protocol_version"] as? String, "2026-07-28")
    XCTAssertEqual(kind["automatic_retry"] as? Bool, false)
    let authentication = try XCTUnwrap(kind["authentication"] as? [String: Any])
    XCTAssertEqual(authentication["type"] as? String, "none")

    let result = try await egress.call(
      routeID: route.id,
      deliveryID: "mcp-call-1",
      payload: ["detail": true]
    )
    XCTAssertEqual(result.deliveryID, "mcp-call-1")
    XCTAssertEqual(result.category, .succeeded)
    let output = try XCTUnwrap(
      try JSONSerialization.jsonObject(with: result.rawJSON) as? [String: Any]
    )
    let content = try XCTUnwrap(output["content"] as? [[String: Any]])
    XCTAssertEqual(content.first?["text"] as? String, "ok")

    await assertThrowsErrorAsync(
      try await egress.call(
        routeID: route.id,
        payload: ["detail": true],
        maxResultBytes: 1
      )
    ) { error in
      XCTAssertEqual(error as? BondryEgressError, .invalidArgument)
    }
  }

  private func makeRuntime() throws -> BondryRuntime {
    let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x55, count: 32))
    return try BondryRuntime.open(
      at: URL(fileURLWithPath: "/tmp/bondry-egress-test.db"),
      key: key
    )
  }

  private func makeSecretProvider() throws -> KeychainSecretProvider {
    KeychainSecretProvider(
      configuration: try KeychainSecretProviderConfiguration(service: "dev.bondry.tests")
    )
  }

  private func capturedEgressConfiguration() -> Data {
    Data(
      (0..<bondry_test_egress_configuration_length()).map {
        bondry_test_egress_configuration_byte($0)
      }
    )
  }

  private func capturedEgressRoute() -> Data {
    Data(
      (0..<bondry_test_egress_route_length()).map {
        bondry_test_egress_route_byte($0)
      }
    )
  }
}

private func assertThrowsErrorAsync<T>(
  _ expression: @autoclosure () async throws -> T,
  _ errorHandler: (Error) -> Void,
  file: StaticString = #filePath,
  line: UInt = #line
) async {
  do {
    _ = try await expression()
    XCTFail("Expected an error", file: file, line: line)
  } catch {
    errorHandler(error)
  }
}
