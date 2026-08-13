import BondryApple
import BondrySQLCipher
import CBondry
import CBondryTestSupport
import Foundation
import XCTest

final class BondryServerTests: XCTestCase {
  override func setUp() {
    super.setUp()
    bondry_test_reset()
  }

  func testStartsAndStopsWithCompleteConfiguration() throws {
    let store = try makeStore()
    let configuration = BondryServerConfiguration(
      adapters: [.rest, .mcp],
      mcpServer: BondryMCPServerInformation(
        name: "battery-app",
        title: "Battery App",
        version: "2.3.1"
      ),
      bindAddress: "::1",
      port: 18432,
      allowedOrigins: ["https://example.com"],
      requestsPerMinute: 240,
      authenticationFailuresPerMinute: 20,
      maxBodyBytes: 524_288,
      maxConnections: 32,
      headerReadTimeoutMilliseconds: 4_000,
      requestTimeoutMilliseconds: 20_000,
      shutdownGracePeriodMilliseconds: 1_500
    )

    let server = try store.startServer(configuration: configuration)

    XCTAssertTrue(server.isRunning)
    XCTAssertEqual(server.endpoint, BondryServerEndpoint(address: "127.0.0.1", port: 54321))
    XCTAssertEqual(bondry_test_server_start_count(), 1)
    let json = try capturedConfiguration()
    XCTAssertEqual(json["version"] as? Int, Int(BONDRY_SERVER_CONFIGURATION_VERSION_V1))
    XCTAssertEqual(json["bindAddress"] as? String, "::1")
    XCTAssertEqual(json["port"] as? Int, 18432)
    XCTAssertEqual(json["adapters"] as? [String], ["mcp", "rest"])
    XCTAssertEqual(json["allowedOrigins"] as? [String], ["https://example.com"])
    XCTAssertEqual(json["requestsPerMinute"] as? Int, 240)
    XCTAssertEqual(json["authenticationFailuresPerMinute"] as? Int, 20)
    XCTAssertEqual(json["maxBodyBytes"] as? Int, 524_288)
    XCTAssertEqual(json["maxConnections"] as? Int, 32)
    XCTAssertEqual(json["headerReadTimeoutMilliseconds"] as? Int, 4_000)
    XCTAssertEqual(json["requestTimeoutMilliseconds"] as? Int, 20_000)
    XCTAssertEqual(json["shutdownGracePeriodMilliseconds"] as? Int, 1_500)
    XCTAssertEqual(json["allowCleartextNetwork"] as? Bool, false)
    XCTAssertEqual(json["allowUnauthenticatedNetwork"] as? Bool, false)
    let authentication = try XCTUnwrap(json["authentication"] as? [String: Any])
    XCTAssertEqual(authentication["mode"] as? String, "bearer")
    XCTAssertNil(authentication["principalID"])
    let mcp = try XCTUnwrap(json["mcpServer"] as? [String: Any])
    XCTAssertEqual(mcp["name"] as? String, "battery-app")
    XCTAssertEqual(mcp["title"] as? String, "Battery App")
    XCTAssertEqual(mcp["version"] as? String, "2.3.1")

    try server.stop()
    XCTAssertFalse(server.isRunning)
    XCTAssertEqual(bondry_test_server_stop_count(), 1)
    try server.stop()
    XCTAssertEqual(bondry_test_server_stop_count(), 1)
  }

  func testEncodesExplicitDisabledAuthentication() throws {
    let store = try makeStore()
    let server = try store.startServer(
      configuration: BondryServerConfiguration(
        adapters: [.rest],
        authentication: .disabled(principalID: "local-user", kind: .user),
        allowCleartextNetwork: true,
        allowUnauthenticatedNetwork: true
      )
    )

    let json = try capturedConfiguration()
    let authentication = try XCTUnwrap(json["authentication"] as? [String: Any])
    XCTAssertEqual(authentication["mode"] as? String, "disabled")
    XCTAssertEqual(authentication["principalID"] as? String, "local-user")
    XCTAssertEqual(authentication["principalKind"] as? String, "user")
    XCTAssertEqual(json["allowCleartextNetwork"] as? Bool, true)
    XCTAssertEqual(json["allowUnauthenticatedNetwork"] as? Bool, true)
    XCTAssertNil(json["mcpServer"])
    try server.stop()
  }

  func testMapsStartupHandleAddressAndShutdownFailures() throws {
    let store = try makeStore()
    let configuration = BondryServerConfiguration(adapters: [.rest])

    bondry_test_set_server_start_status(BONDRY_STATUS_SERVER_BIND)
    XCTAssertThrowsError(try store.startServer(configuration: configuration)) { error in
      XCTAssertEqual(error as? BondryEncryptedStoreError, .serverBind)
    }

    bondry_test_set_server_start_status(BONDRY_STATUS_OK)
    bondry_test_set_null_server_handle(1)
    XCTAssertThrowsError(try store.startServer(configuration: configuration)) { error in
      XCTAssertEqual(error as? BondryEncryptedStoreError, .invalidHandle)
    }

    bondry_test_set_null_server_handle(0)
    bondry_test_set_invalid_server_address(1)
    XCTAssertThrowsError(try store.startServer(configuration: configuration)) { error in
      XCTAssertEqual(error as? BondryEncryptedStoreError, .invalidData)
    }
    XCTAssertEqual(bondry_test_server_stop_count(), 1)

    bondry_test_set_invalid_server_address(0)
    let server = try store.startServer(configuration: configuration)
    bondry_test_set_server_stop_status(BONDRY_STATUS_SERVER_STOP)
    XCTAssertThrowsError(try server.stop()) { error in
      XCTAssertEqual(error as? BondryEncryptedStoreError, .serverStop)
    }
    XCTAssertFalse(server.isRunning)
  }

  func testServerStopsDuringDeinitialization() throws {
    let store = try makeStore()
    var server: BondryServer? = try store.startServer(
      configuration: BondryServerConfiguration(adapters: [.rest])
    )

    XCTAssertNotNil(server)
    server = nil
    XCTAssertEqual(bondry_test_server_stop_count(), 1)
  }

  private func makeStore() throws -> BondryEncryptedStore {
    let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x71, count: 32))
    return try BondryEncryptedStore.open(
      at: URL(fileURLWithPath: "/tmp/bondry-server-test.db"),
      key: key
    )
  }

  private func capturedConfiguration() throws -> [String: Any] {
    let data = Data(
      (0..<bondry_test_server_configuration_length()).map {
        bondry_test_server_configuration_byte($0)
      }
    )
    return try XCTUnwrap(
      JSONSerialization.jsonObject(with: data) as? [String: Any]
    )
  }
}
