import Bondry
import BondryApple
import BondryLocalServer
import CBondryLocalServer
import CBondryRuntime
import CBondryTestSupport
import Foundation
import XCTest

final class BondryLocalServerTests: XCTestCase {
  override func setUp() {
    super.setUp()
    bondry_test_reset()
  }

  func testStartsAndStopsWithCompleteConfiguration() throws {
    let runtime = try makeRuntime()
    let configuration = try BondryLocalServerConfiguration(
      adapters: [.rest, .mcp],
      mcpServer: try BondryMCPServerInformation(
        name: "battery-app",
        title: "Battery App",
        version: "2.3.1"
      ),
      listeningAddress: "::1",
      port: 18432,
      allowedBrowserOrigins: ["https://example.com"],
      limits: try BondryLocalServerLimits(
        requestsPerMinute: 240,
        authenticationFailuresPerMinute: 20,
        maxBodyBytes: 524_288,
        maxConnections: 32
      ),
      timeouts: try BondryLocalServerTimeouts(
        headerRead: .seconds(4),
        request: .seconds(20),
        shutdownGracePeriod: .milliseconds(1_500)
      )
    )

    let server = try runtime.startLocalServer(configuration: configuration)

    XCTAssertTrue(server.isRunning)
    XCTAssertEqual(server.endpoint, BondryLocalServerEndpoint(address: "127.0.0.1", port: 54321))
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
    XCTAssertNil(authentication["principalId"])
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
    let runtime = try makeRuntime()
    let server = try runtime.startLocalServer(
      configuration: try BondryLocalServerConfiguration(
        adapters: [.rest],
        authentication: .disabled(principalID: "local-user", kind: .user),
        allowsCleartextNetworkAccess: true,
        allowsUnauthenticatedNetworkAccess: true
      )
    )

    let json = try capturedConfiguration()
    let authentication = try XCTUnwrap(json["authentication"] as? [String: Any])
    XCTAssertEqual(authentication["mode"] as? String, "disabled")
    XCTAssertEqual(authentication["principalId"] as? String, "local-user")
    XCTAssertNil(authentication["principalID"])
    XCTAssertEqual(authentication["principalKind"] as? String, "user")
    XCTAssertEqual(json["allowCleartextNetwork"] as? Bool, true)
    XCTAssertEqual(json["allowUnauthenticatedNetwork"] as? Bool, true)
    XCTAssertNil(json["mcpServer"])
    try server.stop()
  }

  func testMapsStartupHandleAddressAndShutdownFailures() throws {
    let runtime = try makeRuntime()
    let configuration = try BondryLocalServerConfiguration(adapters: [.rest])

    bondry_test_set_server_start_status(BONDRY_STATUS_SERVER_BIND)
    XCTAssertThrowsError(try runtime.startLocalServer(configuration: configuration)) { error in
      XCTAssertEqual(error as? BondryLocalServerError, .addressInUse)
    }

    bondry_test_set_server_start_status(BONDRY_STATUS_OK)
    bondry_test_set_null_server_handle(1)
    XCTAssertThrowsError(try runtime.startLocalServer(configuration: configuration)) { error in
      XCTAssertEqual(error as? BondryLocalServerError, .invalidHandle)
    }

    bondry_test_set_null_server_handle(0)
    bondry_test_set_invalid_server_address(1)
    XCTAssertThrowsError(try runtime.startLocalServer(configuration: configuration)) { error in
      XCTAssertEqual(error as? BondryLocalServerError, .invalidAddress)
    }
    XCTAssertEqual(bondry_test_server_stop_count(), 1)

    bondry_test_set_invalid_server_address(0)
    let server = try runtime.startLocalServer(configuration: configuration)
    bondry_test_set_server_stop_status(BONDRY_STATUS_SERVER_STOP)
    XCTAssertThrowsError(try server.stop()) { error in
      XCTAssertEqual(error as? BondryLocalServerError, .stopFailed)
    }
    XCTAssertFalse(server.isRunning)
  }

  func testServerStopsDuringDeinitialization() throws {
    let runtime = try makeRuntime()
    var server: BondryLocalServer? = try runtime.startLocalServer(
      configuration: try BondryLocalServerConfiguration(adapters: [.rest])
    )

    XCTAssertNotNil(server)
    server = nil
    XCTAssertEqual(bondry_test_server_stop_count(), 1)
  }

  func testRejectsStructurallyInvalidConfigurationsBeforeStarting() throws {
    XCTAssertTrue(try BondryLocalServerConfiguration(adapters: []).adapters.isEmpty)
    XCTAssertThrowsError(
      try BondryLocalServerConfiguration(adapters: [.rest], listeningAddress: "localhost")
    ) { error in
      XCTAssertEqual(error as? BondryLocalServerConfigurationError, .invalidListeningAddress)
    }
    XCTAssertThrowsError(
      try BondryLocalServerConfiguration(
        adapters: [.rest],
        allowedBrowserOrigins: ["https://example.com/path"]
      )
    ) { error in
      XCTAssertEqual(error as? BondryLocalServerConfigurationError, .invalidBrowserOrigin)
    }
    XCTAssertThrowsError(
      try BondryLocalServerConfiguration(
        adapters: [.rest],
        authentication: .disabled(principalID: "not portable")
      )
    ) { error in
      XCTAssertEqual(error as? BondryLocalServerConfigurationError, .invalidPrincipalID)
    }
    XCTAssertThrowsError(
      try BondryLocalServerConfiguration(
        adapters: [.rest],
        listeningAddress: "192.0.2.1"
      )
    ) { error in
      XCTAssertEqual(
        error as? BondryLocalServerConfigurationError,
        .cleartextNetworkExposureRequiresAcknowledgement
      )
    }
    XCTAssertThrowsError(
      try BondryLocalServerConfiguration(
        adapters: [.rest],
        listeningAddress: "192.0.2.1",
        authentication: .disabled(principalID: "local-user"),
        allowsCleartextNetworkAccess: true
      )
    ) { error in
      XCTAssertEqual(
        error as? BondryLocalServerConfigurationError,
        .unauthenticatedNetworkExposureRequiresAcknowledgement
      )
    }
    XCTAssertThrowsError(try BondryLocalServerConfiguration(adapters: [.mcp])) { error in
      XCTAssertEqual(error as? BondryLocalServerConfigurationError, .missingMCPServerInformation)
    }
    let information = try BondryMCPServerInformation(name: "app", version: "1")
    XCTAssertThrowsError(
      try BondryLocalServerConfiguration(adapters: [.rest], mcpServer: information)
    ) { error in
      XCTAssertEqual(
        error as? BondryLocalServerConfigurationError,
        .unexpectedMCPServerInformation
      )
    }
    XCTAssertEqual(bondry_test_server_start_count(), 0)
  }

  func testValidatesMCPServerInformation() {
    XCTAssertThrowsError(try BondryMCPServerInformation(name: "", version: "1")) { error in
      XCTAssertEqual(error as? BondryLocalServerConfigurationError, .invalidMCPServerName)
    }
    XCTAssertThrowsError(
      try BondryMCPServerInformation(name: "app", title: "invalid\n", version: "1")
    ) { error in
      XCTAssertEqual(error as? BondryLocalServerConfigurationError, .invalidMCPServerTitle)
    }
    XCTAssertThrowsError(
      try BondryMCPServerInformation(name: "app", version: String(repeating: "x", count: 65))
    ) { error in
      XCTAssertEqual(error as? BondryLocalServerConfigurationError, .invalidMCPServerVersion)
    }
  }

  func testValidatesResourceLimits() {
    XCTAssertThrowsError(
      try BondryLocalServerLimits(
        requestsPerMinute: 0,
        authenticationFailuresPerMinute: 1,
        maxBodyBytes: 1,
        maxConnections: 1
      )
    ) { error in
      XCTAssertEqual(error as? BondryLocalServerConfigurationError, .invalidRateLimit)
    }
    XCTAssertThrowsError(
      try BondryLocalServerLimits(
        requestsPerMinute: 1,
        authenticationFailuresPerMinute: 1,
        maxBodyBytes: 8 * 1_048_576 + 1,
        maxConnections: 1
      )
    ) { error in
      XCTAssertEqual(error as? BondryLocalServerConfigurationError, .invalidBodyLimit)
    }
    XCTAssertThrowsError(
      try BondryLocalServerLimits(
        requestsPerMinute: 1,
        authenticationFailuresPerMinute: 1,
        maxBodyBytes: 1,
        maxConnections: 1_025
      )
    ) { error in
      XCTAssertEqual(error as? BondryLocalServerConfigurationError, .invalidConnectionLimit)
    }
  }

  func testValidatesMillisecondTimeouts() {
    for timeout in [Duration.zero, .microseconds(1), .seconds(301)] {
      XCTAssertThrowsError(
        try BondryLocalServerTimeouts(
          headerRead: timeout,
          request: .seconds(1),
          shutdownGracePeriod: .seconds(1)
        )
      ) { error in
        XCTAssertEqual(error as? BondryLocalServerConfigurationError, .invalidTimeout)
      }
    }
  }

  private func makeRuntime() throws -> BondryRuntime {
    let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x71, count: 32))
    return try BondryRuntime.open(
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
