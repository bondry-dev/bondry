import Bondry
import BondryApple
import BondryRESTServer
import CBondryRESTServer
import CBondryTestSupport
import Foundation
import XCTest

final class BondryRESTServerTests: XCTestCase {
  override func setUp() {
    super.setUp()
    bondry_test_reset()
  }

  func testStartsFixedRESTServerWithCompleteConfiguration() throws {
    let runtime = try makeRuntime()
    let configuration = try BondryRESTServerConfiguration(
      listeningAddress: "::1",
      port: 18432,
      allowedBrowserOrigins: ["https://example.com"],
      limits: try BondryRESTServerLimits(
        requestsPerMinute: 240,
        authenticationFailuresPerMinute: 20,
        maxBodyBytes: 524_288,
        maxConnections: 32
      ),
      timeouts: try BondryRESTServerTimeouts(
        headerRead: .seconds(4),
        request: .seconds(20),
        shutdownGracePeriod: .milliseconds(1_500)
      )
    )

    let server = try runtime.startRESTServer(configuration: configuration)

    XCTAssertTrue(server.isRunning)
    XCTAssertEqual(server.endpoint, BondryRESTServerEndpoint(address: "127.0.0.1", port: 54321))
    let json = try capturedConfiguration()
    XCTAssertEqual(json["version"] as? Int, Int(BONDRY_REST_SERVER_CONFIGURATION_VERSION_V1))
    XCTAssertEqual(json["bindAddress"] as? String, "::1")
    XCTAssertEqual(json["port"] as? Int, 18432)
    XCTAssertEqual(json["allowedOrigins"] as? [String], ["https://example.com"])
    XCTAssertEqual(json["requestsPerMinute"] as? Int, 240)
    XCTAssertEqual(json["authenticationFailuresPerMinute"] as? Int, 20)
    XCTAssertEqual(json["maxBodyBytes"] as? Int, 524_288)
    XCTAssertEqual(json["maxConnections"] as? Int, 32)
    XCTAssertNil(json["adapters"])
    XCTAssertNil(json["mcpServer"])
    XCTAssertNil(json["rawBodyLimits"])

    try server.stop()
    XCTAssertFalse(server.isRunning)
    try server.stop()
    XCTAssertEqual(bondry_test_server_stop_count(), 1)
  }

  func testEncodesDisabledAuthenticationWithoutProtocolSelection() throws {
    let runtime = try makeRuntime()
    let server = try runtime.startRESTServer(
      configuration: try BondryRESTServerConfiguration(
        authentication: .disabled(principalID: "local-user", kind: .user)
      )
    )

    let json = try capturedConfiguration()
    let authentication = try XCTUnwrap(json["authentication"] as? [String: Any])
    XCTAssertEqual(authentication["mode"] as? String, "disabled")
    XCTAssertEqual(authentication["principalId"] as? String, "local-user")
    XCTAssertEqual(authentication["principalKind"] as? String, "user")
    XCTAssertNil(json["adapters"])
    try server.stop()
  }

  func testMapsLifecycleFailures() throws {
    let runtime = try makeRuntime()
    let configuration = try BondryRESTServerConfiguration()

    bondry_test_set_server_start_status(BONDRY_STATUS_SERVER_BIND)
    XCTAssertThrowsError(try runtime.startRESTServer(configuration: configuration)) { error in
      XCTAssertEqual(error as? BondryRESTServerError, .addressInUse)
    }

    bondry_test_set_server_start_status(BONDRY_STATUS_OK)
    bondry_test_set_null_server_handle(1)
    XCTAssertThrowsError(try runtime.startRESTServer(configuration: configuration)) { error in
      XCTAssertEqual(error as? BondryRESTServerError, .invalidHandle)
    }

    bondry_test_set_null_server_handle(0)
    bondry_test_set_invalid_server_address(1)
    XCTAssertThrowsError(try runtime.startRESTServer(configuration: configuration)) { error in
      XCTAssertEqual(error as? BondryRESTServerError, .invalidAddress)
    }
  }

  func testStartsUnixServerWithExplicitPeerPolicy() throws {
    let runtime = try makeRuntime()
    let configuration = try BondryRESTUnixServerConfiguration(
      socketURL: URL(fileURLWithPath: "/tmp/example/server.sock"),
      ownerUserID: 501,
      peerUserID: 502,
      principalID: "local-peer",
      principalKind: .user,
      limits: try BondryRESTServerLimits(
        requestsPerMinute: 240,
        authenticationFailuresPerMinute: 20,
        maxBodyBytes: 524_288,
        maxConnections: 32
      ),
      timeouts: try BondryRESTServerTimeouts(
        headerRead: .seconds(4),
        request: .seconds(20),
        shutdownGracePeriod: .milliseconds(1_500)
      )
    )

    let server = try runtime.startRESTUnixServer(configuration: configuration)

    XCTAssertTrue(server.isRunning)
    XCTAssertEqual(
      server.endpoint,
      BondryRESTUnixServerEndpoint(
        socketURL: URL(fileURLWithPath: "/tmp/bondry-test/server.sock")
      )
    )
    let json = try capturedConfiguration()
    XCTAssertEqual(
      json["version"] as? Int,
      Int(BONDRY_REST_UNIX_SERVER_CONFIGURATION_VERSION_V1)
    )
    XCTAssertEqual(json["socketPath"] as? String, "/tmp/example/server.sock")
    XCTAssertEqual(json["ownerUserId"] as? Int, 501)
    XCTAssertEqual(json["peerUserId"] as? Int, 502)
    XCTAssertEqual(json["principalId"] as? String, "local-peer")
    XCTAssertEqual(json["principalKind"] as? String, "user")
    XCTAssertEqual(json["requestsPerMinute"] as? Int, 240)
    XCTAssertEqual(json["maxBodyBytes"] as? Int, 524_288)
    XCTAssertEqual(json["maxConnections"] as? Int, 32)
    XCTAssertNil(json["authentication"])
    XCTAssertNil(json["allowedOrigins"])
    XCTAssertNil(json["bindAddress"])

    try server.stop()
    XCTAssertFalse(server.isRunning)
    try server.stop()
    XCTAssertEqual(bondry_test_server_stop_count(), 1)
  }

  func testValidatesUnixConfigurationAndMapsLifecycleFailures() throws {
    let networkURL = try XCTUnwrap(URL(string: "https://example.com/server.sock"))
    XCTAssertThrowsError(
      try BondryRESTUnixServerConfiguration(
        socketURL: networkURL,
        ownerUserID: 501,
        peerUserID: 501,
        principalID: "local-peer"
      )
    ) { error in
      XCTAssertEqual(
        error as? BondryRESTUnixServerConfigurationError,
        .invalidSocketURL
      )
    }
    XCTAssertThrowsError(
      try BondryRESTUnixServerConfiguration(
        socketURL: URL(fileURLWithPath: "/tmp/server.sock"),
        ownerUserID: 501,
        peerUserID: 501,
        principalID: "not valid"
      )
    ) { error in
      XCTAssertEqual(
        error as? BondryRESTUnixServerConfigurationError,
        .invalidPrincipalID
      )
    }
    XCTAssertThrowsError(
      try BondryRESTUnixServerConfiguration(
        socketURL: URL(fileURLWithPath: "/tmp/\(String(repeating: "s", count: 110))"),
        ownerUserID: 501,
        peerUserID: 501,
        principalID: "local-peer"
      )
    ) { error in
      XCTAssertEqual(
        error as? BondryRESTUnixServerConfigurationError,
        .invalidSocketURL
      )
    }

    let runtime = try makeRuntime()
    let configuration = try BondryRESTUnixServerConfiguration(
      socketURL: URL(fileURLWithPath: "/tmp/server.sock"),
      ownerUserID: 501,
      peerUserID: 501,
      principalID: "local-peer"
    )
    bondry_test_set_server_start_status(BONDRY_STATUS_SERVER_BIND)
    XCTAssertThrowsError(
      try runtime.startRESTUnixServer(configuration: configuration)
    ) { error in
      XCTAssertEqual(error as? BondryRESTUnixServerError, .bindFailed)
    }

    bondry_test_set_server_start_status(BONDRY_STATUS_OK)
    bondry_test_set_null_server_handle(1)
    XCTAssertThrowsError(
      try runtime.startRESTUnixServer(configuration: configuration)
    ) { error in
      XCTAssertEqual(error as? BondryRESTUnixServerError, .invalidHandle)
    }

    bondry_test_set_null_server_handle(0)
    bondry_test_set_invalid_server_address(1)
    XCTAssertThrowsError(
      try runtime.startRESTUnixServer(configuration: configuration)
    ) { error in
      XCTAssertEqual(error as? BondryRESTUnixServerError, .invalidEndpoint)
    }
  }

  func testValidatesNetworkExposureAndLimits() {
    XCTAssertThrowsError(try BondryRESTServerConfiguration(listeningAddress: "0.0.0.0")) { error in
      XCTAssertEqual(
        error as? BondryRESTServerConfigurationError,
        .cleartextNetworkExposureRequiresAcknowledgement
      )
    }
    XCTAssertThrowsError(
      try BondryRESTServerConfiguration(
        listeningAddress: "0.0.0.0",
        authentication: .disabled(principalID: "remote"),
        allowsCleartextNetworkAccess: true
      )
    ) { error in
      XCTAssertEqual(
        error as? BondryRESTServerConfigurationError,
        .unauthenticatedNetworkExposureRequiresAcknowledgement
      )
    }
    XCTAssertThrowsError(
      try BondryRESTServerLimits(
        requestsPerMinute: 0,
        authenticationFailuresPerMinute: 1,
        maxBodyBytes: 1,
        maxConnections: 1
      )
    ) { error in
      XCTAssertEqual(error as? BondryRESTServerConfigurationError, .invalidRateLimit)
    }
  }

  private func makeRuntime() throws -> BondryRuntime {
    let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x71, count: 32))
    return try BondryRuntime.open(
      at: URL(fileURLWithPath: "/tmp/bondry-rest-server-test.db"),
      key: key
    )
  }

  private func capturedConfiguration() throws -> [String: Any] {
    let data = Data(
      (0..<bondry_test_server_configuration_length()).map {
        bondry_test_server_configuration_byte($0)
      }
    )
    return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
  }
}
