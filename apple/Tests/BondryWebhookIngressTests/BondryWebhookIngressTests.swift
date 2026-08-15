import Bondry
import BondryApple
import BondryLocalServer
import BondryWebhookIngress
import CBondryTestSupport
import CBondryWebhookIngress
import Foundation
import XCTest

final class BondryWebhookIngressTests: XCTestCase {
  override func setUp() {
    super.setUp()
    bondry_test_reset()
  }

  func testValidatesRouteConfigurationAndDefaults() throws {
    let configuration = try BondryWebhookIngressConfiguration(
      routeID: "github.push",
      path: "/hooks/github",
      principal: BondryPrincipal(id: "github", kind: .application),
      capabilityID: "repository.updated",
      semantics: .idempotentMutation,
      verifier: .githubHMACSHA256(secret: try BondrySecretReference("keychain:github")),
      mapping: .envelope(metadataHeaders: ["x-github-event"])
    )

    XCTAssertEqual(configuration.path, "/hooks/github")
    XCTAssertEqual(configuration.successStatus, 204)
    XCTAssertEqual(configuration.limits.bodyBytes, 1_048_576)
    XCTAssertEqual(configuration.limits.retainedBytes, 3 * 1_048_576)
    XCTAssertEqual(configuration.limits.selectedHeaderCount, 16)
  }

  func testRejectsAmbiguousPathsHeadersAndFractionalRetention() throws {
    let secret = try BondrySecretReference("keychain:test")
    XCTAssertThrowsError(
      try BondryWebhookIngressConfiguration(
        routeID: "route",
        path: "/hooks path",
        principal: BondryPrincipal(id: "sender", kind: .application),
        capabilityID: "event",
        semantics: .readOnly,
        verifier: .bearer(secret: secret)
      )
    )
    XCTAssertThrowsError(
      try BondryWebhookIngressConfiguration(
        routeID: "route",
        path: "/hooks",
        principal: BondryPrincipal(id: "sender", kind: .application),
        capabilityID: "event",
        semantics: .readOnly,
        verifier: .bearer(secret: secret),
        mapping: .envelope(metadataHeaders: ["X-Event", "x-event"])
      )
    )
    XCTAssertThrowsError(
      try BondryWebhookIngressConfiguration(
        routeID: "route",
        path: "/hooks",
        principal: BondryPrincipal(id: "sender", kind: .application),
        capabilityID: "event",
        semantics: .readOnly,
        verifier: .bearer(secret: secret),
        mapping: .envelope(metadataHeaders: ["authorization"])
      )
    )
    XCTAssertThrowsError(
      try BondryWebhookIngressConfiguration(
        routeID: "route",
        path: "/hooks",
        principal: BondryPrincipal(id: "sender", kind: .application),
        capabilityID: "event",
        semantics: .readOnly,
        verifier: .bondryHMACSHA256(secret: secret),
        mapping: .envelope(metadataHeaders: ["x-event"]),
        limits: try BondryWebhookIngressLimits(
          bodyBytes: 1_048_576,
          retainedBytes: 3 * 1_048_576,
          selectedHeaderCount: 4
        )
      )
    )
    XCTAssertThrowsError(
      try BondryWebhookIngressConfiguration(
        routeID: "route",
        path: "/hooks",
        principal: BondryPrincipal(id: "sender", kind: .application),
        capabilityID: "event",
        semantics: .readOnly,
        verifier: .bondryHMACSHA256(secret: secret),
        limits: try BondryWebhookIngressLimits(
          bodyBytes: 1_048_576,
          retainedBytes: 3 * 1_048_576,
          selectedHeaderCount: 3
        )
      )
    ) { error in
      XCTAssertEqual(
        error as? BondryWebhookIngressConfigurationError,
        .invalidLimits
      )
    }
    XCTAssertThrowsError(
      try BondryWebhookDedupStoreLimits(
        records: 10_000,
        bytes: 8 * 1_048_576,
        retention: .milliseconds(86_400_001)
      )
    ) { error in
      XCTAssertEqual(
        error as? BondryWebhookIngressConfigurationError,
        .invalidDeduplicationLimits
      )
    }
  }

  func testRegistersFixedRouteWithoutSerializingSecretMaterial() throws {
    let runtime = try makeRuntime()
    let server = try runtime.startLocalServer(
      configuration: BondryLocalServerConfiguration(adapters: [])
    )
    defer { try? server.stop() }
    let configuration = try makeConfiguration()
    let deduplication = try BondryWebhookDedupStoreLimits(
      records: 20_000,
      bytes: 12 * 1_048_576,
      retention: .seconds(14 * 86_400)
    )

    let registration = try runtime.registerWebhook(
      on: server,
      configuration: configuration,
      deduplication: deduplication,
      secretProvider: TestSecretProvider()
    )

    XCTAssertEqual(try registration.lifecycle(), .enabled)
    XCTAssertEqual(bondry_test_webhook_register_count(), 1)
    XCTAssertEqual(bondry_test_webhook_dedup_records(), 20_000)
    XCTAssertEqual(bondry_test_webhook_dedup_bytes(), 12 * 1_048_576)
    XCTAssertEqual(bondry_test_webhook_dedup_retention_seconds(), 14 * 86_400)
    let encoded = capturedConfiguration()
    let root = try XCTUnwrap(
      try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
    )
    XCTAssertEqual(root["routeId"] as? String, "github.push")
    XCTAssertEqual(root["capabilityId"] as? String, "repository.updated")
    let verifier = try XCTUnwrap(root["verifier"] as? [String: Any])
    XCTAssertEqual(verifier["type"] as? String, "github_hmac_sha256")
    XCTAssertEqual(verifier["secretRef"] as? String, "keychain:github")
    XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains("secret-material"))
  }

  func testDisablePreservesDrainingGenerationAfterTimeout() async throws {
    let runtime = try makeRuntime()
    let server = try runtime.startLocalServer(
      configuration: BondryLocalServerConfiguration(adapters: [])
    )
    defer { try? server.stop() }
    let registration = try runtime.registerWebhook(
      on: server,
      configuration: try makeConfiguration(),
      secretProvider: TestSecretProvider()
    )

    bondry_test_set_webhook_disable_status(BONDRY_STATUS_RAW_BODY_DRAIN_TIMED_OUT)
    do {
      try await registration.disable(deadline: .seconds(1))
      XCTFail("expected drain timeout")
    } catch {
      XCTAssertEqual(error as? BondryWebhookIngressError, .drainTimedOut)
    }
    XCTAssertEqual(try registration.lifecycle(), .draining)
    XCTAssertEqual(bondry_test_webhook_release_count(), 0)

    bondry_test_set_webhook_disable_status(BONDRY_STATUS_OK)
    try await registration.disable(deadline: .seconds(1))
    XCTAssertEqual(try registration.lifecycle(), .detached)
    XCTAssertEqual(bondry_test_webhook_release_count(), 1)
  }

  func testRejectsIncompatibleIngressABI() throws {
    let runtime = try makeRuntime()
    let server = try runtime.startLocalServer(
      configuration: BondryLocalServerConfiguration(adapters: [])
    )
    defer { try? server.stop() }
    bondry_test_set_webhook_ingress_abi_version(BONDRY_WEBHOOK_INGRESS_ABI_VERSION_V1 + 1)

    XCTAssertThrowsError(
      try runtime.registerWebhook(
        on: server,
        configuration: makeConfiguration(),
        secretProvider: TestSecretProvider()
      )
    ) { error in
      XCTAssertEqual(
        error as? BondryWebhookIngressError,
        .incompatibleABI(
          expected: BONDRY_WEBHOOK_INGRESS_ABI_VERSION_V1,
          actual: BONDRY_WEBHOOK_INGRESS_ABI_VERSION_V1 + 1
        )
      )
    }
    XCTAssertEqual(bondry_test_webhook_register_count(), 0)
  }

  private func makeRuntime() throws -> BondryRuntime {
    try BondryRuntime.open(
      at: URL(fileURLWithPath: "/tmp/bondry-webhook-ingress-test.db"),
      key: DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x55, count: 32))
    )
  }

  private func makeConfiguration() throws -> BondryWebhookIngressConfiguration {
    try BondryWebhookIngressConfiguration(
      routeID: "github.push",
      path: "/hooks/github",
      principal: BondryPrincipal(id: "github", kind: .application),
      capabilityID: "repository.updated",
      semantics: .idempotentMutation,
      verifier: .githubHMACSHA256(secret: BondrySecretReference("keychain:github")),
      mapping: .envelope(metadataHeaders: ["x-github-event"])
    )
  }

  private func capturedConfiguration() -> Data {
    Data(
      (0..<bondry_test_webhook_configuration_length()).map {
        bondry_test_webhook_configuration_byte($0)
      }
    )
  }
}

private struct TestSecretProvider: BondryWebhookSecretProvider {
  func resolve(_ reference: BondrySecretReference) throws -> BondryResolvedSecret {
    try BondryResolvedSecret(current: Data("secret-material".utf8))
  }
}
