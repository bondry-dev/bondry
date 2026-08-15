import Bondry
import BondryApple
import Foundation

public enum BondryWebhookCapabilitySemantics: String, Sendable {
  case readOnly = "read_only"
  case idempotentMutation = "idempotent_mutation"
  case nonIdempotentMutation = "non_idempotent_mutation"
}

public enum BondryWebhookVerifier: Sendable {
  case bearer(secret: BondrySecretReference)
  case bondryHMACSHA256(secret: BondrySecretReference, tolerance: Duration = .seconds(300))
  case githubHMACSHA256(secret: BondrySecretReference)
  case stripeHMACSHA256(secret: BondrySecretReference, tolerance: Duration = .seconds(300))
}

public enum BondryWebhookPayloadMapping: Sendable {
  case jsonBody
  case envelope(metadataHeaders: [String])
}

public struct BondryWebhookIngressLimits: Equatable, Sendable {
  public static let standard = BondryWebhookIngressLimits(
    bodyBytes: 1_048_576,
    retainedBytes: 3 * 1_048_576,
    selectedHeaderCount: 16,
    selectedHeaderBytes: 2 * 1_024,
    selectedHeadersBytes: 32 * 1_024,
    preAuthenticationRequestsPerPeerMinute: 60,
    preAuthenticationRequestsPerRouteMinute: 120,
    validated: ()
  )

  public let bodyBytes: Int
  public let retainedBytes: Int
  public let selectedHeaderCount: Int
  public let selectedHeaderBytes: Int
  public let selectedHeadersBytes: Int
  public let preAuthenticationRequestsPerPeerMinute: UInt32
  public let preAuthenticationRequestsPerRouteMinute: UInt32

  public init(
    bodyBytes: Int,
    retainedBytes: Int,
    selectedHeaderCount: Int = 16,
    selectedHeaderBytes: Int = 2 * 1_024,
    selectedHeadersBytes: Int = 32 * 1_024,
    preAuthenticationRequestsPerPeerMinute: UInt32 = 60,
    preAuthenticationRequestsPerRouteMinute: UInt32 = 120
  ) throws {
    guard (1_024...(4 * 1_048_576)).contains(bodyBytes),
      (bodyBytes...(10 * 1_048_576)).contains(retainedBytes),
      (1...32).contains(selectedHeaderCount),
      (1...(8 * 1_024)).contains(selectedHeaderBytes),
      (1...(64 * 1_024)).contains(selectedHeadersBytes),
      (1...600).contains(preAuthenticationRequestsPerPeerMinute),
      (1...1_200).contains(preAuthenticationRequestsPerRouteMinute)
    else {
      throw BondryWebhookIngressConfigurationError.invalidLimits
    }
    self.init(
      bodyBytes: bodyBytes,
      retainedBytes: retainedBytes,
      selectedHeaderCount: selectedHeaderCount,
      selectedHeaderBytes: selectedHeaderBytes,
      selectedHeadersBytes: selectedHeadersBytes,
      preAuthenticationRequestsPerPeerMinute: preAuthenticationRequestsPerPeerMinute,
      preAuthenticationRequestsPerRouteMinute: preAuthenticationRequestsPerRouteMinute,
      validated: ()
    )
  }

  private init(
    bodyBytes: Int,
    retainedBytes: Int,
    selectedHeaderCount: Int,
    selectedHeaderBytes: Int,
    selectedHeadersBytes: Int,
    preAuthenticationRequestsPerPeerMinute: UInt32,
    preAuthenticationRequestsPerRouteMinute: UInt32,
    validated: Void
  ) {
    self.bodyBytes = bodyBytes
    self.retainedBytes = retainedBytes
    self.selectedHeaderCount = selectedHeaderCount
    self.selectedHeaderBytes = selectedHeaderBytes
    self.selectedHeadersBytes = selectedHeadersBytes
    self.preAuthenticationRequestsPerPeerMinute = preAuthenticationRequestsPerPeerMinute
    self.preAuthenticationRequestsPerRouteMinute = preAuthenticationRequestsPerRouteMinute
  }
}

public struct BondryWebhookDedupStoreLimits: Equatable, Sendable {
  public static let standard = BondryWebhookDedupStoreLimits(
    records: 100_000,
    bytes: 16 * 1_048_576,
    retention: .seconds(7 * 86_400),
    retentionSeconds: 7 * 86_400
  )

  public let records: UInt32
  public let bytes: UInt64
  public let retention: Duration
  let retentionSeconds: UInt64

  public init(records: UInt32, bytes: UInt64, retention: Duration) throws {
    let seconds = try webhookWholeSeconds(retention, error: .invalidDeduplicationLimits)
    guard (1_000...1_000_000).contains(records),
      (1_048_576...(128 * 1_048_576)).contains(bytes),
      (86_400...(90 * 86_400)).contains(seconds)
    else {
      throw BondryWebhookIngressConfigurationError.invalidDeduplicationLimits
    }
    self.init(records: records, bytes: bytes, retention: retention, retentionSeconds: seconds)
  }

  private init(records: UInt32, bytes: UInt64, retention: Duration, retentionSeconds: UInt64) {
    self.records = records
    self.bytes = bytes
    self.retention = retention
    self.retentionSeconds = retentionSeconds
  }
}

public struct BondryWebhookIngressConfiguration: Sendable {
  public let routeID: String
  public let path: String
  public let principal: BondryPrincipal
  public let capabilityID: String
  public let semantics: BondryWebhookCapabilitySemantics
  public let verifier: BondryWebhookVerifier
  public let mapping: BondryWebhookPayloadMapping
  public let successStatus: UInt16
  public let limits: BondryWebhookIngressLimits

  public init(
    routeID: String,
    path: String,
    principal: BondryPrincipal,
    capabilityID: String,
    semantics: BondryWebhookCapabilitySemantics,
    verifier: BondryWebhookVerifier,
    mapping: BondryWebhookPayloadMapping = .jsonBody,
    successStatus: UInt16 = 204,
    limits: BondryWebhookIngressLimits = .standard
  ) throws {
    guard validIdentifier(routeID), validIdentifier(principal.id), validIdentifier(capabilityID)
    else {
      throw BondryWebhookIngressConfigurationError.invalidIdentifier
    }
    guard validPath(path) else {
      throw BondryWebhookIngressConfigurationError.invalidPath
    }
    guard (200...299).contains(successStatus) else {
      throw BondryWebhookIngressConfigurationError.invalidSuccessStatus
    }
    try validate(verifier)
    var normalizedHeaders: [String] = []
    if case .envelope(let headers) = mapping {
      normalizedHeaders = headers.map { $0.lowercased() }
      let credentialHeaders = verifierCredentialHeaders(verifier)
      guard headers.count <= 32, Set(normalizedHeaders).count == headers.count,
        credentialHeaders.isDisjoint(with: normalizedHeaders),
        headers.allSatisfy(validHeaderName)
      else {
        throw BondryWebhookIngressConfigurationError.invalidMetadataHeaders
      }
    }
    let selectedHeaders =
      Set(normalizedHeaders)
      .union(verifierSelectedHeaders(verifier))
      .union(["content-type"])
    guard selectedHeaders.count <= limits.selectedHeaderCount else {
      throw BondryWebhookIngressConfigurationError.invalidLimits
    }
    self.routeID = routeID
    self.path = path
    self.principal = principal
    self.capabilityID = capabilityID
    self.semantics = semantics
    self.verifier = verifier
    self.mapping = mapping
    self.successStatus = successStatus
    self.limits = limits
  }
}

public protocol BondryWebhookSecretProvider: Sendable {
  func resolve(_ reference: BondrySecretReference) throws -> BondryResolvedSecret
}

extension KeychainSecretProvider: BondryWebhookSecretProvider {}

public enum BondryWebhookIngressConfigurationError: Error, Equatable, Sendable {
  case invalidIdentifier
  case invalidPath
  case invalidSuccessStatus
  case invalidVerifierTolerance
  case invalidMetadataHeaders
  case invalidLimits
  case invalidDeduplicationLimits
}

public enum BondryWebhookIngressError: Error, Equatable, Sendable {
  case incompatibleABI(expected: UInt32, actual: UInt32)
  case invalidConfiguration
  case unavailable
  case capacityExhausted
  case routeAlreadyExists
  case notFound
  case invalidTransition
  case invalidData
  case invalidHandle
  case busy
  case drainTimedOut
  case invalidDeadline
  case internalFailure(Int32)
}

public enum BondryWebhookIngressLifecycle: Equatable, Sendable {
  case enabled
  case draining
  case detached
}

public struct BondryWebhookUnknownDelivery: Equatable, Sendable {
  public let routeID: String
  public let verifierNamespace: String
  public let deliveryIDHash: Data
  public let updatedAt: Date
}

public enum BondryWebhookUnknownResolution: Sendable {
  case completed
  case retryAllowed
}

private func validate(_ verifier: BondryWebhookVerifier) throws {
  let tolerance: Duration?
  switch verifier {
  case .bondryHMACSHA256(_, let value), .stripeHMACSHA256(_, let value):
    tolerance = value
  case .bearer, .githubHMACSHA256:
    tolerance = nil
  }
  if let tolerance {
    let seconds = try webhookWholeSeconds(tolerance, error: .invalidVerifierTolerance)
    guard (30...900).contains(seconds) else {
      throw BondryWebhookIngressConfigurationError.invalidVerifierTolerance
    }
  }
}

private func verifierSelectedHeaders(_ verifier: BondryWebhookVerifier) -> Set<String> {
  switch verifier {
  case .bearer:
    ["authorization"]
  case .bondryHMACSHA256:
    ["x-bondry-delivery-id", "x-bondry-timestamp", "x-bondry-signature"]
  case .githubHMACSHA256:
    ["x-hub-signature-256"]
  case .stripeHMACSHA256:
    ["stripe-signature"]
  }
}

private func verifierCredentialHeaders(_ verifier: BondryWebhookVerifier) -> Set<String> {
  switch verifier {
  case .bearer:
    ["authorization"]
  case .bondryHMACSHA256:
    ["x-bondry-signature"]
  case .githubHMACSHA256:
    ["x-hub-signature-256"]
  case .stripeHMACSHA256:
    ["stripe-signature"]
  }
}

func webhookWholeSeconds(
  _ duration: Duration,
  error: BondryWebhookIngressConfigurationError
) throws -> UInt64 {
  let components = duration.components
  guard components.seconds >= 0, components.attoseconds == 0 else {
    throw error
  }
  return UInt64(components.seconds)
}

private func validIdentifier(_ value: String) -> Bool {
  !value.isEmpty && value.utf8.count <= 128
    && value.utf8.allSatisfy {
      (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
        || [45, 46, 58, 95].contains($0)
    }
}

private func validPath(_ value: String) -> Bool {
  value.utf8.count > 1 && value.first == "/" && !value.contains("?") && !value.contains("#")
    && value.utf8.allSatisfy { (0x21...0x7e).contains($0) }
}

private func validHeaderName(_ value: String) -> Bool {
  !value.isEmpty && value.utf8.count <= 128
    && value.utf8.allSatisfy {
      (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
        || "!#$%&'*+-.^_`|~".utf8.contains($0)
    }
}
