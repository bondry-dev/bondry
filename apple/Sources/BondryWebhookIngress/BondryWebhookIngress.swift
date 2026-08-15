import Bondry
import BondryLocalServer
import CBondryWebhookIngress
import Foundation

public final class BondryWebhookIngressRegistration: @unchecked Sendable {
  private let condition = NSCondition()
  private let routeID: String
  private var handle: OpaquePointer?
  private var dedup: BondryDedupStoreV1
  private var activeHandleOperations = 0
  private var disabling = false

  public func lifecycle() throws -> BondryWebhookIngressLifecycle {
    let handle = try beginHandleOperation()
    guard let handle else {
      return .detached
    }
    defer { endHandleOperation() }
    var rawValue: UInt32 = 0
    try requireWebhookSuccess(
      bondry_server_raw_body_handler_lifecycle_v1(handle, &rawValue)
    )
    switch rawValue {
    case BONDRY_RAW_BODY_LIFECYCLE_ENABLED_V1:
      return .enabled
    case BONDRY_RAW_BODY_LIFECYCLE_DRAINING_V1:
      return .draining
    case BONDRY_RAW_BODY_LIFECYCLE_DETACHED_V1:
      return .detached
    default:
      throw BondryWebhookIngressError.invalidData
    }
  }

  public func disable(deadline: Duration = .seconds(10)) async throws {
    let milliseconds = try webhookDeadlineMilliseconds(deadline)
    try await Task.detached {
      try self.disableSynchronously(deadlineMilliseconds: milliseconds)
    }.value
  }

  public func unknownDeliveries() throws -> [BondryWebhookUnknownDelivery] {
    guard let visit = dedup.visit_unknown, let context = dedup.context else {
      throw BondryWebhookIngressError.invalidHandle
    }
    let collector = UnknownDeliveryCollector(routeID: routeID)
    let collectorContext = Unmanaged.passUnretained(collector).toOpaque()
    try requireWebhookSuccess(visit(context, collectUnknownDelivery, collectorContext))
    if let error = collector.error {
      throw error
    }
    return collector.deliveries
  }

  public func resolveUnknown(
    _ delivery: BondryWebhookUnknownDelivery,
    as resolution: BondryWebhookUnknownResolution
  ) throws {
    guard delivery.routeID == routeID, delivery.deliveryIDHash.count == 32 else {
      throw BondryWebhookIngressError.invalidData
    }
    guard let resolve = dedup.resolve_unknown, let context = dedup.context else {
      throw BondryWebhookIngressError.invalidHandle
    }
    let route = Array(delivery.routeID.utf8)
    let namespace = Array(delivery.verifierNamespace.utf8)
    let updatedAt = try currentUnixMilliseconds()
    let rawResolution: UInt32 =
      switch resolution {
      case .completed: BONDRY_DEDUP_RESOLVE_COMPLETED_V1
      case .retryAllowed: BONDRY_DEDUP_RESOLVE_RETRY_ALLOWED_V1
      }
    let status = route.withUnsafeBufferPointer { route in
      namespace.withUnsafeBufferPointer { namespace in
        delivery.deliveryIDHash.withUnsafeBytes { hash in
          resolve(
            context,
            route.baseAddress,
            route.count,
            namespace.baseAddress,
            namespace.count,
            hash.bindMemory(to: UInt8.self).baseAddress,
            hash.count,
            rawResolution,
            updatedAt
          )
        }
      }
    }
    try requireWebhookSuccess(status)
  }

  /// Clears completed records across the shared runtime store. Unknown records are preserved.
  @discardableResult
  public func clearCompletedReplayRecords(before cutoff: Date) throws -> UInt64 {
    guard let clear = dedup.clear_completed, let context = dedup.context else {
      throw BondryWebhookIngressError.invalidHandle
    }
    let milliseconds = try unixMilliseconds(cutoff)
    var cleared: UInt64 = 0
    try requireWebhookSuccess(clear(context, milliseconds, &cleared))
    return cleared
  }

  deinit {
    condition.lock()
    let handle = self.handle
    self.handle = nil
    condition.unlock()
    if let handle {
      bondry_server_raw_body_handler_release_v1(handle)
    }
    releaseDedupDescriptor(&dedup)
  }

  init(handle: OpaquePointer, routeID: String, dedup: BondryDedupStoreV1) {
    self.handle = handle
    self.routeID = routeID
    self.dedup = dedup
  }

  private func beginHandleOperation() throws -> OpaquePointer? {
    condition.lock()
    defer { condition.unlock() }
    guard let handle else {
      return nil
    }
    activeHandleOperations += 1
    return handle
  }

  private func endHandleOperation() {
    condition.lock()
    activeHandleOperations -= 1
    if activeHandleOperations == 0 {
      condition.broadcast()
    }
    condition.unlock()
  }

  private func disableSynchronously(deadlineMilliseconds: UInt64) throws {
    condition.lock()
    guard let handle else {
      condition.unlock()
      return
    }
    guard !disabling else {
      condition.unlock()
      throw BondryWebhookIngressError.busy
    }
    disabling = true
    activeHandleOperations += 1
    condition.unlock()

    let status = bondry_server_raw_body_handler_disable_v1(handle, deadlineMilliseconds)

    condition.lock()
    activeHandleOperations -= 1
    disabling = false
    var detachedHandle: OpaquePointer?
    if status == BONDRY_STATUS_OK {
      self.handle = nil
      while activeHandleOperations > 0 {
        condition.wait()
      }
      detachedHandle = handle
    }
    condition.broadcast()
    condition.unlock()

    if let detachedHandle {
      bondry_server_raw_body_handler_release_v1(detachedHandle)
    }
    try requireWebhookSuccess(status)
  }
}

extension BondryRuntime {
  public func registerWebhook(
    on server: BondryLocalServer,
    configuration: BondryWebhookIngressConfiguration,
    deduplication: BondryWebhookDedupStoreLimits = .standard,
    secretProvider: any BondryWebhookSecretProvider
  ) throws -> BondryWebhookIngressRegistration {
    let actualVersion = bondry_webhook_ingress_abi_version_v1()
    guard actualVersion == BONDRY_WEBHOOK_INGRESS_ABI_VERSION_V1 else {
      throw BondryWebhookIngressError.incompatibleABI(
        expected: BONDRY_WEBHOOK_INGRESS_ABI_VERSION_V1,
        actual: actualVersion
      )
    }
    let configurationJSON = try JSONEncoder().encode(WebhookConfigurationInput(configuration))
    guard configurationJSON.count <= BONDRY_WEBHOOK_MAX_CONFIGURATION_BYTES_V1 else {
      throw BondryWebhookIngressError.invalidConfiguration
    }

    var automation = BondryAutomationServiceV1()
    try requireWebhookSuccess(bondry_automation_service_v1(handle, &automation))
    defer { releaseAutomationDescriptor(&automation) }

    var dedup = BondryDedupStoreV1()
    try requireWebhookSuccess(
      bondry_store_dedup_v1(
        handle,
        deduplication.records,
        deduplication.bytes,
        deduplication.retentionSeconds,
        &dedup
      )
    )
    var ownsDedup = true
    defer {
      if ownsDedup {
        releaseDedupDescriptor(&dedup)
      }
    }

    let services = WebhookHostServices(secrets: secretProvider)
    let servicesContext = Unmanaged.passUnretained(services).toOpaque()
    let secrets = makeWebhookSecretDescriptor(context: servicesContext)
    var rawHandler = BondryRawBodyHandlerDescriptorV1()
    let handlerStatus = configurationJSON.withUnsafeBytes { buffer in
      let bytes = buffer.bindMemory(to: UInt8.self)
      var descriptor = BondryWebhookIngressRegistrationDescriptorV1(
        abi_version: BONDRY_WEBHOOK_INGRESS_ABI_VERSION_V1,
        struct_size: MemoryLayout<BondryWebhookIngressRegistrationDescriptorV1>.size,
        configuration_json: bytes.baseAddress,
        configuration_json_length: bytes.count,
        automation: automation,
        dedup: dedup,
        secrets: secrets
      )
      return bondry_webhook_ingress_handler_v1(&descriptor, &rawHandler)
    }
    try requireWebhookSuccess(handlerStatus)
    defer { bondry_webhook_ingress_handler_release_v1(&rawHandler) }

    var registrationHandle: OpaquePointer?
    try server.withNativeHandle { serverHandle in
      try requireWebhookSuccess(
        bondry_server_raw_body_handler_register_v1(
          serverHandle,
          &rawHandler,
          &registrationHandle
        )
      )
    }
    guard let registrationHandle else {
      throw BondryWebhookIngressError.invalidHandle
    }
    ownsDedup = false
    return BondryWebhookIngressRegistration(
      handle: registrationHandle,
      routeID: configuration.routeID,
      dedup: dedup
    )
  }
}

private struct WebhookConfigurationInput: Encodable {
  let version = 1
  let routeID: String
  let path: String
  let principal: PrincipalInput
  let capabilityID: String
  let semantics: String
  let verifier: VerifierInput
  let mapping: MappingInput
  let successStatus: UInt16
  let limits: LimitsInput

  private enum CodingKeys: String, CodingKey {
    case version
    case routeID = "routeId"
    case path
    case principal
    case capabilityID = "capabilityId"
    case semantics
    case verifier
    case mapping
    case successStatus
    case limits
  }

  init(_ configuration: BondryWebhookIngressConfiguration) throws {
    routeID = configuration.routeID
    path = configuration.path
    principal = PrincipalInput(configuration.principal)
    capabilityID = configuration.capabilityID
    semantics = configuration.semantics.rawValue
    verifier = try VerifierInput(configuration.verifier)
    mapping = MappingInput(configuration.mapping)
    successStatus = configuration.successStatus
    limits = LimitsInput(configuration.limits)
  }
}

private struct PrincipalInput: Encodable {
  let id: String
  let kind: String

  init(_ principal: BondryPrincipal) {
    id = principal.id
    kind =
      switch principal.kind {
      case .user: "user"
      case .application: "application"
      case .system: "system"
      }
  }
}

private struct VerifierInput: Encodable {
  let type: String
  let secretRef: String
  let toleranceSeconds: UInt64?

  init(_ verifier: BondryWebhookVerifier) throws {
    switch verifier {
    case .bearer(let secret):
      type = "bearer"
      secretRef = secret.rawValue
      toleranceSeconds = nil
    case .bondryHMACSHA256(let secret, let tolerance):
      type = "bondry_hmac_sha256"
      secretRef = secret.rawValue
      toleranceSeconds = try webhookWholeSeconds(
        tolerance,
        error: .invalidVerifierTolerance
      )
    case .githubHMACSHA256(let secret):
      type = "github_hmac_sha256"
      secretRef = secret.rawValue
      toleranceSeconds = nil
    case .stripeHMACSHA256(let secret, let tolerance):
      type = "stripe_hmac_sha256"
      secretRef = secret.rawValue
      toleranceSeconds = try webhookWholeSeconds(
        tolerance,
        error: .invalidVerifierTolerance
      )
    }
  }
}

private struct MappingInput: Encodable {
  let type: String
  let metadataHeaders: [String]?

  init(_ mapping: BondryWebhookPayloadMapping) {
    switch mapping {
    case .jsonBody:
      type = "json_body"
      metadataHeaders = nil
    case .envelope(let headers):
      type = "envelope"
      metadataHeaders = headers
    }
  }
}

private struct LimitsInput: Encodable {
  let bodyBytes: Int
  let retainedBytes: Int
  let selectedHeaders: Int
  let selectedHeaderBytes: Int
  let selectedHeadersBytes: Int
  let preAuthenticationRequestsPerPeerMinute: UInt32
  let preAuthenticationRequestsPerRouteMinute: UInt32

  init(_ limits: BondryWebhookIngressLimits) {
    bodyBytes = limits.bodyBytes
    retainedBytes = limits.retainedBytes
    selectedHeaders = limits.selectedHeaderCount
    selectedHeaderBytes = limits.selectedHeaderBytes
    selectedHeadersBytes = limits.selectedHeadersBytes
    preAuthenticationRequestsPerPeerMinute = limits.preAuthenticationRequestsPerPeerMinute
    preAuthenticationRequestsPerRouteMinute = limits.preAuthenticationRequestsPerRouteMinute
  }
}

private final class UnknownDeliveryCollector {
  let routeID: String
  var deliveries: [BondryWebhookUnknownDelivery] = []
  var error: BondryWebhookIngressError?

  init(routeID: String) {
    self.routeID = routeID
  }
}

private func collectUnknownDelivery(
  _ context: UnsafeMutableRawPointer?,
  _ record: UnsafePointer<BondryDedupRecordV1>?
) -> UInt8 {
  guard let context, let record else {
    return 0
  }
  let collector = Unmanaged<UnknownDeliveryCollector>.fromOpaque(context).takeUnretainedValue()
  do {
    let record = record.pointee
    let routeID = try decodeTerminated(record.route_id)
    guard routeID == collector.routeID else {
      return 1
    }
    var hash = record.delivery_hash
    let hashData = withUnsafeBytes(of: &hash) { Data($0) }
    collector.deliveries.append(
      BondryWebhookUnknownDelivery(
        routeID: routeID,
        verifierNamespace: try decodeTerminated(record.verifier_namespace),
        deliveryIDHash: hashData,
        updatedAt: Date(timeIntervalSince1970: TimeInterval(record.updated_at_unix_ms) / 1_000)
      )
    )
    return 1
  } catch {
    collector.error = .invalidData
    return 0
  }
}

private func decodeTerminated<Value>(_ value: Value) throws -> String {
  try withUnsafeBytes(of: value) { bytes in
    guard let end = bytes.firstIndex(of: 0), end > 0,
      bytes[(end + 1)...].allSatisfy({ $0 == 0 }),
      let string = String(bytes: bytes[..<end], encoding: .utf8)
    else {
      throw BondryWebhookIngressError.invalidData
    }
    return string
  }
}

private func releaseAutomationDescriptor(_ descriptor: inout BondryAutomationServiceV1) {
  if let release = descriptor.release, let context = descriptor.context {
    descriptor.context = nil
    release(context)
  }
}

private func releaseDedupDescriptor(_ descriptor: inout BondryDedupStoreV1) {
  if let release = descriptor.release, let context = descriptor.context {
    descriptor.context = nil
    release(context)
  }
}

private func webhookDeadlineMilliseconds(_ duration: Duration) throws -> UInt64 {
  let components = duration.components
  let attosecondsPerMillisecond: Int64 = 1_000_000_000_000_000
  guard components.seconds >= 0, components.attoseconds >= 0,
    components.attoseconds.isMultiple(of: attosecondsPerMillisecond)
  else {
    throw BondryWebhookIngressError.invalidDeadline
  }
  let (seconds, secondsOverflow) = UInt64(components.seconds).multipliedReportingOverflow(by: 1_000)
  let subseconds = UInt64(components.attoseconds / attosecondsPerMillisecond)
  let (milliseconds, additionOverflow) = seconds.addingReportingOverflow(subseconds)
  guard !secondsOverflow, !additionOverflow, (1_000...60_000).contains(milliseconds) else {
    throw BondryWebhookIngressError.invalidDeadline
  }
  return milliseconds
}

private func currentUnixMilliseconds() throws -> UInt64 {
  try unixMilliseconds(Date())
}

private func unixMilliseconds(_ date: Date) throws -> UInt64 {
  let value = date.timeIntervalSince1970 * 1_000
  guard value.isFinite, value >= 0, value <= Double(UInt64.max) else {
    throw BondryWebhookIngressError.invalidData
  }
  return UInt64(value.rounded(.down))
}

private func requireWebhookSuccess(_ status: BondryStatus) throws {
  guard status == BONDRY_STATUS_OK else {
    throw BondryWebhookIngressError(status: status)
  }
}

extension BondryWebhookIngressError {
  fileprivate init(status: BondryStatus) {
    switch status {
    case BONDRY_STATUS_NULL_POINTER:
      self = .invalidHandle
    case BONDRY_STATUS_INVALID_LENGTH, BONDRY_STATUS_INVALID_UTF8,
      BONDRY_STATUS_INVALID_ARGUMENT, BONDRY_STATUS_INVALID_JSON,
      BONDRY_STATUS_PAYLOAD_TOO_LARGE:
      self = .invalidConfiguration
    case BONDRY_STATUS_INVALID_DATA:
      self = .invalidData
    case BONDRY_STATUS_UNAVAILABLE:
      self = .unavailable
    case BONDRY_STATUS_NOT_FOUND:
      self = .notFound
    case BONDRY_STATUS_ALREADY_EXISTS:
      self = .routeAlreadyExists
    case BONDRY_STATUS_CAPACITY_EXHAUSTED:
      self = .capacityExhausted
    case BONDRY_STATUS_INVALID_TRANSITION:
      self = .invalidTransition
    case BONDRY_STATUS_RAW_BODY_DRAIN_TIMED_OUT:
      self = .drainTimedOut
    default:
      self = .internalFailure(status)
    }
  }
}
