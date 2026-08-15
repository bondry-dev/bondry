import Bondry
import BondryApple
import CBondryEgress
import Foundation

public final class BondryEgress: @unchecked Sendable {
  private let lock = NSLock()
  private var handle: OpaquePointer?

  public var isRunning: Bool {
    lock.withLock { handle != nil }
  }

  public func register(_ route: BondryWebhookRoute) throws {
    let input = try encodeRoute(route)
    try withHandle { handle in
      let status = input.withUnsafeBytes { buffer in
        let bytes = buffer.bindMemory(to: UInt8.self)
        return bondry_egress_route_register_v1(
          handle,
          bytes.baseAddress,
          bytes.count
        )
      }
      try requireEgressSuccess(status)
    }
  }

  public func enable(routeID: String) throws {
    try routeOperation(routeID, bondry_egress_route_enable_v1)
  }

  public func disable(routeID: String) throws {
    try routeOperation(routeID, bondry_egress_route_disable_v1)
  }

  public func unregister(routeID: String) throws {
    try routeOperation(routeID, bondry_egress_route_unregister_v1)
  }

  public func routes() throws -> [BondryEgressRouteSummary] {
    let data = try withHandle { handle in
      try queryEgressBytes { output, capacity, length in
        bondry_egress_routes_json_v1(handle, output, capacity, length)
      }
    }
    do {
      return try JSONDecoder().decode([BondryEgressRouteSummary].self, from: data)
    } catch {
      throw BondryEgressError.invalidData
    }
  }

  public func emit(
    routeID: String,
    deliveryID: String = UUID().uuidString,
    payloadJSON: Data
  ) throws {
    try withHandle { handle in
      let routeBytes = Array(routeID.utf8)
      let deliveryBytes = Array(deliveryID.utf8)
      let status = routeBytes.withUnsafeBufferPointer { route in
        deliveryBytes.withUnsafeBufferPointer { delivery in
          payloadJSON.withUnsafeBytes { payload in
            bondry_egress_emit_v1(
              handle,
              route.baseAddress,
              route.count,
              delivery.baseAddress,
              delivery.count,
              payload.bindMemory(to: UInt8.self).baseAddress,
              payload.count
            )
          }
        }
      }
      try requireEgressSuccess(status)
    }
  }

  public func emit<Payload: Encodable>(
    routeID: String,
    deliveryID: String = UUID().uuidString,
    payload: Payload
  ) throws {
    try emit(
      routeID: routeID,
      deliveryID: deliveryID,
      payloadJSON: try JSONEncoder().encode(payload)
    )
  }

  public func deliveryStatus(for deliveryID: String) throws -> BondryDeliveryStatus? {
    try withHandle { handle in
      var found: UInt8 = 0
      var record = BondryEgressDeliveryStatusV1()
      let deliveryBytes = Array(deliveryID.utf8)
      let status = deliveryBytes.withUnsafeBufferPointer { delivery in
        bondry_egress_delivery_status_v1(
          handle,
          delivery.baseAddress,
          delivery.count,
          &found,
          &record
        )
      }
      try requireEgressSuccess(status)
      switch found {
      case 0: return nil
      case 1: return try BondryDeliveryStatus(record: record)
      default: throw BondryEgressError.invalidData
      }
    }
  }

  public func stop() throws {
    let handle = lock.withLock {
      let value = self.handle
      self.handle = nil
      return value
    }
    guard let handle else {
      return
    }
    try requireEgressSuccess(bondry_egress_stop_v1(handle))
  }

  deinit {
    try? stop()
  }

  init(handle: OpaquePointer) {
    self.handle = handle
  }

  private func withHandle<Result>(_ operation: (OpaquePointer) throws -> Result) throws -> Result {
    try lock.withLock {
      guard let handle else {
        throw BondryEgressError.stopped
      }
      return try operation(handle)
    }
  }

  private func routeOperation(
    _ routeID: String,
    _ operation: (OpaquePointer?, UnsafePointer<UInt8>?, Int) -> BondryStatus
  ) throws {
    try withHandle { handle in
      let routeBytes = Array(routeID.utf8)
      let status = routeBytes.withUnsafeBufferPointer { route in
        operation(handle, route.baseAddress, route.count)
      }
      try requireEgressSuccess(status)
    }
  }
}

extension BondryRuntime {
  public func startEgress(
    configuration: BondryEgressConfiguration = .standard,
    secretProvider: any BondryEgressSecretProvider,
    transport: BondryAppleHTTPTransport = BondryAppleHTTPTransport()
  ) throws -> BondryEgress {
    let actualVersion = bondry_egress_abi_version_v1()
    guard actualVersion == BONDRY_EGRESS_ABI_VERSION_V1 else {
      throw BondryEgressError.incompatibleABI(
        expected: BONDRY_EGRESS_ABI_VERSION_V1,
        actual: actualVersion
      )
    }
    let input = try encodeRuntimeConfiguration(configuration)
    let services = EgressHostServices(transport: transport, secrets: secretProvider)
    let context = Unmanaged.passUnretained(services).toOpaque()
    var transportDescriptor = makeTransportDescriptor(context: context)
    var secretDescriptor = makeSecretDescriptor(context: context)
    var egressHandle: OpaquePointer?
    let status = input.withUnsafeBytes { buffer in
      let bytes = buffer.bindMemory(to: UInt8.self)
      return bondry_egress_start_v1(
        handle,
        bytes.baseAddress,
        bytes.count,
        &transportDescriptor,
        &secretDescriptor,
        &egressHandle
      )
    }
    guard status == BONDRY_STATUS_OK else {
      if let egressHandle {
        _ = bondry_egress_stop_v1(egressHandle)
      }
      throw BondryEgressError(status: status)
    }
    guard let egressHandle else {
      throw BondryEgressError.invalidHandle
    }
    return BondryEgress(handle: egressHandle)
  }
}

private struct RuntimeConfigurationInput: Encodable {
  let version = 1
  let registry: RegistryInput
  let runtime: RuntimeInput
  let deliveryLog: DeliveryLogInput

  init(_ configuration: BondryEgressConfiguration) {
    registry = RegistryInput(configuration.registry)
    runtime = RuntimeInput(configuration.runtime)
    deliveryLog = DeliveryLogInput(configuration.deliveryLog)
  }
}

private struct RegistryInput: Encodable {
  let maxRoutes: UInt16
  let globalRefillPerSecond: UInt16
  let globalCapacity: UInt16

  init(_ limits: BondryEgressRegistryLimits) {
    maxRoutes = limits.maxRoutes
    globalRefillPerSecond = limits.globalRefillPerSecond
    globalCapacity = limits.globalCapacity
  }
}

private struct RuntimeInput: Encodable {
  let globalPendingDeliveries: UInt16
  let routePendingDeliveries: UInt16
  let globalPendingBytes: Int
  let routePendingBytes: Int
  let globalInFlight: UInt8
  let routeInFlight: UInt8
  let callInFlight: UInt8
  let drainTimeoutMilliseconds: UInt64

  init(_ limits: BondryEgressRuntimeLimits) {
    globalPendingDeliveries = limits.globalPendingDeliveries
    routePendingDeliveries = limits.routePendingDeliveries
    globalPendingBytes = limits.globalPendingBytes
    routePendingBytes = limits.routePendingBytes
    globalInFlight = limits.globalInFlight
    routeInFlight = limits.routeInFlight
    callInFlight = limits.callInFlight
    drainTimeoutMilliseconds = limits.drainTimeoutMilliseconds
  }
}

private struct DeliveryLogInput: Encodable {
  let maxRecords: UInt32
  let maxBytes: UInt64
  let retentionSeconds: UInt64

  init(_ limits: BondryDeliveryLogLimits) {
    maxRecords = limits.maxRecords
    maxBytes = limits.maxBytes
    retentionSeconds = limits.retentionSeconds
  }
}

private struct RouteInput: Encodable {
  let version = 1
  let id: String
  let enabled: Bool
  let payload: PayloadInput
  let requestTimeoutMilliseconds: UInt64
  let retry: RetryInput
  let admission: AdmissionInput
  let kind: WebhookKindInput

  init(_ route: BondryWebhookRoute) {
    id = route.id
    enabled = route.enabled
    payload = PayloadInput(route.payload)
    requestTimeoutMilliseconds = route.requestTimeoutMilliseconds
    retry = RetryInput(route.retry)
    admission = AdmissionInput(route.admission)
    kind = WebhookKindInput(route)
  }
}

private struct PayloadInput: Encodable {
  let maxBytes: Int
  let fields: [PayloadFieldInput]

  init(_ payload: BondryPayloadContract) {
    maxBytes = payload.maxBytes
    fields = payload.fields.map(PayloadFieldInput.init)
  }
}

private struct PayloadFieldInput: Encodable {
  let name: String
  let type: String
  let required: Bool

  init(_ field: BondryPayloadField) {
    name = field.name
    type = field.type.rawValue
    required = field.required
  }
}

private struct RetryInput: Encodable {
  let retries: UInt8
  let baseMilliseconds: UInt64
  let capMilliseconds: UInt64

  init(_ retry: BondryEgressRetryPolicy) {
    retries = retry.retries
    baseMilliseconds = retry.baseMilliseconds
    capMilliseconds = retry.capMilliseconds
  }
}

private struct AdmissionInput: Encodable {
  let refillPerSecond: UInt16
  let capacity: UInt16

  init(_ admission: BondryEgressAdmissionPolicy) {
    refillPerSecond = admission.refillPerSecond
    capacity = admission.capacity
  }
}

private struct WebhookKindInput: Encodable {
  let type = "webhook"
  let authentication: AuthenticationInput
  let policy: PolicyInput
  let limits: WebhookLimitsInput

  init(_ route: BondryWebhookRoute) {
    authentication = AuthenticationInput(route.authentication)
    policy = PolicyInput(route.endpointPolicy)
    limits = WebhookLimitsInput(route.limits)
  }
}

private enum AuthenticationInput: Encodable {
  case none(endpoint: String)
  case bearer(endpoint: String, secretRef: String)
  case hmac(endpoint: String, secretRef: String)
  case urlTemplate(String, secretRef: String)

  init(_ authentication: BondryWebhookAuthentication) {
    switch authentication {
    case .none(let endpoint):
      self = .none(endpoint: endpoint.absoluteString)
    case .bearer(let endpoint, let secret):
      self = .bearer(endpoint: endpoint.absoluteString, secretRef: secret.rawValue)
    case .hmac(let endpoint, let secret):
      self = .hmac(endpoint: endpoint.absoluteString, secretRef: secret.rawValue)
    case .urlTemplate(let template, let secret):
      self = .urlTemplate(template, secretRef: secret.rawValue)
    }
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    switch self {
    case .none(let endpoint):
      try container.encode("none", forKey: .type)
      try container.encode(endpoint, forKey: .endpoint)
    case .bearer(let endpoint, let secretRef):
      try container.encode("bearer", forKey: .type)
      try container.encode(endpoint, forKey: .endpoint)
      try container.encode(secretRef, forKey: .secretRef)
    case .hmac(let endpoint, let secretRef):
      try container.encode("hmac", forKey: .type)
      try container.encode(endpoint, forKey: .endpoint)
      try container.encode(secretRef, forKey: .secretRef)
    case .urlTemplate(let template, let secretRef):
      try container.encode("url_template", forKey: .type)
      try container.encode(template, forKey: .template)
      try container.encode(secretRef, forKey: .secretRef)
    }
  }

  private enum CodingKeys: String, CodingKey {
    case type
    case endpoint
    case template
    case secretRef
  }
}

private struct PolicyInput: Encodable {
  let allowHostnameLoopbackCleartext: Bool
  let allowPrivateCleartext: Bool
  let allowLinkLocalCleartext: Bool
  let additionalTrustAnchorsBase64: [String]

  init(_ policy: BondryEndpointPolicy) {
    allowHostnameLoopbackCleartext = policy.allowHostnameLoopbackCleartext
    allowPrivateCleartext = policy.allowPrivateCleartext
    allowLinkLocalCleartext = policy.allowLinkLocalCleartext
    additionalTrustAnchorsBase64 = policy.additionalTrustAnchors.map { $0.base64EncodedString() }
  }
}

private struct WebhookLimitsInput: Encodable {
  let bodyBytes: Int
  let responseBodyBytes: Int
  let urlTemplateBytes: Int
  let expandedURLBytes: Int

  init(_ limits: BondryWebhookLimits) {
    bodyBytes = limits.bodyBytes
    responseBodyBytes = limits.responseBodyBytes
    urlTemplateBytes = limits.urlTemplateBytes
    expandedURLBytes = limits.expandedURLBytes
  }
}

private func encodeRuntimeConfiguration(_ configuration: BondryEgressConfiguration) throws -> Data {
  try encodeEgressJSON(RuntimeConfigurationInput(configuration))
}

private func encodeRoute(_ route: BondryWebhookRoute) throws -> Data {
  try encodeEgressJSON(RouteInput(route))
}

private func encodeEgressJSON<Value: Encodable>(_ value: Value) throws -> Data {
  let encoder = JSONEncoder()
  encoder.keyEncodingStrategy = .convertToSnakeCase
  do {
    return try encoder.encode(value)
  } catch {
    throw BondryEgressError.invalidConfiguration
  }
}

private func queryEgressBytes(
  _ operation: (UnsafeMutablePointer<UInt8>?, Int, UnsafeMutablePointer<Int>?) -> BondryStatus
) throws -> Data {
  var length = 0
  try requireEgressSuccess(operation(nil, 0, &length))
  guard length >= 0 else {
    throw BondryEgressError.invalidData
  }
  var data = Data(count: length)
  let status = data.withUnsafeMutableBytes { buffer in
    operation(buffer.bindMemory(to: UInt8.self).baseAddress, buffer.count, &length)
  }
  try requireEgressSuccess(status)
  guard length == data.count else {
    throw BondryEgressError.invalidData
  }
  return data
}

private func requireEgressSuccess(_ status: BondryStatus) throws {
  guard status == BONDRY_STATUS_OK else {
    throw BondryEgressError(status: status)
  }
}

extension BondryDeliveryStatus {
  fileprivate init(record: BondryEgressDeliveryStatusV1) throws {
    routeID = try decodeEgressCString(record.route_id)
    deliveryID = try decodeEgressCString(record.delivery_id)
    acceptedAtUnixMilliseconds = record.accepted_at_unix_ms
    updatedAtUnixMilliseconds = record.updated_at_unix_ms
    attempts = record.attempts
    state = try decodeDeliveryState(record)
    resultCategory = try decodeResultCategory(record.result_category, bytes: record.result_bytes)
    resultBytes = record.result_bytes
  }
}

private func decodeDeliveryState(
  _ record: BondryEgressDeliveryStatusV1
) throws -> BondryDeliveryState {
  switch (record.state, record.outcome, record.failure) {
  case (
    BONDRY_DELIVERY_STATE_PENDING_V1, BONDRY_DELIVERY_OUTCOME_NONE_V1,
    BONDRY_DELIVERY_FAILURE_NONE_V1
  ):
    return .pending
  case (
    BONDRY_DELIVERY_STATE_TERMINAL_V1, BONDRY_DELIVERY_OUTCOME_DELIVERED_V1,
    BONDRY_DELIVERY_FAILURE_NONE_V1
  ):
    return .terminal(.delivered)
  case (BONDRY_DELIVERY_STATE_TERMINAL_V1, BONDRY_DELIVERY_OUTCOME_FAILED_V1, let failure):
    return .terminal(.failed(try decodeDeliveryFailure(failure)))
  case (
    BONDRY_DELIVERY_STATE_TERMINAL_V1, BONDRY_DELIVERY_OUTCOME_LOST_ON_SHUTDOWN_V1,
    BONDRY_DELIVERY_FAILURE_NONE_V1
  ):
    return .terminal(.lostOnShutdown)
  case (
    BONDRY_DELIVERY_STATE_TERMINAL_V1, BONDRY_DELIVERY_OUTCOME_UNKNOWN_AFTER_CRASH_V1,
    BONDRY_DELIVERY_FAILURE_NONE_V1
  ):
    return .terminal(.unknownAfterCrash)
  default:
    throw BondryEgressError.invalidData
  }
}

private func decodeDeliveryFailure(_ value: UInt32) throws -> BondryDeliveryFailure {
  switch value {
  case BONDRY_DELIVERY_FAILURE_CANCELLED_V1: return .cancelled
  case BONDRY_DELIVERY_FAILURE_DEADLINE_EXCEEDED_V1: return .deadlineExceeded
  case BONDRY_DELIVERY_FAILURE_ENDPOINT_POLICY_V1: return .endpointPolicy
  case BONDRY_DELIVERY_FAILURE_SECRET_UNAVAILABLE_V1: return .secretUnavailable
  case BONDRY_DELIVERY_FAILURE_TRANSPORT_UNAVAILABLE_V1: return .transportUnavailable
  case BONDRY_DELIVERY_FAILURE_RECEIVER_REJECTED_V1: return .receiverRejected
  case BONDRY_DELIVERY_FAILURE_RETRY_EXHAUSTED_V1: return .retryExhausted
  case BONDRY_DELIVERY_FAILURE_INTERNAL_V1: return .internal
  default: throw BondryEgressError.invalidData
  }
}

private func decodeResultCategory(
  _ value: UInt32,
  bytes: UInt32
) throws -> BondryDeliveryResultCategory? {
  switch value {
  case BONDRY_DELIVERY_RESULT_NONE_V1 where bytes == 0: return nil
  case BONDRY_DELIVERY_RESULT_SUCCEEDED_V1: return .succeeded
  case BONDRY_DELIVERY_RESULT_FAILED_V1: return .failed
  case BONDRY_DELIVERY_RESULT_INVALID_V1: return .invalid
  default: throw BondryEgressError.invalidData
  }
}

private func decodeEgressCString<Value>(_ value: Value) throws -> String {
  try withUnsafeBytes(of: value) { bytes in
    guard let end = bytes.firstIndex(of: 0), end > 0,
      let string = String(bytes: bytes[..<end], encoding: .utf8)
    else {
      throw BondryEgressError.invalidData
    }
    return string
  }
}
