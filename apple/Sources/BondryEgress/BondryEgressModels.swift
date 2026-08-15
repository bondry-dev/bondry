import BondryApple
import CBondryEgress
import Foundation

public struct BondryEgressRegistryLimits: Equatable, Sendable {
  public static let standard = BondryEgressRegistryLimits(
    maxRoutes: 64,
    globalRefillPerSecond: 200,
    globalCapacity: 512
  )

  public let maxRoutes: UInt16
  public let globalRefillPerSecond: UInt16
  public let globalCapacity: UInt16

  public init(maxRoutes: UInt16, globalRefillPerSecond: UInt16, globalCapacity: UInt16) {
    self.maxRoutes = maxRoutes
    self.globalRefillPerSecond = globalRefillPerSecond
    self.globalCapacity = globalCapacity
  }
}

public struct BondryEgressRuntimeLimits: Equatable, Sendable {
  public static let standard = BondryEgressRuntimeLimits(
    globalPendingDeliveries: 1_024,
    routePendingDeliveries: 64,
    globalPendingBytes: 8 * 1_024 * 1_024,
    routePendingBytes: 1_024 * 1_024,
    globalInFlight: 4,
    routeInFlight: 2,
    callInFlight: 4,
    drainTimeoutMilliseconds: 10_000
  )

  public let globalPendingDeliveries: UInt16
  public let routePendingDeliveries: UInt16
  public let globalPendingBytes: Int
  public let routePendingBytes: Int
  public let globalInFlight: UInt8
  public let routeInFlight: UInt8
  public let callInFlight: UInt8
  public let drainTimeoutMilliseconds: UInt64

  public init(
    globalPendingDeliveries: UInt16,
    routePendingDeliveries: UInt16,
    globalPendingBytes: Int,
    routePendingBytes: Int,
    globalInFlight: UInt8,
    routeInFlight: UInt8,
    callInFlight: UInt8,
    drainTimeoutMilliseconds: UInt64
  ) {
    self.globalPendingDeliveries = globalPendingDeliveries
    self.routePendingDeliveries = routePendingDeliveries
    self.globalPendingBytes = globalPendingBytes
    self.routePendingBytes = routePendingBytes
    self.globalInFlight = globalInFlight
    self.routeInFlight = routeInFlight
    self.callInFlight = callInFlight
    self.drainTimeoutMilliseconds = drainTimeoutMilliseconds
  }
}

public struct BondryDeliveryLogLimits: Equatable, Sendable {
  public static let standard = BondryDeliveryLogLimits(
    maxRecords: 100_000,
    maxBytes: 64 * 1_024 * 1_024,
    retentionSeconds: 7 * 86_400
  )

  public let maxRecords: UInt32
  public let maxBytes: UInt64
  public let retentionSeconds: UInt64

  public init(maxRecords: UInt32, maxBytes: UInt64, retentionSeconds: UInt64) {
    self.maxRecords = maxRecords
    self.maxBytes = maxBytes
    self.retentionSeconds = retentionSeconds
  }
}

public struct BondryEgressConfiguration: Equatable, Sendable {
  public static let standard = BondryEgressConfiguration()

  public let registry: BondryEgressRegistryLimits
  public let runtime: BondryEgressRuntimeLimits
  public let deliveryLog: BondryDeliveryLogLimits

  public init(
    registry: BondryEgressRegistryLimits = .standard,
    runtime: BondryEgressRuntimeLimits = .standard,
    deliveryLog: BondryDeliveryLogLimits = .standard
  ) {
    self.registry = registry
    self.runtime = runtime
    self.deliveryLog = deliveryLog
  }
}

public enum BondryPayloadFieldType: String, CaseIterable, Sendable {
  case any
  case null
  case boolean
  case number
  case string
  case array
  case object
}

public struct BondryPayloadField: Equatable, Sendable {
  public let name: String
  public let type: BondryPayloadFieldType
  public let required: Bool

  public init(name: String, type: BondryPayloadFieldType, required: Bool = false) {
    self.name = name
    self.type = type
    self.required = required
  }
}

public struct BondryPayloadContract: Equatable, Sendable {
  public let maxBytes: Int
  public let fields: [BondryPayloadField]

  public init(maxBytes: Int = 16 * 1_024, fields: [BondryPayloadField]) {
    self.maxBytes = maxBytes
    self.fields = fields
  }
}

public struct BondryEgressRetryPolicy: Equatable, Sendable {
  public static let standard = BondryEgressRetryPolicy(
    retries: 5,
    baseMilliseconds: 1_000,
    capMilliseconds: 60_000
  )

  public let retries: UInt8
  public let baseMilliseconds: UInt64
  public let capMilliseconds: UInt64

  public init(retries: UInt8, baseMilliseconds: UInt64, capMilliseconds: UInt64) {
    self.retries = retries
    self.baseMilliseconds = baseMilliseconds
    self.capMilliseconds = capMilliseconds
  }
}

public struct BondryEgressAdmissionPolicy: Equatable, Sendable {
  public static let standard = BondryEgressAdmissionPolicy(
    refillPerSecond: 50,
    capacity: 64
  )

  public let refillPerSecond: UInt16
  public let capacity: UInt16

  public init(refillPerSecond: UInt16, capacity: UInt16) {
    self.refillPerSecond = refillPerSecond
    self.capacity = capacity
  }
}

public struct BondryWebhookLimits: Equatable, Sendable {
  public static let standard = BondryWebhookLimits(
    bodyBytes: 32 * 1_024,
    responseBodyBytes: 64 * 1_024,
    urlTemplateBytes: 1_024,
    expandedURLBytes: 2 * 1_024
  )

  public let bodyBytes: Int
  public let responseBodyBytes: Int
  public let urlTemplateBytes: Int
  public let expandedURLBytes: Int

  public init(
    bodyBytes: Int,
    responseBodyBytes: Int,
    urlTemplateBytes: Int,
    expandedURLBytes: Int
  ) {
    self.bodyBytes = bodyBytes
    self.responseBodyBytes = responseBodyBytes
    self.urlTemplateBytes = urlTemplateBytes
    self.expandedURLBytes = expandedURLBytes
  }
}

public enum BondryWebhookAuthentication: Equatable, Sendable {
  case none(endpoint: URL)
  case bearer(endpoint: URL, secret: BondrySecretReference)
  case hmac(endpoint: URL, secret: BondrySecretReference)
  case urlTemplate(String, secret: BondrySecretReference)
}

public struct BondryWebhookRoute: Equatable, Sendable {
  public let id: String
  public let enabled: Bool
  public let payload: BondryPayloadContract
  public let requestTimeoutMilliseconds: UInt64
  public let retry: BondryEgressRetryPolicy
  public let admission: BondryEgressAdmissionPolicy
  public let authentication: BondryWebhookAuthentication
  public let endpointPolicy: BondryEndpointPolicy
  public let limits: BondryWebhookLimits

  public init(
    id: String,
    enabled: Bool = true,
    payload: BondryPayloadContract,
    requestTimeoutMilliseconds: UInt64 = 30_000,
    retry: BondryEgressRetryPolicy = .standard,
    admission: BondryEgressAdmissionPolicy = .standard,
    authentication: BondryWebhookAuthentication,
    endpointPolicy: BondryEndpointPolicy = BondryEndpointPolicy(),
    limits: BondryWebhookLimits = .standard
  ) {
    self.id = id
    self.enabled = enabled
    self.payload = payload
    self.requestTimeoutMilliseconds = requestTimeoutMilliseconds
    self.retry = retry
    self.admission = admission
    self.authentication = authentication
    self.endpointPolicy = endpointPolicy
    self.limits = limits
  }
}

public indirect enum BondryJSONValue: Codable, Equatable, Sendable {
  case null
  case boolean(Bool)
  case integer(Int64)
  case number(Double)
  case string(String)
  case array([BondryJSONValue])
  case object([String: BondryJSONValue])

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    if container.decodeNil() {
      self = .null
    } else if let value = try? container.decode(Bool.self) {
      self = .boolean(value)
    } else if let value = try? container.decode(Int64.self) {
      self = .integer(value)
    } else if let value = try? container.decode(Double.self) {
      self = .number(value)
    } else if let value = try? container.decode(String.self) {
      self = .string(value)
    } else if let value = try? container.decode([BondryJSONValue].self) {
      self = .array(value)
    } else {
      self = .object(try container.decode([String: BondryJSONValue].self))
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    switch self {
    case .null: try container.encodeNil()
    case .boolean(let value): try container.encode(value)
    case .integer(let value): try container.encode(value)
    case .number(let value): try container.encode(value)
    case .string(let value): try container.encode(value)
    case .array(let value): try container.encode(value)
    case .object(let value): try container.encode(value)
    }
  }
}

public enum BondryMCPProtocolVersion: String, Codable, Equatable, Sendable {
  case v20260728 = "2026-07-28"
  case v20251125 = "2025-11-25"
}

public struct BondryMCPTool: Codable, Equatable, Sendable {
  public let name: String
  public let description: String?
  public let inputSchema: BondryJSONValue

  public init(name: String, description: String? = nil, inputSchema: BondryJSONValue) {
    self.name = name
    self.description = description
    self.inputSchema = inputSchema
  }

  private enum CodingKeys: String, CodingKey {
    case name
    case description
    case inputSchema = "input_schema"
  }
}

public struct BondryMCPDiscoveryResult: Decodable, Equatable, Sendable {
  public let protocolVersion: BondryMCPProtocolVersion
  public let tools: [BondryMCPTool]

  private enum CodingKeys: String, CodingKey {
    case protocolVersion = "protocol_version"
    case tools
  }
}

public enum BondryMCPAuthentication: Equatable, Sendable {
  case none(endpoint: URL)
  case bearer(endpoint: URL, secret: BondrySecretReference)
}

public struct BondryMCPLimits: Equatable, Sendable {
  public static let standard = BondryMCPLimits(
    schemaBytes: 16 * 1_024,
    resultBytes: 256 * 1_024
  )

  public let schemaBytes: Int
  public let resultBytes: Int

  public init(schemaBytes: Int, resultBytes: Int) {
    self.schemaBytes = schemaBytes
    self.resultBytes = resultBytes
  }
}

public struct BondryMCPDiscoveryLimits: Equatable, Sendable {
  public static let standard = BondryMCPDiscoveryLimits(
    tools: 128,
    schemaBytes: 16 * 1_024,
    responseBytes: 64 * 1_024
  )

  public let tools: Int
  public let schemaBytes: Int
  public let responseBytes: Int

  public init(tools: Int, schemaBytes: Int, responseBytes: Int) {
    self.tools = tools
    self.schemaBytes = schemaBytes
    self.responseBytes = responseBytes
  }
}

public struct BondryMCPDiscoveryConfiguration: Equatable, Sendable {
  public let authentication: BondryMCPAuthentication
  public let endpointPolicy: BondryEndpointPolicy
  public let limits: BondryMCPDiscoveryLimits
  public let requestTimeoutMilliseconds: UInt64

  public init(
    authentication: BondryMCPAuthentication,
    endpointPolicy: BondryEndpointPolicy = BondryEndpointPolicy(),
    limits: BondryMCPDiscoveryLimits = .standard,
    requestTimeoutMilliseconds: UInt64 = 30_000
  ) {
    self.authentication = authentication
    self.endpointPolicy = endpointPolicy
    self.limits = limits
    self.requestTimeoutMilliseconds = requestTimeoutMilliseconds
  }
}

public struct BondryMCPRoute: Equatable, Sendable {
  public let id: String
  public let enabled: Bool
  public let payload: BondryPayloadContract
  public let requestTimeoutMilliseconds: UInt64
  public let retry: BondryEgressRetryPolicy
  public let admission: BondryEgressAdmissionPolicy
  public let authentication: BondryMCPAuthentication
  public let endpointPolicy: BondryEndpointPolicy
  public let protocolVersion: BondryMCPProtocolVersion
  public let tool: BondryMCPTool
  public let limits: BondryMCPLimits
  public let automaticRetry: Bool

  public init(
    id: String,
    enabled: Bool = true,
    payload: BondryPayloadContract,
    requestTimeoutMilliseconds: UInt64 = 30_000,
    retry: BondryEgressRetryPolicy = .standard,
    admission: BondryEgressAdmissionPolicy = .standard,
    authentication: BondryMCPAuthentication,
    endpointPolicy: BondryEndpointPolicy = BondryEndpointPolicy(),
    protocolVersion: BondryMCPProtocolVersion,
    tool: BondryMCPTool,
    limits: BondryMCPLimits = .standard,
    automaticRetry: Bool = false
  ) {
    self.id = id
    self.enabled = enabled
    self.payload = payload
    self.requestTimeoutMilliseconds = requestTimeoutMilliseconds
    self.retry = retry
    self.admission = admission
    self.authentication = authentication
    self.endpointPolicy = endpointPolicy
    self.protocolVersion = protocolVersion
    self.tool = tool
    self.limits = limits
    self.automaticRetry = automaticRetry
  }
}

public struct BondryMCPCallResult: Equatable, Sendable {
  public let deliveryID: String
  public let category: BondryDeliveryResultCategory
  public let rawJSON: Data

  public init(deliveryID: String, category: BondryDeliveryResultCategory, rawJSON: Data) {
    self.deliveryID = deliveryID
    self.category = category
    self.rawJSON = rawJSON
  }
}

public struct BondryEgressRouteSummary: Decodable, Equatable, Sendable {
  public let id: String
  public let enabled: Bool
  public let kind: String
  public let target: String
}

public enum BondryDeliveryFailure: Equatable, Sendable {
  case cancelled
  case deadlineExceeded
  case endpointPolicy
  case secretUnavailable
  case transportUnavailable
  case receiverRejected
  case retryExhausted
  case `internal`
}

public enum BondryDeliveryOutcome: Equatable, Sendable {
  case delivered
  case failed(BondryDeliveryFailure)
  case lostOnShutdown
  case unknownAfterCrash
}

public enum BondryDeliveryState: Equatable, Sendable {
  case pending
  case terminal(BondryDeliveryOutcome)
}

public enum BondryDeliveryResultCategory: Equatable, Sendable {
  case succeeded
  case failed
  case invalid
}

public struct BondryDeliveryStatus: Equatable, Sendable {
  public let routeID: String
  public let deliveryID: String
  public let acceptedAtUnixMilliseconds: UInt64
  public let updatedAtUnixMilliseconds: UInt64
  public let attempts: UInt16
  public let state: BondryDeliveryState
  public let resultCategory: BondryDeliveryResultCategory?
  public let resultBytes: UInt32
}

public enum BondryEgressError: Error, Equatable, Sendable {
  case incompatibleABI(expected: UInt32, actual: UInt32)
  case invalidConfiguration
  case invalidHandle
  case invalidData
  case nullPointer
  case invalidLength
  case invalidUTF8
  case invalidArgument
  case bufferTooSmall
  case invalidJSON
  case payloadTooLarge
  case unavailable
  case notFound
  case alreadyExists
  case capacityExhausted
  case startFailed
  case stopFailed
  case busy
  case stopped
  case routeDraining
  case pendingCapacity
  case pendingBytes
  case globalRateLimited
  case routeRateLimited
  case routeDisabled
  case unsupportedOperation
  case deliveryLog
  case callCapacity
  case callFailed
  case resultTooLarge
  case discoverySecretUnavailable
  case discoveryEndpointPolicy
  case discoveryDeadlineExceeded
  case discoveryUnavailable
  case discoveryResponseTooLarge
  case discoveryUnsupportedProtocol
  case discoveryUnsupportedResponseMode
  case discoveryRejected
  case discoveryInvalidResponse
  case discoveryToolLimit
  case discoveryInvalidSchema
  case internalFailure(Int32)

  init(status: BondryStatus) {
    switch status {
    case BONDRY_STATUS_NULL_POINTER: self = .nullPointer
    case BONDRY_STATUS_INVALID_LENGTH: self = .invalidLength
    case BONDRY_STATUS_INVALID_UTF8: self = .invalidUTF8
    case BONDRY_STATUS_INVALID_ARGUMENT: self = .invalidArgument
    case BONDRY_STATUS_BUFFER_TOO_SMALL: self = .bufferTooSmall
    case BONDRY_STATUS_INVALID_JSON: self = .invalidJSON
    case BONDRY_STATUS_PAYLOAD_TOO_LARGE: self = .payloadTooLarge
    case BONDRY_STATUS_UNAVAILABLE: self = .unavailable
    case BONDRY_STATUS_NOT_FOUND: self = .notFound
    case BONDRY_STATUS_ALREADY_EXISTS: self = .alreadyExists
    case BONDRY_STATUS_CAPACITY_EXHAUSTED: self = .capacityExhausted
    case BONDRY_STATUS_EGRESS_START_FAILED: self = .startFailed
    case BONDRY_STATUS_EGRESS_STOP_FAILED: self = .stopFailed
    case BONDRY_STATUS_EGRESS_BUSY: self = .busy
    case BONDRY_STATUS_EGRESS_STOPPED: self = .stopped
    case BONDRY_STATUS_EGRESS_ROUTE_DRAINING: self = .routeDraining
    case BONDRY_STATUS_EGRESS_PENDING_CAPACITY: self = .pendingCapacity
    case BONDRY_STATUS_EGRESS_PENDING_BYTES: self = .pendingBytes
    case BONDRY_STATUS_EGRESS_GLOBAL_RATE_LIMITED: self = .globalRateLimited
    case BONDRY_STATUS_EGRESS_ROUTE_RATE_LIMITED: self = .routeRateLimited
    case BONDRY_STATUS_EGRESS_ROUTE_DISABLED: self = .routeDisabled
    case BONDRY_STATUS_EGRESS_UNSUPPORTED_OPERATION: self = .unsupportedOperation
    case BONDRY_STATUS_EGRESS_DELIVERY_LOG: self = .deliveryLog
    case BONDRY_STATUS_EGRESS_CALL_CAPACITY: self = .callCapacity
    case BONDRY_STATUS_EGRESS_CALL_FAILED: self = .callFailed
    case BONDRY_STATUS_EGRESS_RESULT_TOO_LARGE: self = .resultTooLarge
    case BONDRY_STATUS_EGRESS_DISCOVERY_SECRET: self = .discoverySecretUnavailable
    case BONDRY_STATUS_EGRESS_DISCOVERY_ENDPOINT_POLICY: self = .discoveryEndpointPolicy
    case BONDRY_STATUS_EGRESS_DISCOVERY_DEADLINE: self = .discoveryDeadlineExceeded
    case BONDRY_STATUS_EGRESS_DISCOVERY_UNAVAILABLE: self = .discoveryUnavailable
    case BONDRY_STATUS_EGRESS_DISCOVERY_RESPONSE_TOO_LARGE: self = .discoveryResponseTooLarge
    case BONDRY_STATUS_EGRESS_DISCOVERY_UNSUPPORTED_PROTOCOL:
      self = .discoveryUnsupportedProtocol
    case BONDRY_STATUS_EGRESS_DISCOVERY_UNSUPPORTED_RESPONSE_MODE:
      self = .discoveryUnsupportedResponseMode
    case BONDRY_STATUS_EGRESS_DISCOVERY_REJECTED: self = .discoveryRejected
    case BONDRY_STATUS_EGRESS_DISCOVERY_INVALID_RESPONSE: self = .discoveryInvalidResponse
    case BONDRY_STATUS_EGRESS_DISCOVERY_TOOL_LIMIT: self = .discoveryToolLimit
    case BONDRY_STATUS_EGRESS_DISCOVERY_INVALID_SCHEMA: self = .discoveryInvalidSchema
    default: self = .internalFailure(status)
    }
  }
}
