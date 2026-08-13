import CBondry
import Foundation

public enum BondryServerAdapter: String, CaseIterable, Hashable, Sendable {
  case rest
  case mcp
}

public struct BondryMCPServerInformation: Equatable, Sendable {
  public var name: String
  public var title: String?
  public var version: String

  public init(name: String, title: String? = nil, version: String) {
    self.name = name
    self.title = title
    self.version = version
  }
}

public enum BondryServerAuthentication: Equatable, Sendable {
  case bearerToken
  case disabled(principalID: String, kind: BondryPrincipalKind = .application)
}

public struct BondryServerConfiguration: Equatable, Sendable {
  public var adapters: Set<BondryServerAdapter>
  public var mcpServer: BondryMCPServerInformation?
  public var bindAddress: String
  public var port: UInt16
  public var authentication: BondryServerAuthentication
  public var allowedOrigins: [String]
  public var requestsPerMinute: UInt32
  public var authenticationFailuresPerMinute: UInt32
  public var maxBodyBytes: Int
  public var maxConnections: Int
  public var headerReadTimeoutMilliseconds: UInt64
  public var requestTimeoutMilliseconds: UInt64
  public var shutdownGracePeriodMilliseconds: UInt64
  public var allowCleartextNetwork: Bool
  public var allowUnauthenticatedNetwork: Bool

  public init(
    adapters: Set<BondryServerAdapter>,
    mcpServer: BondryMCPServerInformation? = nil,
    bindAddress: String = "127.0.0.1",
    port: UInt16 = 0,
    authentication: BondryServerAuthentication = .bearerToken,
    allowedOrigins: [String] = [],
    requestsPerMinute: UInt32 = 120,
    authenticationFailuresPerMinute: UInt32 = 30,
    maxBodyBytes: Int = 1_048_576,
    maxConnections: Int = 64,
    headerReadTimeoutMilliseconds: UInt64 = 5_000,
    requestTimeoutMilliseconds: UInt64 = 30_000,
    shutdownGracePeriodMilliseconds: UInt64 = 2_000,
    allowCleartextNetwork: Bool = false,
    allowUnauthenticatedNetwork: Bool = false
  ) {
    self.adapters = adapters
    self.mcpServer = mcpServer
    self.bindAddress = bindAddress
    self.port = port
    self.authentication = authentication
    self.allowedOrigins = allowedOrigins
    self.requestsPerMinute = requestsPerMinute
    self.authenticationFailuresPerMinute = authenticationFailuresPerMinute
    self.maxBodyBytes = maxBodyBytes
    self.maxConnections = maxConnections
    self.headerReadTimeoutMilliseconds = headerReadTimeoutMilliseconds
    self.requestTimeoutMilliseconds = requestTimeoutMilliseconds
    self.shutdownGracePeriodMilliseconds = shutdownGracePeriodMilliseconds
    self.allowCleartextNetwork = allowCleartextNetwork
    self.allowUnauthenticatedNetwork = allowUnauthenticatedNetwork
  }
}

public struct BondryServerEndpoint: Equatable, Sendable {
  public let address: String
  public let port: UInt16

  public init(address: String, port: UInt16) {
    self.address = address
    self.port = port
  }
}

struct BondryServerInput: Encodable {
  let version = BONDRY_SERVER_CONFIGURATION_VERSION_V1
  let bindAddress: String
  let port: UInt16
  let authentication: AuthenticationInput
  let adapters: [String]
  let mcpServer: MCPServerInput?
  let allowedOrigins: [String]
  let requestsPerMinute: UInt32
  let authenticationFailuresPerMinute: UInt32
  let maxBodyBytes: Int
  let maxConnections: Int
  let headerReadTimeoutMilliseconds: UInt64
  let requestTimeoutMilliseconds: UInt64
  let shutdownGracePeriodMilliseconds: UInt64
  let allowCleartextNetwork: Bool
  let allowUnauthenticatedNetwork: Bool

  init(_ configuration: BondryServerConfiguration) {
    bindAddress = configuration.bindAddress
    port = configuration.port
    authentication = AuthenticationInput(configuration.authentication)
    adapters = configuration.adapters.map(\.rawValue).sorted()
    mcpServer = configuration.mcpServer.map(MCPServerInput.init)
    allowedOrigins = configuration.allowedOrigins
    requestsPerMinute = configuration.requestsPerMinute
    authenticationFailuresPerMinute = configuration.authenticationFailuresPerMinute
    maxBodyBytes = configuration.maxBodyBytes
    maxConnections = configuration.maxConnections
    headerReadTimeoutMilliseconds = configuration.headerReadTimeoutMilliseconds
    requestTimeoutMilliseconds = configuration.requestTimeoutMilliseconds
    shutdownGracePeriodMilliseconds = configuration.shutdownGracePeriodMilliseconds
    allowCleartextNetwork = configuration.allowCleartextNetwork
    allowUnauthenticatedNetwork = configuration.allowUnauthenticatedNetwork
  }
}

struct AuthenticationInput: Encodable {
  let mode: String
  let principalID: String?
  let principalKind: String?

  init(_ authentication: BondryServerAuthentication) {
    switch authentication {
    case .bearerToken:
      mode = "bearer"
      principalID = nil
      principalKind = nil
    case .disabled(let principalID, let kind):
      mode = "disabled"
      self.principalID = principalID
      principalKind = kind.serverValue
    }
  }
}

struct MCPServerInput: Encodable {
  let name: String
  let title: String?
  let version: String

  init(_ information: BondryMCPServerInformation) {
    name = information.name
    title = information.title
    version = information.version
  }
}

extension BondryPrincipalKind {
  fileprivate var serverValue: String {
    switch self {
    case .user: "user"
    case .application: "application"
    case .system: "system"
    }
  }
}
