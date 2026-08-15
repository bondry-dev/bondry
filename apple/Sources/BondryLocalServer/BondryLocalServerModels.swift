import Bondry
import CBondryLocalServer
import Darwin
import Foundation

public enum BondryLocalServerAdapter: String, CaseIterable, Hashable, Sendable {
  case rest
  case mcp
}

public struct BondryMCPServerInformation: Equatable, Sendable {
  public let name: String
  public let title: String?
  public let version: String

  public init(name: String, title: String? = nil, version: String) throws {
    guard isValidMetadata(name, maximumUTF8Length: 128) else {
      throw BondryLocalServerConfigurationError.invalidMCPServerName
    }
    if let title, !isValidMetadata(title, maximumUTF8Length: 256) {
      throw BondryLocalServerConfigurationError.invalidMCPServerTitle
    }
    guard isValidMetadata(version, maximumUTF8Length: 64) else {
      throw BondryLocalServerConfigurationError.invalidMCPServerVersion
    }
    self.name = name
    self.title = title
    self.version = version
  }
}

public enum BondryLocalServerAuthentication: Equatable, Sendable {
  case bearerToken
  case disabled(principalID: String, kind: BondryPrincipalKind = .application)
}

public struct BondryLocalServerLimits: Equatable, Sendable {
  public static let standard = BondryLocalServerLimits(
    validatedRequestsPerMinute: 120,
    authenticationFailuresPerMinute: 30,
    maxBodyBytes: 1_048_576,
    maxConnections: 64
  )

  public let requestsPerMinute: UInt32
  public let authenticationFailuresPerMinute: UInt32
  public let maxBodyBytes: Int
  public let maxConnections: Int

  public init(
    requestsPerMinute: UInt32,
    authenticationFailuresPerMinute: UInt32,
    maxBodyBytes: Int,
    maxConnections: Int
  ) throws {
    guard (1...60_000).contains(requestsPerMinute) else {
      throw BondryLocalServerConfigurationError.invalidRateLimit
    }
    guard (1...60_000).contains(authenticationFailuresPerMinute) else {
      throw BondryLocalServerConfigurationError.invalidRateLimit
    }
    guard (1...(8 * 1_048_576)).contains(maxBodyBytes) else {
      throw BondryLocalServerConfigurationError.invalidBodyLimit
    }
    guard (1...1_024).contains(maxConnections) else {
      throw BondryLocalServerConfigurationError.invalidConnectionLimit
    }
    self.init(
      validatedRequestsPerMinute: requestsPerMinute,
      authenticationFailuresPerMinute: authenticationFailuresPerMinute,
      maxBodyBytes: maxBodyBytes,
      maxConnections: maxConnections
    )
  }

  private init(
    validatedRequestsPerMinute requestsPerMinute: UInt32,
    authenticationFailuresPerMinute: UInt32,
    maxBodyBytes: Int,
    maxConnections: Int
  ) {
    self.requestsPerMinute = requestsPerMinute
    self.authenticationFailuresPerMinute = authenticationFailuresPerMinute
    self.maxBodyBytes = maxBodyBytes
    self.maxConnections = maxConnections
  }
}

public struct BondryLocalServerTimeouts: Equatable, Sendable {
  public static let standard = BondryLocalServerTimeouts(
    headerRead: .seconds(5),
    request: .seconds(30),
    shutdownGracePeriod: .seconds(2),
    validatedMilliseconds: (5_000, 30_000, 2_000)
  )

  public let headerRead: Duration
  public let request: Duration
  public let shutdownGracePeriod: Duration

  let headerReadMilliseconds: UInt64
  let requestMilliseconds: UInt64
  let shutdownGracePeriodMilliseconds: UInt64

  public init(
    headerRead: Duration,
    request: Duration,
    shutdownGracePeriod: Duration
  ) throws {
    let headerReadMilliseconds = try validatedMilliseconds(headerRead)
    let requestMilliseconds = try validatedMilliseconds(request)
    let shutdownGracePeriodMilliseconds = try validatedMilliseconds(shutdownGracePeriod)
    self.init(
      headerRead: headerRead,
      request: request,
      shutdownGracePeriod: shutdownGracePeriod,
      validatedMilliseconds: (
        headerReadMilliseconds,
        requestMilliseconds,
        shutdownGracePeriodMilliseconds
      )
    )
  }

  private init(
    headerRead: Duration,
    request: Duration,
    shutdownGracePeriod: Duration,
    validatedMilliseconds: (UInt64, UInt64, UInt64)
  ) {
    self.headerRead = headerRead
    self.request = request
    self.shutdownGracePeriod = shutdownGracePeriod
    headerReadMilliseconds = validatedMilliseconds.0
    requestMilliseconds = validatedMilliseconds.1
    shutdownGracePeriodMilliseconds = validatedMilliseconds.2
  }
}

public struct BondryLocalServerConfiguration: Equatable, Sendable {
  public let adapters: Set<BondryLocalServerAdapter>
  public let mcpServer: BondryMCPServerInformation?
  public let listeningAddress: String
  public let port: UInt16
  public let authentication: BondryLocalServerAuthentication
  public let allowedBrowserOrigins: [String]
  public let limits: BondryLocalServerLimits
  public let timeouts: BondryLocalServerTimeouts
  public let allowsCleartextNetworkAccess: Bool
  public let allowsUnauthenticatedNetworkAccess: Bool

  public init(
    adapters: Set<BondryLocalServerAdapter>,
    mcpServer: BondryMCPServerInformation? = nil,
    listeningAddress: String = "127.0.0.1",
    port: UInt16 = 0,
    authentication: BondryLocalServerAuthentication = .bearerToken,
    allowedBrowserOrigins: [String] = [],
    limits: BondryLocalServerLimits = .standard,
    timeouts: BondryLocalServerTimeouts = .standard,
    allowsCleartextNetworkAccess: Bool = false,
    allowsUnauthenticatedNetworkAccess: Bool = false
  ) throws {
    guard isValidIPAddress(listeningAddress) else {
      throw BondryLocalServerConfigurationError.invalidListeningAddress
    }
    let isLoopback = isLoopbackIPAddress(listeningAddress)
    guard isLoopback || allowsCleartextNetworkAccess else {
      throw BondryLocalServerConfigurationError.cleartextNetworkExposureRequiresAcknowledgement
    }
    if case .disabled = authentication,
      !isLoopback && !allowsUnauthenticatedNetworkAccess
    {
      throw BondryLocalServerConfigurationError
        .unauthenticatedNetworkExposureRequiresAcknowledgement
    }
    guard allowedBrowserOrigins.allSatisfy(isValidBrowserOrigin) else {
      throw BondryLocalServerConfigurationError.invalidBrowserOrigin
    }
    if case .disabled(let principalID, _) = authentication,
      !isValidIdentifier(principalID)
    {
      throw BondryLocalServerConfigurationError.invalidPrincipalID
    }
    switch (adapters.contains(.mcp), mcpServer) {
    case (true, nil):
      throw BondryLocalServerConfigurationError.missingMCPServerInformation
    case (false, .some):
      throw BondryLocalServerConfigurationError.unexpectedMCPServerInformation
    default:
      break
    }
    self.adapters = adapters
    self.mcpServer = mcpServer
    self.listeningAddress = listeningAddress
    self.port = port
    self.authentication = authentication
    self.allowedBrowserOrigins = allowedBrowserOrigins
    self.limits = limits
    self.timeouts = timeouts
    self.allowsCleartextNetworkAccess = allowsCleartextNetworkAccess
    self.allowsUnauthenticatedNetworkAccess = allowsUnauthenticatedNetworkAccess
  }
}

public struct BondryLocalServerEndpoint: Equatable, Sendable {
  public let address: String
  public let port: UInt16

  public init(address: String, port: UInt16) {
    self.address = address
    self.port = port
  }
}

public enum BondryLocalServerConfigurationError: Error, Equatable, Sendable {
  case noAdapters
  case invalidListeningAddress
  case invalidBrowserOrigin
  case invalidPrincipalID
  case missingMCPServerInformation
  case unexpectedMCPServerInformation
  case invalidMCPServerName
  case invalidMCPServerTitle
  case invalidMCPServerVersion
  case invalidRateLimit
  case invalidBodyLimit
  case invalidConnectionLimit
  case invalidTimeout
  case cleartextNetworkExposureRequiresAcknowledgement
  case unauthenticatedNetworkExposureRequiresAcknowledgement
}

struct LocalServerInput: Encodable {
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

  init(_ configuration: BondryLocalServerConfiguration) {
    bindAddress = configuration.listeningAddress
    port = configuration.port
    authentication = AuthenticationInput(configuration.authentication)
    adapters = configuration.adapters.map(\.rawValue).sorted()
    mcpServer = configuration.mcpServer.map(MCPServerInput.init)
    allowedOrigins = configuration.allowedBrowserOrigins
    requestsPerMinute = configuration.limits.requestsPerMinute
    authenticationFailuresPerMinute = configuration.limits.authenticationFailuresPerMinute
    maxBodyBytes = configuration.limits.maxBodyBytes
    maxConnections = configuration.limits.maxConnections
    headerReadTimeoutMilliseconds = configuration.timeouts.headerReadMilliseconds
    requestTimeoutMilliseconds = configuration.timeouts.requestMilliseconds
    shutdownGracePeriodMilliseconds = configuration.timeouts.shutdownGracePeriodMilliseconds
    allowCleartextNetwork = configuration.allowsCleartextNetworkAccess
    allowUnauthenticatedNetwork = configuration.allowsUnauthenticatedNetworkAccess
  }
}

struct AuthenticationInput: Encodable {
  let mode: String
  let principalID: String?
  let principalKind: String?

  private enum CodingKeys: String, CodingKey {
    case mode
    case principalID = "principalId"
    case principalKind
  }

  init(_ authentication: BondryLocalServerAuthentication) {
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

public enum BondryLocalServerError: Error, Equatable, Sendable {
  case invalidConfiguration
  case addressInUse
  case startFailed
  case stopFailed
  case invalidHandle
  case invalidAddress
  case internalFailure(Int32)

  init(status: BondryStatus) {
    switch status {
    case BONDRY_STATUS_SERVER_BIND:
      self = .addressInUse
    case BONDRY_STATUS_SERVER_START:
      self = .startFailed
    case BONDRY_STATUS_SERVER_STOP:
      self = .stopFailed
    case BONDRY_STATUS_NULL_POINTER, BONDRY_STATUS_INVALID_LENGTH,
      BONDRY_STATUS_INVALID_ARGUMENT, BONDRY_STATUS_INVALID_JSON,
      BONDRY_STATUS_PAYLOAD_TOO_LARGE:
      self = .invalidConfiguration
    default:
      self = .internalFailure(status)
    }
  }
}

private func validatedMilliseconds(_ duration: Duration) throws -> UInt64 {
  let components = duration.components
  let attosecondsPerMillisecond: Int64 = 1_000_000_000_000_000
  guard components.seconds >= 0, components.attoseconds >= 0,
    components.attoseconds.isMultiple(of: attosecondsPerMillisecond)
  else {
    throw BondryLocalServerConfigurationError.invalidTimeout
  }
  let (seconds, secondsOverflow) = UInt64(components.seconds).multipliedReportingOverflow(by: 1_000)
  let subseconds = UInt64(components.attoseconds / attosecondsPerMillisecond)
  let (milliseconds, additionOverflow) = seconds.addingReportingOverflow(subseconds)
  guard !secondsOverflow, !additionOverflow, (1...300_000).contains(milliseconds) else {
    throw BondryLocalServerConfigurationError.invalidTimeout
  }
  return milliseconds
}

private func isValidMetadata(_ value: String, maximumUTF8Length: Int) -> Bool {
  !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    && value.utf8.count <= maximumUTF8Length
    && !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
}

private func isValidIdentifier(_ value: String) -> Bool {
  !value.isEmpty && value.utf8.count <= 128
    && value.utf8.allSatisfy {
      (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
        || [45, 46, 58, 95].contains($0)
    }
}

private func isValidIPAddress(_ value: String) -> Bool {
  var ipv4 = in_addr()
  if value.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
    return true
  }
  var ipv6 = in6_addr()
  return value.withCString { inet_pton(AF_INET6, $0, &ipv6) } == 1
}

private func isLoopbackIPAddress(_ value: String) -> Bool {
  var ipv4 = in_addr()
  if value.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
    return withUnsafeBytes(of: &ipv4) { $0.first == 127 }
  }
  var ipv6 = in6_addr()
  guard value.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 else {
    return false
  }
  return withUnsafeBytes(of: &ipv6) { bytes in
    bytes.dropLast().allSatisfy { $0 == 0 } && bytes.last == 1
  }
}

private func isValidBrowserOrigin(_ value: String) -> Bool {
  guard value.utf8.allSatisfy({ (0x21...0x7E).contains($0) }),
    !value.hasSuffix("/"),
    let components = URLComponents(string: value),
    let scheme = components.scheme,
    scheme == "http" || scheme == "https",
    components.host != nil,
    components.user == nil,
    components.password == nil,
    components.path.isEmpty,
    components.query == nil,
    components.fragment == nil
  else {
    return false
  }
  return true
}
