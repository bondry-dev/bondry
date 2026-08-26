import CBondryRESTServer
import Foundation

public struct BondryRESTTLSServerConfiguration: Equatable, Sendable {
  public let listeningAddress: String
  public let port: UInt16
  public let authentication: BondryRESTServerAuthentication
  public let allowedBrowserOrigins: [String]
  public let limits: BondryRESTServerLimits
  public let timeouts: BondryRESTServerTimeouts
  public let handshakeTimeout: Duration
  public let allowsUnauthenticatedNetworkAccess: Bool

  let handshakeTimeoutMilliseconds: UInt64

  public init(
    listeningAddress: String = "127.0.0.1",
    port: UInt16 = 0,
    authentication: BondryRESTServerAuthentication = .bearerToken,
    allowedBrowserOrigins: [String] = [],
    limits: BondryRESTServerLimits = .standard,
    timeouts: BondryRESTServerTimeouts = .standard,
    handshakeTimeout: Duration = .seconds(5),
    allowsUnauthenticatedNetworkAccess: Bool = false
  ) throws {
    guard isValidIPAddress(listeningAddress) else {
      throw BondryRESTServerConfigurationError.invalidListeningAddress
    }
    if case .disabled(let principalID, _) = authentication {
      guard isValidIdentifier(principalID) else {
        throw BondryRESTServerConfigurationError.invalidPrincipalID
      }
      guard isLoopbackIPAddress(listeningAddress) || allowsUnauthenticatedNetworkAccess else {
        throw BondryRESTServerConfigurationError
          .unauthenticatedNetworkExposureRequiresAcknowledgement
      }
    }
    guard allowedBrowserOrigins.allSatisfy(isValidBrowserOrigin) else {
      throw BondryRESTServerConfigurationError.invalidBrowserOrigin
    }
    let handshakeTimeoutMilliseconds = try validatedMilliseconds(handshakeTimeout)
    guard handshakeTimeoutMilliseconds <= 60_000 else {
      throw BondryRESTServerConfigurationError.invalidTimeout
    }
    self.listeningAddress = listeningAddress
    self.port = port
    self.authentication = authentication
    self.allowedBrowserOrigins = allowedBrowserOrigins
    self.limits = limits
    self.timeouts = timeouts
    self.handshakeTimeout = handshakeTimeout
    self.allowsUnauthenticatedNetworkAccess = allowsUnauthenticatedNetworkAccess
    self.handshakeTimeoutMilliseconds = handshakeTimeoutMilliseconds
  }
}

struct RESTTLSServerInput: Encodable {
  let version = BONDRY_REST_TLS_SERVER_CONFIGURATION_VERSION_V1
  let bindAddress: String
  let port: UInt16
  let authentication: RESTAuthenticationInput
  let allowedOrigins: [String]
  let requestsPerMinute: UInt32
  let authenticationFailuresPerMinute: UInt32
  let maxBodyBytes: Int
  let maxConnections: Int
  let headerReadTimeoutMilliseconds: UInt64
  let requestTimeoutMilliseconds: UInt64
  let shutdownGracePeriodMilliseconds: UInt64
  let tlsHandshakeTimeoutMilliseconds: UInt64
  let allowUnauthenticatedNetwork: Bool

  init(_ configuration: BondryRESTTLSServerConfiguration) {
    bindAddress = configuration.listeningAddress
    port = configuration.port
    authentication = RESTAuthenticationInput(configuration.authentication)
    allowedOrigins = configuration.allowedBrowserOrigins
    requestsPerMinute = configuration.limits.requestsPerMinute
    authenticationFailuresPerMinute = configuration.limits.authenticationFailuresPerMinute
    maxBodyBytes = configuration.limits.maxBodyBytes
    maxConnections = configuration.limits.maxConnections
    headerReadTimeoutMilliseconds = configuration.timeouts.headerReadMilliseconds
    requestTimeoutMilliseconds = configuration.timeouts.requestMilliseconds
    shutdownGracePeriodMilliseconds = configuration.timeouts.shutdownGracePeriodMilliseconds
    tlsHandshakeTimeoutMilliseconds = configuration.handshakeTimeoutMilliseconds
    allowUnauthenticatedNetwork = configuration.allowsUnauthenticatedNetworkAccess
  }
}
