import Bondry
import CBondryRESTServer
import Foundation

public struct BondryRESTUnixServerConfiguration: Equatable, Sendable {
  public let socketURL: URL
  public let ownerUserID: UInt32
  public let peerUserID: UInt32
  public let principalID: String
  public let principalKind: BondryPrincipalKind
  public let limits: BondryRESTServerLimits
  public let timeouts: BondryRESTServerTimeouts

  public init(
    socketURL: URL,
    ownerUserID: UInt32,
    peerUserID: UInt32,
    principalID: String,
    principalKind: BondryPrincipalKind = .application,
    limits: BondryRESTServerLimits = .standard,
    timeouts: BondryRESTServerTimeouts = .standard
  ) throws {
    let path = socketURL.path
    guard socketURL.isFileURL, path.hasPrefix("/"), socketURL.lastPathComponent != ".",
      socketURL.lastPathComponent != "..", !socketURL.lastPathComponent.isEmpty,
      !path.utf8.contains(0), path.utf8.count < BONDRY_REST_UNIX_SERVER_PATH_CAPACITY_V1
    else {
      throw BondryRESTUnixServerConfigurationError.invalidSocketURL
    }
    guard isValidRESTUnixServerIdentifier(principalID) else {
      throw BondryRESTUnixServerConfigurationError.invalidPrincipalID
    }
    self.socketURL = socketURL
    self.ownerUserID = ownerUserID
    self.peerUserID = peerUserID
    self.principalID = principalID
    self.principalKind = principalKind
    self.limits = limits
    self.timeouts = timeouts
  }
}

public struct BondryRESTUnixServerEndpoint: Equatable, Sendable {
  public let socketURL: URL

  public init(socketURL: URL) {
    self.socketURL = socketURL
  }
}

public enum BondryRESTUnixServerConfigurationError: Error, Equatable, Sendable {
  case invalidSocketURL
  case invalidPrincipalID
}

public enum BondryRESTUnixServerError: Error, Equatable, Sendable {
  case invalidConfiguration
  case bindFailed
  case startFailed
  case stopFailed
  case invalidHandle
  case invalidEndpoint
  case internalFailure(Int32)

  init(status: BondryStatus) {
    switch status {
    case BONDRY_STATUS_SERVER_BIND:
      self = .bindFailed
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

struct RESTUnixServerInput: Encodable {
  let version = BONDRY_REST_UNIX_SERVER_CONFIGURATION_VERSION_V1
  let socketPath: String
  let ownerUserID: UInt32
  let peerUserID: UInt32
  let principalID: String
  let principalKind: String
  let requestsPerMinute: UInt32
  let maxBodyBytes: Int
  let maxConnections: Int
  let headerReadTimeoutMilliseconds: UInt64
  let requestTimeoutMilliseconds: UInt64
  let shutdownGracePeriodMilliseconds: UInt64

  private enum CodingKeys: String, CodingKey {
    case version
    case socketPath
    case ownerUserID = "ownerUserId"
    case peerUserID = "peerUserId"
    case principalID = "principalId"
    case principalKind
    case requestsPerMinute
    case maxBodyBytes
    case maxConnections
    case headerReadTimeoutMilliseconds
    case requestTimeoutMilliseconds
    case shutdownGracePeriodMilliseconds
  }

  init(_ configuration: BondryRESTUnixServerConfiguration) {
    socketPath = configuration.socketURL.path
    ownerUserID = configuration.ownerUserID
    peerUserID = configuration.peerUserID
    principalID = configuration.principalID
    principalKind = configuration.principalKind.restServerValue
    requestsPerMinute = configuration.limits.requestsPerMinute
    maxBodyBytes = configuration.limits.maxBodyBytes
    maxConnections = configuration.limits.maxConnections
    headerReadTimeoutMilliseconds = configuration.timeouts.headerReadMilliseconds
    requestTimeoutMilliseconds = configuration.timeouts.requestMilliseconds
    shutdownGracePeriodMilliseconds = configuration.timeouts.shutdownGracePeriodMilliseconds
  }
}

private func isValidRESTUnixServerIdentifier(_ value: String) -> Bool {
  !value.isEmpty && value.utf8.count <= 128
    && value.utf8.allSatisfy {
      (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
        || [45, 46, 58, 95].contains($0)
    }
}
