import Foundation

public enum BondryHTTPTransportError: Error, Equatable, Sendable {
  case unsupportedEndpoint
  case invalidLimits
  case requestTooLarge
  case responseTooLarge
  case missingConnectionEvidence
  case connectionEvidenceMismatch
  case tlsIdentityMismatch
  case privateCleartextDenied
  case linkLocalCleartextDenied
  case linkLocalScopeRequired
  case cleartextDenied
  case redirectDenied
  case deadlineExceeded
  case connectionFailed
  case tlsFailed
  case invalidResponse
}

public enum BondryIPAddress: Equatable, Sendable {
  case v4(Data)
  case v6(Data)

  public init(bytes: Data) throws {
    switch bytes.count {
    case 4:
      self = .v4(bytes)
    case 16:
      self = .v6(bytes)
    default:
      throw BondryHTTPTransportError.missingConnectionEvidence
    }
  }

  var normalized: BondryIPAddress {
    guard case .v6(let bytes) = self,
      bytes.prefix(10).allSatisfy({ $0 == 0 }),
      bytes[bytes.startIndex + 10] == 0xff,
      bytes[bytes.startIndex + 11] == 0xff
    else {
      return self
    }
    return .v4(Data(bytes.suffix(4)))
  }
}

public enum BondryConnectionEvidence: Equatable, Sendable {
  case missing
  case tls(serverName: String)
  case cleartext(address: BondryIPAddress, port: UInt16, interfaceScope: UInt32?)
}

public struct BondryEndpointPolicy: Equatable, Sendable, CustomDebugStringConvertible {
  public let allowPrivateCleartext: Bool
  public let allowLinkLocalCleartext: Bool
  public let additionalTrustAnchors: [Data]

  public init(
    allowPrivateCleartext: Bool = false,
    allowLinkLocalCleartext: Bool = false,
    additionalTrustAnchors: [Data] = []
  ) {
    self.allowPrivateCleartext = allowPrivateCleartext
    self.allowLinkLocalCleartext = allowLinkLocalCleartext
    self.additionalTrustAnchors = additionalTrustAnchors
  }

  public var debugDescription: String {
    "BondryEndpointPolicy(allowPrivateCleartext: \(allowPrivateCleartext), "
      + "allowLinkLocalCleartext: \(allowLinkLocalCleartext), "
      + "additionalTrustAnchors: \(additionalTrustAnchors.count))"
  }

  public func verify(
    url: URL,
    evidence: BondryConnectionEvidence
  ) throws {
    guard let scheme = url.scheme?.lowercased(), let host = url.host else {
      throw BondryHTTPTransportError.unsupportedEndpoint
    }
    if scheme == "https" {
      guard case .tls(let serverName) = evidence else {
        if evidence == .missing {
          throw BondryHTTPTransportError.missingConnectionEvidence
        }
        throw BondryHTTPTransportError.connectionEvidenceMismatch
      }
      guard Self.serverNamesMatch(host, serverName) else {
        throw BondryHTTPTransportError.tlsIdentityMismatch
      }
      return
    }
    guard scheme == "http" else {
      throw BondryHTTPTransportError.unsupportedEndpoint
    }
    guard case .cleartext(let address, let port, let interfaceScope) = evidence else {
      if evidence == .missing {
        throw BondryHTTPTransportError.missingConnectionEvidence
      }
      throw BondryHTTPTransportError.connectionEvidenceMismatch
    }
    guard let expectedPort = UInt16(exactly: url.port ?? 80), expectedPort != 0,
      port == expectedPort
    else {
      throw BondryHTTPTransportError.connectionEvidenceMismatch
    }
    switch address.addressClass {
    case .loopback:
      return
    case .privateNetwork where allowPrivateCleartext:
      return
    case .privateNetwork:
      throw BondryHTTPTransportError.privateCleartextDenied
    case .linkLocal where !allowLinkLocalCleartext:
      throw BondryHTTPTransportError.linkLocalCleartextDenied
    case .linkLocal where interfaceScope == nil:
      throw BondryHTTPTransportError.linkLocalScopeRequired
    case .linkLocal:
      return
    case .denied:
      throw BondryHTTPTransportError.cleartextDenied
    }
  }

  private static func serverNamesMatch(_ endpoint: String, _ verified: String) -> Bool {
    endpoint.trimmingCharacters(in: CharacterSet(charactersIn: "."))
      .caseInsensitiveCompare(
        verified.trimmingCharacters(in: CharacterSet(charactersIn: "."))
      ) == .orderedSame
  }
}

public struct BondryHTTPRequest: Sendable, CustomDebugStringConvertible {
  public static let maximumBodyBytes = 256 * 1_024
  public static let maximumEndpointBytes = 4 * 1_024
  public static let maximumHeaderBytes = 16 * 1_024
  public static let maximumHeaders = 64
  public static let minimumResponseBodyBytes = 4 * 1_024
  public static let maximumResponseBodyBytes = 1_024 * 1_024

  public let method: String
  public let url: URL
  public let headers: [(String, String)]
  public let body: Data
  public let timeout: Duration
  public let policy: BondryEndpointPolicy
  public let maximumResponseBodyBytes: Int

  public init(
    method: String,
    url: URL,
    headers: [(String, String)] = [],
    body: Data = Data(),
    timeout: Duration = .seconds(30),
    policy: BondryEndpointPolicy = BondryEndpointPolicy(),
    maximumResponseBodyBytes: Int = 64 * 1_024
  ) throws {
    guard ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"].contains(method),
      let scheme = url.scheme?.lowercased(),
      scheme == "http" || scheme == "https",
      let port = UInt16(exactly: url.port ?? (scheme == "http" ? 80 : 443)),
      port != 0,
      url.host != nil,
      url.user == nil,
      url.password == nil,
      url.fragment == nil,
      url.absoluteString.utf8.count <= Self.maximumEndpointBytes
    else {
      throw BondryHTTPTransportError.unsupportedEndpoint
    }
    guard body.count <= Self.maximumBodyBytes,
      headers.count <= Self.maximumHeaders,
      headers.reduce(0, { $0 + $1.0.utf8.count + $1.1.utf8.count + 4 })
        <= Self.maximumHeaderBytes
    else {
      throw BondryHTTPTransportError.requestTooLarge
    }
    guard timeout >= .seconds(1), timeout <= .seconds(120),
      maximumResponseBodyBytes >= Self.minimumResponseBodyBytes,
      maximumResponseBodyBytes <= Self.maximumResponseBodyBytes,
      headers.allSatisfy({ Self.validHeader(name: $0.0, value: $0.1) })
    else {
      throw BondryHTTPTransportError.invalidLimits
    }
    self.method = method
    self.url = url
    self.headers = headers
    self.body = body
    self.timeout = timeout
    self.policy = policy
    self.maximumResponseBodyBytes = maximumResponseBodyBytes
  }

  public var debugDescription: String {
    let port = url.port.map { ":\($0)" } ?? ""
    let origin = "\(url.scheme ?? "unknown")://\(url.host ?? "unknown")\(port)"
    return "BondryHTTPRequest(method: \(method), origin: \(origin), "
      + "pathAndQuery: [REDACTED], headers: [REDACTED], bodyBytes: \(body.count))"
  }

  var timeoutSeconds: TimeInterval {
    let components = timeout.components
    return TimeInterval(components.seconds)
      + TimeInterval(components.attoseconds) / 1_000_000_000_000_000_000
  }

  private static func validHeader(name: String, value: String) -> Bool {
    return !name.isEmpty
      && name.utf8.allSatisfy { byte in
        byte.isASCIIAlphaNumeric || "!#$%&'*+-.^_`|~".utf8.contains(byte)
      }
      && !value.contains("\r")
      && !value.contains("\n")
      && value.utf8.allSatisfy { $0 == 0x09 || (0x20...0x7e).contains($0) }
  }
}

public struct BondryHTTPResponse: Sendable, CustomDebugStringConvertible {
  public let statusCode: Int
  public let headers: [(String, String)]
  public let body: Data
  public let connection: BondryConnectionEvidence

  public var debugDescription: String {
    "BondryHTTPResponse(statusCode: \(statusCode), headers: [REDACTED], "
      + "bodyBytes: \(body.count), connection: \(connection))"
  }
}

public struct BondryAppleHTTPTransport: Sendable {
  private let encrypted = URLSessionHTTPTransport()
  private let cleartext = NetworkHTTPTransport()

  public init() {}

  public func send(_ request: BondryHTTPRequest) async throws -> BondryHTTPResponse {
    switch request.url.scheme?.lowercased() {
    case "https":
      return try await encrypted.send(request)
    case "http":
      return try await cleartext.send(request)
    default:
      throw BondryHTTPTransportError.unsupportedEndpoint
    }
  }
}

private enum BondryIPAddressClass {
  case loopback
  case privateNetwork
  case linkLocal
  case denied
}

extension BondryIPAddress {
  fileprivate var addressClass: BondryIPAddressClass {
    switch normalized {
    case .v4(let data):
      let bytes = [UInt8](data)
      if bytes[0] == 127 { return .loopback }
      if bytes[0] == 10
        || (bytes[0] == 172 && (16...31).contains(bytes[1]))
        || (bytes[0] == 192 && bytes[1] == 168)
      {
        return .privateNetwork
      }
      if bytes[0] == 169 && bytes[1] == 254 { return .linkLocal }
      return .denied
    case .v6(let data):
      let bytes = [UInt8](data)
      if bytes.dropLast().allSatisfy({ $0 == 0 }) && bytes[15] == 1 { return .loopback }
      if bytes[0] & 0xfe == 0xfc { return .privateNetwork }
      if bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80 { return .linkLocal }
      return .denied
    }
  }
}

extension UInt8 {
  fileprivate var isASCIIAlphaNumeric: Bool {
    (0x30...0x39).contains(self)
      || (0x41...0x5a).contains(self)
      || (0x61...0x7a).contains(self)
  }
}
