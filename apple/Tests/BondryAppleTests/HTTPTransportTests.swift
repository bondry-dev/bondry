import Foundation
import Network
import Security
import XCTest

@testable import BondryApple

final class HTTPTransportTests: XCTestCase {
  func testPolicyMatchesSharedFixtures() throws {
    let bundle = try JSONDecoder().decode(
      TransportPolicyFixtureBundle.self,
      from: Data(contentsOf: fixtureURL("policy.json"))
    )
    XCTAssertEqual(
      bundle.hostTransportContract.policyEnforcement,
      "established_peer_before_application_bytes"
    )
    XCTAssertEqual(bundle.hostTransportContract.missingEvidence, "reject")
    XCTAssertEqual(bundle.hostTransportContract.verifiedConnectionMetadata, "required")
    XCTAssertEqual(bundle.hostTransportContract.redirects, "deny")

    for vector in bundle.vectors {
      let policy = BondryEndpointPolicy(
        allowPrivateCleartext: vector.allowPrivateCleartext ?? false,
        allowLinkLocalCleartext: vector.allowLinkLocalCleartext ?? false
      )
      let result: String
      do {
        try policy.verify(
          url: try XCTUnwrap(URL(string: vector.endpoint)),
          evidence: try vector.evidence
        )
        result = "allowed"
      } catch let error as BondryHTTPTransportError {
        result = error.fixtureName
      }
      XCTAssertEqual(result, vector.expected, vector.id)
    }
  }

  func testRequestRejectsUnboundedOrMalformedMetadata() throws {
    let oversized = try XCTUnwrap(
      URL(string: "http://localhost/\(String(repeating: "a", count: 4 * 1_024))")
    )
    XCTAssertThrowsError(try BondryHTTPRequest(method: "GET", url: oversized)) { error in
      XCTAssertEqual(error as? BondryHTTPTransportError, .unsupportedEndpoint)
    }
    XCTAssertThrowsError(
      try BondryHTTPRequest(
        method: "GET",
        url: try XCTUnwrap(URL(string: "http://localhost/#fragment"))
      )
    ) { error in
      XCTAssertEqual(error as? BondryHTTPTransportError, .unsupportedEndpoint)
    }
    XCTAssertThrowsError(
      try BondryHTTPRequest(
        method: "GET",
        url: try XCTUnwrap(URL(string: "http://localhost/")),
        headers: [("X-Test", "invalid\0value")]
      )
    ) { error in
      XCTAssertEqual(error as? BondryHTTPTransportError, .invalidLimits)
    }
    for endpoint in ["http://localhost:0/", "http://localhost:99999/"] {
      XCTAssertThrowsError(
        try BondryHTTPRequest(method: "GET", url: try XCTUnwrap(URL(string: endpoint)))
      ) { error in
        XCTAssertEqual(error as? BondryHTTPTransportError, .unsupportedEndpoint)
      }
    }
  }

  func testEncryptedTransportDelegateDisablesRedirects() throws {
    let source = try XCTUnwrap(URL(string: "https://example.com/source"))
    let destination = try XCTUnwrap(URL(string: "https://example.com/destination"))
    let response = try XCTUnwrap(
      HTTPURLResponse(
        url: source,
        statusCode: 302,
        httpVersion: "HTTP/1.1",
        headerFields: ["Location": destination.absoluteString]
      )
    )
    let session = URLSession(configuration: .ephemeral)
    defer { session.invalidateAndCancel() }
    let task = session.dataTask(with: source)
    let delegate = URLSessionPolicyDelegate(additionalTrustAnchors: [])
    let capture = RedirectCapture()

    delegate.urlSession(
      session,
      task: task,
      willPerformHTTPRedirection: response,
      newRequest: URLRequest(url: destination)
    ) { request in
      capture.store(request)
    }

    XCTAssertNil(capture.request)
    XCTAssertTrue(delegate.didRedirect)
  }

  func testAbsoluteDeadlineDoesNotResetWhenWorkMakesProgress() async throws {
    let clock = ContinuousClock()
    let start = clock.now

    do {
      _ = try await withAbsoluteDeadline(.milliseconds(25)) {
        for _ in 0..<100 {
          try await Task.sleep(for: .milliseconds(5))
        }
        return true
      }
      XCTFail("expected the absolute deadline to expire")
    } catch let error as BondryHTTPTransportError {
      XCTAssertEqual(error, .deadlineExceeded)
    }

    XCTAssertLessThan(start.duration(to: clock.now), .milliseconds(200))
  }

  func testEncryptedConnectionPoolsArePartitionedByTrustPolicy() {
    let pool = URLSessionPool(configuration: .ephemeral)
    let defaultSession = pool.session(for: [])

    XCTAssertTrue(defaultSession === pool.session(for: []))
    XCTAssertFalse(defaultSession === pool.session(for: [Data([1, 2, 3])]))
  }

  func testAdditionalTrustAnchorPreservesHostnameVerification() throws {
    let fixture = try JSONDecoder().decode(
      TLSFixture.self,
      from: Data(contentsOf: fixtureURL("localhost-tls.json"))
    )
    let root = try XCTUnwrap(
      SecCertificateCreateWithData(
        nil,
        try XCTUnwrap(Data(base64Encoded: fixture.trustAnchorDERBase64)) as CFData
      )
    )
    let leaf = try XCTUnwrap(
      SecCertificateCreateWithData(
        nil,
        try XCTUnwrap(Data(base64Encoded: fixture.serverCertificateDERBase64)) as CFData
      )
    )
    let anchors = [SecCertificateCopyData(root) as Data]

    XCTAssertTrue(
      URLSessionPolicyDelegate.evaluate(
        trust: try trust(for: leaf, hostname: "localhost"),
        additionalTrustAnchors: anchors
      )
    )
    XCTAssertFalse(
      URLSessionPolicyDelegate.evaluate(
        trust: try trust(for: leaf, hostname: "other.example"),
        additionalTrustAnchors: anchors
      )
    )
  }

  func testParserRejectsSharedMalformedResponses() throws {
    let bundle = try JSONDecoder().decode(
      MalformedHTTPFixtureBundle.self,
      from: Data(contentsOf: fixtureURL("malformed-http1.json"))
    )

    for vector in bundle.vectors {
      var parser = BoundedHTTP1ResponseParser(requestMethod: "POST", maximumBodyBytes: 64 * 1_024)
      XCTAssertThrowsError(
        try parser.consume(
          try XCTUnwrap(Data(base64Encoded: vector.responseBase64)), isComplete: true),
        vector.id
      ) { error in
        XCTAssertEqual(error as? BondryHTTPTransportError, .invalidResponse, vector.id)
      }
    }
  }

  func testParserAcceptsFragmentedContentLengthAndChunkedResponses() throws {
    let contentLength = Data("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".utf8)
    let chunked = Data(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n".utf8
    )

    for response in [contentLength, chunked] {
      var parser = BoundedHTTP1ResponseParser(requestMethod: "GET", maximumBodyBytes: 4 * 1_024)
      var parsed: ParsedHTTPResponse?
      for (index, byte) in response.enumerated() {
        parsed = try parser.consume(Data([byte]), isComplete: index == response.count - 1)
      }
      XCTAssertEqual(parsed?.statusCode, 200)
      XCTAssertEqual(parsed?.body, Data("ok".utf8))
    }
  }

  func testParserContinuesPastInformationalResponses() throws {
    let responseText =
      "HTTP/1.1 100 Continue\r\nX-Interim: true\r\n\r\n"
      + "HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n"
      + "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    let response = Data(responseText.utf8)
    var parser = BoundedHTTP1ResponseParser(requestMethod: "POST", maximumBodyBytes: 4 * 1_024)

    let parsed = try parser.consume(response, isComplete: true)

    XCTAssertEqual(parsed?.statusCode, 200)
    XCTAssertEqual(parsed?.body, Data("ok".utf8))
  }

  func testParserRejectsProtocolUpgradeWithoutReturningAnHTTPResponse() throws {
    let response = Data("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n".utf8)
    var parser = BoundedHTTP1ResponseParser(requestMethod: "GET", maximumBodyBytes: 4 * 1_024)

    XCTAssertThrowsError(try parser.consume(response, isComplete: true)) { error in
      XCTAssertEqual(error as? BondryHTTPTransportError, .invalidResponse)
    }
  }

  #if os(macOS)
    func testCleartextTransportUsesConnectedLoopbackPeer() async throws {
      let server = try LoopbackHTTPServer()
      defer { server.stop() }
      try await server.waitUntilReady()
      let port = try XCTUnwrap(server.port)
      let request = try BondryHTTPRequest(
        method: "POST",
        url: try XCTUnwrap(URL(string: "http://localhost:\(port)/deliver?source=test")),
        headers: [("Content-Type", "application/json")],
        body: Data("{}".utf8)
      )

      let response = try await BondryAppleHTTPTransport().send(request)

      XCTAssertEqual(response.statusCode, 200)
      XCTAssertEqual(response.body, Data("ok".utf8))
      guard case .cleartext(_, let connectedPort, _) = response.connection else {
        return XCTFail("expected cleartext connection evidence")
      }
      XCTAssertEqual(connectedPort, port)
      XCTAssertNotNil(
        server.request.range(of: Data("POST /deliver?source=test HTTP/1.1".utf8))
      )
    }
  #endif

  private func fixtureURL(_ name: String) -> URL {
    URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("fixtures/transport-v1/\(name)")
  }

  private func trust(for certificate: SecCertificate, hostname: String) throws -> SecTrust {
    var trust: SecTrust?
    let status = SecTrustCreateWithCertificates(
      certificate,
      SecPolicyCreateSSL(true, hostname as CFString),
      &trust
    )
    guard status == errSecSuccess, let trust else {
      throw BondryHTTPTransportError.tlsFailed
    }
    return trust
  }
}

private final class RedirectCapture: @unchecked Sendable {
  private let lock = NSLock()
  private var storedRequest: URLRequest?

  var request: URLRequest? {
    lock.withLock { storedRequest }
  }

  func store(_ request: URLRequest?) {
    lock.withLock { storedRequest = request }
  }
}

private struct TransportPolicyFixtureBundle: Decodable {
  let hostTransportContract: HostTransportContractFixture
  let vectors: [TransportPolicyFixture]

  enum CodingKeys: String, CodingKey {
    case hostTransportContract = "host_transport_contract"
    case vectors
  }
}

private struct HostTransportContractFixture: Decodable {
  let policyEnforcement: String
  let missingEvidence: String
  let verifiedConnectionMetadata: String
  let redirects: String

  enum CodingKeys: String, CodingKey {
    case policyEnforcement = "policy_enforcement"
    case missingEvidence = "missing_evidence"
    case verifiedConnectionMetadata = "verified_connection_metadata"
    case redirects
  }
}

private struct TransportPolicyFixture: Decodable {
  let id: String
  let endpoint: String
  let allowPrivateCleartext: Bool?
  let allowLinkLocalCleartext: Bool?
  let evidenceValue: TransportEvidenceFixture
  let expected: String

  var evidence: BondryConnectionEvidence {
    get throws {
      switch evidenceValue.type {
      case "missing":
        return .missing
      case "tls":
        return .tls(serverName: evidenceValue.serverName ?? "")
      case "cleartext":
        return .cleartext(
          address: try BondryIPAddress(bytes: Data(evidenceValue.ip ?? [])),
          port: evidenceValue.port ?? 0,
          interfaceScope: evidenceValue.interfaceScope
        )
      default:
        throw BondryHTTPTransportError.missingConnectionEvidence
      }
    }
  }

  enum CodingKeys: String, CodingKey {
    case id
    case endpoint
    case allowPrivateCleartext = "allow_private_cleartext"
    case allowLinkLocalCleartext = "allow_link_local_cleartext"
    case evidenceValue = "evidence"
    case expected
  }
}

private struct TransportEvidenceFixture: Decodable {
  let type: String
  let ip: [UInt8]?
  let port: UInt16?
  let interfaceScope: UInt32?
  let serverName: String?

  enum CodingKeys: String, CodingKey {
    case type
    case ip
    case port
    case interfaceScope = "interface_scope"
    case serverName = "server_name"
  }
}

private struct MalformedHTTPFixtureBundle: Decodable {
  let vectors: [MalformedHTTPFixture]
}

private struct MalformedHTTPFixture: Decodable {
  let id: String
  let responseBase64: String

  enum CodingKeys: String, CodingKey {
    case id
    case responseBase64 = "response_base64"
  }
}

private struct TLSFixture: Decodable {
  let trustAnchorDERBase64: String
  let serverCertificateDERBase64: String

  enum CodingKeys: String, CodingKey {
    case trustAnchorDERBase64 = "trust_anchor_der_base64"
    case serverCertificateDERBase64 = "server_certificate_der_base64"
  }
}

extension BondryHTTPTransportError {
  fileprivate var fixtureName: String {
    switch self {
    case .privateCleartextDenied:
      return "privateCleartextDenied"
    case .connectionEvidenceMismatch:
      return "evidenceMismatch"
    case .linkLocalCleartextDenied:
      return "linkLocalCleartextDenied"
    case .linkLocalScopeRequired:
      return "linkLocalScopeRequired"
    case .cleartextDenied:
      return "cleartextDenied"
    case .tlsIdentityMismatch:
      return "tlsIdentityMismatch"
    case .missingConnectionEvidence:
      return "missingEvidence"
    default:
      return "unexpected"
    }
  }
}

#if os(macOS)
  private final class LoopbackHTTPServer: @unchecked Sendable {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "dev.bondry.http-transport-test")
    private let lock = NSLock()
    private var received = Data()
    private var connections: [NWConnection] = []

    init() throws {
      listener = try NWListener(using: .tcp, on: .any)
      listener.newConnectionHandler = { connection in
        self.accept(connection)
      }
      listener.start(queue: queue)
    }

    var port: UInt16? {
      listener.port?.rawValue
    }

    var request: Data {
      lock.withLock { received }
    }

    func waitUntilReady() async throws {
      try await withCheckedThrowingContinuation { continuation in
        queue.async {
          if case .ready = self.listener.state {
            continuation.resume()
            return
          }
          self.listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
              self.listener.stateUpdateHandler = nil
              continuation.resume()
            case .failed:
              self.listener.stateUpdateHandler = nil
              continuation.resume(throwing: BondryHTTPTransportError.connectionFailed)
            default:
              break
            }
          }
        }
      }
    }

    func stop() {
      listener.cancel()
      lock.withLock {
        for connection in connections {
          connection.cancel()
        }
        connections.removeAll()
      }
    }

    private func accept(_ connection: NWConnection) {
      lock.withLock { connections.append(connection) }
      connection.start(queue: queue)
      receive(from: connection)
    }

    private func receive(from connection: NWConnection) {
      connection.receive(minimumIncompleteLength: 1, maximumLength: 512 * 1_024) {
        content,
        _,
        _,
        error in
        guard error == nil else { return }
        if let content {
          self.lock.withLock { self.received.append(content) }
        }
        guard self.request.range(of: Data("\r\n\r\n".utf8)) != nil else {
          self.receive(from: connection)
          return
        }
        let response = Data(
          "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".utf8
        )
        connection.send(content: response, completion: .contentProcessed { _ in })
      }
    }
  }
#endif
