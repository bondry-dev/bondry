import Foundation
import Security

struct URLSessionHTTPTransport: Sendable {
  private let sessions: URLSessionPool

  init(configuration: URLSessionConfiguration = .ephemeral) {
    sessions = URLSessionPool(configuration: configuration)
  }

  func send(_ request: BondryHTTPRequest) async throws -> BondryHTTPResponse {
    try await withAbsoluteDeadline(request.timeout) {
      try await sendBeforeDeadline(request)
    }
  }

  private func sendBeforeDeadline(_ request: BondryHTTPRequest) async throws
    -> BondryHTTPResponse
  {
    var urlRequest = URLRequest(url: request.url)
    urlRequest.httpMethod = request.method
    urlRequest.httpBody = request.body
    urlRequest.timeoutInterval = request.timeoutSeconds
    for (name, value) in request.headers where !Self.reservedHeader(name) {
      urlRequest.addValue(value, forHTTPHeaderField: name)
    }

    let delegate = URLSessionPolicyDelegate(
      additionalTrustAnchors: request.policy.additionalTrustAnchors
    )
    let session = sessions.session(for: request.policy.additionalTrustAnchors)
    do {
      let (bytes, response) = try await session.bytes(for: urlRequest, delegate: delegate)
      guard let response = response as? HTTPURLResponse else {
        throw BondryHTTPTransportError.invalidResponse
      }
      if delegate.didRedirect || (300...399).contains(response.statusCode) {
        throw BondryHTTPTransportError.redirectDenied
      }
      if response.expectedContentLength > Int64(request.maximumResponseBodyBytes) {
        throw BondryHTTPTransportError.responseTooLarge
      }
      let headers = try Self.headers(from: response)
      var body = Data()
      let expectedLength = max(0, Int(clamping: response.expectedContentLength))
      body.reserveCapacity(min(request.maximumResponseBodyBytes, expectedLength))
      for try await byte in bytes {
        guard body.count < request.maximumResponseBodyBytes else {
          throw BondryHTTPTransportError.responseTooLarge
        }
        body.append(byte)
      }
      let host = request.url.host ?? ""
      let evidence = BondryConnectionEvidence.tls(serverName: host)
      try request.policy.verify(url: request.url, evidence: evidence)
      return BondryHTTPResponse(
        statusCode: response.statusCode,
        headers: headers,
        body: body,
        connection: evidence
      )
    } catch let error as BondryHTTPTransportError {
      throw error
    } catch let error as URLError where error.code == .timedOut {
      throw BondryHTTPTransportError.deadlineExceeded
    } catch let error as URLError where error.code == .cancelled {
      throw CancellationError()
    } catch let error as URLError where Self.isTLSError(error.code) {
      throw BondryHTTPTransportError.tlsFailed
    } catch {
      throw BondryHTTPTransportError.connectionFailed
    }
  }

  private static func headers(from response: HTTPURLResponse) throws -> [(String, String)] {
    guard response.allHeaderFields.count <= BondryHTTPRequest.maximumHeaders else {
      throw BondryHTTPTransportError.responseTooLarge
    }
    var result: [(String, String)] = []
    var bytes = 0
    for (rawName, rawValue) in response.allHeaderFields {
      guard let name = rawName as? String else {
        throw BondryHTTPTransportError.invalidResponse
      }
      let value = String(describing: rawValue)
      bytes += name.utf8.count + value.utf8.count + 4
      guard bytes <= BondryHTTPRequest.maximumHeaderBytes else {
        throw BondryHTTPTransportError.responseTooLarge
      }
      result.append((name, value))
    }
    return result
  }

  private static func reservedHeader(_ name: String) -> Bool {
    ["connection", "content-length", "host", "transfer-encoding"].contains(name.lowercased())
  }

  private static func isTLSError(_ code: URLError.Code) -> Bool {
    [
      .clientCertificateRejected,
      .clientCertificateRequired,
      .secureConnectionFailed,
      .serverCertificateHasBadDate,
      .serverCertificateHasUnknownRoot,
      .serverCertificateNotYetValid,
      .serverCertificateUntrusted,
    ].contains(code)
  }
}

func withAbsoluteDeadline<Result: Sendable>(
  _ timeout: Duration,
  operation: @escaping @Sendable () async throws -> Result
) async throws -> Result {
  try await withThrowingTaskGroup(of: Result.self) { group in
    group.addTask(operation: operation)
    group.addTask {
      try await ContinuousClock().sleep(for: timeout)
      throw BondryHTTPTransportError.deadlineExceeded
    }
    defer { group.cancelAll() }
    guard let result = try await group.next() else {
      throw BondryHTTPTransportError.connectionFailed
    }
    return result
  }
}

final class URLSessionPool: @unchecked Sendable {
  private let configuration: URLSessionConfiguration
  private let lock = NSLock()
  private var sessions: [[Data]: URLSession] = [:]

  init(configuration: URLSessionConfiguration) {
    self.configuration = configuration
  }

  deinit {
    for session in sessions.values {
      session.invalidateAndCancel()
    }
  }

  func session(for additionalTrustAnchors: [Data]) -> URLSession {
    lock.withLock {
      if let session = sessions[additionalTrustAnchors] {
        return session
      }
      let session = URLSession(configuration: configuration)
      sessions[additionalTrustAnchors] = session
      return session
    }
  }
}

final class URLSessionPolicyDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
  private let additionalTrustAnchors: [Data]
  private let lock = NSLock()
  private var redirected = false

  init(additionalTrustAnchors: [Data]) {
    self.additionalTrustAnchors = additionalTrustAnchors
  }

  var didRedirect: Bool {
    lock.withLock { redirected }
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest,
    completionHandler: @escaping @Sendable (URLRequest?) -> Void
  ) {
    lock.withLock { redirected = true }
    completionHandler(nil)
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler:
      @escaping @Sendable (
        URLSession.AuthChallengeDisposition,
        URLCredential?
      ) -> Void
  ) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
      !additionalTrustAnchors.isEmpty,
      let trust = challenge.protectionSpace.serverTrust
    else {
      completionHandler(.performDefaultHandling, nil)
      return
    }
    guard Self.evaluate(trust: trust, additionalTrustAnchors: additionalTrustAnchors) else {
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }
    completionHandler(.useCredential, URLCredential(trust: trust))
  }

  static func evaluate(trust: SecTrust, additionalTrustAnchors: [Data]) -> Bool {
    let anchors = additionalTrustAnchors.compactMap {
      SecCertificateCreateWithData(nil, $0 as CFData)
    }
    return anchors.count == additionalTrustAnchors.count
      && SecTrustSetAnchorCertificates(trust, anchors as CFArray) == errSecSuccess
      && SecTrustSetAnchorCertificatesOnly(trust, false) == errSecSuccess
      && SecTrustEvaluateWithError(trust, nil)
  }
}
