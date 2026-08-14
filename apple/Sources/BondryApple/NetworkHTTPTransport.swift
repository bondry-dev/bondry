import Foundation
@preconcurrency import Network

struct NetworkHTTPTransport: Sendable {
  func send(_ request: BondryHTTPRequest) async throws -> BondryHTTPResponse {
    guard let host = request.url.host,
      let rawPort = UInt16(exactly: request.url.port ?? 80),
      let port = NWEndpoint.Port(rawValue: rawPort)
    else {
      throw BondryHTTPTransportError.unsupportedEndpoint
    }
    let connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: .tcp)
    return try await NetworkHTTPExchange(connection: connection, request: request).run()
  }
}

private final class NetworkHTTPExchange: @unchecked Sendable {
  private let connection: NWConnection
  private let queue = DispatchQueue(label: "dev.bondry.http-transport")
  private let request: BondryHTTPRequest
  private var continuation: CheckedContinuation<BondryHTTPResponse, any Error>?
  private var deadlineTimer: DispatchSourceTimer?
  private var parser: BoundedHTTP1ResponseParser
  private var startedRequest = false
  private var finished = false

  init(connection: NWConnection, request: BondryHTTPRequest) {
    self.connection = connection
    self.request = request
    parser = BoundedHTTP1ResponseParser(
      requestMethod: request.method,
      maximumBodyBytes: request.maximumResponseBodyBytes
    )
  }

  func run() async throws -> BondryHTTPResponse {
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        queue.async {
          guard !Task.isCancelled, !self.finished else {
            continuation.resume(throwing: CancellationError())
            return
          }
          self.continuation = continuation
          self.start()
        }
      }
    } onCancel: {
      self.queue.async {
        self.complete(.failure(CancellationError()))
      }
    }
  }

  private func start() {
    connection.stateUpdateHandler = { state in
      self.handle(state)
    }
    let timer = DispatchSource.makeTimerSource(queue: queue)
    timer.schedule(deadline: .now() + request.timeoutSeconds)
    timer.setEventHandler {
      self.complete(.failure(BondryHTTPTransportError.deadlineExceeded))
    }
    deadlineTimer = timer
    timer.resume()
    connection.start(queue: queue)
  }

  private func handle(_ state: NWConnection.State) {
    switch state {
    case .ready where !startedRequest:
      startedRequest = true
      do {
        let evidence = try connectionEvidence()
        try request.policy.verify(url: request.url, evidence: evidence)
        let wireRequest = try serializedRequest()
        send(wireRequest, evidence: evidence)
      } catch {
        complete(.failure(error))
      }
    case .failed:
      complete(.failure(BondryHTTPTransportError.connectionFailed))
    case .cancelled where !finished:
      complete(.failure(BondryHTTPTransportError.connectionFailed))
    default:
      break
    }
  }

  private func connectionEvidence() throws -> BondryConnectionEvidence {
    guard let remoteEndpoint = connection.currentPath?.remoteEndpoint,
      case .hostPort(let host, let port) = remoteEndpoint
    else {
      throw BondryHTTPTransportError.missingConnectionEvidence
    }
    let address: BondryIPAddress
    let interfaceIndex: Int?
    switch host {
    case .ipv4(let ipv4):
      address = try BondryIPAddress(bytes: ipv4.rawValue)
      interfaceIndex = ipv4.interface?.index
    case .ipv6(let ipv6):
      address = try BondryIPAddress(bytes: ipv6.rawValue)
      interfaceIndex = ipv6.interface?.index
    case .name:
      throw BondryHTTPTransportError.missingConnectionEvidence
    @unknown default:
      throw BondryHTTPTransportError.missingConnectionEvidence
    }
    let scope = interfaceIndex.flatMap { UInt32(exactly: $0) }.flatMap { $0 == 0 ? nil : $0 }
    return .cleartext(address: address, port: port.rawValue, interfaceScope: scope)
  }

  private func serializedRequest() throws -> Data {
    guard let components = URLComponents(url: request.url, resolvingAgainstBaseURL: false),
      let host = components.percentEncodedHost
    else {
      throw BondryHTTPTransportError.unsupportedEndpoint
    }
    var pathComponents = components
    pathComponents.scheme = nil
    pathComponents.host = nil
    pathComponents.port = nil
    pathComponents.user = nil
    pathComponents.password = nil
    let pathAndQuery = pathComponents.string.flatMap { $0.isEmpty ? nil : $0 } ?? "/"
    let defaultPort = request.url.port == nil || request.url.port == 80
    let authority = defaultPort ? host : "\(host):\(request.url.port ?? 80)"
    var head = "\(request.method) \(pathAndQuery) HTTP/1.1\r\n"
    head += "Host: \(authority)\r\n"
    head += "Connection: close\r\n"
    head += "Content-Length: \(request.body.count)\r\n"
    for (name, value) in request.headers where !Self.reservedHeader(name) {
      head += "\(name): \(value)\r\n"
    }
    head += "\r\n"
    guard var data = head.data(using: .utf8) else {
      throw BondryHTTPTransportError.unsupportedEndpoint
    }
    data.append(request.body)
    return data
  }

  private func send(_ data: Data, evidence: BondryConnectionEvidence) {
    connection.send(
      content: data,
      completion: .contentProcessed { error in
        guard error == nil else {
          self.complete(.failure(BondryHTTPTransportError.connectionFailed))
          return
        }
        self.receive(evidence: evidence)
      })
  }

  private func receive(evidence: BondryConnectionEvidence) {
    connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1_024) {
      content,
      _,
      isComplete,
      error in
      guard error == nil else {
        self.complete(.failure(BondryHTTPTransportError.connectionFailed))
        return
      }
      do {
        if let response = try self.parser.consume(content ?? Data(), isComplete: isComplete) {
          self.complete(
            .success(
              BondryHTTPResponse(
                statusCode: response.statusCode,
                headers: response.headers,
                body: response.body,
                connection: evidence
              )
            )
          )
        } else {
          self.receive(evidence: evidence)
        }
      } catch {
        self.complete(.failure(error))
      }
    }
  }

  private func complete(_ result: Result<BondryHTTPResponse, any Error>) {
    guard !finished else { return }
    finished = true
    deadlineTimer?.setEventHandler {}
    deadlineTimer?.cancel()
    deadlineTimer = nil
    connection.stateUpdateHandler = nil
    connection.cancel()
    continuation?.resume(with: result)
    continuation = nil
  }

  private static func reservedHeader(_ name: String) -> Bool {
    ["connection", "content-length", "host", "transfer-encoding"].contains(name.lowercased())
  }
}
