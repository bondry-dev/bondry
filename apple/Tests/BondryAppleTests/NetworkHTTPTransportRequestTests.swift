import Foundation
import Network
import XCTest

@testable import BondryApple

#if os(macOS)
  final class NetworkHTTPTransportRequestTests: XCTestCase {
    func testSerializesOriginFormWithoutChangingEscapedPathsOrQueries() async throws {
      let targets = [
        ("", "/"),
        ("?key=value", "/?key=value"),
        ("?", "/?"),
        ("/a%2Fb?key=x%20y&key=%2F", "/a%2Fb?key=x%20y&key=%2F"),
        ("//nested?key=value", "//nested?key=value"),
      ]

      for (suffix, expectedTarget) in targets {
        let server = try RequestTargetHTTPServer()
        defer { server.stop() }
        let port = try await server.readyPort()
        let request = try BondryHTTPRequest(
          method: "GET",
          url: try XCTUnwrap(URL(string: "http://127.0.0.1:\(port)\(suffix)"))
        )

        let response = try await NetworkHTTPTransport().send(request)

        XCTAssertEqual(response.statusCode, 204)
        XCTAssertEqual(server.requestLine, "GET \(expectedTarget) HTTP/1.1")
      }
    }
  }

  private final class RequestTargetHTTPServer: @unchecked Sendable {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "dev.bondry.request-target-test")
    private let lock = NSLock()
    private var received = Data()
    private var connections: [NWConnection] = []

    init() throws {
      listener = try NWListener(using: .tcp, on: .any)
      listener.newConnectionHandler = { [weak self] connection in
        self?.accept(connection)
      }
      listener.start(queue: queue)
    }

    var requestLine: String? {
      lock.withLock {
        guard let end = received.range(of: Data("\r\n".utf8))?.lowerBound else { return nil }
        return String(data: received[..<end], encoding: .utf8)
      }
    }

    func readyPort() async throws -> UInt16 {
      try await withCheckedThrowingContinuation { continuation in
        queue.async {
          if case .ready = self.listener.state, let port = self.listener.port {
            continuation.resume(returning: port.rawValue)
            return
          }
          self.listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
              self.listener.stateUpdateHandler = nil
              guard let port = self.listener.port else {
                continuation.resume(throwing: BondryHTTPTransportError.connectionFailed)
                return
              }
              continuation.resume(returning: port.rawValue)
            case .failed, .cancelled:
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
        for connection in connections { connection.cancel() }
        connections.removeAll()
      }
    }

    private func accept(_ connection: NWConnection) {
      lock.withLock { connections.append(connection) }
      connection.start(queue: queue)
      receive(from: connection)
    }

    private func receive(from connection: NWConnection) {
      connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1_024) {
        [weak self] content, _, isComplete, error in
        guard let self, error == nil else { return }
        let completeHead = self.lock.withLock {
          if let content { self.received.append(content) }
          return self.received.range(of: Data("\r\n\r\n".utf8)) != nil
        }
        guard completeHead else {
          if !isComplete { self.receive(from: connection) }
          return
        }
        connection.send(
          content: Data("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".utf8),
          completion: .contentProcessed { _ in }
        )
      }
    }
  }
#endif
