import Foundation
import Network

@testable import BondryApple

#if os(macOS)
  final class LoopbackHTTPServer: @unchecked Sendable {
    private let listener: NWListener
    private let queue = DispatchQueue(label: "dev.bondry.http-test")
    private let lock = NSLock()
    private let response: Data
    private var received = Data()
    private var connections: [NWConnection] = []
    private var stopped = false
    private var readiness: Result<UInt16, any Error>?
    private var waiters: [CheckedContinuation<UInt16, any Error>] = []
    private var timeouts: [DispatchWorkItem] = []

    init(
      response: Data = Data(
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".utf8),
      startImmediately: Bool = true
    ) throws {
      self.response = response
      listener = try NWListener(using: .tcp, on: .any)
      listener.stateUpdateHandler = { [weak self] state in
        guard let self else { return }
        switch state {
        case .ready:
          if let port = self.listener.port {
            self.finishReadiness(.success(port.rawValue))
          } else {
            self.finishReadiness(.failure(BondryHTTPTransportError.connectionFailed))
          }
        case .failed:
          self.finishReadiness(.failure(BondryHTTPTransportError.connectionFailed))
        case .cancelled:
          self.finishReadiness(.failure(CancellationError()))
        default:
          break
        }
      }
      listener.newConnectionHandler = { [weak self] connection in
        guard let self else {
          connection.cancel()
          return
        }
        self.accept(connection)
      }
      if startImmediately { listener.start(queue: queue) }
    }

    deinit {
      stop()
    }

    var request: Data {
      lock.withLock { received }
    }

    var requestLine: String? {
      let request = request
      guard let end = request.range(of: Data("\r\n".utf8))?.lowerBound else { return nil }
      return String(data: request[..<end], encoding: .utf8)
    }

    var hasReadinessWaiters: Bool {
      lock.withLock { !waiters.isEmpty }
    }

    func readyPort(timeout: TimeInterval = 2) async throws -> UInt16 {
      try await withTaskCancellationHandler {
        try await withCheckedThrowingContinuation { continuation in
          let timer = DispatchWorkItem { [weak self] in
            guard let self else { return }
            if self.finishReadiness(.failure(BondryHTTPTransportError.deadlineExceeded)) {
              self.stop()
            }
          }
          let result = lock.withLock { () -> Result<UInt16, any Error>? in
            if stopped { return .failure(CancellationError()) }
            if let readiness { return readiness }
            waiters.append(continuation)
            timeouts.append(timer)
            return nil
          }
          if let result {
            continuation.resume(with: result)
          } else {
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timer)
          }
        }
      } onCancel: {
        self.stop()
      }
    }

    func stop() {
      let connections = lock.withLock {
        stopped = true
        let connections = self.connections
        self.connections.removeAll()
        return connections
      }
      finishReadiness(.failure(CancellationError()))
      listener.cancel()
      for connection in connections { connection.cancel() }
    }

    @discardableResult
    private func finishReadiness(_ result: Result<UInt16, any Error>) -> Bool {
      let pending = lock.withLock {
        () -> (
          Result<UInt16, any Error>, [CheckedContinuation<UInt16, any Error>], [DispatchWorkItem]
        )? in
        guard readiness == nil else { return nil }
        let outcome: Result<UInt16, any Error> = stopped ? .failure(CancellationError()) : result
        readiness = outcome
        let pending = (outcome, waiters, timeouts)
        waiters.removeAll()
        timeouts.removeAll()
        return pending
      }
      guard let (outcome, waiters, timeouts) = pending else { return false }
      for timer in timeouts { timer.cancel() }
      for waiter in waiters { waiter.resume(with: outcome) }
      return true
    }

    private func accept(_ connection: NWConnection) {
      let accepted = lock.withLock {
        guard !stopped else { return false }
        connections.append(connection)
        return true
      }
      guard accepted else {
        connection.cancel()
        return
      }
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
        connection.send(content: self.response, completion: .contentProcessed { _ in })
      }
    }
  }
#endif
