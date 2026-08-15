import Bondry
import BondryApple
import BondryEgress
import Foundation
import Network

private enum ProbeError: Error {
  case listenerFailed
  case missingPort
  case deliveryFailed
  case requestMissing
}

private struct ProbeSecretProvider: BondryEgressSecretProvider {
  let reference: BondrySecretReference
  let value: Data

  func resolve(_ reference: BondrySecretReference) throws -> BondryResolvedSecret {
    guard reference == self.reference else {
      throw BondrySecretProviderError.secretNotFound
    }
    return try BondryResolvedSecret(current: value)
  }
}

private final class LoopbackReceiver: @unchecked Sendable {
  private let listener: NWListener
  private let queue = DispatchQueue(label: "dev.bondry.egress-probe")
  private let lock = NSLock()
  private var connections: [NWConnection] = []
  private var received = Data()

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
            continuation.resume(throwing: ProbeError.listenerFailed)
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
      guard self.requestIsComplete else {
        self.receive(from: connection)
        return
      }
      let response = Data("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".utf8)
      connection.send(content: response, completion: .contentProcessed { _ in })
    }
  }

  private var requestIsComplete: Bool {
    let request = request
    let delimiter = Data("\r\n\r\n".utf8)
    guard let headerRange = request.range(of: delimiter) else {
      return false
    }
    let header = String(decoding: request[..<headerRange.lowerBound], as: UTF8.self)
    let contentLength =
      header.components(separatedBy: "\r\n").compactMap { line -> Int? in
        let parts = line.split(separator: ":", maxSplits: 1)
        guard parts.count == 2,
          parts[0].trimmingCharacters(in: .whitespaces).lowercased() == "content-length"
        else {
          return nil
        }
        return Int(parts[1].trimmingCharacters(in: .whitespaces))
      }.first ?? 0
    return request.count >= headerRange.upperBound + contentLength
  }
}

private let receiver = try LoopbackReceiver()
defer { receiver.stop() }
try await receiver.waitUntilReady()
guard let port = receiver.port else {
  throw ProbeError.missingPort
}

let databaseURL = URL(fileURLWithPath: CommandLine.arguments[1])
let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x44, count: 32))
let runtime = try BondryRuntime.open(at: databaseURL, key: key)
let secret = try BondrySecretReference("keychain:probe-topic")
let egress = try runtime.startEgress(
  secretProvider: ProbeSecretProvider(reference: secret, value: Data("events".utf8))
)
defer { try? egress.stop() }

try egress.register(
  BondryWebhookRoute(
    id: "ntfy-pilot",
    payload: BondryPayloadContract(
      fields: [BondryPayloadField(name: "message", type: .string, required: true)]
    ),
    authentication: .urlTemplate(
      "http://127.0.0.1:\(port)/{secret}",
      secret: secret
    )
  )
)
try egress.emit(
  routeID: "ntfy-pilot",
  deliveryID: "swift-delivery",
  payload: ["message": "hello"]
)

var delivered = false
for _ in 0..<200 {
  if try egress.deliveryStatus(for: "swift-delivery")?.state == .terminal(.delivered) {
    delivered = true
    break
  }
  try await ContinuousClock().sleep(for: .milliseconds(5))
}
guard delivered else {
  throw ProbeError.deliveryFailed
}
guard String(decoding: receiver.request, as: UTF8.self).contains("{\"message\":\"hello\"}") else {
  throw ProbeError.requestMissing
}
try egress.stop()
