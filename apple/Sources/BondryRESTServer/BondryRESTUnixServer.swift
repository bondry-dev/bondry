import Bondry
import CBondryRESTServer
import Foundation

public final class BondryRESTUnixServer: @unchecked Sendable {
  public let endpoint: BondryRESTUnixServerEndpoint

  private let lock = NSLock()
  private var handle: OpaquePointer?

  public var isRunning: Bool {
    lock.withLock { handle != nil }
  }

  public func stop() throws {
    let handle = lock.withLock {
      let value = self.handle
      self.handle = nil
      return value
    }
    guard let handle else {
      return
    }
    let status = bondry_rest_server_stop_unix_v1(handle)
    guard status == BONDRY_STATUS_OK else {
      throw BondryRESTUnixServerError(status: status)
    }
  }

  deinit {
    try? stop()
  }

  init(handle: OpaquePointer, endpoint: BondryRESTUnixServerEndpoint) {
    self.handle = handle
    self.endpoint = endpoint
  }
}

extension BondryRuntime {
  public func startRESTUnixServer(
    configuration: BondryRESTUnixServerConfiguration
  ) throws -> BondryRESTUnixServer {
    let input = try JSONEncoder().encode(RESTUnixServerInput(configuration))
    var serverHandle: OpaquePointer?
    var endpoint = BondryRestUnixServerEndpointV1()
    let status = input.withUnsafeBytes { buffer in
      let bytes = buffer.bindMemory(to: UInt8.self)
      return bondry_rest_server_start_unix_v1(
        handle,
        bytes.baseAddress,
        bytes.count,
        &serverHandle,
        &endpoint
      )
    }
    guard status == BONDRY_STATUS_OK else {
      if let serverHandle {
        _ = bondry_rest_server_stop_unix_v1(serverHandle)
      }
      throw BondryRESTUnixServerError(status: status)
    }
    guard let serverHandle else {
      throw BondryRESTUnixServerError.invalidHandle
    }
    do {
      let path = try decodeRESTUnixServerPath(endpoint.path)
      return BondryRESTUnixServer(
        handle: serverHandle,
        endpoint: BondryRESTUnixServerEndpoint(
          socketURL: URL(fileURLWithPath: path)
        )
      )
    } catch {
      _ = bondry_rest_server_stop_unix_v1(serverHandle)
      throw error
    }
  }
}

private func decodeRESTUnixServerPath<Value>(_ value: Value) throws -> String {
  try withUnsafeBytes(of: value) { bytes in
    guard let end = bytes.firstIndex(of: 0), end > 0,
      let string = String(bytes: bytes[..<end], encoding: .utf8), string.hasPrefix("/")
    else {
      throw BondryRESTUnixServerError.invalidEndpoint
    }
    return string
  }
}
