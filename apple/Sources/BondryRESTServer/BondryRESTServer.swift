import Bondry
import CBondryRESTServer
import Foundation

public final class BondryRESTServer: @unchecked Sendable {
  public let endpoint: BondryRESTServerEndpoint

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
    let status = bondry_rest_server_stop_v1(handle)
    guard status == BONDRY_STATUS_OK else {
      throw BondryRESTServerError(status: status)
    }
  }

  deinit {
    try? stop()
  }

  init(handle: OpaquePointer, endpoint: BondryRESTServerEndpoint) {
    self.handle = handle
    self.endpoint = endpoint
  }
}

extension BondryRuntime {
  public func startRESTServer(
    configuration: BondryRESTServerConfiguration
  ) throws -> BondryRESTServer {
    let input = try JSONEncoder().encode(RESTServerInput(configuration))
    var serverHandle: OpaquePointer?
    var address = BondryRestServerAddressV1()
    let status = input.withUnsafeBytes { buffer in
      let bytes = buffer.bindMemory(to: UInt8.self)
      return bondry_rest_server_start_v1(
        handle,
        bytes.baseAddress,
        bytes.count,
        &serverHandle,
        &address
      )
    }
    guard status == BONDRY_STATUS_OK else {
      if let serverHandle {
        _ = bondry_rest_server_stop_v1(serverHandle)
      }
      throw BondryRESTServerError(status: status)
    }
    guard let serverHandle else {
      throw BondryRESTServerError.invalidHandle
    }
    do {
      return BondryRESTServer(
        handle: serverHandle,
        endpoint: BondryRESTServerEndpoint(
          address: try decodeRESTServerAddress(address.address),
          port: address.port
        )
      )
    } catch {
      _ = bondry_rest_server_stop_v1(serverHandle)
      throw error
    }
  }
}

private func decodeRESTServerAddress<Value>(_ value: Value) throws -> String {
  try withUnsafeBytes(of: value) { bytes in
    guard let end = bytes.firstIndex(of: 0), end > 0,
      let string = String(bytes: bytes[..<end], encoding: .utf8)
    else {
      throw BondryRESTServerError.invalidAddress
    }
    return string
  }
}
