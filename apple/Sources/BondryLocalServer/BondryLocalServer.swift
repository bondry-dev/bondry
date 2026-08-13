import Bondry
import CBondryLocalServer
import Foundation

// The lock serializes native handle ownership; the endpoint is immutable.
public final class BondryLocalServer: @unchecked Sendable {
  public let endpoint: BondryLocalServerEndpoint

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
    let status = bondry_server_stop_v1(handle)
    guard status == BONDRY_STATUS_OK else {
      throw BondryLocalServerError(status: status)
    }
  }

  deinit {
    try? stop()
  }

  init(handle: OpaquePointer, endpoint: BondryLocalServerEndpoint) {
    self.handle = handle
    self.endpoint = endpoint
  }
}

extension BondryRuntime {
  public func startLocalServer(
    configuration: BondryLocalServerConfiguration
  ) throws -> BondryLocalServer {
    let input = try JSONEncoder().encode(LocalServerInput(configuration))
    var serverHandle: OpaquePointer?
    var address = BondryServerAddressV1()
    let status = input.withUnsafeBytes { buffer in
      let bytes = buffer.bindMemory(to: UInt8.self)
      return bondry_server_start_v1(
        handle,
        bytes.baseAddress,
        bytes.count,
        &serverHandle,
        &address
      )
    }
    guard status == BONDRY_STATUS_OK else {
      if let serverHandle {
        _ = bondry_server_stop_v1(serverHandle)
      }
      throw BondryLocalServerError(status: status)
    }
    guard let serverHandle else {
      throw BondryLocalServerError.invalidHandle
    }
    do {
      return BondryLocalServer(
        handle: serverHandle,
        endpoint: BondryLocalServerEndpoint(
          address: try decodeLocalServerAddress(address.address),
          port: address.port
        )
      )
    } catch {
      _ = bondry_server_stop_v1(serverHandle)
      throw error
    }
  }
}

private func decodeLocalServerAddress<Value>(_ value: Value) throws -> String {
  try withUnsafeBytes(of: value) { bytes in
    guard let end = bytes.firstIndex(of: 0), end > 0,
      let string = String(bytes: bytes[..<end], encoding: .utf8)
    else {
      throw BondryLocalServerError.invalidAddress
    }
    return string
  }
}
