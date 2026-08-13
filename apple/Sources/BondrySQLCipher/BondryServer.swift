import CBondry
import Foundation

public final class BondryServer: @unchecked Sendable {
  public let endpoint: BondryServerEndpoint

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
      throw BondryEncryptedStoreError(status: status)
    }
  }

  deinit {
    try? stop()
  }

  init(handle: OpaquePointer, endpoint: BondryServerEndpoint) {
    self.handle = handle
    self.endpoint = endpoint
  }
}

extension BondryEncryptedStore {
  public func startServer(configuration: BondryServerConfiguration) throws -> BondryServer {
    let input = try JSONEncoder().encode(BondryServerInput(configuration))
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
      throw BondryEncryptedStoreError(status: status)
    }
    guard let serverHandle else {
      throw BondryEncryptedStoreError.invalidHandle
    }
    do {
      return BondryServer(
        handle: serverHandle,
        endpoint: BondryServerEndpoint(
          address: try decodeCString(address.address),
          port: address.port
        )
      )
    } catch {
      _ = bondry_server_stop_v1(serverHandle)
      throw error
    }
  }
}
