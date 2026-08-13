import BondryApple
import CBondry
import Foundation

public final class BondryEncryptedStore: @unchecked Sendable {
  private let handle: OpaquePointer

  deinit {
    _ = bondry_store_close_v1(handle)
  }

  public static func open(
    at fileURL: URL,
    key: DatabaseKeyMaterial
  ) throws -> BondryEncryptedStore {
    let actualVersion = bondry_abi_version_v1()
    guard actualVersion == BONDRY_ABI_VERSION_V1 else {
      throw BondryEncryptedStoreError.incompatibleABI(
        expected: BONDRY_ABI_VERSION_V1,
        actual: actualVersion
      )
    }
    guard fileURL.isFileURL else {
      throw BondryEncryptedStoreError.invalidFileURL
    }

    let path = Array(fileURL.path.utf8)
    guard !path.isEmpty, !path.contains(0) else {
      throw BondryEncryptedStoreError.invalidFileURL
    }

    let keyData = key.rawRepresentation
    var openedHandle: OpaquePointer?
    let status = path.withUnsafeBufferPointer { pathBuffer in
      keyData.withUnsafeBytes { keyBuffer in
        bondry_store_open_v1(
          pathBuffer.baseAddress,
          pathBuffer.count,
          keyBuffer.bindMemory(to: UInt8.self).baseAddress,
          keyBuffer.count,
          &openedHandle
        )
      }
    }

    guard status == BONDRY_STATUS_OK else {
      if let openedHandle {
        _ = bondry_store_close_v1(openedHandle)
      }
      throw BondryEncryptedStoreError(status: status)
    }
    guard let openedHandle else {
      throw BondryEncryptedStoreError.invalidHandle
    }
    return BondryEncryptedStore(handle: openedHandle)
  }

  public func checkHealth() throws {
    let status = bondry_store_check_v1(handle)
    guard status == BONDRY_STATUS_OK else {
      throw BondryEncryptedStoreError(status: status)
    }
  }

  private init(handle: OpaquePointer) {
    self.handle = handle
  }
}
