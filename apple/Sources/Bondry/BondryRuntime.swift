import BondryApple
import CBondryRuntime
import Foundation

// Native operations are synchronized, and this instance owns one immutable handle.
public final class BondryRuntime: @unchecked Sendable {
  package let handle: OpaquePointer

  deinit {
    _ = bondry_store_close_v1(handle)
  }

  public static func open(
    at fileURL: URL,
    key: DatabaseKeyMaterial
  ) throws -> BondryRuntime {
    let actualVersion = bondry_abi_version_v1()
    guard actualVersion == BONDRY_ABI_VERSION_V1 else {
      throw BondryRuntimeError.incompatibleABI(
        expected: BONDRY_ABI_VERSION_V1,
        actual: actualVersion
      )
    }
    guard fileURL.isFileURL else {
      throw BondryRuntimeError.invalidFileURL
    }

    let path = Array(fileURL.path.utf8)
    guard !path.isEmpty, !path.contains(0) else {
      throw BondryRuntimeError.invalidFileURL
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
      throw BondryRuntimeError(status: status)
    }
    guard let openedHandle else {
      throw BondryRuntimeError.invalidHandle
    }
    return BondryRuntime(handle: openedHandle)
  }

  public func checkHealth() throws {
    let status = bondry_store_check_v1(handle)
    guard status == BONDRY_STATUS_OK else {
      throw BondryRuntimeError(status: status)
    }
  }

  package init(handle: OpaquePointer) {
    self.handle = handle
  }
}
