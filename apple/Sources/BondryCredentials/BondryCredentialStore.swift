import CBondryCredentials
import Foundation

public final class BondryCredentialStore: @unchecked Sendable {
  public static let maximumCredentialByteCount = Int(BONDRY_MAX_CREDENTIAL_LENGTH_V1)

  private let handle: OpaquePointer

  deinit {
    _ = bondry_credential_store_close_v1(handle)
  }

  public static func openUnixFileStore(at directoryURL: URL) throws -> BondryCredentialStore {
    let actualVersion = bondry_credentials_abi_version_v1()
    guard actualVersion == BONDRY_CREDENTIAL_ABI_VERSION_V1 else {
      throw BondryCredentialStoreError.incompatibleABI(
        expected: BONDRY_CREDENTIAL_ABI_VERSION_V1,
        actual: actualVersion
      )
    }
    guard directoryURL.isFileURL else {
      throw BondryCredentialStoreError.invalidDirectoryURL
    }
    let path = Array(directoryURL.path.utf8)
    guard !path.isEmpty, !path.contains(0), path.first == 0x2F else {
      throw BondryCredentialStoreError.invalidDirectoryURL
    }

    var openedHandle: OpaquePointer?
    let status = path.withUnsafeBufferPointer { buffer in
      bondry_unix_file_credential_store_open_v1(
        buffer.baseAddress,
        buffer.count,
        &openedHandle
      )
    }
    guard status == BONDRY_CREDENTIAL_STATUS_OK else {
      if let openedHandle {
        _ = bondry_credential_store_close_v1(openedHandle)
      }
      throw BondryCredentialStoreError(status: status)
    }
    guard let openedHandle else {
      throw BondryCredentialStoreError.invalidHandle
    }
    return BondryCredentialStore(handle: openedHandle)
  }

  public func capabilities() throws -> BondryCredentialStoreCapabilities {
    var native = BondryCredentialStoreCapabilitiesV1()
    let status = bondry_credential_store_capabilities_v1(handle, &native)
    guard status == BONDRY_CREDENTIAL_STATUS_OK else {
      throw BondryCredentialStoreError(status: status)
    }
    return try BondryCredentialStoreCapabilities(native: native)
  }

  public func load(_ id: BondryCredentialID) throws -> Data? {
    let identifier = Array(id.rawValue.utf8)
    for _ in 0..<3 {
      var requiredLength = 0
      let queryStatus = identifier.withUnsafeBufferPointer { identifierBuffer in
        bondry_credential_store_load_v1(
          handle,
          identifierBuffer.baseAddress,
          identifierBuffer.count,
          nil,
          0,
          &requiredLength
        )
      }
      if queryStatus == BONDRY_CREDENTIAL_STATUS_NOT_FOUND {
        return nil
      }
      guard queryStatus == BONDRY_CREDENTIAL_STATUS_OK else {
        throw BondryCredentialStoreError(status: queryStatus)
      }
      guard requiredLength > 0, requiredLength <= Self.maximumCredentialByteCount else {
        throw BondryCredentialStoreError.invalidMaterial
      }

      var bytes = [UInt8](repeating: 0, count: requiredLength)
      defer {
        _ = bytes.withUnsafeMutableBytes { buffer in
          buffer.initializeMemory(as: UInt8.self, repeating: 0)
        }
      }
      var actualLength = 0
      let loadStatus = identifier.withUnsafeBufferPointer { identifierBuffer in
        bytes.withUnsafeMutableBufferPointer { outputBuffer in
          bondry_credential_store_load_v1(
            handle,
            identifierBuffer.baseAddress,
            identifierBuffer.count,
            outputBuffer.baseAddress,
            outputBuffer.count,
            &actualLength
          )
        }
      }
      if loadStatus == BONDRY_CREDENTIAL_STATUS_BUFFER_TOO_SMALL {
        continue
      }
      if loadStatus == BONDRY_CREDENTIAL_STATUS_NOT_FOUND {
        return nil
      }
      guard loadStatus == BONDRY_CREDENTIAL_STATUS_OK else {
        throw BondryCredentialStoreError(status: loadStatus)
      }
      guard actualLength > 0, actualLength <= bytes.count else {
        throw BondryCredentialStoreError.invalidMaterial
      }
      return Data(bytes.prefix(actualLength))
    }
    throw BondryCredentialStoreError.unavailable
  }

  public func store(_ value: Data, for id: BondryCredentialID) throws {
    guard !value.isEmpty, value.count <= Self.maximumCredentialByteCount else {
      throw BondryCredentialStoreError.invalidLength
    }
    let identifier = Array(id.rawValue.utf8)
    let status = identifier.withUnsafeBufferPointer { identifierBuffer in
      value.withUnsafeBytes { valueBuffer in
        bondry_credential_store_store_v1(
          handle,
          identifierBuffer.baseAddress,
          identifierBuffer.count,
          valueBuffer.bindMemory(to: UInt8.self).baseAddress,
          valueBuffer.count
        )
      }
    }
    guard status == BONDRY_CREDENTIAL_STATUS_OK else {
      throw BondryCredentialStoreError(status: status)
    }
  }

  @discardableResult
  public func delete(_ id: BondryCredentialID) throws -> Bool {
    let identifier = Array(id.rawValue.utf8)
    var deleted: UInt8 = 0
    let status = identifier.withUnsafeBufferPointer { identifierBuffer in
      bondry_credential_store_delete_v1(
        handle,
        identifierBuffer.baseAddress,
        identifierBuffer.count,
        &deleted
      )
    }
    guard status == BONDRY_CREDENTIAL_STATUS_OK else {
      throw BondryCredentialStoreError(status: status)
    }
    return deleted != 0
  }

  private init(handle: OpaquePointer) {
    self.handle = handle
  }
}

extension BondryCredentialStoreCapabilities {
  fileprivate init(native: BondryCredentialStoreCapabilitiesV1) throws {
    switch native.protection {
    case BONDRY_CREDENTIAL_PROTECTION_ACCESS_CONTROLLED_V1:
      protection = .accessControlled
    case BONDRY_CREDENTIAL_PROTECTION_HOST_BOUND_V1:
      protection = .hostBound
    case BONDRY_CREDENTIAL_PROTECTION_HARDWARE_BOUND_V1:
      protection = .hardwareBound
    case BONDRY_CREDENTIAL_PROTECTION_EXTERNAL_V1:
      protection = .external
    default:
      throw BondryCredentialStoreError.invalidCapabilities
    }
    switch native.access {
    case BONDRY_CREDENTIAL_STORE_ACCESS_READ_ONLY_V1:
      access = .readOnly
    case BONDRY_CREDENTIAL_STORE_ACCESS_READ_WRITE_V1:
      access = .readWrite
    default:
      throw BondryCredentialStoreError.invalidCapabilities
    }
    guard native.supports_unattended_access <= 1 else {
      throw BondryCredentialStoreError.invalidCapabilities
    }
    supportsUnattendedAccess = native.supports_unattended_access == 1
  }
}

extension BondryCredentialStoreError {
  fileprivate init(status: BondryCredentialStatus) {
    switch status {
    case BONDRY_CREDENTIAL_STATUS_NULL_POINTER:
      self = .nullPointer
    case BONDRY_CREDENTIAL_STATUS_INVALID_LENGTH:
      self = .invalidLength
    case BONDRY_CREDENTIAL_STATUS_INVALID_UTF8:
      self = .invalidUTF8
    case BONDRY_CREDENTIAL_STATUS_INVALID_PATH:
      self = .invalidPath
    case BONDRY_CREDENTIAL_STATUS_INVALID_ARGUMENT:
      self = .invalidArgument
    case BONDRY_CREDENTIAL_STATUS_BUFFER_TOO_SMALL:
      self = .bufferTooSmall
    case BONDRY_CREDENTIAL_STATUS_INVALID_MATERIAL:
      self = .invalidMaterial
    case BONDRY_CREDENTIAL_STATUS_UNAVAILABLE:
      self = .unavailable
    case BONDRY_CREDENTIAL_STATUS_UNSAFE_STORAGE:
      self = .unsafeStorage
    case BONDRY_CREDENTIAL_STATUS_ACCESS_DENIED:
      self = .accessDenied
    case BONDRY_CREDENTIAL_STATUS_READ_ONLY:
      self = .readOnly
    default:
      self = .internalFailure(status)
    }
  }
}
