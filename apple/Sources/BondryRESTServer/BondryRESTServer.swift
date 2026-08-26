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

  public func startRESTTLSServer(
    configuration: BondryRESTTLSServerConfiguration,
    certificateChainDER: [Data],
    privateKeyPKCS8DER: inout Data
  ) throws -> BondryRESTServer {
    defer {
      privateKeyPKCS8DER.resetBytes(
        in: privateKeyPKCS8DER.startIndex..<privateKeyPKCS8DER.endIndex
      )
    }
    guard (1...Int(BONDRY_REST_TLS_CERTIFICATE_COUNT_V1)).contains(certificateChainDER.count),
      certificateChainDER.allSatisfy({ !$0.isEmpty })
    else {
      throw BondryRESTServerConfigurationError.invalidTLSCertificateChain
    }
    var certificateBytes = 0
    for certificate in certificateChainDER {
      let addition = certificateBytes.addingReportingOverflow(certificate.count)
      guard !addition.overflow else {
        throw BondryRESTServerConfigurationError.invalidTLSCertificateChain
      }
      certificateBytes = addition.partialValue
    }
    guard certificateBytes <= Int(BONDRY_REST_TLS_CERTIFICATE_CHAIN_BYTES_V1) else {
      throw BondryRESTServerConfigurationError.invalidTLSCertificateChain
    }
    guard (1...Int(BONDRY_REST_TLS_PRIVATE_KEY_BYTES_V1)).contains(
      privateKeyPKCS8DER.count
    ) else {
      throw BondryRESTServerConfigurationError.invalidTLSPrivateKey
    }

    let input = try JSONEncoder().encode(RESTTLSServerInput(configuration))
    let certificates = certificateChainDER.map { $0 as NSData }
    let slices = certificates.map {
      BondryRestTLSByteSliceV1(
        bytes: $0.bytes.assumingMemoryBound(to: UInt8.self),
        length: $0.length
      )
    }
    var serverHandle: OpaquePointer?
    var address = BondryRestServerAddressV1()
    let status = input.withUnsafeBytes { inputBuffer in
      privateKeyPKCS8DER.withUnsafeMutableBytes { keyBuffer in
        slices.withUnsafeBufferPointer { certificateBuffer in
          var identity = BondryRestTLSIdentityV1(
            abi_version: BONDRY_REST_TLS_IDENTITY_ABI_VERSION_V1,
            struct_size: MemoryLayout<BondryRestTLSIdentityV1>.size,
            certificate_chain: certificateBuffer.baseAddress,
            certificate_count: certificateBuffer.count,
            private_key_pkcs8: keyBuffer.bindMemory(to: UInt8.self).baseAddress,
            private_key_pkcs8_length: keyBuffer.count
          )
          return bondry_rest_server_start_tls_v1(
            handle,
            inputBuffer.bindMemory(to: UInt8.self).baseAddress,
            inputBuffer.count,
            &identity,
            &serverHandle,
            &address
          )
        }
      }
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
