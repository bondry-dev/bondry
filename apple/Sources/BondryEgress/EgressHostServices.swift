import BondryApple
import CBondryEgress
import Foundation

final class EgressHostServices: @unchecked Sendable {
  let transport: BondryAppleHTTPTransport
  let secrets: any BondryEgressSecretProvider

  init(transport: BondryAppleHTTPTransport, secrets: any BondryEgressSecretProvider) {
    self.transport = transport
    self.secrets = secrets
  }
}

func makeTransportDescriptor(context: UnsafeMutableRawPointer) -> BondryHTTPTransportV1 {
  BondryHTTPTransportV1(
    abi_version: BONDRY_HTTP_TRANSPORT_ABI_VERSION_V1,
    struct_size: MemoryLayout<BondryHTTPTransportV1>.size,
    context: context,
    retain: retainEgressHost,
    release: releaseEgressHost,
    send: sendEgressHTTP
  )
}

func makeSecretDescriptor(context: UnsafeMutableRawPointer) -> BondrySecretProviderV1 {
  BondrySecretProviderV1(
    abi_version: BONDRY_SECRET_PROVIDER_ABI_VERSION_V1,
    struct_size: MemoryLayout<BondrySecretProviderV1>.size,
    context: context,
    retain: retainEgressHost,
    release: releaseEgressHost,
    resolve: resolveEgressSecret
  )
}

private func retainEgressHost(
  _ context: UnsafeMutableRawPointer?
) -> UnsafeMutableRawPointer? {
  guard let context else {
    return nil
  }
  _ = Unmanaged<EgressHostServices>.fromOpaque(context).retain()
  return context
}

private func releaseEgressHost(_ context: UnsafeMutableRawPointer?) {
  guard let context else {
    return
  }
  Unmanaged<EgressHostServices>.fromOpaque(context).release()
}

private func sendEgressHTTP(
  _ context: UnsafeMutableRawPointer?,
  _ request: UnsafePointer<BondryHTTPRequestV1>?,
  _ completion: BondryHTTPCompletionV1?,
  _ completionContext: UnsafeMutableRawPointer?
) -> BondryStatus {
  guard let context, let request, let completion, let completionContext else {
    return BONDRY_STATUS_NULL_POINTER
  }
  let value: BondryHTTPRequest
  do {
    value = try decodeHTTPRequest(request.pointee)
  } catch {
    return BONDRY_STATUS_INVALID_ARGUMENT
  }
  let services = Unmanaged<EgressHostServices>.fromOpaque(context).takeUnretainedValue()
  let completionBox = EgressHTTPCompletion(completion: completion, context: completionContext)
  Task {
    do {
      completionBox.succeed(try await services.transport.send(value))
    } catch {
      completionBox.fail(error)
    }
  }
  return BONDRY_STATUS_OK
}

private func resolveEgressSecret(
  _ context: UnsafeMutableRawPointer?,
  _ reference: UnsafePointer<UInt8>?,
  _ referenceLength: Int,
  _ completion: BondrySecretResolutionV1?,
  _ completionContext: UnsafeMutableRawPointer?
) -> BondryStatus {
  guard let context, let completion, let completionContext else {
    return BONDRY_STATUS_NULL_POINTER
  }
  let secretReference: BondrySecretReference
  do {
    let value = try copyUTF8(reference, count: referenceLength, allowEmpty: false)
    secretReference = try BondrySecretReference(value)
  } catch {
    return BONDRY_STATUS_INVALID_DATA
  }
  let services = Unmanaged<EgressHostServices>.fromOpaque(context).takeUnretainedValue()
  do {
    let secret = try services.secrets.resolve(secretReference)
    secret.current.withUnsafeBytes { current in
      if let previous = secret.previous {
        previous.withUnsafeBytes { previous in
          completion(
            completionContext,
            current.bindMemory(to: UInt8.self).baseAddress,
            current.count,
            previous.bindMemory(to: UInt8.self).baseAddress,
            previous.count,
            1
          )
        }
      } else {
        completion(
          completionContext,
          current.bindMemory(to: UInt8.self).baseAddress,
          current.count,
          nil,
          0,
          0
        )
      }
    }
    return BONDRY_STATUS_OK
  } catch BondrySecretProviderError.secretNotFound {
    return BONDRY_STATUS_NOT_FOUND
  } catch BondrySecretProviderError.corruptStoredSecret {
    return BONDRY_STATUS_INVALID_DATA
  } catch {
    return BONDRY_STATUS_UNAVAILABLE
  }
}

private final class EgressHTTPCompletion: @unchecked Sendable {
  private let completion: BondryHTTPCompletionV1
  private let context: UnsafeMutableRawPointer

  init(completion: @escaping BondryHTTPCompletionV1, context: UnsafeMutableRawPointer) {
    self.completion = completion
    self.context = context
  }

  func succeed(_ response: BondryHTTPResponse) {
    guard let statusCode = UInt16(exactly: response.statusCode) else {
      fail(BondryHTTPTransportError.invalidResponse)
      return
    }
    let encodedHeaders = EncodedHeaders(response.headers)
    encodedHeaders.withUnsafeHeaders { headers in
      response.body.withUnsafeBytes { body in
        withConnectionEvidence(response.connection) { connection in
          var result = BondryHTTPResultV1(
            kind: BONDRY_HTTP_RESULT_RESPONSE_V1,
            error: 0,
            status_code: statusCode,
            headers: headers.baseAddress,
            header_count: headers.count,
            body: body.bindMemory(to: UInt8.self).baseAddress,
            body_length: body.count,
            connection: connection
          )
          completion(context, &result)
        }
      }
    }
  }

  func fail(_ error: any Error) {
    var result = BondryHTTPResultV1(
      kind: BONDRY_HTTP_RESULT_ERROR_V1,
      error: transportErrorCode(error),
      status_code: 0,
      headers: nil,
      header_count: 0,
      body: nil,
      body_length: 0,
      connection: missingConnectionEvidence()
    )
    completion(context, &result)
  }
}

private struct EncodedHeaders {
  private struct Offsets {
    let name: Range<Int>
    let value: Range<Int>
  }

  private let bytes: [UInt8]
  private let offsets: [Offsets]

  init(_ headers: [(String, String)]) {
    var bytes: [UInt8] = []
    var offsets: [Offsets] = []
    bytes.reserveCapacity(headers.reduce(0) { $0 + $1.0.utf8.count + $1.1.utf8.count })
    offsets.reserveCapacity(headers.count)
    for (name, value) in headers {
      let nameStart = bytes.count
      bytes.append(contentsOf: name.utf8)
      let valueStart = bytes.count
      bytes.append(contentsOf: value.utf8)
      offsets.append(
        Offsets(name: nameStart..<valueStart, value: valueStart..<bytes.count)
      )
    }
    self.bytes = bytes
    self.offsets = offsets
  }

  func withUnsafeHeaders<Result>(
    _ body: (UnsafeBufferPointer<BondryHTTPHeaderV1>) throws -> Result
  ) rethrows -> Result {
    try bytes.withUnsafeBufferPointer { storage in
      let headers = offsets.map { offset in
        BondryHTTPHeaderV1(
          name: storage.baseAddress?.advanced(by: offset.name.lowerBound),
          name_length: offset.name.count,
          value: storage.baseAddress?.advanced(by: offset.value.lowerBound),
          value_length: offset.value.count
        )
      }
      return try headers.withUnsafeBufferPointer(body)
    }
  }
}

private func decodeHTTPRequest(_ request: BondryHTTPRequestV1) throws -> BondryHTTPRequest {
  let method = try copyUTF8(request.method, count: request.method_length, allowEmpty: false)
  let rawURL = try copyUTF8(request.url, count: request.url_length, allowEmpty: false)
  guard let url = URL(string: rawURL), url.absoluteString == rawURL else {
    throw BondryHTTPTransportError.unsupportedEndpoint
  }
  let headers = try copyHeaders(request.headers, count: request.header_count)
  let body = try copyData(request.body, count: request.body_length, allowEmpty: true)
  let anchors = try copyAnchors(
    request.policy.additional_trust_anchors,
    count: request.policy.additional_trust_anchor_count
  )
  let policy = try BondryEndpointPolicy(
    allowHostnameLoopbackCleartext: try decodeFlag(
      request.policy.allow_hostname_loopback_cleartext
    ),
    allowPrivateCleartext: try decodeFlag(request.policy.allow_private_cleartext),
    allowLinkLocalCleartext: try decodeFlag(request.policy.allow_link_local_cleartext),
    additionalTrustAnchors: anchors
  )
  guard request.timeout_milliseconds <= UInt64(Int64.max) else {
    throw BondryHTTPTransportError.invalidLimits
  }
  return try BondryHTTPRequest(
    method: method,
    url: url,
    headers: headers,
    body: body,
    timeout: .milliseconds(Int64(request.timeout_milliseconds)),
    policy: policy,
    maximumResponseBodyBytes: request.max_response_body_bytes
  )
}

private func copyHeaders(
  _ pointer: UnsafePointer<BondryHTTPHeaderV1>?,
  count: Int
) throws -> [(String, String)] {
  guard count >= 0, count <= BondryHTTPRequest.maximumHeaders else {
    throw BondryHTTPTransportError.requestTooLarge
  }
  guard count == 0 || pointer != nil else {
    throw BondryHTTPTransportError.invalidResponse
  }
  return try UnsafeBufferPointer(start: pointer, count: count).map { header in
    (
      try copyUTF8(header.name, count: header.name_length, allowEmpty: false),
      try copyUTF8(header.value, count: header.value_length, allowEmpty: true)
    )
  }
}

private func copyAnchors(
  _ pointer: UnsafePointer<BondryByteSliceV1>?,
  count: Int
) throws -> [Data] {
  guard count >= 0, count <= BondryEndpointPolicy.maximumAdditionalTrustAnchors,
    count == 0 || pointer != nil
  else {
    throw BondryHTTPTransportError.invalidAdditionalTrustAnchors
  }
  return try UnsafeBufferPointer(start: pointer, count: count).map { anchor in
    try copyData(anchor.bytes, count: anchor.length, allowEmpty: false)
  }
}

private func copyUTF8(
  _ pointer: UnsafePointer<UInt8>?,
  count: Int,
  allowEmpty: Bool
) throws -> String {
  let data = try copyData(pointer, count: count, allowEmpty: allowEmpty)
  guard let value = String(data: data, encoding: .utf8) else {
    throw BondryHTTPTransportError.invalidResponse
  }
  return value
}

private func copyData(
  _ pointer: UnsafePointer<UInt8>?,
  count: Int,
  allowEmpty: Bool
) throws -> Data {
  guard count >= 0, allowEmpty || count > 0, count == 0 || pointer != nil else {
    throw BondryHTTPTransportError.invalidResponse
  }
  if count == 0 {
    return Data()
  }
  guard let pointer else {
    throw BondryHTTPTransportError.invalidResponse
  }
  return Data(bytes: pointer, count: count)
}

private func decodeFlag(_ value: UInt8) throws -> Bool {
  switch value {
  case 0: return false
  case 1: return true
  default: throw BondryHTTPTransportError.invalidResponse
  }
}

private func withConnectionEvidence<Result>(
  _ evidence: BondryConnectionEvidence,
  _ body: (BondryConnectionEvidenceV1) throws -> Result
) rethrows -> Result {
  switch evidence {
  case .missing:
    return try body(missingConnectionEvidence())
  case .tls(let serverName):
    let serverNameBytes = Array(serverName.utf8)
    return try serverNameBytes.withUnsafeBufferPointer { name in
      try body(
        BondryConnectionEvidenceV1(
          kind: BONDRY_CONNECTION_EVIDENCE_TLS_V1,
          server_name: name.baseAddress,
          server_name_length: name.count,
          ip_family: 0,
          ip: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
          port: 0,
          interface_scope: 0,
          has_interface_scope: 0
        )
      )
    }
  case .cleartext(let address, let port, let interfaceScope):
    var result = missingConnectionEvidence()
    result.kind = BONDRY_CONNECTION_EVIDENCE_CLEARTEXT_V1
    result.port = port
    result.interface_scope = interfaceScope ?? 0
    result.has_interface_scope = interfaceScope == nil ? 0 : 1
    let bytes: Data
    switch address {
    case .v4(let value):
      result.ip_family = BONDRY_IP_ADDRESS_V4_V1
      bytes = value
    case .v6(let value):
      result.ip_family = BONDRY_IP_ADDRESS_V6_V1
      bytes = value
    }
    _ = withUnsafeMutableBytes(of: &result.ip) { destination in
      bytes.copyBytes(to: destination)
    }
    return try body(result)
  }
}

private func missingConnectionEvidence() -> BondryConnectionEvidenceV1 {
  BondryConnectionEvidenceV1(
    kind: BONDRY_CONNECTION_EVIDENCE_MISSING_V1,
    server_name: nil,
    server_name_length: 0,
    ip_family: 0,
    ip: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    port: 0,
    interface_scope: 0,
    has_interface_scope: 0
  )
}

private func transportErrorCode(_ error: any Error) -> UInt32 {
  if error is CancellationError {
    return BONDRY_TRANSPORT_ERROR_DEADLINE_EXCEEDED_V1
  }
  guard let error = error as? BondryHTTPTransportError else {
    return BONDRY_TRANSPORT_ERROR_CONNECTION_FAILED_V1
  }
  switch error {
  case .unsupportedEndpoint: return BONDRY_TRANSPORT_ERROR_UNSUPPORTED_ENDPOINT_V1
  case .invalidLimits, .invalidAdditionalTrustAnchors:
    return BONDRY_TRANSPORT_ERROR_INVALID_LIMITS_V1
  case .requestTooLarge: return BONDRY_TRANSPORT_ERROR_REQUEST_TOO_LARGE_V1
  case .responseTooLarge: return BONDRY_TRANSPORT_ERROR_RESPONSE_TOO_LARGE_V1
  case .missingConnectionEvidence: return BONDRY_TRANSPORT_ERROR_MISSING_EVIDENCE_V1
  case .connectionEvidenceMismatch: return BONDRY_TRANSPORT_ERROR_EVIDENCE_MISMATCH_V1
  case .tlsIdentityMismatch: return BONDRY_TRANSPORT_ERROR_TLS_IDENTITY_MISMATCH_V1
  case .loopbackIntentRequired: return BONDRY_TRANSPORT_ERROR_LOOPBACK_INTENT_REQUIRED_V1
  case .privateCleartextDenied: return BONDRY_TRANSPORT_ERROR_PRIVATE_CLEARTEXT_DENIED_V1
  case .linkLocalCleartextDenied: return BONDRY_TRANSPORT_ERROR_LINK_LOCAL_CLEARTEXT_DENIED_V1
  case .linkLocalScopeRequired: return BONDRY_TRANSPORT_ERROR_LINK_LOCAL_SCOPE_REQUIRED_V1
  case .cleartextDenied: return BONDRY_TRANSPORT_ERROR_CLEARTEXT_DENIED_V1
  case .redirectDenied: return BONDRY_TRANSPORT_ERROR_REDIRECT_DENIED_V1
  case .deadlineExceeded: return BONDRY_TRANSPORT_ERROR_DEADLINE_EXCEEDED_V1
  case .connectionFailed: return BONDRY_TRANSPORT_ERROR_CONNECTION_FAILED_V1
  case .tlsFailed: return BONDRY_TRANSPORT_ERROR_TLS_FAILED_V1
  case .invalidResponse: return BONDRY_TRANSPORT_ERROR_INVALID_RESPONSE_V1
  }
}
