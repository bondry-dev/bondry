import CBondryRuntime
import Foundation

extension BondryRuntime {
  public func registerCapability(
    _ capability: BondryCapability,
    handler: @escaping BondryCapabilityHandler
  ) throws {
    let context = Unmanaged.passRetained(CapabilityHandlerBox(handler: handler)).toOpaque()
    let status = withUTF8Bytes(capability.id) { idBytes, idLength in
      withUTF8Bytes(capability.summary) { summaryBytes, summaryLength in
        withDataBytes(capability.inputSchema.jsonRepresentation) { schemaBytes, schemaLength in
          bondry_capability_register_with_schema_v1(
            handle,
            idBytes,
            idLength,
            summaryBytes,
            summaryLength,
            capability.effect.cValue,
            schemaBytes,
            schemaLength,
            context,
            invokeSwiftCapability,
            releaseSwiftCapability
          )
        }
      }
    }
    guard status == BONDRY_STATUS_OK else {
      Unmanaged<CapabilityHandlerBox>.fromOpaque(context).release()
      throw BondryRuntimeError(status: status)
    }
  }

  @discardableResult
  public func unregisterCapability(_ capabilityID: String) throws -> Bool {
    var changed: UInt8 = 0
    let status = withUTF8Bytes(capabilityID) { idBytes, idLength in
      bondry_capability_unregister_v1(handle, idBytes, idLength, &changed)
    }
    try requireSuccess(status)
    guard changed <= 1 else {
      throw BondryRuntimeError.invalidData
    }
    return changed == 1
  }

  public func capabilities() throws -> [BondryCapability] {
    let data = try queryBytes { output, capacity, length in
      bondry_capabilities_json_v1(handle, output, capacity, length)
    }
    return try decodeCapabilities(data)
  }

  public func capabilities(
    authorizedFor principal: BondryPrincipal,
    adapterID: String
  ) throws -> [BondryCapability] {
    let data = try withUTF8Bytes(principal.id) { principalBytes, principalLength in
      try withUTF8Bytes(adapterID) { adapterBytes, adapterLength in
        try queryBytes { output, capacity, length in
          bondry_capabilities_discover_json_v1(
            handle,
            principalBytes,
            principalLength,
            principal.kind.cValue,
            adapterBytes,
            adapterLength,
            output,
            capacity,
            length
          )
        }
      }
    }
    return try decodeCapabilities(data)
  }

  private func decodeCapabilities(_ data: Data) throws -> [BondryCapability] {
    let value: Any
    do {
      value = try JSONSerialization.jsonObject(with: data)
    } catch {
      throw BondryRuntimeError.invalidData
    }
    guard let records = value as? [[String: Any]] else {
      throw BondryRuntimeError.invalidData
    }
    return try records.map(decodeCapability)
  }

  public func dispatch(
    invocationID: String = UUID().uuidString,
    adapterID: String,
    token: String,
    capabilityID: String,
    inputJSON: Data
  ) async throws -> Data {
    try Task.checkCancellation()
    return try await withCheckedThrowingContinuation { continuation in
      let context = Unmanaged.passRetained(
        DispatchContinuationBox(continuation: continuation)
      ).toOpaque()
      let status = withUTF8Bytes(token) { tokenBytes, tokenLength in
        startDispatch(
          invocationID: invocationID,
          adapterID: adapterID,
          tokenBytes: tokenBytes,
          tokenLength: tokenLength,
          capabilityID: capabilityID,
          inputJSON: inputJSON,
          completionContext: context
        )
      }
      handleImmediateDispatchFailure(status, context: context)
    }
  }

  /// Dispatches for a principal whose identity was established by the host platform.
  public func dispatchPlatformInvocation(
    invocationID: String = UUID().uuidString,
    adapterID: String,
    principal: BondryPrincipal,
    capabilityID: String,
    inputJSON: Data
  ) async throws -> Data {
    try Task.checkCancellation()
    return try await withCheckedThrowingContinuation { continuation in
      let context = Unmanaged.passRetained(
        DispatchContinuationBox(continuation: continuation)
      ).toOpaque()
      let status = withUTF8Bytes(invocationID) { invocationBytes, invocationLength in
        withUTF8Bytes(adapterID) { adapterBytes, adapterLength in
          withUTF8Bytes(principal.id) { principalBytes, principalLength in
            withUTF8Bytes(capabilityID) { capabilityBytes, capabilityLength in
              withDataBytes(inputJSON) { inputBytes, inputLength in
                bondry_dispatch_principal_v1(
                  handle,
                  invocationBytes,
                  invocationLength,
                  adapterBytes,
                  adapterLength,
                  principalBytes,
                  principalLength,
                  principal.kind.cValue,
                  capabilityBytes,
                  capabilityLength,
                  inputBytes,
                  inputLength,
                  receiveSwiftDispatch,
                  context
                )
              }
            }
          }
        }
      }
      handleImmediateDispatchFailure(status, context: context)
    }
  }

  public func dispatch(
    invocationID: String = UUID().uuidString,
    adapterID: String,
    token: BondryIssuedToken,
    capabilityID: String,
    inputJSON: Data
  ) async throws -> Data {
    try Task.checkCancellation()
    return try await withCheckedThrowingContinuation { continuation in
      let context = Unmanaged.passRetained(
        DispatchContinuationBox(continuation: continuation)
      ).toOpaque()
      let status = token.withUnsafeSecretBytes { tokenBuffer in
        let bytes = tokenBuffer.bindMemory(to: UInt8.self)
        return startDispatch(
          invocationID: invocationID,
          adapterID: adapterID,
          tokenBytes: bytes.baseAddress,
          tokenLength: bytes.count,
          capabilityID: capabilityID,
          inputJSON: inputJSON,
          completionContext: context
        )
      }
      handleImmediateDispatchFailure(status, context: context)
    }
  }

  private func startDispatch(
    invocationID: String,
    adapterID: String,
    tokenBytes: UnsafePointer<UInt8>?,
    tokenLength: Int,
    capabilityID: String,
    inputJSON: Data,
    completionContext: UnsafeMutableRawPointer
  ) -> BondryStatus {
    withUTF8Bytes(invocationID) { invocationBytes, invocationLength in
      withUTF8Bytes(adapterID) { adapterBytes, adapterLength in
        withUTF8Bytes(capabilityID) { capabilityBytes, capabilityLength in
          withDataBytes(inputJSON) { inputBytes, inputLength in
            bondry_dispatch_token_v1(
              handle,
              invocationBytes,
              invocationLength,
              adapterBytes,
              adapterLength,
              tokenBytes,
              tokenLength,
              capabilityBytes,
              capabilityLength,
              inputBytes,
              inputLength,
              receiveSwiftDispatch,
              completionContext
            )
          }
        }
      }
    }
  }

  private func handleImmediateDispatchFailure(
    _ status: BondryStatus,
    context: UnsafeMutableRawPointer
  ) {
    guard status != BONDRY_STATUS_OK else {
      return
    }
    let box = Unmanaged<DispatchContinuationBox>.fromOpaque(context).takeRetainedValue()
    box.continuation.resume(throwing: BondryRuntimeError(status: status))
  }
}

private func decodeCapability(_ record: [String: Any]) throws -> BondryCapability {
  guard let id = record["id"] as? String,
    let summary = record["summary"] as? String,
    let effectValue = record["effect"] as? String,
    let schema = record["input_schema"] as? [String: Any]
  else {
    throw BondryRuntimeError.invalidData
  }
  let effect: BondryCapabilityEffect
  switch effectValue {
  case "read_only": effect = .readOnly
  case "mutating": effect = .mutating
  default: throw BondryRuntimeError.invalidData
  }
  let schemaData: Data
  do {
    schemaData = try JSONSerialization.data(
      withJSONObject: schema,
      options: [.sortedKeys, .withoutEscapingSlashes]
    )
  } catch {
    throw BondryRuntimeError.invalidData
  }
  return BondryCapability(
    id: id,
    summary: summary,
    effect: effect,
    inputSchema: try BondryCapabilityInputSchema(jsonRepresentation: schemaData)
  )
}

private final class CapabilityHandlerBox: Sendable {
  let handler: BondryCapabilityHandler

  init(handler: @escaping BondryCapabilityHandler) {
    self.handler = handler
  }
}

// The C callback and its context remain valid until exactly one completion call.
private final class CapabilityCompletionBox: @unchecked Sendable {
  let completion: BondryCapabilityCompletionV1
  let context: UnsafeMutableRawPointer

  init(completion: @escaping BondryCapabilityCompletionV1, context: UnsafeMutableRawPointer) {
    self.completion = completion
    self.context = context
  }

  func succeed(with output: Data) {
    withDataBytes(output) { bytes, length in
      completion(context, BONDRY_HANDLER_RESULT_SUCCEEDED_V1, bytes, length)
    }
  }

  func fail(with code: String) {
    withUTF8Bytes(code) { bytes, length in
      completion(context, BONDRY_HANDLER_RESULT_FAILED_V1, bytes, length)
    }
  }
}

private final class DispatchContinuationBox: Sendable {
  let continuation: CheckedContinuation<Data, any Error>

  init(continuation: CheckedContinuation<Data, any Error>) {
    self.continuation = continuation
  }
}

private func invokeSwiftCapability(
  _ context: UnsafeMutableRawPointer?,
  _ invocation: UnsafePointer<BondryInvocationV1>?,
  _ completion: BondryCapabilityCompletionV1?,
  _ completionContext: UnsafeMutableRawPointer?
) {
  guard let context, let invocation, let completion, let completionContext else {
    return
  }
  let handler = Unmanaged<CapabilityHandlerBox>.fromOpaque(context).takeUnretainedValue()
  let completionBox = CapabilityCompletionBox(
    completion: completion,
    context: completionContext
  )
  let value: BondryCapabilityInvocation
  do {
    value = try BondryCapabilityInvocation(record: invocation.pointee)
  } catch {
    completionBox.fail(with: "invalid_invocation")
    return
  }
  Task {
    do {
      completionBox.succeed(with: try await handler.handler(value))
    } catch let error as BondryCapabilityHandlerError {
      switch error {
      case .failed(let code):
        completionBox.fail(with: code)
      }
    } catch is CancellationError {
      completionBox.fail(with: "cancelled")
    } catch {
      completionBox.fail(with: "handler_failed")
    }
  }
}

private func releaseSwiftCapability(_ context: UnsafeMutableRawPointer?) {
  guard let context else {
    return
  }
  Unmanaged<CapabilityHandlerBox>.fromOpaque(context).release()
}

private func receiveSwiftDispatch(
  _ context: UnsafeMutableRawPointer?,
  _ result: UnsafePointer<BondryDispatchResultV1>?
) {
  guard let context else {
    return
  }
  let box = Unmanaged<DispatchContinuationBox>.fromOpaque(context).takeRetainedValue()
  guard let result else {
    box.continuation.resume(throwing: BondryRuntimeError.invalidData)
    return
  }
  do {
    box.continuation.resume(returning: try decodeDispatchResult(result.pointee))
  } catch {
    box.continuation.resume(throwing: error)
  }
}

private func decodeDispatchResult(_ result: BondryDispatchResultV1) throws -> Data {
  let detail: String?
  switch result.has_detail_code {
  case 0:
    detail = nil
  case 1:
    detail = try decodeCString(result.detail_code)
  default:
    throw BondryRuntimeError.invalidData
  }

  switch (result.outcome, detail) {
  case (BONDRY_DISPATCH_OUTCOME_SUCCEEDED_V1, nil):
    guard let output = result.output_json, result.output_json_length > 0 else {
      throw BondryRuntimeError.invalidData
    }
    return Data(bytes: output, count: result.output_json_length)
  case (BONDRY_DISPATCH_OUTCOME_CAPABILITY_NOT_FOUND_V1, nil):
    throw BondryDispatchError.capabilityNotFound
  case (BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1, "not_granted"):
    throw BondryDispatchError.accessDenied(.notGranted)
  case (BONDRY_DISPATCH_OUTCOME_ACCESS_DENIED_V1, "policy_unavailable"):
    throw BondryDispatchError.accessDenied(.policyUnavailable)
  case (BONDRY_DISPATCH_OUTCOME_INVALID_INPUT_V1, nil):
    throw BondryDispatchError.invalidInput
  case (BONDRY_DISPATCH_OUTCOME_AUDIT_UNAVAILABLE_V1, nil):
    throw BondryDispatchError.auditUnavailable
  case (BONDRY_DISPATCH_OUTCOME_HANDLER_FAILED_V1, .some(let code)):
    throw BondryDispatchError.handlerFailed(code: code)
  default:
    throw BondryRuntimeError.invalidData
  }
}

extension BondryCapabilityEffect {
  fileprivate var cValue: UInt32 {
    switch self {
    case .readOnly: BONDRY_CAPABILITY_EFFECT_READ_ONLY_V1
    case .mutating: BONDRY_CAPABILITY_EFFECT_MUTATING_V1
    }
  }
}

extension BondryPrincipalKind {
  fileprivate var cValue: UInt32 {
    switch self {
    case .user: BONDRY_PRINCIPAL_KIND_USER_V1
    case .application: BONDRY_PRINCIPAL_KIND_APPLICATION_V1
    case .system: BONDRY_PRINCIPAL_KIND_SYSTEM_V1
    }
  }
}

private func withDataBytes<Result>(
  _ data: Data,
  _ body: (UnsafePointer<UInt8>, Int) throws -> Result
) rethrows -> Result {
  if data.isEmpty {
    var empty: UInt8 = 0
    return try withUnsafePointer(to: &empty) { pointer in
      try body(pointer, 0)
    }
  }
  return try data.withUnsafeBytes { buffer in
    try body(buffer.bindMemory(to: UInt8.self).baseAddress!, buffer.count)
  }
}
