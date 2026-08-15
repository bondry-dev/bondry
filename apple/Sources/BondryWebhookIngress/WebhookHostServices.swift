import BondryApple
import CBondryWebhookIngress
import Foundation

final class WebhookHostServices: @unchecked Sendable {
  let secrets: any BondryWebhookSecretProvider

  init(secrets: any BondryWebhookSecretProvider) {
    self.secrets = secrets
  }
}

func makeWebhookSecretDescriptor(
  context: UnsafeMutableRawPointer
) -> BondryWebhookSecretProviderV1 {
  BondryWebhookSecretProviderV1(
    abi_version: BONDRY_WEBHOOK_SECRET_PROVIDER_ABI_VERSION_V1,
    struct_size: MemoryLayout<BondryWebhookSecretProviderV1>.size,
    context: context,
    retain: retainWebhookHost,
    release: releaseWebhookHost,
    resolve: resolveWebhookSecret
  )
}

private func retainWebhookHost(
  _ context: UnsafeMutableRawPointer?
) -> UnsafeMutableRawPointer? {
  guard let context else {
    return nil
  }
  _ = Unmanaged<WebhookHostServices>.fromOpaque(context).retain()
  return context
}

private func releaseWebhookHost(_ context: UnsafeMutableRawPointer?) {
  guard let context else {
    return
  }
  Unmanaged<WebhookHostServices>.fromOpaque(context).release()
}

private func resolveWebhookSecret(
  _ context: UnsafeMutableRawPointer?,
  _ reference: UnsafePointer<UInt8>?,
  _ referenceLength: Int,
  _ completion: BondryWebhookSecretResolutionV1?,
  _ completionContext: UnsafeMutableRawPointer?
) -> BondryStatus {
  guard let context, let completion, let completionContext else {
    return BONDRY_STATUS_NULL_POINTER
  }
  let secretReference: BondrySecretReference
  do {
    guard referenceLength > 0, let reference,
      let value = String(
        bytes: UnsafeBufferPointer(start: reference, count: referenceLength), encoding: .utf8)
    else {
      return BONDRY_STATUS_INVALID_DATA
    }
    secretReference = try BondrySecretReference(value)
  } catch {
    return BONDRY_STATUS_INVALID_DATA
  }
  let services = Unmanaged<WebhookHostServices>.fromOpaque(context).takeUnretainedValue()
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
