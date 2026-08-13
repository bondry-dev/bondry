import Foundation
import Security

struct SecurityKeychainClient: KeychainClient {
  func copyData(for locator: KeychainItemLocator) -> KeychainReadResult {
    var result: CFTypeRef?
    let status = SecItemCopyMatching(Self.copyQuery(for: locator) as CFDictionary, &result)

    switch status {
    case errSecSuccess:
      guard let data = result as? Data else {
        return .unexpectedResult
      }
      return .found(data)
    case errSecItemNotFound:
      return .missing
    default:
      return .failure(status)
    }
  }

  func add(data: Data, for locator: KeychainItemLocator) -> OSStatus {
    SecItemAdd(Self.addQuery(data: data, for: locator) as CFDictionary, nil)
  }

  static func copyQuery(for locator: KeychainItemLocator) -> [CFString: Any] {
    var query = baseQuery(for: locator)
    query[kSecReturnData] = true
    query[kSecMatchLimit] = kSecMatchLimitOne
    return query
  }

  static func addQuery(data: Data, for locator: KeychainItemLocator) -> [CFString: Any] {
    var query = baseQuery(for: locator)
    query[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    query[kSecValueData] = data
    return query
  }

  private static func baseQuery(for locator: KeychainItemLocator) -> [CFString: Any] {
    var query: [CFString: Any] = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: locator.service,
      kSecAttrAccount: locator.account,
      kSecAttrSynchronizable: false,
      kSecUseDataProtectionKeychain: true,
    ]

    if let accessGroup = locator.accessGroup {
      query[kSecAttrAccessGroup] = accessGroup
    }

    return query
  }
}
