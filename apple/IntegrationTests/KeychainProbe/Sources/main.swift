import BondryApple
import Darwin
import Foundation
import Security

enum ProbeError: Error {
  case inconsistentKeys
  case cleanupFailed(OSStatus)
}

func deleteItem(service: String, account: String) -> OSStatus {
  SecItemDelete(
    [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: service,
      kSecAttrAccount: account,
      kSecAttrSynchronizable: false,
      kSecUseDataProtectionKeychain: true,
    ] as CFDictionary
  )
}

func fail(_ message: String) -> Never {
  FileHandle.standardError.write(Data("\(message)\n".utf8))
  exit(EXIT_FAILURE)
}

do {
  let service = "dev.bondry.keychain-probe.\(UUID().uuidString)"
  let account = "database-key"
  let configuration = try KeychainDatabaseKeyConfiguration(service: service, account: account)
  let provider = KeychainDatabaseKeyProvider(configuration: configuration)
  let created = try provider.loadOrCreate()
  var needsCleanup = true

  defer {
    if needsCleanup {
      _ = deleteItem(service: service, account: account)
    }
  }

  guard try provider.load() == created, try provider.loadOrCreate() == created else {
    throw ProbeError.inconsistentKeys
  }

  let deleteStatus = deleteItem(service: service, account: account)
  needsCleanup = false
  guard deleteStatus == errSecSuccess else {
    throw ProbeError.cleanupFailed(deleteStatus)
  }

  print("Data Protection Keychain round trip passed and the temporary item was removed.")
} catch {
  fail("Keychain probe failed: \(error)")
}
