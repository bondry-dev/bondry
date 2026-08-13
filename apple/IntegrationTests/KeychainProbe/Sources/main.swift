import BondryApple
import BondrySQLCipher
import Darwin
import Foundation
import Security

enum ProbeError: Error {
  case inconsistentKeys
  case plaintextDatabase
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
  let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
  var needsDirectoryCleanup = true
  defer {
    if needsDirectoryCleanup {
      try? FileManager.default.removeItem(at: directory)
    }
  }
  var needsCleanup = true

  defer {
    if needsCleanup {
      _ = deleteItem(service: service, account: account)
    }
  }

  guard try provider.load() == created, try provider.loadOrCreate() == created else {
    throw ProbeError.inconsistentKeys
  }

  let databaseURL = directory.appendingPathComponent("bondry.db")
  do {
    let store = try BondryEncryptedStore.open(at: databaseURL, key: created)
    try store.checkHealth()
  }
  let databaseBytes = try Data(contentsOf: databaseURL)
  guard !databaseBytes.starts(with: Data("SQLite format 3\0".utf8)) else {
    throw ProbeError.plaintextDatabase
  }
  try FileManager.default.removeItem(at: directory)
  needsDirectoryCleanup = false

  let deleteStatus = deleteItem(service: service, account: account)
  needsCleanup = false
  guard deleteStatus == errSecSuccess else {
    throw ProbeError.cleanupFailed(deleteStatus)
  }

  print("Data Protection Keychain round trip passed and the temporary item was removed.")
} catch {
  fail("Keychain probe failed: \(error)")
}
