import BondryApple
import BondrySQLCipher
import Darwin
import Foundation
import Security

enum ProbeError: Error {
  case administrationMismatch
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
    let client = try store.createClient(named: "Keychain Probe")
    guard try store.clients() == [client] else {
      throw ProbeError.administrationMismatch
    }
    guard
      try store.addGrant(
        principalID: client.id,
        adapterID: "rest",
        capabilityID: "probe.read"
      ),
      try store.grants(for: client.id)
        == [
          BondryCapabilityGrant(
            principalID: client.id,
            adapterID: "rest",
            capabilityID: "probe.read"
          )
        ]
    else {
      throw ProbeError.administrationMismatch
    }
    let issued = try store.issueToken(for: client.id, label: "Initial")
    guard try store.authenticate(token: issued).id == client.id,
      try store.tokens(for: client.id).count == 1
    else {
      throw ProbeError.administrationMismatch
    }
    let replacement = try store.rotateToken(issued.metadata.id, label: "Rotated")
    do {
      _ = try store.authenticate(token: issued)
      throw ProbeError.administrationMismatch
    } catch BondryEncryptedStoreError.authenticationRejected {
    }
    guard try store.authenticate(token: replacement).id == client.id,
      try store.revokeToken(replacement.metadata.id),
      try store.tokens(for: client.id).count == 2,
      try store.recentAuditEvents(limit: 10).isEmpty
    else {
      throw ProbeError.administrationMismatch
    }
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

  print("Keychain, SQLCipher, and authentication round trips passed; temporary data was removed.")
} catch {
  fail("Keychain probe failed: \(error)")
}
