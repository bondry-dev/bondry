import Bondry
import BondryApple
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
    let runtime = try BondryRuntime.open(at: databaseURL, key: created)
    try runtime.checkHealth()
    let client = try runtime.createClient(named: "Keychain Probe")
    guard try runtime.clients() == [client] else {
      throw ProbeError.administrationMismatch
    }
    guard
      try runtime.addGrant(
        principalID: client.id,
        adapterID: "rest",
        capabilityID: "probe.read"
      ),
      try runtime.grants(for: client.id)
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
    let issued = try runtime.issueToken(for: client.id, label: "Initial")
    guard try runtime.authenticate(token: issued).id == client.id,
      try runtime.tokens(for: client.id).count == 1
    else {
      throw ProbeError.administrationMismatch
    }
    let replacement = try runtime.rotateToken(issued.metadata.id, label: "Rotated")
    do {
      _ = try runtime.authenticate(token: issued)
      throw ProbeError.administrationMismatch
    } catch BondryRuntimeError.authenticationRejected {
    }
    guard try runtime.authenticate(token: replacement).id == client.id,
      try runtime.tokens(for: client.id).count == 2
    else {
      throw ProbeError.administrationMismatch
    }
    try runtime.registerCapability(
      BondryCapability(
        id: "probe.read",
        summary: "Read probe state",
        effect: .readOnly
      )
    ) { invocation in
      guard invocation.principal.id == client.id,
        invocation.adapterID == "rest",
        invocation.capabilityID == "probe.read",
        invocation.inputJSON == Data(#"{"detail":true}"#.utf8)
      else {
        throw ProbeError.administrationMismatch
      }
      return Data(#"{"ready":true}"#.utf8)
    }
    guard try runtime.capabilities().map(\.id) == ["probe.read"],
      try await runtime.dispatch(
        invocationID: "probe-request",
        adapterID: "rest",
        token: replacement,
        capabilityID: "probe.read",
        inputJSON: Data(#"{"detail":true}"#.utf8)
      ) == Data(#"{"ready":true}"#.utf8),
      try runtime.recentAuditEvents(limit: 10).map(\.outcome) == [.succeeded, .started],
      try runtime.unregisterCapability("probe.read"),
      try runtime.revokeToken(replacement.metadata.id)
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

  print(
    "Keychain, SQLCipher, and capability dispatch round trips passed; "
      + "temporary data was removed."
  )
} catch {
  fail("Keychain probe failed: \(error)")
}
