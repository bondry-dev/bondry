import BondryCredentials
import Foundation
import XCTest

final class BondryCredentialStoreLinuxTests: XCTestCase {
  func testRoundTripsCredentialThroughRustProvider() throws {
    let directory = try makePrivateDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try BondryCredentialStore.openUnixFileStore(at: directory)
    let id = try BondryCredentialID("database-key")
    let value = Data(repeating: 0xA5, count: 32)

    XCTAssertEqual(
      try store.capabilities(),
      BondryCredentialStoreCapabilities(
        protection: .accessControlled,
        access: .readWrite,
        supportsUnattendedAccess: true
      )
    )
    XCTAssertNil(try store.load(id))
    try store.store(value, for: id)
    XCTAssertEqual(try store.load(id), value)
    XCTAssertTrue(try store.delete(id))
    XCTAssertFalse(try store.delete(id))
  }

  func testRejectsPermissiveCredentialDirectory() throws {
    let directory = try makePrivateDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o750],
      ofItemAtPath: directory.path
    )

    XCTAssertThrowsError(try BondryCredentialStore.openUnixFileStore(at: directory)) {
      XCTAssertEqual($0 as? BondryCredentialStoreError, .unsafeStorage)
    }
  }

  private func makePrivateDirectory() throws -> URL {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
      UUID().uuidString,
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700]
    )
    return directory
  }
}
