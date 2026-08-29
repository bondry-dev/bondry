import Bondry
import Foundation
import XCTest

final class BondryRuntimeLinuxTests: XCTestCase {
  func testPersistsEncryptedRuntimeState() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
      UUID().uuidString,
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: directory) }
    let databaseURL = directory.appendingPathComponent("runtime.sqlite3")
    let key = try DatabaseKeyMaterial(
      rawRepresentation: Data(repeating: 0x6D, count: DatabaseKeyMaterial.byteCount)
    )

    var runtime: BondryRuntime? = try BondryRuntime.open(at: databaseURL, key: key)
    try runtime?.checkHealth()
    _ = try runtime?.createClient(named: "Linux Test Client")
    XCTAssertEqual(try runtime?.clients().map(\.name), ["Linux Test Client"])
    weak let closedRuntime = runtime
    runtime = nil
    XCTAssertNil(closedRuntime)

    var reopened: BondryRuntime? = try BondryRuntime.open(at: databaseURL, key: key)
    XCTAssertEqual(try reopened?.clients().map(\.name), ["Linux Test Client"])
    weak let closedReopened = reopened
    reopened = nil
    XCTAssertNil(closedReopened)
  }

  func testRejectsWrongDatabaseKey() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
      UUID().uuidString,
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: directory) }
    let databaseURL = directory.appendingPathComponent("runtime.sqlite3")
    let firstKey = try key(byte: 0x31)
    let wrongKey = try key(byte: 0x32)

    var runtime: BondryRuntime? = try BondryRuntime.open(at: databaseURL, key: firstKey)
    try runtime?.checkHealth()
    weak let closedRuntime = runtime
    runtime = nil
    XCTAssertNil(closedRuntime)

    XCTAssertThrowsError(try BondryRuntime.open(at: databaseURL, key: wrongKey)) {
      XCTAssertEqual($0 as? BondryRuntimeError, .invalidDatabaseKey)
    }
  }

  func testValidatesAndRedactsDatabaseKeyMaterial() throws {
    XCTAssertThrowsError(try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0, count: 31)))
    {
      XCTAssertEqual($0 as? BondryRuntimeError, .invalidDatabaseKey)
    }
    let key = try key(byte: 0x51)

    XCTAssertEqual(String(describing: key), "DatabaseKeyMaterial(<redacted>)")
    XCTAssertEqual(String(reflecting: key), "DatabaseKeyMaterial(<redacted>)")
  }

  private func key(byte: UInt8) throws -> DatabaseKeyMaterial {
    try DatabaseKeyMaterial(
      rawRepresentation: Data(repeating: byte, count: DatabaseKeyMaterial.byteCount)
    )
  }
}
