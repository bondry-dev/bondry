import Foundation
import XCTest

@testable import BondryApple

final class DatabaseKeyMaterialTests: XCTestCase {
  func testAcceptsExactlyThirtyTwoBytes() throws {
    let data = Data(repeating: 0xA5, count: DatabaseKeyMaterial.byteCount)
    let key = try DatabaseKeyMaterial(rawRepresentation: data)

    XCTAssertEqual(key.rawRepresentation, data)
  }

  func testRejectsIncorrectLengths() {
    for count in [0, 31, 33, 64] {
      XCTAssertThrowsError(
        try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0, count: count))
      ) { error in
        XCTAssertEqual(error as? KeychainDatabaseKeyError, .invalidKeyLength(count))
      }
    }
  }

  func testDebugDescriptionRedactsKeyBytes() throws {
    let data = Data(repeating: 0xAB, count: DatabaseKeyMaterial.byteCount)
    let key = try DatabaseKeyMaterial(rawRepresentation: data)

    XCTAssertEqual(String(describing: key), "DatabaseKeyMaterial(<redacted>)")
    XCTAssertEqual(String(reflecting: key), "DatabaseKeyMaterial(<redacted>)")
    XCTAssertFalse(
      String(reflecting: key).lowercased().contains(String(repeating: "ab", count: 32))
    )
  }
}
