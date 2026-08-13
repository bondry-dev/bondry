import XCTest

@testable import BondryApple

final class SecurityRandomByteGeneratorTests: XCTestCase {
  func testGeneratesRequestedNumberOfIndependentBytes() throws {
    let generator = SecurityRandomByteGenerator()
    let first = try generator.generate(count: DatabaseKeyMaterial.byteCount)
    let second = try generator.generate(count: DatabaseKeyMaterial.byteCount)

    XCTAssertEqual(first.count, DatabaseKeyMaterial.byteCount)
    XCTAssertEqual(second.count, DatabaseKeyMaterial.byteCount)
    XCTAssertNotEqual(first, second)
  }
}
