import Foundation
import Security
import XCTest

@testable import BondryApple

final class SecurityKeychainClientTests: XCTestCase {
  private let locator = KeychainItemLocator(
    configuration: try! KeychainDatabaseKeyConfiguration(
      service: "dev.bondry.database",
      account: "primary",
      accessGroup: "TEAMID.dev.bondry.shared"
    )
  )

  func testCopyQueryUsesDataProtectionKeychainWithoutSynchronization() {
    let query = SecurityKeychainClient.copyQuery(for: locator)

    XCTAssertEqual(query[kSecClass] as? String, kSecClassGenericPassword as String)
    XCTAssertEqual(query[kSecAttrService] as? String, "dev.bondry.database")
    XCTAssertEqual(query[kSecAttrAccount] as? String, "primary")
    XCTAssertEqual(query[kSecAttrAccessGroup] as? String, "TEAMID.dev.bondry.shared")
    XCTAssertEqual(query[kSecAttrSynchronizable] as? Bool, false)
    XCTAssertEqual(query[kSecUseDataProtectionKeychain] as? Bool, true)
    XCTAssertEqual(query[kSecReturnData] as? Bool, true)
    XCTAssertEqual(query[kSecMatchLimit] as? String, kSecMatchLimitOne as String)
    XCTAssertEqual(query.count, 8)
  }

  func testAddQueryUsesDeviceOnlyUnlockedAccessibility() {
    let data = Data(repeating: 0x88, count: DatabaseKeyMaterial.byteCount)
    let query = SecurityKeychainClient.addQuery(data: data, for: locator)

    XCTAssertEqual(
      query[kSecAttrAccessible] as? String,
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String
    )
    XCTAssertEqual(query[kSecValueData] as? Data, data)
    XCTAssertNil(query[kSecReturnData])
    XCTAssertEqual(query.count, 8)
  }

  func testQueryOmitsAccessGroupWhenNotConfigured() throws {
    let configuration = try KeychainDatabaseKeyConfiguration(
      service: "dev.bondry.database",
      account: "primary"
    )
    let query = SecurityKeychainClient.copyQuery(
      for: KeychainItemLocator(configuration: configuration)
    )

    XCTAssertNil(query[kSecAttrAccessGroup])
  }
}
