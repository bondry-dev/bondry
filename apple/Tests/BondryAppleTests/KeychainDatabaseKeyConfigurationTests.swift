import XCTest

@testable import BondryApple

final class KeychainDatabaseKeyConfigurationTests: XCTestCase {
  func testAcceptsValidConfiguration() throws {
    let configuration = try KeychainDatabaseKeyConfiguration(
      service: "dev.bondry.database",
      account: "primary",
      accessGroup: "TEAMID.dev.bondry.shared"
    )

    XCTAssertEqual(configuration.service, "dev.bondry.database")
    XCTAssertEqual(configuration.account, "primary")
    XCTAssertEqual(configuration.accessGroup, "TEAMID.dev.bondry.shared")
  }

  func testRejectsEmptyRequiredValues() {
    XCTAssertThrowsError(
      try KeychainDatabaseKeyConfiguration(service: " ", account: "primary")
    ) { error in
      XCTAssertEqual(error as? KeychainDatabaseKeyError, .invalidConfiguration(.service))
    }

    XCTAssertThrowsError(
      try KeychainDatabaseKeyConfiguration(service: "dev.bondry.database", account: "\n")
    ) { error in
      XCTAssertEqual(error as? KeychainDatabaseKeyError, .invalidConfiguration(.account))
    }
  }

  func testRejectsEmptyAccessGroup() {
    XCTAssertThrowsError(
      try KeychainDatabaseKeyConfiguration(
        service: "dev.bondry.database",
        account: "primary",
        accessGroup: "\t"
      )
    ) { error in
      XCTAssertEqual(error as? KeychainDatabaseKeyError, .invalidConfiguration(.accessGroup))
    }
  }
}
