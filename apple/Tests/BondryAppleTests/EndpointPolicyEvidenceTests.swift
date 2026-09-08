import Foundation
import XCTest

@testable import BondryApple

final class EndpointPolicyEvidenceTests: XCTestCase {
  func testRejectsMalformedPublicIPAddressCases() throws {
    let url = try XCTUnwrap(URL(string: "http://localhost/"))
    let addresses: [BondryIPAddress] = [
      .v4(Data()),
      .v4(Data([127])),
      .v4(Data([127, 0, 0])),
      .v4(Data([127, 0, 0, 1, 0])),
      .v6(Data()),
      .v6(Data(repeating: 0, count: 10)),
      .v6(Data(repeating: 0, count: 15)),
      .v6(Data(repeating: 0, count: 17)),
    ]

    for address in addresses {
      XCTAssertThrowsError(
        try BondryEndpointPolicy().verify(
          url: url,
          evidence: .cleartext(address: address, port: 80, interfaceScope: nil)
        )
      ) { error in
        XCTAssertEqual(error as? BondryHTTPTransportError, .missingConnectionEvidence)
      }
    }
  }

  func testAcceptsValidDirectAndSlicedAddressCases() throws {
    let url = try XCTUnwrap(URL(string: "http://localhost/"))
    let ipv4 = Data([42, 127, 0, 0, 1]).dropFirst()
    let ipv6 = Data([42] + Array(repeating: 0, count: 15) + [1]).dropFirst()
    let mapped = Data([42] + Array(repeating: 0, count: 10) + [255, 255, 127, 0, 0, 1])
      .dropFirst()
    XCTAssertNotEqual(ipv4.startIndex, 0)
    XCTAssertNotEqual(ipv6.startIndex, 0)

    for address in [BondryIPAddress.v4(ipv4), .v6(ipv6), .v6(mapped)] {
      XCTAssertNoThrow(
        try BondryEndpointPolicy().verify(
          url: url,
          evidence: .cleartext(address: address, port: 80, interfaceScope: nil)
        )
      )
    }
  }

  func testLinkLocalRequiresNonzeroInterfaceScope() throws {
    let url = try XCTUnwrap(URL(string: "http://169.254.1.2/"))
    let policy = BondryEndpointPolicy(allowLinkLocalCleartext: true)
    let address = BondryIPAddress.v4(Data([169, 254, 1, 2]))

    for scope: UInt32? in [nil, 0] {
      XCTAssertThrowsError(
        try policy.verify(
          url: url,
          evidence: .cleartext(address: address, port: 80, interfaceScope: scope)
        )
      ) { error in
        XCTAssertEqual(error as? BondryHTTPTransportError, .linkLocalScopeRequired)
      }
    }
    XCTAssertNoThrow(
      try policy.verify(
        url: url,
        evidence: .cleartext(address: address, port: 80, interfaceScope: 1)
      )
    )
  }
}
