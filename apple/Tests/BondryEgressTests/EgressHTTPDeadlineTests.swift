import BondryApple
import CBondryEgress
import Foundation
import XCTest

@testable import BondryEgress

final class EgressHTTPDeadlineTests: XCTestCase {
  func testPreservesRemainingDeadlineBelowConfigurationMinimum() throws {
    for milliseconds: UInt64 in [1, 999, 1_000, 120_000] {
      let request = try decodeRequest(timeoutMilliseconds: milliseconds)
      XCTAssertEqual(request.timeout, .milliseconds(Int64(milliseconds)))
    }
  }

  func testRejectsExpiredAndUnboundedRemainingDeadlines() {
    for milliseconds: UInt64 in [0, 120_001, UInt64.max] {
      XCTAssertThrowsError(try decodeRequest(timeoutMilliseconds: milliseconds)) { error in
        XCTAssertEqual(error as? BondryHTTPTransportError, .invalidLimits)
      }
    }
  }

  func testPublicRequestPreservesMinimumConfiguredTimeout() throws {
    let url = try XCTUnwrap(URL(string: "http://127.0.0.1/"))
    XCTAssertThrowsError(
      try BondryHTTPRequest(method: "GET", url: url, timeout: .milliseconds(999))
    ) {
      error in
      XCTAssertEqual(error as? BondryHTTPTransportError, .invalidLimits)
    }
    XCTAssertNoThrow(try BondryHTTPRequest(method: "GET", url: url, timeout: .seconds(1)))
  }

  private func decodeRequest(timeoutMilliseconds: UInt64) throws -> BondryHTTPRequest {
    let method = Array("GET".utf8)
    let url = Array("http://127.0.0.1/".utf8)
    return try method.withUnsafeBufferPointer { method in
      try url.withUnsafeBufferPointer { url in
        var request = BondryHTTPRequestV1()
        request.method = method.baseAddress
        request.method_length = method.count
        request.url = url.baseAddress
        request.url_length = url.count
        request.timeout_milliseconds = timeoutMilliseconds
        request.max_response_body_bytes = 4 * 1_024
        return try decodeHTTPRequest(request)
      }
    }
  }
}
