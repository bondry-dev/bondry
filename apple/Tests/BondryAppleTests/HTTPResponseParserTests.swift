import Foundation
import XCTest

@testable import BondryApple

final class HTTPResponseParserTests: XCTestCase {
  private let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"

  func testChunkedResponseAtEveryFragmentBoundary() throws {
    let response = Data((head + "1\r\na\r\n2\r\nbc\r\n3\r\ndef\r\n0\r\n\r\n").utf8)
    for split in 1..<response.count {
      var parser = BoundedHTTP1ResponseParser(requestMethod: "GET", maximumBodyBytes: 6)
      XCTAssertNil(try parser.consume(Data(response[..<split]), isComplete: false))
      let parsed = try XCTUnwrap(
        parser.consume(Data(response[split...]), isComplete: true)
      )
      XCTAssertEqual(parsed.statusCode, 200)
      XCTAssertEqual(parsed.body, Data("abcdef".utf8))
    }
  }

  func testManySmallChunksWithCoalescedAndFragmentedReads() throws {
    let count = 16 * 1_024
    let response = Data((head + String(repeating: "1\r\nx\r\n", count: count) + "0\r\n\r\n").utf8)
    for fragmentSize in [13, 16 * 1_024, response.count] {
      var parser = BoundedHTTP1ResponseParser(requestMethod: "GET", maximumBodyBytes: count)
      var parsed: ParsedHTTPResponse?
      for offset in stride(from: 0, to: response.count, by: fragmentSize) {
        let end = min(offset + fragmentSize, response.count)
        parsed = try parser.consume(Data(response[offset..<end]), isComplete: end == response.count)
      }
      XCTAssertEqual(parsed?.body, Data(repeating: 120, count: count))
    }
  }

  func testRejectsInvalidFramingAfterCompleteChunks() throws {
    for suffix in ["g\r\n", "1\r\nx!!", "0\r\n\r\nextra", "0\r\nX-Trailer: value\r\n\r\n"] {
      for splitRead in [false, true] {
        var parser = BoundedHTTP1ResponseParser(requestMethod: "GET", maximumBodyBytes: 6)
        let prefix = head + "1\r\na\r\n2\r\nbc\r\n"
        if splitRead {
          XCTAssertNil(try parser.consume(Data(prefix.utf8), isComplete: false))
        }
        XCTAssertThrowsError(
          try parser.consume(Data(((splitRead ? "" : prefix) + suffix).utf8), isComplete: true)
        ) { error in
          XCTAssertEqual(error as? BondryHTTPTransportError, .invalidResponse)
        }
      }
    }
  }

  func testEnforcesAggregateDecodedBodyLimitAcrossReads() throws {
    var parser = BoundedHTTP1ResponseParser(requestMethod: "GET", maximumBodyBytes: 3)
    XCTAssertNil(try parser.consume(Data((head + "2\r\nab\r\n").utf8), isComplete: false))
    XCTAssertThrowsError(try parser.consume(Data("2\r\ncd\r\n0\r\n\r\n".utf8), isComplete: true)) {
      error in
      XCTAssertEqual(error as? BondryHTTPTransportError, .responseTooLarge)
    }
  }
}
