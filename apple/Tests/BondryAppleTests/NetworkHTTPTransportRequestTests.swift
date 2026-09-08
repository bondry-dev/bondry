import Foundation
import XCTest

@testable import BondryApple

#if os(macOS)
  final class NetworkHTTPTransportRequestTests: XCTestCase {
    func testSerializesOriginFormWithoutChangingEscapedPathsOrQueries() async throws {
      let targets = [
        ("", "/"),
        ("?key=value", "/?key=value"),
        ("?", "/?"),
        ("/a%2Fb?key=x%20y&key=%2F", "/a%2Fb?key=x%20y&key=%2F"),
        ("//nested?key=value", "//nested?key=value"),
      ]

      for (suffix, expectedTarget) in targets {
        let server = try LoopbackHTTPServer(
          response: Data("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".utf8)
        )
        defer { server.stop() }
        let port = try await server.readyPort()
        let request = try BondryHTTPRequest(
          method: "GET",
          url: try XCTUnwrap(URL(string: "http://127.0.0.1:\(port)\(suffix)"))
        )

        let response = try await NetworkHTTPTransport().send(request)

        XCTAssertEqual(response.statusCode, 204)
        XCTAssertEqual(server.requestLine, "GET \(expectedTarget) HTTP/1.1")
      }
    }
  }

#endif
