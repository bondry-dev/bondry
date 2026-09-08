import Foundation
import XCTest

@testable import BondryApple

final class URLSessionResponseLimitTests: XCTestCase {
  func testHeadAllowsRepresentationLargerThanResponseBodyLimit() async throws {
    let request = try request(method: "HEAD")

    let response = try await transport().send(request)

    XCTAssertEqual(response.statusCode, 200)
    XCTAssertTrue(response.body.isEmpty)
    XCTAssertTrue(
      response.headers.contains {
        $0.0.lowercased() == "content-length" && $0.1 == "1048576"
      }
    )
  }

  func testGetStillRejectsDeclaredOversizedBody() async throws {
    do {
      _ = try await transport().send(request(method: "GET"))
      XCTFail("Expected the response body limit to reject the response")
    } catch let error as BondryHTTPTransportError {
      XCTAssertEqual(error, .responseTooLarge)
    }
  }

  private func request(method: String) throws -> BondryHTTPRequest {
    try BondryHTTPRequest(
      method: method,
      url: XCTUnwrap(URL(string: "https://response-limit.test/resource")),
      maximumResponseBodyBytes: 4 * 1_024
    )
  }

  private func transport() -> URLSessionHTTPTransport {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [LargeRepresentationURLProtocol.self]
    return URLSessionHTTPTransport(configuration: configuration)
  }
}

private final class LargeRepresentationURLProtocol: URLProtocol {
  override class func canInit(with request: URLRequest) -> Bool {
    request.url?.host == "response-limit.test"
  }

  override class func canonicalRequest(for request: URLRequest) -> URLRequest {
    request
  }

  override func startLoading() {
    guard let url = request.url,
      let response = HTTPURLResponse(
        url: url,
        statusCode: 200,
        httpVersion: "HTTP/1.1",
        headerFields: ["Content-Length": "1048576"]
      )
    else {
      client?.urlProtocol(self, didFailWithError: URLError(.badURL))
      return
    }
    client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
    client?.urlProtocolDidFinishLoading(self)
  }

  override func stopLoading() {}
}
