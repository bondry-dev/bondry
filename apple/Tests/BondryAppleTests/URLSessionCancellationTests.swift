import Foundation
import XCTest

@testable import BondryApple

final class URLSessionCancellationTests: XCTestCase {
  func testRejectedResponsesCancelTheirUnfinishedTransfers() async throws {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [UnfinishedResponseURLProtocol.self]
    let transport = URLSessionHTTPTransport(configuration: configuration)
    defer { withExtendedLifetime(transport) {} }

    for scenario in ["declared-body", "streamed-body", "headers", "redirect"] {
      let stopped = expectation(description: "Rejected \(scenario) transfer stops")
      UnfinishedResponseURLProtocol.control.expectStop(stopped)
      defer { UnfinishedResponseURLProtocol.control.reset() }
      let request = try BondryHTTPRequest(
        method: "GET",
        url: XCTUnwrap(URL(string: "https://cancel.test/\(scenario)")),
        timeout: .seconds(1),
        maximumResponseBodyBytes: 4 * 1_024
      )

      do {
        _ = try await transport.send(request)
        XCTFail("Expected the response to be rejected")
      } catch let error as BondryHTTPTransportError {
        XCTAssertEqual(error, scenario == "redirect" ? .redirectDenied : .responseTooLarge)
      }

      await fulfillment(of: [stopped], timeout: 0.25)
    }
  }
}

private final class UnfinishedResponseURLProtocol: URLProtocol {
  static let control = TransferCancellationControl()

  override class func canInit(with request: URLRequest) -> Bool {
    request.url?.host == "cancel.test"
  }

  override class func canonicalRequest(for request: URLRequest) -> URLRequest {
    request
  }

  override func startLoading() {
    Self.control.start(self)
    guard let url = request.url else {
      client?.urlProtocol(self, didFailWithError: URLError(.badURL))
      return
    }
    let headers: [String: String]
    switch url.path {
    case "/declared-body":
      headers = ["Content-Length": "65536"]
    case "/headers":
      headers = Dictionary(uniqueKeysWithValues: (0..<65).map { ("X-Field-\($0)", "value") })
    case "/redirect":
      headers = ["Location": "https://cancel.test/destination"]
    default:
      headers = [:]
    }
    guard
      let response = HTTPURLResponse(
        url: url,
        statusCode: url.path == "/redirect" ? 302 : 200,
        httpVersion: "HTTP/1.1",
        headerFields: headers
      )
    else {
      client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
      return
    }
    client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
    client?.urlProtocol(self, didLoad: Data(repeating: 0, count: 32 * 1_024))
  }

  override func stopLoading() {
    Self.control.stop()
  }
}

private final class TransferCancellationControl: @unchecked Sendable {
  private let lock = NSLock()
  private var stopped: XCTestExpectation?
  private var pending: UnfinishedResponseURLProtocol?

  func expectStop(_ expectation: XCTestExpectation) {
    lock.withLock { stopped = expectation }
  }

  func start(_ request: UnfinishedResponseURLProtocol) {
    lock.withLock { pending = request }
  }

  func stop() {
    let expectation = lock.withLock {
      pending = nil
      let expectation = stopped
      stopped = nil
      return expectation
    }
    expectation?.fulfill()
  }

  func reset() {
    let request = lock.withLock {
      let request = pending
      stopped = nil
      pending = nil
      return request
    }
    if let request {
      request.client?.urlProtocol(request, didFailWithError: URLError(.cancelled))
    }
  }
}
