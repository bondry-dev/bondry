import Foundation
import XCTest

@testable import BondryApple

final class URLSessionPoolTests: XCTestCase {
  func testPoolEvictsLeastRecentlyUsedTrustPolicy() {
    let pool = URLSessionPool(configuration: .ephemeral)
    let recent = pool.session(for: anchors(0))
    weak let oldest = pool.session(for: anchors(1))
    for index in 2..<URLSessionPool.maximumSessions {
      _ = pool.session(for: anchors(index))
    }
    XCTAssertNotNil(oldest)
    XCTAssertTrue(recent === pool.session(for: anchors(0)))

    _ = pool.session(for: anchors(URLSessionPool.maximumSessions))

    XCTAssertNil(oldest)
    XCTAssertTrue(recent === pool.session(for: anchors(0)))
  }

  func testPoolCopiesConfigurationBeforeCreatingSessions() {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.timeoutIntervalForRequest = 17
    let pool = URLSessionPool(configuration: configuration)
    configuration.timeoutIntervalForRequest = 42

    XCTAssertEqual(pool.session(for: []).session.configuration.timeoutIntervalForRequest, 17)
  }

  func testEvictionPreservesBorrowedSessionBeforeRequestStarts() async throws {
    let pool = makePool()
    let borrowed = pool.session(for: [])
    evictDefaultSession(from: pool)
    let started = expectation(description: "Request starts after its session is evicted")
    PoolTestURLProtocol.control.expectStart(started)
    defer { PoolTestURLProtocol.control.reset() }
    let request = Task {
      try await borrowed.session.data(from: XCTUnwrap(URL(string: "https://pool.test/resource")))
    }
    await fulfillment(of: [started], timeout: 2)
    PoolTestURLProtocol.control.finish()

    let (data, response) = try await request.value

    XCTAssertEqual(data, Data("ok".utf8))
    XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 200)
    withExtendedLifetime(borrowed) {}
  }

  func testEvictionFinishesActiveRequestAfterLastBorrowerReleasesSession() async throws {
    let pool = makePool()
    var borrowed: PooledURLSession? = pool.session(for: [])
    let session = try XCTUnwrap(borrowed?.session)
    let started = expectation(description: "Request is active before eviction")
    PoolTestURLProtocol.control.expectStart(started)
    defer { PoolTestURLProtocol.control.reset() }
    let request = Task {
      try await session.data(from: XCTUnwrap(URL(string: "https://pool.test/resource")))
    }
    await fulfillment(of: [started], timeout: 2)

    evictDefaultSession(from: pool)
    borrowed = nil
    PoolTestURLProtocol.control.finish()

    let (data, response) = try await request.value

    XCTAssertEqual(data, Data("ok".utf8))
    XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 200)
  }

  private func makePool() -> URLSessionPool {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [PoolTestURLProtocol.self]
    configuration.timeoutIntervalForRequest = 2
    return URLSessionPool(configuration: configuration)
  }

  private func anchors(_ index: Int) -> [Data] {
    [Data(String(index).utf8)]
  }

  private func evictDefaultSession(from pool: URLSessionPool) {
    for index in 0..<URLSessionPool.maximumSessions {
      _ = pool.session(for: anchors(index))
    }
  }
}

private final class PoolTestURLProtocol: URLProtocol {
  static let control = PoolProtocolControl()

  override class func canInit(with request: URLRequest) -> Bool {
    request.url?.host == "pool.test"
  }

  override class func canonicalRequest(for request: URLRequest) -> URLRequest {
    request
  }

  override func startLoading() {
    Self.control.start(self)
  }

  override func stopLoading() {}

  func finish() {
    guard let url = request.url,
      let response = HTTPURLResponse(
        url: url,
        statusCode: 200,
        httpVersion: "HTTP/1.1",
        headerFields: ["Content-Length": "2"]
      )
    else {
      client?.urlProtocol(self, didFailWithError: URLError(.badURL))
      return
    }
    client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
    client?.urlProtocol(self, didLoad: Data("ok".utf8))
    client?.urlProtocolDidFinishLoading(self)
  }
}

private final class PoolProtocolControl: @unchecked Sendable {
  private let lock = NSLock()
  private var started: XCTestExpectation?
  private var pending: PoolTestURLProtocol?

  func expectStart(_ expectation: XCTestExpectation) {
    lock.withLock { started = expectation }
  }

  func start(_ request: PoolTestURLProtocol) {
    let expectation = lock.withLock {
      pending = request
      return started
    }
    expectation?.fulfill()
  }

  func finish() {
    let request = lock.withLock {
      let request = pending
      pending = nil
      return request
    }
    request?.finish()
  }

  func reset() {
    lock.withLock {
      started = nil
      pending = nil
    }
  }
}
