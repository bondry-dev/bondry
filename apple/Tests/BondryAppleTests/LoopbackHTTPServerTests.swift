import XCTest

@testable import BondryApple

#if os(macOS)
  final class LoopbackHTTPServerTests: XCTestCase {
    func testReadinessWaitAfterStopThrowsCancellation() async throws {
      let server = try LoopbackHTTPServer(startImmediately: false)
      server.stop()

      do {
        _ = try await server.readyPort(timeout: 0.1)
        XCTFail("Expected the stopped listener to reject readiness")
      } catch {
        XCTAssertTrue(error is CancellationError)
      }
    }

    func testCancelledReadinessWaitThrowsCancellation() async throws {
      let server = try LoopbackHTTPServer(startImmediately: false)
      defer { server.stop() }
      let ready = Task { try await server.readyPort(timeout: 0.1) }
      ready.cancel()

      do {
        _ = try await ready.value
        XCTFail("Expected the cancelled readiness wait to finish")
      } catch {
        XCTAssertTrue(error is CancellationError)
      }
    }

    func testReadinessTimeoutDoesNotWaitForListenerCallbacks() async throws {
      let server = try LoopbackHTTPServer(startImmediately: false)
      defer { server.stop() }

      do {
        _ = try await server.readyPort(timeout: 0.01)
        XCTFail("Expected readiness to time out")
      } catch {
        XCTAssertEqual(error as? BondryHTTPTransportError, .deadlineExceeded)
      }
    }

    func testStopAndCancellationResumeRegisteredReadinessWaiters() async throws {
      for cancelTask in [false, true] {
        let server = try LoopbackHTTPServer(startImmediately: false)
        defer { server.stop() }
        let ready = Task { try await server.readyPort() }
        let deadline = ContinuousClock.now.advanced(by: .seconds(1))
        while !server.hasReadinessWaiters && ContinuousClock.now < deadline {
          try await Task.sleep(for: .milliseconds(1))
        }
        XCTAssertTrue(server.hasReadinessWaiters)

        if cancelTask { ready.cancel() } else { server.stop() }

        do {
          _ = try await ready.value
          XCTFail("Expected the registered readiness wait to finish")
        } catch {
          XCTAssertTrue(error is CancellationError)
        }
      }
    }
  }
#endif
