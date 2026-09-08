import Foundation

@main
struct HTTPParserProbe {
  static func main() throws {
    let count = 64 * 1_024
    let response = Data(
      ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        + String(repeating: "1\r\nx\r\n", count: count)
        + "0\r\n\r\n").utf8)
    for fragmentSize in [16 * 1_024, response.count] {
      let clock = ContinuousClock()
      let elapsed = try clock.measure {
        for _ in 0..<10 {
          var parser = BoundedHTTP1ResponseParser(requestMethod: "GET", maximumBodyBytes: count)
          var parsed: ParsedHTTPResponse?
          for offset in stride(from: 0, to: response.count, by: fragmentSize) {
            let end = min(offset + fragmentSize, response.count)
            parsed = try parser.consume(
              Data(response[offset..<end]), isComplete: end == response.count)
          }
          precondition(parsed?.body == Data(repeating: 120, count: count))
        }
      }
      print("fragment_bytes=\(fragmentSize) runs=10 elapsed=\(elapsed)")
    }
  }
}
