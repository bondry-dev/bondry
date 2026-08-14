import Foundation

struct ParsedHTTPResponse {
  let statusCode: Int
  let headers: [(String, String)]
  let body: Data
}

struct BoundedHTTP1ResponseParser {
  private enum Framing {
    case contentLength(Int)
    case chunked
    case empty
  }

  private let requestMethod: String
  private let maximumBodyBytes: Int
  private var buffer = Data()
  private var statusCode: Int?
  private var headers: [(String, String)] = []
  private var framing: Framing?
  private var decodedBody = Data()

  init(requestMethod: String, maximumBodyBytes: Int) {
    self.requestMethod = requestMethod
    self.maximumBodyBytes = maximumBodyBytes
  }

  mutating func consume(_ data: Data, isComplete: Bool) throws -> ParsedHTTPResponse? {
    buffer.append(data)
    while framing == nil {
      guard try parseHeadIfAvailable() else {
        if isComplete {
          throw BondryHTTPTransportError.invalidResponse
        }
        return nil
      }
    }
    let response = try parseBodyIfAvailable()
    if response == nil, isComplete {
      throw BondryHTTPTransportError.invalidResponse
    }
    return response
  }

  private mutating func parseHeadIfAvailable() throws -> Bool {
    let delimiter = Data("\r\n\r\n".utf8)
    guard let range = buffer.range(of: delimiter) else {
      guard buffer.count <= BondryHTTPRequest.maximumHeaderBytes else {
        throw BondryHTTPTransportError.responseTooLarge
      }
      return false
    }
    guard range.upperBound <= BondryHTTPRequest.maximumHeaderBytes else {
      throw BondryHTTPTransportError.responseTooLarge
    }
    let head = Data(buffer[..<range.lowerBound])
    buffer.removeSubrange(..<range.upperBound)
    guard Self.validHeadBytes(head) else {
      throw BondryHTTPTransportError.invalidResponse
    }
    let lines = String(decoding: head, as: UTF8.self).components(separatedBy: "\r\n")
    guard let statusLine = lines.first else {
      throw BondryHTTPTransportError.invalidResponse
    }
    let statusParts = statusLine.split(
      separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
    guard statusParts.count >= 2,
      statusParts[0] == "HTTP/1.1",
      statusParts[1].count == 3,
      statusParts[1].allSatisfy({ $0.isASCII && $0.isNumber }),
      let status = Int(statusParts[1]),
      (100...599).contains(status),
      !(300...399).contains(status)
    else {
      if statusParts.count >= 2,
        let status = Int(statusParts[1]),
        (300...399).contains(status)
      {
        throw BondryHTTPTransportError.redirectDenied
      }
      throw BondryHTTPTransportError.invalidResponse
    }
    let parsedHeaders = try Self.parseHeaders(Array(lines.dropFirst()))
    if (100...199).contains(status) {
      guard status != 101 else {
        throw BondryHTTPTransportError.invalidResponse
      }
      return true
    }
    statusCode = status
    headers = parsedHeaders.list
    framing = try Self.framing(
      method: requestMethod,
      status: status,
      fields: parsedHeaders.fields,
      maximumBodyBytes: maximumBodyBytes
    )
    return true
  }

  private mutating func parseBodyIfAvailable() throws -> ParsedHTTPResponse? {
    guard let statusCode, let framing else {
      return nil
    }
    switch framing {
    case .empty:
      guard buffer.isEmpty else {
        throw BondryHTTPTransportError.invalidResponse
      }
      return ParsedHTTPResponse(statusCode: statusCode, headers: headers, body: Data())
    case .contentLength(let length):
      guard buffer.count >= length else {
        return nil
      }
      guard buffer.count == length else {
        throw BondryHTTPTransportError.invalidResponse
      }
      return ParsedHTTPResponse(statusCode: statusCode, headers: headers, body: buffer)
    case .chunked:
      return try parseChunked(statusCode: statusCode)
    }
  }

  private mutating func parseChunked(statusCode: Int) throws -> ParsedHTTPResponse? {
    let delimiter = Data("\r\n".utf8)
    while true {
      guard let sizeRange = buffer.range(of: delimiter) else {
        guard buffer.count <= 128 else {
          throw BondryHTTPTransportError.invalidResponse
        }
        return nil
      }
      guard sizeRange.lowerBound > buffer.startIndex,
        sizeRange.lowerBound - buffer.startIndex <= 128
      else {
        throw BondryHTTPTransportError.invalidResponse
      }
      let sizeBytes = buffer[..<sizeRange.lowerBound]
      guard sizeBytes.allSatisfy({ $0.isASCIIHexDigit }),
        let size = Int(String(decoding: sizeBytes, as: UTF8.self), radix: 16)
      else {
        throw BondryHTTPTransportError.invalidResponse
      }
      let contentStart = sizeRange.upperBound
      if size == 0 {
        guard buffer.count >= contentStart + 2 else {
          return nil
        }
        guard buffer[contentStart..<(contentStart + 2)] == delimiter,
          buffer.count == contentStart + 2
        else {
          throw BondryHTTPTransportError.invalidResponse
        }
        return ParsedHTTPResponse(
          statusCode: statusCode,
          headers: headers,
          body: decodedBody
        )
      }
      guard size <= maximumBodyBytes - decodedBody.count else {
        throw BondryHTTPTransportError.responseTooLarge
      }
      let contentEnd = contentStart + size
      guard buffer.count >= contentEnd + 2 else {
        return nil
      }
      guard buffer[contentEnd..<(contentEnd + 2)] == delimiter else {
        throw BondryHTTPTransportError.invalidResponse
      }
      decodedBody.append(buffer[contentStart..<contentEnd])
      buffer.removeSubrange(..<(contentEnd + 2))
    }
  }

  private static func parseHeaders(
    _ lines: [String]
  ) throws -> (list: [(String, String)], fields: [String: [String]]) {
    guard lines.count <= BondryHTTPRequest.maximumHeaders else {
      throw BondryHTTPTransportError.responseTooLarge
    }
    var list: [(String, String)] = []
    var fields: [String: [String]] = [:]
    for line in lines {
      guard !line.hasPrefix(" "), !line.hasPrefix("\t"),
        let separator = line.firstIndex(of: ":")
      else {
        throw BondryHTTPTransportError.invalidResponse
      }
      let name = String(line[..<separator])
      let value = line[line.index(after: separator)...]
        .trimmingCharacters(in: .whitespaces)
      guard !name.isEmpty,
        name.utf8.allSatisfy({ $0.isHTTPToken })
      else {
        throw BondryHTTPTransportError.invalidResponse
      }
      list.append((name, value))
      fields[name.lowercased(), default: []].append(value)
    }
    return (list, fields)
  }

  private static func validHeadBytes(_ data: Data) -> Bool {
    let bytes = [UInt8](data)
    var index = 0
    while index < bytes.count {
      if bytes[index] == 0x0d {
        guard index + 1 < bytes.count, bytes[index + 1] == 0x0a else {
          return false
        }
        index += 2
      } else {
        guard bytes[index] == 0x09 || (0x20...0x7e).contains(bytes[index]) else {
          return false
        }
        index += 1
      }
    }
    return true
  }

  private static func framing(
    method: String,
    status: Int,
    fields: [String: [String]],
    maximumBodyBytes: Int
  ) throws -> Framing {
    if method == "HEAD" || (100...199).contains(status) || status == 204 || status == 304 {
      return .empty
    }
    let contentLengths = fields["content-length"] ?? []
    let transferEncodings = fields["transfer-encoding"] ?? []
    guard contentLengths.isEmpty || transferEncodings.isEmpty else {
      throw BondryHTTPTransportError.invalidResponse
    }
    if !contentLengths.isEmpty {
      guard contentLengths.count == 1,
        contentLengths[0].allSatisfy({ $0.isASCII && $0.isNumber }),
        let length = Int(contentLengths[0])
      else {
        throw BondryHTTPTransportError.invalidResponse
      }
      guard length <= maximumBodyBytes else {
        throw BondryHTTPTransportError.responseTooLarge
      }
      return .contentLength(length)
    }
    if !transferEncodings.isEmpty {
      guard transferEncodings.count == 1,
        transferEncodings[0].caseInsensitiveCompare("chunked") == .orderedSame
      else {
        throw BondryHTTPTransportError.invalidResponse
      }
      return .chunked
    }
    throw BondryHTTPTransportError.invalidResponse
  }
}

extension UInt8 {
  fileprivate var isASCIIHexDigit: Bool {
    (0x30...0x39).contains(self)
      || (0x41...0x46).contains(self)
      || (0x61...0x66).contains(self)
  }

  fileprivate var isHTTPToken: Bool {
    (0x30...0x39).contains(self)
      || (0x41...0x5a).contains(self)
      || (0x61...0x7a).contains(self)
      || "!#$%&'*+-.^_`|~".utf8.contains(self)
  }
}
