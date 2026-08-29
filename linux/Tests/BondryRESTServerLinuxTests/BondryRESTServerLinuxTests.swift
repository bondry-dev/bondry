import Bondry
import BondryRESTServer
import Foundation
import Glibc
import XCTest

final class BondryRESTServerLinuxTests: XCTestCase {
  func testServesAuthenticatedPeerOverPrivateUnixSocket() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
      UUID().uuidString,
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: directory) }

    let runtime = try BondryRuntime.open(
      at: directory.appendingPathComponent("runtime.sqlite3"),
      key: try DatabaseKeyMaterial(
        rawRepresentation: Data(repeating: 0x71, count: DatabaseKeyMaterial.byteCount)
      )
    )
    let socketURL = directory.appendingPathComponent("bondry.sock")
    let userID = geteuid()
    let server = try runtime.startRESTUnixServer(
      configuration: try BondryRESTUnixServerConfiguration(
        socketURL: socketURL,
        ownerUserID: userID,
        peerUserID: userID,
        principalID: "linux-test"
      )
    )

    XCTAssertEqual(server.endpoint.socketURL, socketURL)
    XCTAssertTrue(server.isRunning)
    let attributes = try FileManager.default.attributesOfItem(atPath: socketURL.path)
    XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.uint16Value, 0o600)

    let response = try unixRequest(
      socketURL: socketURL,
      request: "GET /api/v1/capabilities HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    XCTAssertTrue(response.hasPrefix("HTTP/1.1 200"))

    try server.stop()
    XCTAssertFalse(server.isRunning)
    XCTAssertFalse(FileManager.default.fileExists(atPath: socketURL.path))
  }

  private func unixRequest(socketURL: URL, request: String) throws -> String {
    let descriptor = socket(AF_UNIX, Int32(SOCK_STREAM.rawValue), 0)
    guard descriptor >= 0 else {
      throw posixError()
    }
    defer { _ = close(descriptor) }

    let path = Array(socketURL.path.utf8CString)
    var address = sockaddr_un()
    guard path.count <= MemoryLayout.size(ofValue: address.sun_path) else {
      throw BondryRESTUnixServerConfigurationError.invalidSocketURL
    }
    address.sun_family = sa_family_t(AF_UNIX)
    withUnsafeMutableBytes(of: &address) { bytes in
      let pathOffset = MemoryLayout<sa_family_t>.size
      for (index, byte) in path.enumerated() {
        bytes[pathOffset + index] = UInt8(bitPattern: byte)
      }
    }
    let addressLength = socklen_t(MemoryLayout<sa_family_t>.size + path.count)
    let connected = withUnsafePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        connect(descriptor, $0, addressLength)
      }
    }
    guard connected == 0 else {
      throw posixError()
    }

    let requestBytes = Array(request.utf8)
    let sent = requestBytes.withUnsafeBytes { bytes in
      send(descriptor, bytes.baseAddress, bytes.count, 0)
    }
    guard sent == requestBytes.count else {
      throw posixError()
    }

    var response = Data()
    var buffer = [UInt8](repeating: 0, count: 4_096)
    while true {
      let count = buffer.withUnsafeMutableBytes { bytes in
        recv(descriptor, bytes.baseAddress, bytes.count, 0)
      }
      if count == 0 {
        break
      }
      guard count > 0 else {
        if errno == EINTR {
          continue
        }
        throw posixError()
      }
      response.append(contentsOf: buffer[..<count])
    }
    guard let string = String(data: response, encoding: .utf8) else {
      throw CocoaError(.fileReadInapplicableStringEncoding)
    }
    return string
  }

  private func posixError() -> NSError {
    NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
  }
}
