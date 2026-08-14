import CryptoKit
import Foundation
import XCTest

final class WebhookSigningFixtureTests: XCTestCase {
  func testSwiftReproducesSharedCanonicalBytesAndSignatures() throws {
    let bundle = try JSONDecoder().decode(
      SigningFixtureBundle.self,
      from: Data(contentsOf: fixtureURL)
    )

    for vector in bundle.vectors {
      let secret = try XCTUnwrap(Data(base64Encoded: vector.secretBase64))
      let body = try XCTUnwrap(Data(base64Encoded: vector.bodyBase64))
      let canonical = canonicalBytes(
        timestamp: vector.timestampUnixSeconds,
        deliveryID: Data(vector.deliveryID.utf8),
        body: body
      )
      XCTAssertEqual(canonical.base64EncodedString(), vector.canonicalBase64)

      let signature = HMAC<SHA256>.authenticationCode(
        for: canonical,
        using: SymmetricKey(data: secret)
      )
      XCTAssertEqual(Data(signature).hexadecimal, vector.signatureHex)
    }
  }

  private var fixtureURL: URL {
    URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .appendingPathComponent("fixtures/signing-v1/webhook-hmac.json")
  }

  private func canonicalBytes(timestamp: Int64, deliveryID: Data, body: Data) -> Data {
    var result = Data("bondry-webhook-v1\n".utf8)
    result.append(Data("\(timestamp)\n\(deliveryID.count)\n".utf8))
    result.append(deliveryID)
    result.append(Data("\n\(body.count)\n".utf8))
    result.append(body)
    return result
  }
}

private struct SigningFixtureBundle: Decodable {
  let vectors: [SigningFixture]
}

private struct SigningFixture: Decodable {
  let secretBase64: String
  let timestampUnixSeconds: Int64
  let deliveryID: String
  let bodyBase64: String
  let canonicalBase64: String
  let signatureHex: String

  enum CodingKeys: String, CodingKey {
    case secretBase64 = "secret_base64"
    case timestampUnixSeconds = "timestamp_unix_seconds"
    case deliveryID = "delivery_id"
    case bodyBase64 = "body_base64"
    case canonicalBase64 = "canonical_base64"
    case signatureHex = "signature_hex"
  }
}

extension Data {
  fileprivate var hexadecimal: String {
    map { String(format: "%02x", $0) }.joined()
  }
}
