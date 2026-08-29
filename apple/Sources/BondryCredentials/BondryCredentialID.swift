import CBondryCredentials

public struct BondryCredentialID: Hashable, Sendable {
  public static let maximumByteCount = Int(BONDRY_MAX_CREDENTIAL_ID_LENGTH_V1)

  public let rawValue: String

  public init(_ rawValue: String) throws {
    guard !rawValue.isEmpty,
      rawValue.utf8.count <= Self.maximumByteCount,
      rawValue.utf8.allSatisfy({
        (0x41...0x5A).contains($0) || (0x61...0x7A).contains($0)
          || (0x30...0x39).contains($0) || $0 == 0x2D || $0 == 0x2E || $0 == 0x5F
      }), rawValue != ".", rawValue != ".."
    else {
      throw BondryCredentialIDError.invalidValue
    }
    self.rawValue = rawValue
  }
}

public enum BondryCredentialIDError: Error, Equatable, Sendable {
  case invalidValue
}
