import Foundation

public struct DatabaseKeyMaterial:
  Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible
{
  public static let byteCount = 32

  private let storage: Data

  public init(rawRepresentation: Data) throws {
    guard rawRepresentation.count == Self.byteCount else {
      throw KeychainDatabaseKeyError.invalidKeyLength(rawRepresentation.count)
    }

    storage = rawRepresentation
  }

  public var rawRepresentation: Data {
    storage
  }

  public var debugDescription: String {
    "DatabaseKeyMaterial(<redacted>)"
  }

  public var description: String {
    debugDescription
  }
}
