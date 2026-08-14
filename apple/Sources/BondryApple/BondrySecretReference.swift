import Foundation

public struct BondrySecretReference: Equatable, Hashable, Sendable {
  public let rawValue: String

  public init(_ rawValue: String) throws {
    guard !rawValue.isEmpty else {
      throw BondrySecretProviderError.emptyReference
    }
    self.rawValue = rawValue
  }
}

public struct BondryResolvedSecret: Equatable, Sendable {
  public static let maximumByteCount = 1_024

  public let current: Data
  public let previous: Data?

  public init(current: Data, previous: Data? = nil) throws {
    try Self.validate(current)
    if let previous {
      try Self.validate(previous)
    }
    self.current = current
    self.previous = previous
  }

  private static func validate(_ value: Data) throws {
    guard !value.isEmpty, value.count <= maximumByteCount else {
      throw BondrySecretProviderError.invalidSecretLength(value.count)
    }
  }
}
