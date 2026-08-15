import BondryApple

public protocol BondryEgressSecretProvider: Sendable {
  func resolve(_ reference: BondrySecretReference) throws -> BondryResolvedSecret
}

extension KeychainSecretProvider: BondryEgressSecretProvider {}
