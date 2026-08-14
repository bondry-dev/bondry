import Foundation

public struct KeychainSecretProviderConfiguration: Equatable, Sendable {
  public let service: String
  public let accessGroup: String?

  public init(service: String, accessGroup: String? = nil) throws {
    guard !service.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
      throw BondrySecretProviderError.invalidConfiguration
    }
    if let accessGroup,
      accessGroup.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    {
      throw BondrySecretProviderError.invalidConfiguration
    }
    self.service = service
    self.accessGroup = accessGroup
  }
}
