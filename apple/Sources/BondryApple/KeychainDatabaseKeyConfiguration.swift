import Foundation

public struct KeychainDatabaseKeyConfiguration: Equatable, Sendable {
  public enum Field: String, Equatable, Sendable {
    case service
    case account
    case accessGroup
  }

  public let service: String
  public let account: String
  public let accessGroup: String?

  public init(service: String, account: String, accessGroup: String? = nil) throws {
    try Self.requireValue(service, field: .service)
    try Self.requireValue(account, field: .account)

    if let accessGroup {
      try Self.requireValue(accessGroup, field: .accessGroup)
    }

    self.service = service
    self.account = account
    self.accessGroup = accessGroup
  }

  private static func requireValue(_ value: String, field: Field) throws {
    guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
      throw KeychainDatabaseKeyError.invalidConfiguration(field)
    }
  }
}
