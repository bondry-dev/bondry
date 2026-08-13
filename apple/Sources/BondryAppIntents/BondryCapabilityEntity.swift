import AppIntents
import BondrySQLCipher
import Foundation

public struct BondryCapabilityEntity: AppEntity, Equatable, Sendable {
  public static let typeDisplayRepresentation: TypeDisplayRepresentation = "Automation Capability"
  public static let defaultQuery = BondryCapabilityQuery()

  public let id: String
  public let summary: String

  public var displayRepresentation: DisplayRepresentation {
    DisplayRepresentation(
      title: LocalizedStringResource(stringLiteral: summary),
      subtitle: LocalizedStringResource(stringLiteral: id)
    )
  }

  public init(id: String, summary: String) {
    self.id = id
    self.summary = summary
  }

  init(_ capability: BondryCapability) {
    self.init(id: capability.id, summary: capability.summary)
  }
}

public struct BondryCapabilityQuery: EntityQuery {
  @Dependency private var runtime: BondryShortcutsRuntime

  public init() {}

  init(runtime: BondryShortcutsRuntime) {
    self.runtime = runtime
  }

  public func entities(for identifiers: [String]) async throws -> [BondryCapabilityEntity] {
    let capabilities = try runtime.authorizedCapabilities()
    let byID = Dictionary(uniqueKeysWithValues: capabilities.map { ($0.id, $0) })
    return identifiers.compactMap { byID[$0].map(BondryCapabilityEntity.init) }
  }

  public func suggestedEntities() async throws -> [BondryCapabilityEntity] {
    try runtime.authorizedCapabilities().map(BondryCapabilityEntity.init)
  }
}
