import AppIntents
import Foundation

public struct BondryRunCapabilityIntent: AppIntent {
  public static let title: LocalizedStringResource = "Run Automation Capability"
  public static let description = IntentDescription(
    "Runs an automation capability that the app has exposed to Shortcuts."
  )
  public static let authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication

  @available(macOS 26.0, iOS 26.0, *)
  public static var supportedModes: IntentModes { .background }

  @Parameter(title: "Capability")
  public var capability: BondryCapabilityEntity

  @Parameter(title: "Input JSON", default: "{}")
  public var inputJSON: String

  @Dependency private var runtime: BondryShortcutsRuntime

  public init() {}

  public init(capability: BondryCapabilityEntity, inputJSON: String = "{}") {
    self.capability = capability
    self.inputJSON = inputJSON
  }

  init(
    capability: BondryCapabilityEntity,
    inputJSON: String,
    runtime: BondryShortcutsRuntime
  ) {
    self.capability = capability
    self.inputJSON = inputJSON
    self.runtime = runtime
  }

  public func perform() async throws -> some IntentResult & ReturnsValue<String> {
    guard let input = inputJSON.data(using: .utf8) else {
      throw BondryShortcutsError.invalidInput
    }
    do {
      _ = try JSONSerialization.jsonObject(with: input, options: .fragmentsAllowed)
    } catch {
      throw BondryShortcutsError.invalidInput
    }
    let output = try await runtime.invoke(capabilityID: capability.id, inputJSON: input)
    guard let outputJSON = String(data: output, encoding: .utf8) else {
      throw BondryShortcutsError.invalidOutput
    }
    return .result(value: outputJSON)
  }
}
