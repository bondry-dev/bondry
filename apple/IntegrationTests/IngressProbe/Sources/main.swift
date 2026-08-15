import Bondry
import BondryApple
import BondryLocalServer
import BondryWebhookIngress
import Foundation

#if BONDRY_COMBINED_PROBE
  import CBondryEgress
#endif

private enum ProbeError: Error {
  case invalidURL
  case rejected
}

private struct ProbeSecrets: BondryWebhookSecretProvider {
  let reference: BondrySecretReference

  func resolve(_ reference: BondrySecretReference) throws -> BondryResolvedSecret {
    guard reference == self.reference else {
      throw BondrySecretProviderError.secretNotFound
    }
    return try BondryResolvedSecret(current: Data("probe-secret".utf8))
  }
}

let databaseURL = URL(fileURLWithPath: CommandLine.arguments[1])
#if BONDRY_COMBINED_PROBE
  _ = bondry_egress_abi_version_v1()
#endif
let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x45, count: 32))
let runtime = try BondryRuntime.open(at: databaseURL, key: key)
let principal = BondryPrincipal(id: "ingress-probe", kind: .application)
let capabilityID = "probe.receive"
try runtime.registerCapability(
  BondryCapability(
    id: capabilityID,
    summary: "Receive a probe webhook",
    effect: .readOnly
  )
) { _ in Data("{}".utf8) }
_ = try runtime.addGrant(
  principalID: principal.id,
  adapterID: "webhook",
  capabilityID: capabilityID
)
let server = try runtime.startLocalServer(
  configuration: BondryLocalServerConfiguration(adapters: [])
)
defer { try? server.stop() }
let secret = try BondrySecretReference("keychain:ingress-probe")
let registration = try runtime.registerWebhook(
  on: server,
  configuration: BondryWebhookIngressConfiguration(
    routeID: "ingress-probe",
    path: "/hooks/probe",
    principal: principal,
    capabilityID: capabilityID,
    semantics: .readOnly,
    verifier: .bearer(secret: secret)
  ),
  secretProvider: ProbeSecrets(reference: secret)
)
guard let url = URL(string: "http://127.0.0.1:\(server.endpoint.port)/hooks/probe") else {
  throw ProbeError.invalidURL
}
var request = URLRequest(url: url)
request.httpMethod = "POST"
request.setValue("Bearer probe-secret", forHTTPHeaderField: "Authorization")
request.setValue("application/json", forHTTPHeaderField: "Content-Type")
request.httpBody = Data(#"{"value":true}"#.utf8)
let (_, response) = try await URLSession.shared.data(for: request)
guard (response as? HTTPURLResponse)?.statusCode == 204 else {
  throw ProbeError.rejected
}
try await registration.disable()
