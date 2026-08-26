# Apple Server Controls

`BondryLocalServer` is an optional product that exposes REST and MCP through native Swift configuration and lifecycle types. Applications choose adapters independently and can bind to a fixed port or use port zero for automatic selection. An empty adapter set is valid for a server used only by a separately linked raw-body add-on such as `BondryWebhookIngress`. Applications using only `Bondry` or `BondryAppIntents` do not link server code.

```swift
let configuration = try BondryLocalServerConfiguration(
  adapters: [.rest, .mcp],
  mcpServer: try BondryMCPServerInformation(
    name: "battery-app",
    title: "Battery App",
    version: "2.3.1"
  )
)

let server = try runtime.startLocalServer(configuration: configuration)
print(server.endpoint.address, server.endpoint.port)
```

Applications that need only REST can depend on `BondryRESTServer`. Its configuration has no adapter selection or MCP metadata, and its native binary is built without the MCP feature:

```swift
let configuration = try BondryRESTServerConfiguration()
let server = try runtime.startRESTServer(configuration: configuration)
print(server.endpoint.address, server.endpoint.port)
```

The REST-only product can terminate TLS 1.3 without putting certificate or private-key bytes in JSON configuration. The certificate chain is public input; the private key is an `inout Data` buffer that is cleared after every startup attempt:

```swift
let configuration = try BondryRESTTLSServerConfiguration(
  listeningAddress: selectedAddress,
  port: 8443
)
var privateKey = loadPrivateKeyFromSecureStorage()
let server = try runtime.startRESTTLSServer(
  configuration: configuration,
  certificateChainDER: certificateChain,
  privateKeyPKCS8DER: &privateKey
)
```

The host owns certificate creation, rotation, trust-anchor distribution, and persistent key storage. TLS handshakes use the shared connection limit and a separate timeout of at most one minute. Plaintext and TLS 1.2 never reach REST authentication or dispatch.

The same product can expose REST through a Unix domain socket without opening a network port. The caller chooses the socket path, its expected owner, the allowed peer user, and the principal used for authorization and audit attribution:

```swift
import Darwin

let userID = getuid()
let configuration = try BondryRESTUnixServerConfiguration(
  socketURL: privateDirectory.appendingPathComponent("service.sock"),
  ownerUserID: userID,
  peerUserID: userID,
  principalID: "local-client"
)
let server = try runtime.startRESTUnixServer(configuration: configuration)
print(server.endpoint.socketURL.path)
```

The socket's immediate parent must already be a real directory owned by `ownerUserID`, with no group or other permissions, and the process user must match that owner. Bondry creates the socket with mode `0600` and accepts only peers whose operating-system credential matches `peerUserID`. Unix transport always uses the explicit host principal; bearer authentication and browser origins do not apply.

Startup removes a stale socket only when its type, owner, permissions, and failed liveness probe all match the expected state. Shutdown removes only the same filesystem object created by that server instance. The caller remains responsible for choosing and managing the parent directory.

The two server products share authentication, network policy, limits, timeouts, endpoint reporting, and lifecycle behavior. They are alternative dependency choices; an application does not need both for REST access.

Bearer-token authentication is the default. Tokens created through `BondryRuntime` work immediately, and revocation or client disablement takes effect on the next request. REST and MCP use separate adapter identifiers, so each principal needs an explicit grant for each enabled protocol and capability.

Applications that deliberately disable tokens must supply the principal used for authorization and audit attribution:

```swift
let configuration = try BondryLocalServerConfiguration(
  adapters: [.rest],
  authentication: .disabled(
    principalID: "local-automation",
    kind: .application
  )
)
```

The safe defaults bind to `127.0.0.1`, choose a random free port, reject browser origins, require bearer authentication, allow 120 authenticated requests and 30 rejected authentication attempts per minute, limit bodies to 1 MiB, and use the shared bounded timeout and connection defaults.

Custom numeric policy is grouped into validated limits and timeouts values for each server product. Timeouts use Swift `Duration` and must resolve to one millisecond through five minutes. Configuration values are immutable, and invalid metadata, IP addresses, origins, principals, limits, and timeouts fail before crossing the C ABI.

`allowedBrowserOrigins` contains exact serialized HTTP or HTTPS origins. Non-loopback cleartext listening requires `allowsCleartextNetworkAccess`; disabled authentication on a non-loopback address additionally requires `allowsUnauthenticatedNetworkAccess`. TLS configuration has no cleartext acknowledgement and accepts a non-loopback address directly, while disabled application authentication still requires an explicit acknowledgement.

`BondryLocalServer.stop()`, `BondryRESTServer.stop()`, and `BondryRESTUnixServer.stop()` are idempotent and thread-safe. They stop accepting requests and wait for bounded graceful shutdown. Deinitialization also stops a running server. The endpoint reports the address and port or socket path selected by the configuration. Startup and shutdown failures use their server product's error domain, not the runtime storage error domain.

See [Webhook ingress](webhook-ingress.md) for verified route registration,
draining, replay administration, and TLS-proxy requirements. The legacy
`noAdapters` configuration error remains in the public enum for source
compatibility but is no longer emitted.
