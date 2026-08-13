# Apple Server Controls

`BondryLocalServer` is an optional product that exposes REST and MCP through native Swift configuration and lifecycle types. Applications choose adapters independently and can bind to a fixed port or use port zero for automatic selection. Applications using only `Bondry` or `BondryAppIntents` do not link server code.

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

Custom numeric policy is grouped into validated `BondryLocalServerLimits` and `BondryLocalServerTimeouts` values. Timeouts use Swift `Duration` and must resolve to one millisecond through five minutes. Configuration values are immutable, and invalid adapter combinations, metadata, IP addresses, origins, principals, limits, and timeouts fail before crossing the C ABI.

`allowedBrowserOrigins` contains exact serialized HTTP or HTTPS origins. Non-loopback cleartext listening requires `allowsCleartextNetworkAccess`; disabled authentication on a non-loopback address additionally requires `allowsUnauthenticatedNetworkAccess`. These flags acknowledge risk and do not provide TLS.

`BondryLocalServer.stop()` is idempotent and thread-safe. It stops accepting requests and waits for bounded graceful shutdown. Deinitialization also stops a running server. The endpoint reports the actual address and port selected by the operating system. Startup and shutdown failures use `BondryLocalServerError`, not the runtime storage error domain.
