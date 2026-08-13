# Apple Server Controls

`BondrySQLCipher` exposes the shared REST and MCP runtime through native Swift configuration and lifecycle types. Applications choose adapters independently and can bind to a fixed port or use port zero for automatic selection.

```swift
let configuration = BondryServerConfiguration(
  adapters: [.rest, .mcp],
  mcpServer: BondryMCPServerInformation(
    name: "battery-app",
    title: "Battery App",
    version: "2.3.1"
  )
)

let server = try store.startServer(configuration: configuration)
print(server.endpoint.address, server.endpoint.port)
```

Bearer-token authentication is the default. Tokens created through `BondryEncryptedStore` work immediately, and revocation or client disablement takes effect on the next request. REST and MCP use separate adapter identifiers, so each principal needs an explicit grant for each enabled protocol and capability.

Applications that deliberately disable tokens must supply the principal used for authorization and audit attribution:

```swift
var configuration = BondryServerConfiguration(
  adapters: [.rest],
  authentication: .disabled(
    principalID: "local-automation",
    kind: .application
  )
)
```

The safe defaults bind to `127.0.0.1`, choose a random free port, reject browser origins, require bearer authentication, allow 120 authenticated requests and 30 rejected authentication attempts per minute, limit bodies to 1 MiB, and use the shared bounded timeout and connection defaults.

`allowedOrigins` contains exact serialized HTTP or HTTPS origins. Non-loopback cleartext listening requires `allowCleartextNetwork`; disabled authentication on a non-loopback address additionally requires `allowUnauthenticatedNetwork`. These flags acknowledge risk and do not provide TLS.

`BondryServer.stop()` is idempotent. It stops accepting requests and waits for bounded graceful shutdown. Deinitialization also stops a running server. The endpoint reports the actual address and port selected by the operating system.
