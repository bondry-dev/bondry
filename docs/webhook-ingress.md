# Webhook ingress

`BondryWebhookIngress` receives authenticated HTTP `POST` deliveries and
dispatches each route to one fixed Bondry capability. The sender cannot choose
the principal, adapter, or capability. Every route uses the `webhook` adapter,
so the host must grant that exact principal-adapter-capability tuple before
registration.

The product is optional. A host that does not select it links no webhook
verification or ingress code. Selecting it also requires `BondryLocalServer`,
but does not add egress code.

## Apple integration

Register the capability and grant before mounting the route. A webhook-only
server uses an empty protocol-adapter set:

```swift
import Bondry
import BondryApple
import BondryLocalServer
import BondryWebhookIngress
import Foundation

let principal = BondryPrincipal(id: "automation.webhook", kind: .application)
let capabilityID = "automation.receive"

try runtime.registerCapability(
  BondryCapability(
    id: capabilityID,
    summary: "Receive an automation event",
    effect: .readOnly
  )
) { invocation in
  try await receiveAutomationEvent(invocation.inputJSON)
  return Data("{}".utf8)
}

_ = try runtime.addGrant(
  principalID: principal.id,
  adapterID: "webhook",
  capabilityID: capabilityID
)

let secretReference = try BondrySecretReference("webhook:automation")
let secretProvider = KeychainSecretProvider(
  configuration: try KeychainSecretProviderConfiguration(
    service: "com.example.application.webhooks"
  )
)
let server = try runtime.startLocalServer(
  configuration: BondryLocalServerConfiguration(adapters: [])
)
let registration = try runtime.registerWebhook(
  on: server,
  configuration: BondryWebhookIngressConfiguration(
    routeID: "automation-webhook",
    path: "/hooks/automation",
    principal: principal,
    capabilityID: capabilityID,
    semantics: .readOnly,
    verifier: .bearer(secret: secretReference)
  ),
  secretProvider: secretProvider
)
```

Provision a high-entropy secret through a trusted host flow before registering
the route. Configuration contains only `BondrySecretReference`; secret bytes
remain in the host provider and are never serialized into route metadata,
logs, audit events, or responses. `KeychainSecretProvider` supports current
and previous values for bounded rotation overlap.

Initial verifier support includes bearer secrets, Bondry HMAC-SHA-256, GitHub
HMAC-SHA-256, and Stripe HMAC-SHA-256. Provider-specific compatibility is
limited to the fixture-tested formats. HMAC verifiers compare signatures in
constant time and consume the exact raw request body.

## Fixed mapping and authorization

The default mapping parses the body as the complete JSON capability input.
Envelope mapping wraps the parsed body with only explicitly selected,
non-credential headers. Credential headers cannot enter capability input, and
handler output is never returned to the sender.

Route registration fails unless the fixed capability exists, the fixed
principal has a `webhook` grant, and the declared semantics match the
capability effect. A non-idempotent mutating route additionally requires a
verifier-provided trusted delivery identity and persistent replay storage.
Merely selecting an identifier header never makes it trusted.

## Replay and uncertain outcomes

Trusted delivery identities are stored as a hash under the route and verifier
namespace. The SQLCipher store is shared with the runtime; Apple composition
does not open a second database or load a second key.

- A completed duplicate receives the configured success status without a
  second dispatch.
- An in-flight duplicate receives `503` with `Retry-After` and never starts a
  second dispatch.
- A process restart converts unfinished records to `unknown`. An `unknown`
  duplicate receives the configured success status and is never dispatched
  automatically.
- `unknown` records never expire and count against the bounded store. When
  capacity is exhausted, new deliveries fail closed.

Use `unknownDeliveries()` to inspect uncertain records and
`resolveUnknown(_:as:)` only after reconciling the side effect in the host
system. Resolving as `completed` preserves the no-redelivery decision;
resolving as `retryAllowed` permits a future sender retry. Clearing completed
records is an explicit store-wide administrative operation. Doing so can
shorten replay protection and must follow the route's verified-freshness and
retention policy.

## Request and resource limits

The server matches the method and exact path, then applies per-peer and
per-route limits before reading the body. It collects only the selected
headers and an exact bounded body. Authentication, an additional per-principal
limit, JSON parsing, replay claim, authorization, schema validation, dispatch,
and audit follow in that order.

| Bound | Default | Configurable range |
| --- | --- | --- |
| Exact raw body | 1 MiB | 1 KiB–4 MiB |
| Retained bytes for one request lifecycle | 3 MiB | body limit–10 MiB |
| Aggregate retained bytes across active raw-body requests | 8 MiB | 1–32 MiB through the Rust/C server configuration |
| Pre-authentication requests per peer | 60/min | 1–600/min |
| Pre-authentication requests per route | 120/min | 1–1,200/min |
| Selected or signed headers | 16 | 1–32 |
| One selected header value | 2 KiB | 1 byte–8 KiB |
| Selected header names and values combined | 32 KiB | 1 byte–64 KiB |
| Deduplication records | 100,000 | 1,000–1,000,000 |
| Deduplication bytes | 16 MiB | 1–128 MiB |
| Completed-record retention | 7 days | 1–90 days |
| Signature timestamp tolerance | 5 minutes | 30 seconds–15 minutes |
| Registered raw-body handlers | one per method/path | 16 per server |
| Generation drain deadline | 10 seconds | 1–60 seconds |

Apple exposes route and deduplication limits through
`BondryWebhookIngressLimits` and `BondryWebhookDedupStoreLimits`. Its local
server currently uses the 8 MiB aggregate retained-byte default. Raising a
per-route retained budget above that server-wide budget is rejected during
registration.

## Disable and removal

`registration.disable(deadline:)` atomically closes admission, enters
`draining`, and waits for accepted requests to complete. Closed admission
does not fall through to REST or MCP. Success means the route is detached and
its native context is safely released. A timeout returns `drainTimedOut` and
leaves the generation draining; call `disable` again to finish waiting. The
same path is used during server shutdown.

Dropping a registration also closes admission, but does not wait. Use explicit
disable when the host needs confirmation that queued and in-flight work has
finished before unloading its own resources.

## TLS proxy deployment

The local HTTP runtime does not terminate TLS. Keep Bondry on loopback when
placing it behind a trusted TLS-terminating proxy. If loopback is impossible,
use a protected interface and the explicit cleartext-network acknowledgement;
the acknowledgement does not provide encryption or authenticate the proxy.

The proxy configuration is part of the signature boundary:

- Preserve the request body byte for byte. Do not decompress, transcode,
  normalize JSON, or change transfer representation before Bondry verifies it.
- Preserve the request target required by the selected signature scheme and
  preserve signed header values without merging or rewriting them.
- Bound client and proxy-to-Bondry connections, body size, header size, and
  timeouts at least as tightly as the Bondry route.
- Strip client-supplied forwarding headers. This version does not treat
  forwarding headers as trusted peer identity or authorization input.
- Run fixture and tampering tests through the deployed proxy, not only against
  the loopback listener.

Do not expose the cleartext Bondry listener directly to the internet. Browser
origin policy, opaque paths, and network-risk acknowledgement flags are not a
substitute for TLS, source verification, or firewall isolation.
