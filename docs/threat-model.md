# Threat Model

This document describes the current pre-alpha core. Every adapter and binding will require its own threat-model extension.

## Assets

- Application capabilities and the data they expose or modify
- Client credentials and authenticated identities
- Authorization policy state
- Audit-event integrity and confidentiality
- Host application availability

## Trust Boundaries

External requests, credentials, and payloads are untrusted. A network adapter must validate its transport and authenticate the requester before constructing a `Principal`. A platform adapter may construct a principal only when the operating system controls the invocation path and the host explicitly accepts that trust boundary.

The core trusts that an adapter-created principal has been authenticated correctly. It does not trust the principal to invoke any capability until authorization policy explicitly grants the exact principal, adapter, and capability combination.

Capability handlers are host-application code. They are trusted to enforce domain invariants and to avoid returning secrets that their capability contract does not expose.

## Current Controls

- Empty and unavailable policies fail closed.
- Grants are scoped to one principal, adapter, and capability.
- Durable grant lookup failures deny access as `PolicyUnavailable`.
- Capability identifiers are validated and bounded before entering policy state.
- Capability input schemas are size-bounded, validated as self-contained JSON Schema 2020-12 documents, compiled once, and enforced after authorization but before handler execution.
- Duplicate capability registration is rejected.
- Credentials are excluded from principals and invocation context, and principals cannot be deserialized directly from external input.
- Audit events exclude request and response payloads.
- Authorized handler execution fails closed if its pre-execution audit event cannot be recorded.
- Handler failures expose a stable code instead of an internal error message.
- The optional local reference store encrypts the entire database with SQLCipher and has no plaintext open path.
- The encrypted store requires a caller-supplied 256-bit key and restricts its primary database file to the current operating-system user on Unix platforms.
- The Apple provider stores the database key in Data Protection Keychain as a non-synchronizing, device-only item that is available only while the device is unlocked.
- The Apple provider generates keys with Security.framework cryptographic randomness, rejects malformed stored keys, and resolves concurrent first-use creation without overwriting the winning key.
- The C ABI validates pointer presence, lengths, UTF-8 input, typed values, bounded query limits, ABI versions, and opaque-handle results before use.
- The C server boundary rejects oversized, malformed, unknown, duplicated, or internally inconsistent configuration before opening a listener.
- Rust layouts and error objects never cross the ABI, and unwinding is stopped before control returns to foreign code.
- C authentication failures do not distinguish malformed, unknown, mismatched, expired, revoked, or disabled-client bearer tokens.
- C results use caller-owned fixed-capacity records. One-time token records have an explicit clearing operation, and audit records exclude credentials and payloads.
- Swift keeps each newly issued token in a private C record, redacts its debug representation, and clears it when the last shared owner is released. Deliberate `String` copies remain the host's responsibility.
- The local HTTP runtime defaults to loopback, an operating-system-selected port, rejected browser origins, bounded headers, a 1 MiB body limit, connection and request limits, finite timeouts, and a bounded keep-alive connection lifetime.
- HTTP authenticators receive request metadata but adapters receive only the resulting principal after credential-bearing headers are removed.
- Non-loopback cleartext listening and non-loopback disabled authentication require separate explicit acknowledgements.
- REST discovery returns only capabilities authorized for the authenticated principal and the REST adapter.
- REST uses the same response for missing and unauthorized capabilities, validates JSON media types and payloads before dispatch, and exposes only stable handler failure codes.
- MCP discovery returns only tools authorized for the authenticated principal and MCP adapter.
- MCP rejects duplicated or mismatched routing headers, requires modern per-request protocol metadata, and uses the same response for missing and unauthorized tools.
- MCP strips optional custom-header schema annotations because the adapter does not accept capability-defined transport headers.
- MCP tool results expose generated invocation identifiers and stable handler failure codes without exposing credentials or internal error messages.
- Trusted-platform dispatch requires a host-supplied principal and still enforces the exact principal-adapter-capability grant, input schema, handler lifecycle, and audit path used by token dispatch.
- The Shortcuts adapter discovers only registered capabilities granted to its configured principal under the `shortcuts` adapter identifier, and authorization is evaluated again for every invocation.
- The generic Shortcuts action requires authentication and returns only stable, non-sensitive error descriptions.
- Swift server handles are single-owner, stop idempotently, and perform bounded shutdown during explicit stop or deinitialization.
- Webhook routes fix the principal, `webhook` adapter, and capability at registration; external input cannot override any of them.
- Raw-body routes apply per-peer and per-route limits before body collection, reserve from a server-wide retained-byte budget, and expose only selected bounded headers.
- Webhook verifiers consume exact bounded bodies, resolve secrets through host-owned references, compare HMAC values in constant time, and never expose credential material to capability input or audit.
- Trusted delivery identities are verifier-produced and hash-keyed in persistent replay storage. In-flight and uncertain duplicates never trigger a second automatic dispatch, and capacity exhaustion fails closed.
- Disabling webhook ingress closes admission atomically, drains accepted work without REST or MCP fallback, and releases its generation only after all completions finish.

## Known Gaps

The core does not provide general invocation cancellation or idempotency. Webhook ingress adds route-scoped replay handling, but it cannot prove whether a host side effect completed when required audit persistence fails; such deliveries become `unknown` and require explicit reconciliation. Payload-size limits currently exist at the C ABI and HTTP boundaries rather than in every native Rust entry point. Cleartext network listening remains an explicitly acknowledged advanced mode. The fixed REST composition can instead terminate TLS 1.3 with host-supplied identity material, but the host still owns certificate lifecycle, trust-anchor delivery, and secure persistent key storage. The REST, MCP, Shortcuts, and webhook adapters are pre-alpha and their public contracts may change. The MCP adapter does not yet implement OAuth discovery, SSE response streams, multi-round-trip responses, or subscriptions. Other protocol adapters must not be considered production-ready until their own controls are implemented and tested.

An audit completion can still fail after a handler has changed state. Generic adapters need a host idempotency design before production use. Webhook ingress records a trusted delivery as `unknown` and refuses automatic re-dispatch, but the host still has to reconcile and resolve it.

The encrypted reference store does not yet implement database-key rotation or backup APIs. Only Apple Keychain is implemented as a platform-secure key provider; other platforms still require host implementations. C callers remain responsible for supplying valid memory, completing each accepted handler invocation exactly once, keeping callback contexts live for their documented duration, and closing each handle exactly once without racing an ABI entry point. File encryption and Keychain do not protect data after a valid key is loaded into a compromised host process. Host applications must place database files inside an access-controlled app container and store the key separately.

Shortcuts authorization identifies the host-selected local user context, not each individual shortcut or caller application. Apple does not provide a Bondry bearer credential at the App Intent boundary. A host that needs per-client credentials or independently attributable clients must expose REST or MCP instead.
