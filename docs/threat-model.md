# Threat Model

This document describes the current pre-alpha core. Every adapter and binding will require its own threat-model extension.

## Assets

- Application capabilities and the data they expose or modify
- Client credentials and authenticated identities
- Authorization policy state
- Audit-event integrity and confidentiality
- Host application availability

## Trust Boundaries

External requests, credentials, and payloads are untrusted. An adapter must validate its transport and authenticate the requester before constructing a `Principal`.

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
- Rust layouts and error objects never cross the ABI, and unwinding is stopped before control returns to foreign code.
- C authentication failures do not distinguish malformed, unknown, mismatched, expired, revoked, or disabled-client bearer tokens.
- C results use caller-owned fixed-capacity records. One-time token records have an explicit clearing operation, and audit records exclude credentials and payloads.
- Swift keeps each newly issued token in a private C record, redacts its debug representation, and clears it when the last shared owner is released. Deliberate `String` copies remain the host's responsibility.
- The local HTTP runtime defaults to loopback, an operating-system-selected port, rejected browser origins, bounded headers, a 1 MiB body limit, connection and request limits, finite timeouts, and no keep-alive.
- HTTP authenticators receive request metadata but adapters receive only the resulting principal after credential-bearing headers are removed.
- Non-loopback cleartext listening and non-loopback disabled authentication require separate explicit acknowledgements.
- REST discovery returns only capabilities authorized for the authenticated principal and the REST adapter.
- REST uses the same response for missing and unauthorized capabilities, validates JSON media types and payloads before dispatch, and exposes only stable handler failure codes.
- MCP discovery returns only tools authorized for the authenticated principal and MCP adapter.
- MCP rejects duplicated or mismatched routing headers, requires modern per-request protocol metadata, and uses the same response for missing and unauthorized tools.
- MCP strips optional custom-header schema annotations because the adapter does not accept capability-defined transport headers.
- MCP tool results expose generated invocation identifiers and stable handler failure codes without exposing credentials or internal error messages.

## Known Gaps

The core does not yet provide invocation cancellation or idempotency. Payload-size limits currently exist at the C ABI and local HTTP boundaries rather than in every native Rust entry point. The HTTP runtime does not provide TLS; network listening is an explicitly acknowledged advanced mode and must be protected by a trusted local network or host-supplied secure transport. The REST and MCP adapters are pre-alpha and their public contracts may change. The MCP adapter does not yet implement OAuth discovery, SSE response streams, multi-round-trip responses, or subscriptions. Other protocol adapters must not be considered production-ready until their own controls are implemented and tested.

An audit completion can still fail after a handler has changed state. Mutating capabilities require an idempotency design before production use so that an adapter can safely handle this ambiguous outcome.

The encrypted reference store does not yet implement database-key rotation or backup APIs. Only Apple Keychain is implemented as a platform-secure key provider; other platforms still require host implementations. C callers remain responsible for supplying valid memory, completing each accepted handler invocation exactly once, keeping callback contexts live for their documented duration, and closing each handle exactly once without racing an ABI entry point. File encryption and Keychain do not protect data after a valid key is loaded into a compromised host process. Host applications must place database files inside an access-controlled app container and store the key separately.
