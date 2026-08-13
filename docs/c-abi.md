# C ABI

`bondry-ffi` is the language-neutral boundary for embedding Bondry. The canonical public header is `bindings/c/include/bondry.h`.

## Version One

ABI v1 exposes encrypted-store lifecycle operations:

- `bondry_abi_version_v1`
- `bondry_store_open_v1`
- `bondry_store_check_v1`
- `bondry_store_close_v1`

It also exposes administrative operations without adding transport or application policy:

- Create, enumerate, enable, and disable authentication clients
- Issue, enumerate, rotate, and revoke independent client tokens
- Authenticate a bearer token into a non-secret application principal
- Add, remove, and enumerate exact principal-adapter-capability grants
- Query recent or per-principal audit metadata with a limit from 1 through 1,000
- Register, enumerate, and unregister host-owned capability handlers
- Authenticate and asynchronously dispatch protocol-neutral JSON invocations
- Dispatch trusted operating-system invocations with an explicit platform principal
- Start and stop a shared local HTTP server with independently enabled REST and MCP adapters

The store is an opaque handle. Foreign callers never allocate it, inspect its layout, or receive a Rust reference. Opening transfers one ownership unit to the caller, and closing consumes it. A non-null handle must be closed exactly once and must not be closed concurrently with another operation.

Paths cross the ABI as explicit-length UTF-8 bytes. Database keys must contain exactly 32 bytes. The open call copies the key into zeroizing Rust storage, initializes SQLCipher, and drops the temporary Rust key before returning.

Other strings also cross as explicit-length UTF-8 input. Result records have fixed capacities derived from the validated core limits, contain zero-terminated UTF-8 fields, and are written into caller-owned memory. Optional values use explicit presence fields instead of sentinel timestamps.

List calls use a two-call pattern. A null output with zero capacity reports the complete result count. Insufficient capacity returns `BONDRY_STATUS_BUFFER_TOO_SMALL`, writes no partial records, and reports the required count so the caller can retry. Audit queries remain bounded even during the count call.

Token issuance and rotation return the complete bearer token only once. The caller must call `bondry_issued_token_clear_v1` after deliberately copying or presenting it and must also clear any additional copies it creates. Authentication never retains the presented credential and maps all syntactically valid credential rejections to `BONDRY_STATUS_AUTHENTICATION_REJECTED`.

## Capability Handlers

Capability registration transfers ownership of the handler context only when registration succeeds. Bondry calls the optional release function exactly once after unregistration or store closure and after the last in-flight invocation releases the handler. Invoke and release callbacks may run on any thread and must not unwind across the ABI.

An invocation record and its JSON input are borrowed only until the invoke callback returns. A handler that completes later must copy any required data. Every handler invocation must call its supplied completion function exactly once. Success carries JSON; failure carries a validated, stable, non-sensitive error code. The completion function consumes its opaque context, so calling it more than once is invalid.

Foreign handler completion can be synchronous or asynchronous and can occur on any thread. The callback-driven executor does not block waiting for asynchronous completion or create one thread per request. Unregistration and store closure are safe after the dispatch entry point returns: an in-flight task retains only the handler, policy, audit store, and completion state it still needs.

## Dispatch

`bondry_dispatch_token_v1` validates identifiers and payload bounds, authenticates the bearer token, parses JSON, resolves the capability, checks the exact principal-adapter-capability grant, validates the input schema, records required audit events, and invokes the handler. JSON input and handler output are each limited to 1 MiB. Credentials and payloads are not retained or written to audit storage.

`bondry_dispatch_principal_v1` accepts a validated principal directly for trusted platform integrations such as Apple App Intents. It bypasses credential authentication only. Capability resolution, exact authorization, schema validation, handler execution, result mapping, and auditing are identical to token dispatch. Callers must never populate the principal from untrusted external input.

An `OK` return accepts the dispatch and guarantees exactly one result callback, which may occur before the entry point returns. An immediate validation, authentication, or storage error never calls the result callback and leaves its context caller-owned. Accepted results distinguish success, missing capability, access denial, invalid capability input, audit unavailability, and handler failure. Result pointers remain valid only for the callback duration.

## Local Server

`bondry_server_start_v1` accepts a bounded, versioned JSON configuration and returns an opaque server handle plus the actual bound IP address and port. Port zero requests an operating-system-selected port. The configuration selects REST, MCP, or both; bearer authentication remains the default at the Swift layer. Disabled authentication requires an explicit principal so grants and audit events remain attributable.

The configuration includes the bind address, exact browser origins, rate limits, body and connection limits, timeouts, network-risk acknowledgements, and MCP implementation metadata. Unknown fields, duplicate adapters, inconsistent authentication fields, invalid limits, and MCP metadata without an enabled MCP adapter are rejected. Syntax errors return `BONDRY_STATUS_INVALID_JSON`; a syntactically valid but invalid configuration returns `BONDRY_STATUS_INVALID_ARGUMENT`.

Configuration version one has this complete shape:

```json
{
  "version": 1,
  "bindAddress": "127.0.0.1",
  "port": 0,
  "authentication": {
    "mode": "bearer",
    "principalId": null,
    "principalKind": null
  },
  "adapters": ["rest", "mcp"],
  "mcpServer": {
    "name": "example-app",
    "title": "Example App",
    "version": "1.0.0"
  },
  "allowedOrigins": [],
  "requestsPerMinute": 120,
  "authenticationFailuresPerMinute": 30,
  "maxBodyBytes": 1048576,
  "maxConnections": 64,
  "headerReadTimeoutMilliseconds": 5000,
  "requestTimeoutMilliseconds": 30000,
  "shutdownGracePeriodMilliseconds": 2000,
  "allowCleartextNetwork": false,
  "allowUnauthenticatedNetwork": false
}
```

Disabled authentication uses `mode: "disabled"` with a validated `principalId` and a `principalKind` of `user`, `application`, or `system`. Bearer mode requires both principal fields to be null. `mcpServer` must be null when MCP is disabled and must contain validated implementation metadata when MCP is enabled.

The server clones the encrypted storage and live capability registry references it needs before returning. The store handle may therefore be closed after successful startup, although normal Swift ownership keeps the store and server together. Registration, unregistration, token revocation, client disablement, and grant changes take effect on subsequent requests without restarting the server.

`bondry_server_stop_v1` consumes one server handle and waits for bounded graceful shutdown. Null is a no-op. Startup distinguishes invalid configuration, address binding failure, and other runtime startup failure without returning operating-system error text or paths.

## Errors and Panics

Every function returns a stable integer status except the version query. Status values reveal safe administrative or storage categories but never Rust error text, SQL, paths, key material, or credential lookup details.

Rust unwinding is caught at each fallible ABI entry point and maps to `BONDRY_STATUS_INTERNAL_FAILURE`. Memory violations caused by dangling, undersized, or otherwise invalid foreign pointers cannot be recovered; pointer validity remains part of the C caller contract.

## Compatibility Rules

- Existing v1 function signatures and status values must not change.
- Existing status values must never be reused for another meaning.
- Compatible capabilities use new function names with the `_v1` suffix.
- A breaking ownership or representation change requires a new ABI version.

## Apple Bindings

`BondrySQLCipher` is the native Swift wrapper over ABI v1. It validates the linked ABI version, accepts only file URLs, maps every public status, closes its handle during deinitialization, and never exposes the opaque pointer. It provides Swift models for clients, non-secret token metadata, principals, exact capability grants, audit events, capability descriptors, server configuration, and server lifecycle while transparently retrying list queries that grow between calls.

Swift hosts register `@Sendable async throws` capability handlers and dispatch JSON as `Data`. The wrapper copies every borrowed C invocation before starting Swift concurrency work and retains each handler until the C release callback. Unknown Swift errors become the fixed `handler_failed` code; only an explicit `BondryCapabilityHandlerError` code crosses the trust boundary. Dispatch uses checked continuations and supports completion before the C entry point returns or later from another thread. A Swift task cancelled before dispatch does not start it. Once the C core accepts an invocation, it runs through handler completion and required auditing even if the waiting task is cancelled later.

New token secrets remain in a private C record owned by shared Swift storage. The record is cleared when its last `BondryIssuedToken` value is released. Byte-oriented consumers can avoid a `String` copy with `withUnsafeSecretBytes`; `copySecret()` exists for callers that deliberately need one.

The source package does not commit a prebuilt Rust binary. Build the macOS static library with:

```sh
apple/scripts/build-rust-macos.sh
```

The same Rust crate has been compile-checked for `aarch64-apple-ios` and `aarch64-apple-ios-sim`. Packaging signed release artifacts as an XCFramework remains a separate distribution step.

## C Verification

The C smoke test compiles against only the public header and links the Rust static library:

```sh
clang -std=c11 -Wall -Wextra -Werror -mmacosx-version-min=13.0 \
  bindings/c/tests/store_smoke.c -I bindings/c/include \
  target/apple/macos/debug/libbondry_ffi.a -liconv \
  -o /tmp/bondry-store-smoke
/tmp/bondry-store-smoke /tmp/bondry-store-smoke.db
```
