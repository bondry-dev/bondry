# Architecture

Bondry separates application capabilities from the interfaces that invoke them.

```text
REST       MCP       Webhooks       Shortcuts       Future adapters
  \         |           |              /                   /
   Authentication and protocol translation
                     |
                  Principal
                     |
Registry -> Policy -> Dispatcher -> Capability handler
                     |
                  Audit sink
```

## Core

The portable Rust core owns protocol-neutral concepts:

- Capability metadata, JSON Schema 2020-12 input contracts, and handlers
- Authenticated principal identities
- Authorization policy evaluation
- Invocation dispatch
- Structured audit outcomes

The core does not open sockets, parse authentication credentials, persist secrets, or depend on an operating-system credential store.

## Persistence

Bondry depends on storage contracts, not a particular database. Host applications can implement `AuthStore` and `AuditSink` using an existing persistence layer.

`bondry-store-sqlcipher` is an optional encrypted reference implementation for local transactional authentication, authorization, and audit storage. It is not a core dependency and has no plaintext fallback. Its database key must come from a platform-secure secret provider.

`BondryApple` is a separate Swift product that stores the SQLCipher database key in Apple Data Protection Keychain. The Rust core remains independent of Security.framework and Apple platform behavior.

`bondry-runtime-ffi` exposes runtime ownership through a versioned C ABI. `Bondry` wraps that ABI for Swift without exposing Rust layouts or pointers to application code. `bondry-local-server-ffi` is a separate native boundary that depends on the runtime ABI rather than its Rust implementation. `bondry-webhook-ingress-ffi` composes retained runtime services with the server's versioned raw-body registration hook without a Rust dependency on either FFI implementation.

## Adapters

Adapters translate external protocols into core invocations. Each adapter is responsible for input and output translation and protocol-specific error mapping. Its transport authenticates the caller and supplies only the resulting principal.

An adapter passes only a trusted principal into the core. Network adapters authenticate credentials before this boundary. Platform adapters may instead rely on an operating-system-owned invocation path and a principal selected by the host. Raw bearer tokens, cookies, passkeys, security-key responses, and other credentials must not cross this boundary.

REST and MCP share `bondry-http-server` without sharing protocol translation or authorization grants. The server owns transport concerns and invokes the pure `bondry-rest-proto` and `bondry-mcp-proto` request/response interfaces. The optional `BondryLocalServer` product authenticates and rate-limits before removing credentials and handing a bounded request to a protocol. Applications that use only `Bondry` or `BondryAppIntents` do not link the HTTP, REST, or MCP implementation. `BondryAppIntents` exposes Apple Shortcuts through a host-selected local system principal and the dedicated `shortcuts` adapter identifier.

Inbound webhook routes use the same server through a protocol-neutral raw-body registration seam. `bondry-webhook-verify` verifies exact bounded requests, while `bondry-webhook-ingress` fixes the principal, `webhook` adapter, and capability, claims replay state, and dispatches through the same `AutomationService` as REST and MCP. The server does not depend on either webhook crate, and hosts that do not select `BondryWebhookIngress` link none of that code.

`bondry-rest-proto` exposes authorized descriptors and generic capability invocation under `/api/v1`. It relies on the shared dispatcher for exact grants, input validation, handler execution, and audit outcomes.

`bondry-mcp-proto` exposes the same capability model as MCP tools under `/mcp`. MCP `2026-07-28` is the primary stateless protocol, while `2025-11-25` initialization remains available for legacy clients. The protocol owns negotiation, routing metadata, discovery, tool translation, and JSON-RPC error mapping without changing the core capability contract.

## Host Applications

The host application defines capabilities and decides which principals and adapters can invoke them. Domain logic stays in the host or a host-owned service and is reached through capability handlers.

## Request Flow

1. An adapter validates its transport and establishes a trusted principal.
2. The adapter constructs a principal and a protocol-neutral invocation.
3. The dispatcher resolves the capability and evaluates policy.
4. The dispatcher validates authorized input against the capability schema.
5. An authorized, valid invocation records a pre-execution audit event or fails closed.
6. The authorized handler executes.
7. A completion audit outcome is recorded.
8. The adapter maps the result into its external protocol.

## Portability

The core targets platforms supported by Rust's standard library. Platform behavior belongs in adapters. Persistent local servers are not assumed on platforms that suspend background applications.

Language bindings build on versioned C ABIs. The runtime ABI covers retained runtime ownership, client and token administration, bearer-token authentication, exact authorization grants, bounded audit queries, complete capability descriptors, capability registration, asynchronous dispatch, and retained service/store vtables for add-ons. The separate local-server ABI covers HTTP server ownership and versioned raw-body handler registration while reaching the runtime only through its stable boundary. Foreign handlers receive protocol-neutral JSON and trusted invocation metadata only after exact-grant authorization.
