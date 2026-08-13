# Architecture

Bondry separates application capabilities from the interfaces that invoke them.

```text
REST       MCP       Shortcuts       Future adapters
  \         |           /                   /
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

- Capability metadata and handlers
- Authenticated principal identities
- Authorization policy evaluation
- Invocation dispatch
- Structured audit outcomes

The core does not open sockets, parse authentication credentials, persist secrets, or depend on an operating-system credential store.

## Persistence

Bondry depends on storage contracts, not a particular database. Host applications can implement `AuthStore` and `AuditSink` using an existing persistence layer.

`bondry-store-sqlcipher` is an optional encrypted reference implementation for local transactional storage. It is not a core dependency and has no plaintext fallback. Its database key must come from a platform-secure secret provider such as Keychain on Apple platforms.

## Adapters

Adapters translate external protocols into core invocations. Each adapter is responsible for authentication, input and output translation, protocol-specific error mapping, and transport security.

An adapter passes only an authenticated principal identifier into the core. Raw bearer tokens, cookies, passkeys, security-key responses, and other credentials must not cross this boundary.

REST and MCP can share an HTTP transport without sharing authorization policy. Apple Shortcuts uses App Intents in a Swift adapter and can represent the operating system as an authenticated local principal.

## Host Applications

The host application defines capabilities and decides which principals and adapters can invoke them. Domain logic stays in the host or a host-owned service and is reached through capability handlers.

## Request Flow

1. An adapter validates the transport and authenticates a client.
2. The adapter constructs a principal and a protocol-neutral invocation.
3. The dispatcher resolves the capability and evaluates policy.
4. An authorized invocation records a pre-execution audit event or fails closed.
5. The authorized handler executes.
6. A completion audit outcome is recorded.
7. The adapter maps the result into its external protocol.

## Portability

The core targets platforms supported by Rust's standard library. Platform behavior belongs in adapters. Persistent local servers are not assumed on platforms that suspend background applications.

Language bindings will be built over a versioned C ABI after the native Rust API and ownership model have stabilized.
