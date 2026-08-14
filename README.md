<p align="center">
  <img src="assets/bondry-logo.svg" width="160" height="160" alt="Bondry">
</p>

<h1 align="center">Bondry</h1>

Bondry is an embeddable automation foundation for exposing an application's capabilities through multiple interfaces without coupling application logic to any one protocol.

The project is in pre-alpha development. Its APIs are not stable yet.

## Goals

- Keep capability implementation independent from REST, MCP, Apple Shortcuts, and future adapters.
- Authenticate clients once and authorize every invocation with least privilege.
- Deny access by default and make exposure an explicit host-application decision.
- Produce protocol-neutral audit events without recording credentials or sensitive payloads.
- Provide a portable core with platform-specific adapters and language bindings layered above it.

## Architecture

The workspace contains the protocol-neutral dispatch core with JSON Schema 2020-12 input validation, client authentication lifecycle, exact authorization grants, runtime-neutral outbound transport contracts, a shared local HTTP runtime, generic REST and MCP adapters, an optional encrypted SQLCipher reference store, separate runtime and local-server C ABIs, an Apple Keychain provider, modular native Swift products, and an Apple Shortcuts adapter built with App Intents.

See [Architecture](docs/architecture.md), [Authentication](docs/authentication.md), [Authorization](docs/authorization.md), [Outbound transport](docs/transport.md), [Local HTTP](docs/http.md), [Implementation limits](docs/implementation-limits.md), [REST](docs/rest.md), [MCP](docs/mcp.md), [Apple server controls](docs/apple-server.md), [Apple Shortcuts](docs/apple-shortcuts.md), [Apple distribution](docs/apple-distribution.md), [Releasing](docs/releasing.md), [Storage](docs/storage.md), [C ABI](docs/c-abi.md), [Apple Keychain](docs/apple-keychain.md), [Threat model](docs/threat-model.md), [Repository safety](docs/repository-safety.md), and the [Phase 0 performance baseline](docs/performance/phase-0/README.md) for the current design constraints.

## Development

The workspace requires Rust 1.85 or newer.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo xtask gate
cargo audit
cargo deny check
swift format lint --recursive --strict Package.swift apple/Package.swift apple/Distribution/Package.release.swift apple/Sources apple/Tests apple/IntegrationTests/KeychainProbe/Sources
swift test --package-path apple
shellcheck apple/scripts/*.sh
```

Use `cargo xtask affected --base <revision>` to inspect the crate and Apple jobs required by a change.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
