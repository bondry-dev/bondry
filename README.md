# Bondry

Bondry is an embeddable automation foundation for exposing an application's capabilities through multiple interfaces without coupling application logic to any one protocol.

The project is in private, pre-alpha development. Its APIs are not stable yet.

## Goals

- Keep capability implementation independent from REST, MCP, Apple Shortcuts, and future adapters.
- Authenticate clients once and authorize every invocation with least privilege.
- Deny access by default and make exposure an explicit host-application decision.
- Produce protocol-neutral audit events without recording credentials or sensitive payloads.
- Provide a portable core with platform-specific adapters and language bindings layered above it.

## Architecture

The workspace currently contains the protocol-neutral dispatch core, client authentication lifecycle, exact authorization grants, an optional encrypted SQLCipher reference store, a versioned C administration ABI, an Apple Keychain provider, and native Swift store and administration APIs. Network servers, protocol adapters, and Apple App Intents remain separate layers.

See [Architecture](docs/architecture.md), [Authentication](docs/authentication.md), [Authorization](docs/authorization.md), [Storage](docs/storage.md), [C ABI](docs/c-abi.md), [Apple Keychain](docs/apple-keychain.md), [Threat model](docs/threat-model.md), and [Repository safety](docs/repository-safety.md) for the current design constraints.

## Development

The workspace requires Rust 1.85 or newer.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
swift format lint --recursive --strict apple/Package.swift apple/Sources apple/Tests apple/IntegrationTests/KeychainProbe/Sources
swift test --package-path apple
```

## License

No license has been selected yet. Until a license is added, all rights are reserved.
