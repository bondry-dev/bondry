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

The first milestone is the Rust core: capability registration, principals, policy evaluation, dispatch, and audit events. Network servers, protocol adapters, credential storage, Apple platform integration, and language bindings will be separate layers.

See [Architecture](docs/architecture.md) and [Repository safety](docs/repository-safety.md) for the current design constraints.

## Development

The workspace requires Rust 1.85 or newer.

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## License

No license has been selected yet. Until a license is added, all rights are reserved.
