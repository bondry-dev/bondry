# Apple Distribution

Bondry ships four static XCFrameworks so a consumer links only the native functionality selected by its Swift products:

- `BondryRuntime.xcframework` contains encrypted storage, authentication, authorization, audit, capability registration, and dispatch.
- `BondryLocalServer.xcframework` contains the optional local HTTP runtime plus REST and MCP adapters. It calls the runtime through the versioned C ABI and does not contain the SQLCipher store implementation.
- `BondryEgress.xcframework` contains the sans-I/O egress runtime plus webhook and MCP route kinds. It uses host networking on Apple and contains no Rust network or TLS stack.
- `BondryWebhookIngress.xcframework` contains webhook verification and fixed route adaptation. It composes runtime and local-server vtables and contains neither their implementations nor egress code.

`BondryApple` has no native binary dependency. `Bondry` selects `BondryRuntime`; `BondryLocalServer` selects runtime and server; `BondryAppIntents` selects only runtime; `BondryEgress` selects runtime and egress; and `BondryWebhookIngress` selects runtime, server, and ingress. Declaring every binary target in the package manifest may make all developer artifacts available for download, but SwiftPM links only targets in the selected product graph.

The `main` branch manifest uses local wrapper targets for development. Release preparation replaces it atomically with the binary-target manifest stored in `apple/Distribution/Package.release.swift`, with the version and four checksums fixed to the prepared artifacts.

Apple builds use SQLCipher's CommonCrypto provider. Runtime consumers link Security, CoreFoundation, and `libiconv`.

## Build

The builder requires Xcode, Swift, Rust, Cargo, `cargo-about` 0.9.1, and the supported Apple Rust targets:

```sh
cargo install --locked --version 0.9.1 --features cli cargo-about
rustup target add \
  aarch64-apple-darwin \
  x86_64-apple-darwin \
  aarch64-apple-ios \
  aarch64-apple-ios-sim \
  x86_64-apple-ios
```

Build and verify all artifacts:

```sh
apple/scripts/build-xcframework.sh
```

Prepare a local release manifest with all generated checksums:

```sh
apple/scripts/prepare-release.sh 0.1.2
```

Excluded outputs are written below `target/apple/distribution`. Set `BONDRY_APPLE_ARTIFACT_DIR` to choose another destination and `CARGO_TARGET_DIR` to reuse another Cargo cache. Archive timestamps default to the source commit time and can be fixed with `SOURCE_DATE_EPOCH`.

## Verification

The build fails unless:

- macOS contains `arm64` and `x86_64`, iOS device contains `arm64`, and iOS Simulator contains `arm64` and `x86_64`.
- Every slice contains its canonical header and correctly named Clang module.
- Every artifact contains the project license, SQLCipher notice, and generated dependency licenses.
- No native library contains a private build-machine path.
- `BondryRuntime` exports the runtime ABI and no `bondry_server_*` symbol.
- `BondryLocalServer` exports the server ABI and does not define `bondry_store_open_v1`.
- `BondryEgress` exports the egress ABI and contains no runtime store, server, ingress, or Rust network implementation.
- `BondryWebhookIngress` exports the ingress ABI and contains no runtime store, server, or egress implementation.
- C consumers link at the macOS 13 and iOS 16 deployment targets.
- A real runtime-only Swift executable contains neither local-server symbols nor REST or MCP routes and remains below the linked-size budget.
- A real server-enabled Swift executable starts and stops a local server and remains below its linked-size budget.
- A real ingress-enabled Swift executable verifies and dispatches a loopback webhook, drains its route, and remains below the ingress and combined linked-size budgets.
- Every archive is structurally valid, deterministic, and has an independently verified SwiftPM checksum.

Verify existing frameworks directly:

```sh
apple/scripts/verify-xcframework.sh \
  path/to/BondryRuntime.xcframework \
  path/to/BondryLocalServer.xcframework \
  path/to/BondryEgress.xcframework \
  path/to/BondryWebhookIngress.xcframework
```

## Release Contract

Each release contains eight immutable assets: four XCFramework archives and their checksum files. The tagged manifest records all four exact checksums. Preparation builds each archive once; protected publication verifies, attests, and uploads those same bytes without rebuilding them. The complete archive set must remain at or below 250 MiB; `BondryEgress` is capped at 40 MiB and `BondryWebhookIngress` at 30 MiB.

Do not create release tags manually or reuse a tag for different bytes. A source change to either ABI, a transitive native dependency, or a canonical header requires a newly prepared version.
