# Apple Distribution

Bondry ships two static XCFrameworks so a consumer links only the native functionality selected by its Swift products:

- `BondryRuntime.xcframework` contains encrypted storage, authentication, authorization, audit, capability registration, and dispatch.
- `BondryLocalServer.xcframework` contains the optional local HTTP runtime plus REST and MCP adapters. It calls the runtime through the versioned C ABI and does not contain the SQLCipher store implementation.

`BondryApple` has no native binary dependency. `Bondry` selects `BondryRuntime`; `BondryLocalServer` selects both runtime and server; `BondryAppIntents` selects only the runtime. Declaring both binary targets in the package manifest may download both developer artifacts, but SwiftPM links only targets in the selected product graph.

The `main` branch manifest uses local wrapper targets for development. Release preparation replaces it atomically with the binary-target manifest stored in `apple/Distribution/Package.release.swift`, with the version and both checksums fixed to the prepared artifacts.

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

Build and verify both artifacts:

```sh
apple/scripts/build-xcframework.sh
```

Prepare a local release manifest with both generated checksums:

```sh
apple/scripts/prepare-release.sh 0.0.2
```

Excluded outputs are written below `target/apple/distribution`. Set `BONDRY_APPLE_ARTIFACT_DIR` to choose another destination and `CARGO_TARGET_DIR` to reuse another Cargo cache. Archive timestamps default to the source commit time and can be fixed with `SOURCE_DATE_EPOCH`.

## Verification

The build fails unless:

- macOS contains `arm64` and `x86_64`, iOS device contains `arm64`, and iOS Simulator contains `arm64` and `x86_64`.
- Every slice contains its canonical header and correctly named Clang module.
- Both artifacts contain the project license, SQLCipher notice, and generated dependency licenses.
- No native library contains a private build-machine path.
- `BondryRuntime` exports the runtime ABI and no `bondry_server_*` symbol.
- `BondryLocalServer` exports the server ABI and does not define `bondry_store_open_v1`.
- C consumers link at the macOS 13 and iOS 16 deployment targets.
- A real runtime-only Swift executable contains neither local-server symbols nor REST or MCP routes and remains below the linked-size budget.
- A real server-enabled Swift executable starts and stops a local server and remains below its linked-size budget.
- Both archives are structurally valid, deterministic, and have independently verified SwiftPM checksums.

Verify existing frameworks directly:

```sh
apple/scripts/verify-xcframework.sh \
  path/to/BondryRuntime.xcframework \
  path/to/BondryLocalServer.xcframework
```

## Release Contract

Each release contains four immutable assets: two XCFramework archives and their checksum files. The tagged manifest records both exact checksums. Preparation builds each archive once; protected publication verifies, attests, and uploads those same bytes without rebuilding them.

Do not create release tags manually or reuse a tag for different bytes. A source change to either ABI, a transitive native dependency, or a canonical header requires a newly prepared version.
