# Apple Distribution

Bondry's native Swift targets depend on the Rust C ABI. Release builds distribute that ABI as a static `BondryFFI.xcframework`; the binary itself is not committed to the source repository.

Apple builds use SQLCipher's CommonCrypto provider. Swift package targets that link the static binary must also link Security, CoreFoundation, and `libiconv`.

## Build

The builder requires Xcode, Swift, Rust, Cargo, `cargo-about` 0.9.1, and these Rust standard-library targets:

```sh
cargo install --locked --version 0.9.1 --features cli cargo-about
```

```sh
rustup target add \
  aarch64-apple-darwin \
  x86_64-apple-darwin \
  aarch64-apple-ios \
  aarch64-apple-ios-sim \
  x86_64-apple-ios
```

Build a distributable artifact from a clean checkout:

```sh
apple/scripts/build-xcframework.sh
```

For a local or manually managed release, prepare the root Swift package manifest and its release checksum with:

```sh
apple/scripts/prepare-release.sh 0.0.1
```

The command writes excluded build outputs below `target/apple/distribution`:

- `BondryFFI.xcframework`
- `BondryFFI.xcframework.zip`
- `BondryFFI.xcframework.zip.sha256`

Set `BONDRY_APPLE_ARTIFACT_DIR` to place the final outputs elsewhere. Set `CARGO_TARGET_DIR` to reuse another Cargo build cache. Archive timestamps default to the source commit time; controlled build environments can supply `SOURCE_DATE_EPOCH` explicitly.

## Verification

The build fails unless all of these checks pass:

- macOS contains `arm64` and `x86_64` slices.
- iOS device contains `arm64`.
- iOS Simulator contains `arm64` and `x86_64` slices.
- Every slice contains the canonical public header and `CBondry` module map.
- The artifact contains the Bondry license, SQLCipher notice, and generated Rust dependency licenses.
- The public ABI version symbol is exported.
- Rust source paths are remapped, and no private build-machine user path is embedded.
- C consumers link at the macOS 13 and iOS 16 deployment targets.
- The macOS C smoke test opens and checks an encrypted store.
- A temporary SwiftPM consumer compiles all Swift products against the binary target and opens a real encrypted store.
- The release archive is structurally valid and has a SwiftPM checksum.
- Archive entries have stable ordering and normalized file timestamps.

An existing artifact can be checked independently:

```sh
apple/scripts/verify-xcframework.sh path/to/BondryFFI.xcframework
```

## Release Contract

Attach `BondryFFI.xcframework.zip` to the matching GitHub release. The Swift package manifest for that release must use the exact checksum printed by the builder:

```swift
.binaryTarget(
  name: "BondryFFI",
  url: "https://github.com/bondry-dev/bondry/releases/download/v0.0.1/BondryFFI.xcframework.zip",
  checksum: "<swift-package-checksum>"
)
```

`BondrySQLCipher` depends on the binary target and imports its `CBondry` module. `BondryApple` remains independent of the Rust binary, while `BondryAppIntents` depends on `BondrySQLCipher`.

The GitHub release preparation workflow builds the archive once, records that archive's checksum in the tagged manifest, and stores the exact archive for the protected publication workflow. Publication verifies and promotes the stored artifact without rebuilding it. Do not create release tags manually or reuse an existing tag for a different archive or checksum. A source change to the C ABI, its transitive native dependencies, or the canonical header requires a newly prepared artifact and manifest.

During private development, consumers should use a locally generated artifact. Public applications should move to the immutable release URL so a clean clone and CI build never depend on an adjacent checkout or machine-specific library path.
