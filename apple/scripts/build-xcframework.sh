#!/bin/sh
set -eu

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
bondry_root=$(CDPATH='' cd -- "$script_directory/../.." && pwd)
artifact_directory=${BONDRY_APPLE_ARTIFACT_DIR:-"$bondry_root/target/apple/distribution"}
cargo_target_directory=${CARGO_TARGET_DIR:-"$bondry_root/target/apple/xcframework-cargo"}
source_date_epoch=${SOURCE_DATE_EPOCH:-$(git -C "$bondry_root" log -1 --format=%ct)}

case "$source_date_epoch" in
    '' | *[!0-9]*)
        printf 'SOURCE_DATE_EPOCH must contain Unix seconds.\n' >&2
        exit 1
        ;;
esac

required_targets="
aarch64-apple-darwin
x86_64-apple-darwin
aarch64-apple-ios
aarch64-apple-ios-sim
x86_64-apple-ios
"

installed_targets=$(rustup target list --installed)
for target in $required_targets; do
    if ! printf '%s\n' "$installed_targets" | awk -v target="$target" '$0 == target { found = 1 } END { exit !found }'; then
        printf 'Missing Rust target: %s\n' "$target" >&2
        target_arguments=$(printf '%s\n' "$required_targets" | awk 'NF { printf " %s", $0 }')
        printf 'Install all required targets with: rustup target add%s\n' \
            "$target_arguments" >&2
        exit 1
    fi
done

cargo fetch --locked --manifest-path "$bondry_root/Cargo.toml"

mkdir -p "$artifact_directory" "$cargo_target_directory"
artifact_directory=$(CDPATH='' cd -- "$artifact_directory" && pwd)
cargo_target_directory=$(CDPATH='' cd -- "$cargo_target_directory" && pwd)
xcframework="$artifact_directory/BondryFFI.xcframework"
archive="$artifact_directory/BondryFFI.xcframework.zip"
checksum_file="$archive.sha256"
rm -rf "$xcframework"
rm -f "$archive" "$checksum_file"

export CARGO_TARGET_DIR="$cargo_target_directory"
rust_sysroot=$(rustc --print sysroot)
build_user_directory=$(dirname "$(dirname "$(dirname "$rust_sysroot")")")
unit_separator=$(printf '\037')
case "$bondry_root" in
    "$build_user_directory"/*)
        encoded_rustflags="--remap-path-prefix=$build_user_directory=/usr/local/src"
        ;;
    *)
        encoded_rustflags="--remap-path-prefix=$bondry_root=/usr/src/bondry"
        encoded_rustflags="$encoded_rustflags$unit_separator"
        encoded_rustflags="${encoded_rustflags}--remap-path-prefix=$rust_sysroot=/usr/local/rust"
        ;;
esac

for target in $required_targets; do
    case "$target" in
        *-apple-darwin)
            deployment_variable=MACOSX_DEPLOYMENT_TARGET=13.0
            ;;
        *)
            deployment_variable=IPHONEOS_DEPLOYMENT_TARGET=16.0
            ;;
    esac
    env \
        "$deployment_variable" \
        CARGO_ENCODED_RUSTFLAGS="$encoded_rustflags" \
        cargo build \
            --locked \
            --release \
            --manifest-path "$bondry_root/Cargo.toml" \
            --package bondry-ffi \
            --target "$target"
done

staging_directory="$artifact_directory/staging"
headers_directory="$staging_directory/Headers"
macos_directory="$staging_directory/macos"
ios_directory="$staging_directory/ios"
simulator_directory="$staging_directory/ios-simulator"

rm -rf "$staging_directory"
mkdir -p \
    "$headers_directory" \
    "$macos_directory" \
    "$ios_directory" \
    "$simulator_directory"

cp "$bondry_root/bindings/c/include/bondry.h" "$headers_directory/bondry.h"
cp "$bondry_root/apple/Distribution/module.modulemap" \
    "$headers_directory/module.modulemap"

lipo -create \
    "$cargo_target_directory/aarch64-apple-darwin/release/libbondry_ffi.a" \
    "$cargo_target_directory/x86_64-apple-darwin/release/libbondry_ffi.a" \
    -output "$macos_directory/libbondry_ffi.a"

cp \
    "$cargo_target_directory/aarch64-apple-ios/release/libbondry_ffi.a" \
    "$ios_directory/libbondry_ffi.a"

lipo -create \
    "$cargo_target_directory/aarch64-apple-ios-sim/release/libbondry_ffi.a" \
    "$cargo_target_directory/x86_64-apple-ios/release/libbondry_ffi.a" \
    -output "$simulator_directory/libbondry_ffi.a"

xcodebuild -create-xcframework \
    -library "$macos_directory/libbondry_ffi.a" \
    -headers "$headers_directory" \
    -library "$ios_directory/libbondry_ffi.a" \
    -headers "$headers_directory" \
    -library "$simulator_directory/libbondry_ffi.a" \
    -headers "$headers_directory" \
    -output "$xcframework"

cp "$bondry_root/apple/Distribution/BondryFFI.Info.plist" \
    "$xcframework/Info.plist"
cp "$bondry_root/LICENSE" "$xcframework/LICENSE"
cp "$bondry_root/THIRD_PARTY_NOTICES.md" \
    "$xcframework/THIRD_PARTY_NOTICES.md"
cargo about generate \
    --config "$bondry_root/apple/Distribution/about.toml" \
    --fail \
    --locked \
    --manifest-path "$bondry_root/Cargo.toml" \
    --offline \
    --output-file "$xcframework/THIRD_PARTY_LICENSES.txt" \
    --workspace \
    "$bondry_root/apple/Distribution/ThirdPartyLicenses.hbs"
"$script_directory/verify-xcframework.sh" "$xcframework"
archive_timestamp=$(date -u -r "$source_date_epoch" '+%Y%m%d%H%M.%S')
find "$xcframework" -exec touch -h -t "$archive_timestamp" {} +
(
    cd "$artifact_directory"
    find BondryFFI.xcframework -print \
        | LC_ALL=C sort \
        | zip -X -q "$archive" -@
)
unzip -tq "$archive"
swift package compute-checksum "$archive" > "$checksum_file"

printf 'XCFramework: %s\n' "$xcframework"
printf 'Archive: %s\n' "$archive"
printf 'Checksum: %s\n' "$(sed -n '1p' "$checksum_file")"
