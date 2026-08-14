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
rm -rf \
    "$artifact_directory/BondryRuntime.xcframework" \
    "$artifact_directory/BondryLocalServer.xcframework" \
    "$artifact_directory/staging"
rm -f \
    "$artifact_directory/BondryRuntime.xcframework.zip" \
    "$artifact_directory/BondryRuntime.xcframework.zip.sha256" \
    "$artifact_directory/BondryLocalServer.xcframework.zip" \
    "$artifact_directory/BondryLocalServer.xcframework.zip.sha256"

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
            --package bondry-runtime-ffi \
            --package bondry-local-server-ffi \
            --target "$target"
done

create_xcframework() {
    framework_name=$1
    source_library_name=$2
    packaged_library_name=$3
    header=$4
    module_map=$5
    module_name=$6
    licenses=$7
    staging_directory="$artifact_directory/staging/$framework_name"
    headers_root="$staging_directory/Headers"
    headers_directory="$headers_root/$module_name"
    macos_directory="$staging_directory/macos"
    ios_directory="$staging_directory/ios"
    simulator_directory="$staging_directory/ios-simulator"
    xcframework="$artifact_directory/$framework_name.xcframework"

    mkdir -p \
        "$headers_directory" \
        "$macos_directory" \
        "$ios_directory" \
        "$simulator_directory"
    cp "$bondry_root/bindings/c/include/$header" "$headers_directory/$header"
    cp "$bondry_root/apple/Distribution/$module_map" "$headers_directory/module.modulemap"

    lipo -create \
        "$cargo_target_directory/aarch64-apple-darwin/release/$source_library_name" \
        "$cargo_target_directory/x86_64-apple-darwin/release/$source_library_name" \
        -output "$macos_directory/$packaged_library_name"
    cp \
        "$cargo_target_directory/aarch64-apple-ios/release/$source_library_name" \
        "$ios_directory/$packaged_library_name"
    lipo -create \
        "$cargo_target_directory/aarch64-apple-ios-sim/release/$source_library_name" \
        "$cargo_target_directory/x86_64-apple-ios/release/$source_library_name" \
        -output "$simulator_directory/$packaged_library_name"

    xcodebuild -create-xcframework \
        -library "$macos_directory/$packaged_library_name" \
        -headers "$headers_root" \
        -library "$ios_directory/$packaged_library_name" \
        -headers "$headers_root" \
        -library "$simulator_directory/$packaged_library_name" \
        -headers "$headers_root" \
        -output "$xcframework"

    cp "$bondry_root/LICENSE" "$xcframework/LICENSE"
    cp "$bondry_root/THIRD_PARTY_NOTICES.md" "$xcframework/THIRD_PARTY_NOTICES.md"
    cp "$licenses" "$xcframework/THIRD_PARTY_LICENSES.txt"
}

generate_licenses() {
    manifest=$1
    output=$2
    cargo about generate \
        --config "$bondry_root/apple/Distribution/about.toml" \
        --fail \
        --locked \
        --manifest-path "$manifest" \
        --offline \
        --output-file "$output" \
        "$bondry_root/apple/Distribution/ThirdPartyLicenses.hbs"
}

runtime_licenses="$artifact_directory/BondryRuntime-THIRD_PARTY_LICENSES.txt"
local_server_licenses="$artifact_directory/BondryLocalServer-THIRD_PARTY_LICENSES.txt"
generate_licenses \
    "$bondry_root/crates/ffi/bondry-runtime-ffi/Cargo.toml" \
    "$runtime_licenses"
generate_licenses \
    "$bondry_root/crates/ffi/bondry-local-server-ffi/Cargo.toml" \
    "$local_server_licenses"

create_xcframework \
    BondryRuntime \
    libbondry_runtime_ffi.a \
    libbondry_runtime.a \
    bondry.h \
    BondryRuntime.modulemap \
    CBondryRuntime \
    "$runtime_licenses"
create_xcframework \
    BondryLocalServer \
    libbondry_local_server_ffi.a \
    libbondry_local_server.a \
    bondry_local_server.h \
    BondryLocalServer.modulemap \
    CBondryLocalServer \
    "$local_server_licenses"

"$script_directory/verify-xcframework.sh" \
    "$artifact_directory/BondryRuntime.xcframework" \
    "$artifact_directory/BondryLocalServer.xcframework"

archive_timestamp=$(date -u -r "$source_date_epoch" '+%Y%m%d%H%M.%S')
for framework_name in BondryRuntime BondryLocalServer; do
    xcframework="$artifact_directory/$framework_name.xcframework"
    archive="$xcframework.zip"
    find "$xcframework" -exec touch -h -t "$archive_timestamp" {} +
    (
        cd "$artifact_directory"
        find "$framework_name.xcframework" -print \
            | LC_ALL=C sort \
            | zip -X -q "$archive" -@
    )
    unzip -tq "$archive"
    swift package compute-checksum "$archive" > "$archive.sha256"
    printf '%s: %s\n' "$framework_name" "$archive"
    printf 'Checksum: %s\n' "$(sed -n '1p' "$archive.sha256")"
done
