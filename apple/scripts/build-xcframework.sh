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

apple_strip=$(xcrun --find strip)
apple_ar=$(xcrun --find ar)
apple_ranlib=$(xcrun --find ranlib)

cargo fetch --locked --manifest-path "$bondry_root/Cargo.toml"

mkdir -p "$artifact_directory" "$cargo_target_directory"
artifact_directory=$(CDPATH='' cd -- "$artifact_directory" && pwd)
cargo_target_directory=$(CDPATH='' cd -- "$cargo_target_directory" && pwd)
packaged_library_directory="$artifact_directory/staging/libraries"
rm -rf \
    "$artifact_directory/BondryRuntime.xcframework" \
    "$artifact_directory/BondryLocalServer.xcframework" \
    "$artifact_directory/BondryRESTServer.xcframework" \
    "$artifact_directory/BondryEgress.xcframework" \
    "$artifact_directory/BondryWebhookIngress.xcframework" \
    "$artifact_directory/staging"
rm -f \
    "$artifact_directory/BondryRuntime.xcframework.zip" \
    "$artifact_directory/BondryRuntime.xcframework.zip.sha256" \
    "$artifact_directory/BondryLocalServer.xcframework.zip" \
    "$artifact_directory/BondryLocalServer.xcframework.zip.sha256" \
    "$artifact_directory/BondryRESTServer.xcframework.zip" \
    "$artifact_directory/BondryRESTServer.xcframework.zip.sha256" \
    "$artifact_directory/BondryEgress.xcframework.zip" \
    "$artifact_directory/BondryEgress.xcframework.zip.sha256" \
    "$artifact_directory/BondryWebhookIngress.xcframework.zip" \
    "$artifact_directory/BondryWebhookIngress.xcframework.zip.sha256"

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

deduplicate_static_addon() {
    prerequisite=$1
    addon=$2
    target=$3
    label=$4
    working_directory="$artifact_directory/staging/deduplication/$label/$target"
    prerequisite_directory="$working_directory/prerequisite"
    addon_directory="$working_directory/addon"
    prerequisite_members="$working_directory/prerequisite-members.txt"
    addon_members="$working_directory/addon-members.txt"
    shared_members="$working_directory/shared-members.txt"

    rm -rf "$working_directory"
    mkdir -p "$prerequisite_directory" "$addon_directory"
    "$apple_ar" -t "$prerequisite" | LC_ALL=C sort > "$prerequisite_members"
    "$apple_ar" -t "$addon" | LC_ALL=C sort > "$addon_members"
    if uniq -d "$prerequisite_members" | grep -q . \
        || uniq -d "$addon_members" | grep -q .; then
        printf 'Cannot deduplicate an archive with duplicate member names: %s\n' \
            "$target" >&2
        exit 1
    fi
    LC_ALL=C comm -12 "$prerequisite_members" "$addon_members" > "$shared_members"
    (
        cd "$prerequisite_directory"
        "$apple_ar" -x "$prerequisite"
    )
    (
        cd "$addon_directory"
        "$apple_ar" -x "$addon"
    )

    set --
    shared_count=0
    while IFS= read -r member; do
        if [ "$member" = '__.SYMDEF SORTED' ]; then
            continue
        fi
        if ! cmp -s \
            "$prerequisite_directory/$member" \
            "$addon_directory/$member"; then
            printf 'Shared archive member differs in %s: %s (%s)\n' \
                "$label" "$member" "$target" >&2
            exit 1
        fi
        set -- "$@" "$member"
        shared_count=$((shared_count + 1))
    done < "$shared_members"
    if [ "$shared_count" -eq 0 ]; then
        printf 'Static add-on has no shared archive members: %s (%s)\n' \
            "$label" "$target" >&2
        exit 1
    fi
    "$apple_ar" -d "$addon" "$@"
    "$apple_ranlib" -D "$addon"
    "$apple_ar" -t "$addon" | LC_ALL=C sort > "$addon_members"
    if LC_ALL=C comm -12 "$prerequisite_members" "$addon_members" \
        | grep -Fvx '__.SYMDEF SORTED' \
        | grep -q .; then
        printf '%s still contains prerequisite-owned objects: %s\n' \
            "$label" "$target" >&2
        exit 1
    fi
    printf 'Deduplicated %s prerequisite-owned objects from %s (%s).\n' \
        "$shared_count" "$label" "$target"
}

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
            --package bondry-egress-ffi \
            --package bondry-webhook-ingress-ffi \
            --target "$target"
    "$apple_strip" -x \
        "$cargo_target_directory/$target/release/libbondry_runtime_ffi.a" \
        "$cargo_target_directory/$target/release/libbondry_local_server_ffi.a" \
        "$cargo_target_directory/$target/release/libbondry_egress_ffi.a" \
        "$cargo_target_directory/$target/release/libbondry_webhook_ingress_ffi.a"
    "$apple_ranlib" -D \
        "$cargo_target_directory/$target/release/libbondry_runtime_ffi.a" \
        "$cargo_target_directory/$target/release/libbondry_local_server_ffi.a" \
        "$cargo_target_directory/$target/release/libbondry_egress_ffi.a" \
        "$cargo_target_directory/$target/release/libbondry_webhook_ingress_ffi.a"
    target_library_directory="$packaged_library_directory/$target"
    mkdir -p "$target_library_directory"
    cp \
        "$cargo_target_directory/$target/release/libbondry_runtime_ffi.a" \
        "$cargo_target_directory/$target/release/libbondry_local_server_ffi.a" \
        "$cargo_target_directory/$target/release/libbondry_egress_ffi.a" \
        "$cargo_target_directory/$target/release/libbondry_webhook_ingress_ffi.a" \
        "$target_library_directory/"
    env \
        "$deployment_variable" \
        CARGO_ENCODED_RUSTFLAGS="$encoded_rustflags" \
        cargo build \
            --locked \
            --release \
            --manifest-path "$bondry_root/Cargo.toml" \
            --package bondry-local-server-ffi \
            --no-default-features \
            --features rest-server \
            --target "$target"
    "$apple_strip" -x \
        "$cargo_target_directory/$target/release/libbondry_local_server_ffi.a"
    "$apple_ranlib" -D \
        "$cargo_target_directory/$target/release/libbondry_local_server_ffi.a"
    cp \
        "$cargo_target_directory/$target/release/libbondry_local_server_ffi.a" \
        "$target_library_directory/libbondry_rest_server_ffi.a"
    deduplicate_static_addon \
        "$target_library_directory/libbondry_runtime_ffi.a" \
        "$target_library_directory/libbondry_egress_ffi.a" \
        "$target" \
        BondryEgress
    deduplicate_static_addon \
        "$target_library_directory/libbondry_runtime_ffi.a" \
        "$target_library_directory/libbondry_webhook_ingress_ffi.a" \
        "$target" \
        BondryWebhookIngress-runtime
    deduplicate_static_addon \
        "$target_library_directory/libbondry_local_server_ffi.a" \
        "$target_library_directory/libbondry_webhook_ingress_ffi.a" \
        "$target" \
        BondryWebhookIngress-server
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
        "$packaged_library_directory/aarch64-apple-darwin/$source_library_name" \
        "$packaged_library_directory/x86_64-apple-darwin/$source_library_name" \
        -output "$macos_directory/$packaged_library_name"
    cp \
        "$packaged_library_directory/aarch64-apple-ios/$source_library_name" \
        "$ios_directory/$packaged_library_name"
    lipo -create \
        "$packaged_library_directory/aarch64-apple-ios-sim/$source_library_name" \
        "$packaged_library_directory/x86_64-apple-ios/$source_library_name" \
        -output "$simulator_directory/$packaged_library_name"

    xcodebuild -create-xcframework \
        -library "$macos_directory/$packaged_library_name" \
        -headers "$headers_root" \
        -library "$ios_directory/$packaged_library_name" \
        -headers "$headers_root" \
        -library "$simulator_directory/$packaged_library_name" \
        -headers "$headers_root" \
        -output "$xcframework"
    sed "s/__LIBRARY_NAME__/$packaged_library_name/g" \
        "$bondry_root/apple/Distribution/XCFrameworkInfo.plist" \
        > "$xcframework/Info.plist"
    plutil -lint "$xcframework/Info.plist" > /dev/null

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
rest_server_licenses="$artifact_directory/BondryRESTServer-THIRD_PARTY_LICENSES.txt"
egress_licenses="$artifact_directory/BondryEgress-THIRD_PARTY_LICENSES.txt"
ingress_licenses="$artifact_directory/BondryWebhookIngress-THIRD_PARTY_LICENSES.txt"
generate_licenses \
    "$bondry_root/crates/ffi/bondry-runtime-ffi/Cargo.toml" \
    "$runtime_licenses"
generate_licenses \
    "$bondry_root/crates/ffi/bondry-local-server-ffi/Cargo.toml" \
    "$local_server_licenses"
cargo about generate \
    --config "$bondry_root/apple/Distribution/about.toml" \
    --fail \
    --locked \
    --manifest-path "$bondry_root/crates/ffi/bondry-local-server-ffi/Cargo.toml" \
    --no-default-features \
    --features rest-server \
    --offline \
    --output-file "$rest_server_licenses" \
    "$bondry_root/apple/Distribution/ThirdPartyLicenses.hbs"
generate_licenses \
    "$bondry_root/crates/ffi/bondry-egress-ffi/Cargo.toml" \
    "$egress_licenses"
generate_licenses \
    "$bondry_root/crates/ffi/bondry-webhook-ingress-ffi/Cargo.toml" \
    "$ingress_licenses"

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
create_xcframework \
    BondryRESTServer \
    libbondry_rest_server_ffi.a \
    libbondry_rest_server.a \
    bondry_rest_server.h \
    BondryRESTServer.modulemap \
    CBondryRESTServer \
    "$rest_server_licenses"
create_xcframework \
    BondryEgress \
    libbondry_egress_ffi.a \
    libbondry_egress.a \
    bondry_egress.h \
    BondryEgress.modulemap \
    CBondryEgress \
    "$egress_licenses"
create_xcframework \
    BondryWebhookIngress \
    libbondry_webhook_ingress_ffi.a \
    libbondry_webhook_ingress.a \
    bondry_webhook_ingress.h \
    BondryWebhookIngress.modulemap \
    CBondryWebhookIngress \
    "$ingress_licenses"

"$script_directory/verify-xcframework.sh" \
    "$artifact_directory/BondryRuntime.xcframework" \
    "$artifact_directory/BondryLocalServer.xcframework" \
    "$artifact_directory/BondryRESTServer.xcframework" \
    "$artifact_directory/BondryEgress.xcframework" \
    "$artifact_directory/BondryWebhookIngress.xcframework"

archive_timestamp=$(date -u -r "$source_date_epoch" '+%Y%m%d%H%M.%S')
aggregate_archive_size=0
for framework_name in BondryRuntime BondryLocalServer BondryRESTServer BondryEgress BondryWebhookIngress; do
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
    archive_size=$(stat -f %z "$archive")
    aggregate_archive_size=$((aggregate_archive_size + archive_size))
    if [ "$framework_name" = BondryEgress ] && [ "$archive_size" -gt 41943040 ]; then
        printf 'BondryEgress archive exceeds 40 MiB: %s bytes.\n' "$archive_size" >&2
        exit 1
    fi
    if [ "$framework_name" = BondryWebhookIngress ] && [ "$archive_size" -gt 31457280 ]; then
        printf 'BondryWebhookIngress archive exceeds 30 MiB: %s bytes.\n' \
            "$archive_size" >&2
        exit 1
    fi
    printf '%s: %s\n' "$framework_name" "$archive"
    printf 'Checksum: %s\n' "$(sed -n '1p' "$archive.sha256")"
done
if [ "$aggregate_archive_size" -gt 262144000 ]; then
    printf 'Aggregate Apple archives exceed 250 MiB: %s bytes.\n' \
        "$aggregate_archive_size" >&2
    exit 1
fi
