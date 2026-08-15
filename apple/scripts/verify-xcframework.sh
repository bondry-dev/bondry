#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    printf 'Usage: %s <BondryRuntime.xcframework> <BondryLocalServer.xcframework> <BondryEgress.xcframework>\n' "$0" >&2
    exit 64
fi

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
bondry_root=$(CDPATH='' cd -- "$script_directory/../.." && pwd)
runtime_framework=$1
server_framework=$2
egress_framework=$3
runtime_macos_slice="$runtime_framework/macos-arm64_x86_64"
runtime_ios_slice="$runtime_framework/ios-arm64"
runtime_simulator_slice="$runtime_framework/ios-arm64_x86_64-simulator"
server_macos_slice="$server_framework/macos-arm64_x86_64"
server_ios_slice="$server_framework/ios-arm64"
server_simulator_slice="$server_framework/ios-arm64_x86_64-simulator"
egress_macos_slice="$egress_framework/macos-arm64_x86_64"
egress_ios_slice="$egress_framework/ios-arm64"
egress_simulator_slice="$egress_framework/ios-arm64_x86_64-simulator"
runtime_macos_library="$runtime_macos_slice/libbondry_runtime.a"
runtime_ios_library="$runtime_ios_slice/libbondry_runtime.a"
runtime_simulator_library="$runtime_simulator_slice/libbondry_runtime.a"
server_macos_library="$server_macos_slice/libbondry_local_server.a"
server_ios_library="$server_ios_slice/libbondry_local_server.a"
server_simulator_library="$server_simulator_slice/libbondry_local_server.a"
egress_macos_library="$egress_macos_slice/libbondry_egress.a"
egress_ios_library="$egress_ios_slice/libbondry_egress.a"
egress_simulator_library="$egress_simulator_slice/libbondry_egress.a"
runtime_macos_headers="$runtime_macos_slice/Headers/CBondryRuntime"
runtime_ios_headers="$runtime_ios_slice/Headers/CBondryRuntime"
runtime_simulator_headers="$runtime_simulator_slice/Headers/CBondryRuntime"
egress_macos_headers="$egress_macos_slice/Headers/CBondryEgress"
egress_ios_headers="$egress_ios_slice/Headers/CBondryEgress"
egress_simulator_headers="$egress_simulator_slice/Headers/CBondryEgress"

for framework in "$runtime_framework" "$server_framework" "$egress_framework"; do
    test -f "$framework/Info.plist"
    cmp "$bondry_root/LICENSE" "$framework/LICENSE"
    cmp "$bondry_root/THIRD_PARTY_NOTICES.md" "$framework/THIRD_PARTY_NOTICES.md"
    test -s "$framework/THIRD_PARTY_LICENSES.txt"
done

lipo "$runtime_macos_library" -verify_arch arm64 x86_64
lipo "$runtime_ios_library" -verify_arch arm64
lipo "$runtime_simulator_library" -verify_arch arm64 x86_64
lipo "$server_macos_library" -verify_arch arm64 x86_64
lipo "$server_ios_library" -verify_arch arm64
lipo "$server_simulator_library" -verify_arch arm64 x86_64
lipo "$egress_macos_library" -verify_arch arm64 x86_64
lipo "$egress_ios_library" -verify_arch arm64
lipo "$egress_simulator_library" -verify_arch arm64 x86_64

for slice in "$runtime_macos_slice" "$runtime_ios_slice" "$runtime_simulator_slice"; do
    cmp "$bondry_root/bindings/c/include/bondry.h" \
        "$slice/Headers/CBondryRuntime/bondry.h"
    cmp "$bondry_root/apple/Distribution/BondryRuntime.modulemap" \
        "$slice/Headers/CBondryRuntime/module.modulemap"
done
for slice in "$egress_macos_slice" "$egress_ios_slice" "$egress_simulator_slice"; do
    cmp "$bondry_root/bindings/c/include/bondry_egress.h" \
        "$slice/Headers/CBondryEgress/bondry_egress.h"
    cmp "$bondry_root/apple/Distribution/BondryEgress.modulemap" \
        "$slice/Headers/CBondryEgress/module.modulemap"
done
for slice in "$server_macos_slice" "$server_ios_slice" "$server_simulator_slice"; do
    cmp "$bondry_root/bindings/c/include/bondry_local_server.h" \
        "$slice/Headers/CBondryLocalServer/bondry_local_server.h"
    cmp "$bondry_root/apple/Distribution/BondryLocalServer.modulemap" \
        "$slice/Headers/CBondryLocalServer/module.modulemap"
done

for library in \
    "$runtime_macos_library" \
    "$runtime_ios_library" \
    "$runtime_simulator_library" \
    "$server_macos_library" \
    "$server_ios_library" \
    "$server_simulator_library" \
    "$egress_macos_library" \
    "$egress_ios_library" \
    "$egress_simulator_library"
do
    if strings -a "$library" | grep -E -q '/Users/|/home/|[A-Za-z]:\\Users'; then
        printf 'An XCFramework contains a private build-machine path: %s\n' "$library" >&2
        exit 1
    fi
done

if ! nm -gU "$runtime_macos_library" 2>/dev/null \
    | awk '$NF == "_bondry_abi_version_v1" { found = 1 } END { exit !found }'; then
    printf 'BondryRuntime does not export bondry_abi_version_v1.\n' >&2
    exit 1
fi
if nm -gU "$runtime_macos_library" 2>/dev/null \
    | awk '$NF ~ /^_bondry_server_/ { found = 1 } END { exit !found }'; then
    printf 'BondryRuntime exports local-server symbols.\n' >&2
    exit 1
fi
if ! nm -gU "$server_macos_library" 2>/dev/null \
    | awk '$NF == "_bondry_server_start_v1" { found = 1 } END { exit !found }'; then
    printf 'BondryLocalServer does not export bondry_server_start_v1.\n' >&2
    exit 1
fi
if nm -gU "$server_macos_library" 2>/dev/null \
    | awk '$NF == "_bondry_store_open_v1" { found = 1 } END { exit !found }'; then
    printf 'BondryLocalServer defines the runtime store implementation.\n' >&2
    exit 1
fi
if ! nm -gU "$egress_macos_library" 2>/dev/null \
    | awk '$NF == "_bondry_egress_start_v1" { found = 1 } END { exit !found }'; then
    printf 'BondryEgress does not export bondry_egress_start_v1.\n' >&2
    exit 1
fi
if nm -gU "$egress_macos_library" 2>/dev/null \
    | awk '$NF == "_bondry_store_open_v1" { found = 1 } END { exit !found }'; then
    printf 'BondryEgress defines the runtime store implementation.\n' >&2
    exit 1
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/bondry-xcframework.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM
iphoneos_sdk=$(xcrun --sdk iphoneos --show-sdk-path)
iphonesimulator_sdk=$(xcrun --sdk iphonesimulator --show-sdk-path)
apple_clang=$(xcrun --find clang)

printf '%s\n' \
    '@import CBondryRuntime;' \
    '@import CBondryLocalServer;' \
    '@import CBondryEgress;' \
    'uint32_t bondry_module_smoke(void) { return bondry_abi_version_v1(); }' \
    > "$temporary_directory/module-smoke.m"

cc \
    -fmodules \
    -fmodules-cache-path="$temporary_directory/modules" \
    -I "$runtime_macos_slice/Headers" \
    -I "$server_macos_slice/Headers" \
    -I "$egress_macos_slice/Headers" \
    -fsyntax-only \
    "$temporary_directory/module-smoke.m"

cc \
    -std=c11 \
    -Wall \
    -Wextra \
    -Werror \
    -mmacosx-version-min=13.0 \
    -Wl,-fatal_warnings \
    "$bondry_root/bindings/c/tests/store_smoke.c" \
    -I "$runtime_macos_headers" \
    "$runtime_macos_library" \
    -framework CoreFoundation \
    -framework Security \
    -liconv \
    -o "$temporary_directory/bondry-runtime-smoke"

"$temporary_directory/bondry-runtime-smoke" "$temporary_directory/store.db"

cc \
    -std=c11 \
    -Wall \
    -Wextra \
    -Werror \
    -mmacosx-version-min=13.0 \
    -Wl,-fatal_warnings \
    "$bondry_root/bindings/c/tests/egress_smoke.c" \
    -I "$runtime_macos_headers" \
    -I "$egress_macos_headers" \
    "$runtime_macos_library" \
    "$egress_macos_library" \
    -framework CoreFoundation \
    -framework Security \
    -liconv \
    -o "$temporary_directory/bondry-egress-smoke"

"$temporary_directory/bondry-egress-smoke" "$temporary_directory/egress.db"

for platform in ios simulator; do
    case "$platform" in
        ios)
            target=arm64-apple-ios16.0
            sdk=$iphoneos_sdk
            runtime_library=$runtime_ios_library
            runtime_headers=$runtime_ios_headers
            egress_library=$egress_ios_library
            egress_headers=$egress_ios_headers
            ;;
        simulator)
            target=arm64-apple-ios16.0-simulator
            sdk=$iphonesimulator_sdk
            runtime_library=$runtime_simulator_library
            runtime_headers=$runtime_simulator_headers
            egress_library=$egress_simulator_library
            egress_headers=$egress_simulator_headers
            ;;
    esac
    "$apple_clang" \
        -std=c11 \
        -Wall \
        -Wextra \
        -Werror \
        -target "$target" \
        -isysroot "$sdk" \
        -Wl,-fatal_warnings \
        "$bondry_root/bindings/c/tests/store_smoke.c" \
        -I "$runtime_headers" \
        "$runtime_library" \
        -framework CoreFoundation \
        -framework Security \
        -liconv \
        -o "$temporary_directory/bondry-runtime-smoke-$platform"
    "$apple_clang" \
        -std=c11 \
        -Wall \
        -Wextra \
        -Werror \
        -target "$target" \
        -isysroot "$sdk" \
        -Wl,-fatal_warnings \
        "$bondry_root/bindings/c/tests/egress_smoke.c" \
        -I "$runtime_headers" \
        -I "$egress_headers" \
        "$runtime_library" \
        "$egress_library" \
        -framework CoreFoundation \
        -framework Security \
        -liconv \
        -o "$temporary_directory/bondry-egress-smoke-$platform"
done

package_directory="$temporary_directory/BondryBinaryProbe"
mkdir -p \
    "$package_directory/Sources/Bondry" \
    "$package_directory/Sources/BondryApple" \
    "$package_directory/Sources/BondryEgress" \
    "$package_directory/Sources/BondryLocalServer" \
    "$package_directory/Sources/EgressProbe" \
    "$package_directory/Sources/RuntimeProbe" \
    "$package_directory/Sources/ServerProbe"

cp -R "$runtime_framework" "$package_directory/BondryRuntime.xcframework"
cp -R "$server_framework" "$package_directory/BondryLocalServer.xcframework"
cp -R "$egress_framework" "$package_directory/BondryEgress.xcframework"
cp "$bondry_root/apple/Sources/Bondry/"*.swift "$package_directory/Sources/Bondry/"
cp "$bondry_root/apple/Sources/BondryApple/"*.swift "$package_directory/Sources/BondryApple/"
cp "$bondry_root/apple/Sources/BondryLocalServer/"*.swift \
    "$package_directory/Sources/BondryLocalServer/"
cp "$bondry_root/apple/Sources/BondryEgress/"*.swift \
    "$package_directory/Sources/BondryEgress/"
cp "$bondry_root/apple/IntegrationTests/EgressProbe/Sources/main.swift" \
    "$package_directory/Sources/EgressProbe/main.swift"

printf '%s\n' \
    '// swift-tools-version: 6.2' \
    '' \
    'import PackageDescription' \
    '' \
    'let package = Package(' \
    '  name: "BondryBinaryProbe",' \
    '  platforms: [.macOS(.v13), .iOS(.v16)],' \
    '  targets: [' \
    '    .binaryTarget(name: "CBondryRuntime", path: "BondryRuntime.xcframework"),' \
    '    .binaryTarget(name: "CBondryLocalServer", path: "BondryLocalServer.xcframework"),' \
    '    .binaryTarget(name: "CBondryEgress", path: "BondryEgress.xcframework"),' \
    '    .target(' \
    '      name: "BondryApple",' \
    '      linkerSettings: [.linkedFramework("Security")]' \
    '    ),' \
    '    .target(' \
    '      name: "Bondry",' \
    '      dependencies: ["BondryApple", "CBondryRuntime"],' \
    '      linkerSettings: [' \
    '        .linkedFramework("CoreFoundation"),' \
    '        .linkedFramework("Security"),' \
    '        .linkedLibrary("iconv"),' \
    '      ]' \
    '    ),' \
    '    .target(' \
    '      name: "BondryLocalServer",' \
    '      dependencies: ["Bondry", "CBondryLocalServer"]' \
    '    ),' \
    '    .target(' \
    '      name: "BondryEgress",' \
    '      dependencies: ["Bondry", "BondryApple", "CBondryEgress"]' \
    '    ),' \
    '    .executableTarget(name: "RuntimeProbe", dependencies: ["Bondry", "BondryApple"]),' \
    '    .executableTarget(' \
    '      name: "EgressProbe",' \
    '      dependencies: ["Bondry", "BondryApple", "BondryEgress"]' \
    '    ),' \
    '    .executableTarget(' \
    '      name: "ServerProbe",' \
    '      dependencies: ["Bondry", "BondryApple", "BondryLocalServer"]' \
    '    ),' \
    '  ]' \
    ')' > "$package_directory/Package.swift"

printf '%s\n' \
    'import Bondry' \
    'import BondryApple' \
    'import Foundation' \
    '' \
    'let databaseURL = URL(fileURLWithPath: CommandLine.arguments[1])' \
    'let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x42, count: 32))' \
    'let runtime = try BondryRuntime.open(at: databaseURL, key: key)' \
    'try runtime.checkHealth()' \
    > "$package_directory/Sources/RuntimeProbe/main.swift"

printf '%s\n' \
    'import Bondry' \
    'import BondryApple' \
    'import BondryLocalServer' \
    'import Foundation' \
    '' \
    'let databaseURL = URL(fileURLWithPath: CommandLine.arguments[1])' \
    'let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x43, count: 32))' \
    'let runtime = try BondryRuntime.open(at: databaseURL, key: key)' \
    'let server = try runtime.startLocalServer(' \
    '  configuration: try BondryLocalServerConfiguration(' \
    '    adapters: [.rest],' \
    '    authentication: .disabled(principalID: "probe")' \
    '  )' \
    ')' \
    'try server.stop()' \
    > "$package_directory/Sources/ServerProbe/main.swift"

swift build --package-path "$package_directory" --configuration release --product RuntimeProbe
runtime_probe="$package_directory/.build/release/RuntimeProbe"
"$runtime_probe" "$temporary_directory/swift-runtime.db"
if nm -gU "$runtime_probe" 2>/dev/null \
    | awk '$NF ~ /^_bondry_server_/ { found = 1 } END { exit !found }'; then
    printf 'A runtime-only Swift executable contains local-server symbols.\n' >&2
    exit 1
fi
if strings -a "$runtime_probe" | grep -E -q '(^|[^[:alnum:]])/mcp([^[:alnum:]]|$)|/api/v1'; then
    printf 'A runtime-only Swift executable contains local-server routes.\n' >&2
    exit 1
fi
runtime_probe_size=$(stat -f %z "$runtime_probe")
if [ "$runtime_probe_size" -gt 8388608 ]; then
    printf 'The runtime-only Swift executable exceeds 8 MiB: %s bytes.\n' \
        "$runtime_probe_size" >&2
    exit 1
fi

swift build --package-path "$package_directory" --configuration release --product EgressProbe
egress_probe="$package_directory/.build/release/EgressProbe"
"$egress_probe" "$temporary_directory/swift-egress.db"
if ! nm -gU "$egress_probe" 2>/dev/null \
    | awk '$NF == "_bondry_egress_start_v1" { found = 1 } END { exit !found }'; then
    printf 'An egress-enabled Swift executable does not contain its egress entry point.\n' >&2
    exit 1
fi
if nm -gU "$egress_probe" 2>/dev/null \
    | awk '$NF ~ /^_bondry_server_/ { found = 1 } END { exit !found }'; then
    printf 'An egress-only Swift executable contains local-server symbols.\n' >&2
    exit 1
fi
egress_probe_size=$(stat -f %z "$egress_probe")
egress_delta=$((egress_probe_size - runtime_probe_size))
if [ "$egress_delta" -gt 6291456 ]; then
    printf 'The egress linked delta exceeds 6 MiB: %s bytes.\n' "$egress_delta" >&2
    exit 1
fi

(
    cd "$package_directory"
    xcodebuild \
        -quiet \
        -scheme EgressProbe \
        -configuration Release \
        -destination 'generic/platform=iOS' \
        -derivedDataPath "$temporary_directory/ios-derived" \
        CODE_SIGNING_ALLOWED=NO \
        build
)

swift build --package-path "$package_directory" --configuration release --product ServerProbe
server_probe="$package_directory/.build/release/ServerProbe"
"$server_probe" "$temporary_directory/swift-server.db"
if ! nm -gU "$server_probe" 2>/dev/null \
    | awk '$NF == "_bondry_server_start_v1" { found = 1 } END { exit !found }'; then
    printf 'A server-enabled Swift executable does not contain its server entry point.\n' >&2
    exit 1
fi
server_probe_size=$(stat -f %z "$server_probe")
if [ "$server_probe_size" -gt 16777216 ]; then
    printf 'The server-enabled Swift executable exceeds 16 MiB: %s bytes.\n' \
        "$server_probe_size" >&2
    exit 1
fi

printf 'Verified runtime-only executable: %s bytes\n' "$runtime_probe_size"
printf 'Verified egress linked delta: %s bytes\n' "$egress_delta"
printf 'Verified server-enabled executable: %s bytes\n' "$server_probe_size"
