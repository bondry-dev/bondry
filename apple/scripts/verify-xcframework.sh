#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf 'Usage: %s <BondryFFI.xcframework>\n' "$0" >&2
    exit 64
fi

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
bondry_root=$(CDPATH='' cd -- "$script_directory/../.." && pwd)
xcframework=$1
macos_slice="$xcframework/macos-arm64_x86_64"
ios_slice="$xcframework/ios-arm64"
simulator_slice="$xcframework/ios-arm64_x86_64-simulator"
macos_library="$macos_slice/libbondry_ffi.a"
ios_library="$ios_slice/libbondry_ffi.a"
simulator_library="$simulator_slice/libbondry_ffi.a"

test -f "$xcframework/Info.plist"
test -f "$macos_library"
test -f "$ios_library"
test -f "$simulator_library"
cmp "$bondry_root/apple/Distribution/BondryFFI.Info.plist" \
    "$xcframework/Info.plist"
cmp "$bondry_root/LICENSE" "$xcframework/LICENSE"
cmp "$bondry_root/THIRD_PARTY_NOTICES.md" \
    "$xcframework/THIRD_PARTY_NOTICES.md"
test -s "$xcframework/THIRD_PARTY_LICENSES.txt"

lipo "$macos_library" -verify_arch arm64 x86_64
lipo "$ios_library" -verify_arch arm64
lipo "$simulator_library" -verify_arch arm64 x86_64

for slice in "$macos_slice" "$ios_slice" "$simulator_slice"; do
    cmp "$bondry_root/bindings/c/include/bondry.h" "$slice/Headers/bondry.h"
    cmp "$bondry_root/apple/Distribution/module.modulemap" \
        "$slice/Headers/module.modulemap"
done

for library in "$macos_library" "$ios_library" "$simulator_library"; do
    if strings -a "$library" | rg -q '/Users/|/home/|[A-Za-z]:\\Users'; then
        printf 'The XCFramework contains a private build-machine path: %s\n' \
            "$library" >&2
        exit 1
    fi
done

if ! nm -gU "$macos_library" 2>/dev/null \
    | awk '$NF == "_bondry_abi_version_v1" { found = 1 } END { exit !found }'; then
    printf 'The XCFramework does not export bondry_abi_version_v1.\n' >&2
    exit 1
fi

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/bondry-xcframework.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM
iphoneos_sdk=$(xcrun --sdk iphoneos --show-sdk-path)
iphonesimulator_sdk=$(xcrun --sdk iphonesimulator --show-sdk-path)
apple_clang=$(xcrun --find clang)

printf '%s\n' \
    '@import CBondry;' \
    'uint32_t bondry_module_smoke(void) { return bondry_abi_version_v1(); }' \
    > "$temporary_directory/module-smoke.m"

cc \
    -fmodules \
    -fmodules-cache-path="$temporary_directory/modules" \
    -I "$macos_slice/Headers" \
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
    -I "$macos_slice/Headers" \
    "$macos_library" \
    -framework CoreFoundation \
    -framework Security \
    -liconv \
    -o "$temporary_directory/bondry-store-smoke"

"$temporary_directory/bondry-store-smoke" "$temporary_directory/store.db"

"$apple_clang" \
    -std=c11 \
    -Wall \
    -Wextra \
    -Werror \
    -target arm64-apple-ios16.0 \
    -isysroot "$iphoneos_sdk" \
    -Wl,-fatal_warnings \
    "$bondry_root/bindings/c/tests/store_smoke.c" \
    -I "$ios_slice/Headers" \
    "$ios_library" \
    -framework CoreFoundation \
    -framework Security \
    -liconv \
    -o "$temporary_directory/bondry-store-smoke-ios"

"$apple_clang" \
    -std=c11 \
    -Wall \
    -Wextra \
    -Werror \
    -target arm64-apple-ios16.0-simulator \
    -isysroot "$iphonesimulator_sdk" \
    -Wl,-fatal_warnings \
    "$bondry_root/bindings/c/tests/store_smoke.c" \
    -I "$simulator_slice/Headers" \
    "$simulator_library" \
    -framework CoreFoundation \
    -framework Security \
    -liconv \
    -o "$temporary_directory/bondry-store-smoke-ios-simulator"

package_directory="$temporary_directory/BondryBinaryProbe"
mkdir -p \
    "$package_directory/Sources/BondryApple" \
    "$package_directory/Sources/BondrySQLCipher" \
    "$package_directory/Sources/BondryAppIntents" \
    "$package_directory/Sources/Probe"

cp -R "$xcframework" "$package_directory/BondryFFI.xcframework"
cp "$bondry_root/apple/Sources/BondryApple/"*.swift \
    "$package_directory/Sources/BondryApple/"
cp "$bondry_root/apple/Sources/BondrySQLCipher/"*.swift \
    "$package_directory/Sources/BondrySQLCipher/"
cp "$bondry_root/apple/Sources/BondryAppIntents/"*.swift \
    "$package_directory/Sources/BondryAppIntents/"

printf '%s\n' \
    '// swift-tools-version: 6.2' \
    '' \
    'import PackageDescription' \
    '' \
    'let package = Package(' \
    '  name: "BondryBinaryProbe",' \
    '  platforms: [.macOS(.v13), .iOS(.v16)],' \
    '  targets: [' \
    '    .binaryTarget(name: "BondryFFI", path: "BondryFFI.xcframework"),' \
    '    .target(' \
    '      name: "BondryApple",' \
    '      linkerSettings: [.linkedFramework("Security")]' \
    '    ),' \
    '    .target(' \
    '      name: "BondrySQLCipher",' \
    '      dependencies: ["BondryApple", "BondryFFI"],' \
    '      linkerSettings: [' \
    '        .linkedFramework("CoreFoundation"),' \
    '        .linkedFramework("Security"),' \
    '        .linkedLibrary("iconv"),' \
    '      ]' \
    '    ),' \
    '    .target(' \
    '      name: "BondryAppIntents",' \
    '      dependencies: ["BondrySQLCipher"],' \
    '      linkerSettings: [.linkedFramework("AppIntents")]' \
    '    ),' \
    '    .executableTarget(' \
    '      name: "Probe",' \
    '      dependencies: ["BondryAppIntents", "BondryApple", "BondrySQLCipher"]' \
    '    ),' \
    '  ]' \
    ')' > "$package_directory/Package.swift"

printf '%s\n' \
    'import BondryAppIntents' \
    'import BondryApple' \
    'import BondrySQLCipher' \
    'import Foundation' \
    '' \
    'let databaseURL = URL(fileURLWithPath: CommandLine.arguments[1])' \
    'let key = try DatabaseKeyMaterial(rawRepresentation: Data(repeating: 0x42, count: 32))' \
    'let store = try BondryEncryptedStore.open(at: databaseURL, key: key)' \
    'try store.checkHealth()' \
    'let principal = BondryPrincipal(id: "shortcuts.local-user", kind: .system)' \
    '_ = BondryShortcutsRuntime(store: store, principal: principal)' \
    > "$package_directory/Sources/Probe/main.swift"

swift run \
    --package-path "$package_directory" \
    Probe \
    "$temporary_directory/swift-store.db"

printf 'Verified %s\n' "$xcframework"
