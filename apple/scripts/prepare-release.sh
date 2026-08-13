#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf 'Usage: %s <version>\n' "$0" >&2
    exit 64
fi

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
bondry_root=$(CDPATH='' cd -- "$script_directory/../.." && pwd)
version=$1

SOURCE_DATE_EPOCH=946684800 "$script_directory/build-xcframework.sh"
checksum=$(sed -n '1p' \
    "$bondry_root/target/apple/distribution/BondryFFI.xcframework.zip.sha256")
"$script_directory/render-release-package.sh" \
    "$version" \
    "$checksum" \
    "$bondry_root/Package.swift"
swift package dump-package --package-path "$bondry_root" > /dev/null

printf 'Prepared Package.swift for v%s with checksum %s\n' \
    "$version" \
    "$checksum"
