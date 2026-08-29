#!/bin/sh
set -eu

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
bondry_root=$(CDPATH='' cd -- "$script_directory/../.." && pwd)
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/bondry-release-package-test.XXXXXX")
trap 'rm -rf -- "$temporary_directory"' EXIT HUP INT TERM

rendered_package=$temporary_directory/Package.swift
checksum_0=0000000000000000000000000000000000000000000000000000000000000000
checksum_1=1111111111111111111111111111111111111111111111111111111111111111
checksum_2=2222222222222222222222222222222222222222222222222222222222222222
checksum_3=3333333333333333333333333333333333333333333333333333333333333333
checksum_4=4444444444444444444444444444444444444444444444444444444444444444

"$script_directory/render-release-package.sh" \
    0.3.0 \
    "$checksum_0" \
    "$checksum_1" \
    "$checksum_2" \
    "$checksum_3" \
    "$checksum_4" \
    "$rendered_package"

awk '/^#else$/ { exit } { print }' "$bondry_root/Package.swift" \
    > "$temporary_directory/current-linux.swift"
awk '/^#else$/ { exit } { print }' "$rendered_package" \
    > "$temporary_directory/rendered-linux.swift"
cmp "$temporary_directory/current-linux.swift" "$temporary_directory/rendered-linux.swift"

grep -F '#if os(Linux)' "$rendered_package" >/dev/null
grep -F '.library(name: "BondryCredentials", targets: ["BondryCredentials"])' \
    "$rendered_package" >/dev/null
grep -F 'path: "linux/Sources/CBondryRESTServer"' "$rendered_package" >/dev/null
grep -F 'name: "BondryRESTServerLinuxTests"' "$rendered_package" >/dev/null
grep -F 'let bondryVersion = "0.3.0"' "$rendered_package" >/dev/null
grep -F "checksum: \"$checksum_4\"" "$rendered_package" >/dev/null

if grep -E -q '__BONDRY_[A-Z_]+__' "$rendered_package"; then
    printf 'The rendered package contains an unresolved placeholder.\n' >&2
    exit 1
fi
