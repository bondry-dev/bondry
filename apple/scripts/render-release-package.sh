#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    printf 'Usage: %s <version> <checksum> <output>\n' "$0" >&2
    exit 64
fi

version=$1
checksum=$2
output=$3

if ! printf '%s\n' "$version" | awk -F. '
    function component(value) { return value == "0" || value ~ /^[1-9][0-9]*$/ }
    NF == 3 && component($1) && component($2) && component($3) { valid = 1 }
    END { exit !valid }
'; then
    printf 'Version must be a numeric semantic version without a prefix.\n' >&2
    exit 1
fi

if ! printf '%s\n' "$checksum" | awk 'length == 64 && /^[0-9a-f]+$/ { valid = 1 } END { exit !valid }'; then
    printf 'Checksum must contain 64 lowercase hexadecimal characters.\n' >&2
    exit 1
fi

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
template="$script_directory/../Distribution/Package.release.swift"

sed \
    -e "s/__BONDRY_VERSION__/$version/g" \
    -e "s/__BONDRY_CHECKSUM__/$checksum/g" \
    "$template" > "$output"

if rg -q '__BONDRY_(VERSION|CHECKSUM)__' "$output"; then
    printf 'The rendered package contains unresolved placeholders.\n' >&2
    exit 1
fi
