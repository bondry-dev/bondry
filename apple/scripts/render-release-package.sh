#!/bin/sh
set -eu

if [ "$#" -ne 4 ]; then
    printf 'Usage: %s <version> <runtime-checksum> <local-server-checksum> <output>\n' "$0" >&2
    exit 64
fi

version=$1
runtime_checksum=$2
local_server_checksum=$3
output=$4

if ! printf '%s\n' "$version" | awk -F. '
    function component(value) { return value == "0" || value ~ /^[1-9][0-9]*$/ }
    NF == 3 && component($1) && component($2) && component($3) { valid = 1 }
    END { exit !valid }
'; then
    printf 'Version must be a numeric semantic version without a prefix.\n' >&2
    exit 1
fi

for checksum in "$runtime_checksum" "$local_server_checksum"; do
    if ! printf '%s\n' "$checksum" | awk 'length == 64 && /^[0-9a-f]+$/ { valid = 1 } END { exit !valid }'; then
        printf 'Each checksum must contain 64 lowercase hexadecimal characters.\n' >&2
        exit 1
    fi
done

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
template="$script_directory/../Distribution/Package.release.swift"

sed \
    -e "s/__BONDRY_VERSION__/$version/g" \
    -e "s/__BONDRY_RUNTIME_CHECKSUM__/$runtime_checksum/g" \
    -e "s/__BONDRY_LOCAL_SERVER_CHECKSUM__/$local_server_checksum/g" \
    "$template" > "$output"

if grep -E -q '__BONDRY_(VERSION|RUNTIME_CHECKSUM|LOCAL_SERVER_CHECKSUM)__' "$output"; then
    printf 'The rendered package contains unresolved placeholders.\n' >&2
    exit 1
fi
