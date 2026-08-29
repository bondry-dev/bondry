#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf 'usage: %s <prefix>\n' "$0" >&2
    exit 64
fi

if [ "$(uname -s)" != Linux ]; then
    printf 'Bondry Linux SDK staging requires Linux\n' >&2
    exit 69
fi

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
bondry_root=$(CDPATH='' cd -- "$script_directory/../.." && pwd)
stage_prefix=$1
cargo_target_directory=${CARGO_TARGET_DIR:-$bondry_root/target}

cargo build \
    --locked \
    --release \
    --manifest-path "$bondry_root/Cargo.toml" \
    --package bondry-credential-store-ffi

install -d "$stage_prefix/include" "$stage_prefix/lib" "$stage_prefix/lib/pkgconfig"
install -m 0644 \
    "$bondry_root/bindings/c/include/bondry_credentials.h" \
    "$stage_prefix/include/bondry_credentials.h"
install -m 0644 \
    "$cargo_target_directory/release/libbondry_credential_store_ffi.a" \
    "$stage_prefix/lib/libbondry_credential_store_ffi.a"
install -m 0644 \
    "$bondry_root/linux/pkgconfig/bondry-credentials.pc" \
    "$stage_prefix/lib/pkgconfig/bondry-credentials.pc"
