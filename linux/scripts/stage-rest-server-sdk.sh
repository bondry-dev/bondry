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
cargo_target_subdirectory=${CARGO_BUILD_TARGET:+/$CARGO_BUILD_TARGET}
pkgconfig_directory=$bondry_root/linux/pkgconfig
case ${CARGO_BUILD_TARGET:-} in
    *-musl) pkgconfig_directory=$pkgconfig_directory/musl ;;
esac

cargo build \
    --locked \
    --release \
    --manifest-path "$bondry_root/Cargo.toml" \
    --package bondry-local-server-ffi \
    --no-default-features \
    --features rest-server

install -d "$stage_prefix/include" "$stage_prefix/lib" "$stage_prefix/lib/pkgconfig"
install -m 0644 \
    "$bondry_root/bindings/c/include/bondry_rest_server.h" \
    "$stage_prefix/include/bondry_rest_server.h"
install -m 0644 \
    "$cargo_target_directory$cargo_target_subdirectory/release/libbondry_local_server_ffi.a" \
    "$stage_prefix/lib/libbondry_local_server_ffi.a"
install -m 0644 \
    "$pkgconfig_directory/bondry-rest-server.pc" \
    "$stage_prefix/lib/pkgconfig/bondry-rest-server.pc"
