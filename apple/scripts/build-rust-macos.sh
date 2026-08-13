#!/bin/sh
set -eu

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
bondry_root=$(CDPATH='' cd -- "$script_directory/../.." && pwd)

export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$bondry_root/target/apple/macos}"

cargo build --manifest-path "$bondry_root/Cargo.toml" -p bondry-ffi "$@"
