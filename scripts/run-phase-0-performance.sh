#!/usr/bin/env bash

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
readonly root
readonly baseline_revision="2e715e3"
readonly mode="${1:-baseline}"
readonly output_dir="${2:-$root/target/phase-0-performance/results}"
readonly warmup_requests="${BONDRY_BENCH_WARMUP:-5000}"
readonly measured_requests="${BONDRY_BENCH_REQUESTS:-50000}"
readonly connections="${BONDRY_BENCH_CONNECTIONS:-8}"
target="$(rustc -vV | sed -n 's/^host: //p')"
readonly target
current_revision="$(git -C "$root" rev-parse HEAD)"
readonly current_revision
readonly build_root="$root/target/phase-0-performance/build"
temporary_root=""
source=""

cleanup() {
  if [[ -n "$source" ]]; then
    git -C "$root" worktree remove --force "$source" >/dev/null 2>&1 || true
    source=""
  fi
  if [[ -n "$temporary_root" ]]; then
    rmdir "$temporary_root" >/dev/null 2>&1 || true
    temporary_root=""
  fi
}

trap cleanup EXIT

if [[ "$mode" != "baseline" && "$mode" != "matrix" && "$mode" != "all" ]]; then
  echo "usage: $0 [baseline|matrix|all] [output-directory]" >&2
  exit 2
fi

mkdir -p "$output_dir" "$build_root"

run_binary() {
  local binary="$1"
  local revision="$2"
  local label="$3"
  local output="$4"
  "$binary" run \
    --revision "$revision" \
    --profile "$label" \
    --target "$target" \
    --warmup "$warmup_requests" \
    --requests "$measured_requests" \
    --connections "$connections" > "$output"
}

build_current() {
  local optimization="$1"
  local lto="$2"
  local codegen_units="$3"
  CARGO_TARGET_DIR="$build_root/current" \
    CARGO_PROFILE_RELEASE_OPT_LEVEL="$optimization" \
    CARGO_PROFILE_RELEASE_LTO="$lto" \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS="$codegen_units" \
    cargo build \
      --manifest-path "$root/Cargo.toml" \
      --release \
      --locked \
      -p bondry-server-bench
}

run_current() {
  local optimization="$1"
  local lto="$2"
  local codegen_units="$3"
  local label="opt-$optimization-lto-$lto-cgu-$codegen_units"
  build_current "$optimization" "$lto" "$codegen_units"
  run_binary \
    "$build_root/current/release/bondry-server-bench" \
    "$current_revision" \
    "$label" \
    "$output_dir/current-$label.json"
}

run_baseline() {
  temporary_root="$(mktemp -d /tmp/bondry-phase-0-performance.XXXXXX)"
  source="$temporary_root/source"
  git -C "$root" worktree add --detach "$source" "$baseline_revision"

  mkdir -p "$source/itests/server-bench/src"
  cp "$root/itests/server-bench/src/main.rs" "$source/itests/server-bench/src/main.rs"
  cp "$root/itests/server-bench/Cargo.legacy.toml" "$source/itests/server-bench/Cargo.toml"
  CARGO_TARGET_DIR="$build_root/baseline" \
    CARGO_PROFILE_RELEASE_OPT_LEVEL="z" \
    CARGO_PROFILE_RELEASE_LTO="fat" \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS="1" \
    RUSTFLAGS="--cfg bondry_legacy_layout" \
    cargo build \
      --manifest-path "$source/itests/server-bench/Cargo.toml" \
      --release
  run_binary \
    "$build_root/baseline/release/bondry-server-bench" \
    "$baseline_revision" \
    "opt-z-lto-fat-cgu-1" \
    "$output_dir/baseline-v0.1.2-opt-z-lto-fat-cgu-1.json"
  cleanup
}

if [[ "$mode" == "baseline" || "$mode" == "all" ]]; then
  run_baseline
  run_current 3 fat 16
fi

if [[ "$mode" == "matrix" || "$mode" == "all" ]]; then
  for optimization in z s 2 3; do
    for lto in off thin fat; do
      for codegen_units in 1 16; do
        run_current "$optimization" "$lto" "$codegen_units"
      done
    done
  done
fi
