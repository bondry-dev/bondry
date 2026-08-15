#!/usr/bin/env bash

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
readonly root
readonly output_dir="${1:-$root/target/phase-6-performance/results}"
readonly build_root="$root/target/phase-6-performance/build"
readonly warmup_requests="${BONDRY_BENCH_WARMUP:-5000}"
readonly measured_requests="${BONDRY_BENCH_REQUESTS:-50000}"
readonly connections="${BONDRY_BENCH_CONNECTIONS:-8}"
target="$(rustc -vV | sed -n 's/^host: //p')"
readonly target
revision="$(git -C "$root" rev-parse HEAD)"
readonly revision

profiles=(
  "s fat 1"
  "s fat 16"
  "3 fat 16"
)
trial_orders=(
  "3 fat 16;s fat 1;s fat 16"
  "s fat 16;3 fat 16;s fat 1"
  "s fat 1;s fat 16;3 fat 16"
)

mkdir -p "$output_dir" "$build_root"

build_candidate() {
  local optimization="$1"
  local lto="$2"
  local codegen_units="$3"
  local label="opt-$optimization-lto-$lto-cgu-$codegen_units"
  CARGO_TARGET_DIR="$build_root/$label" \
    CARGO_PROFILE_RELEASE_OPT_LEVEL="$optimization" \
    CARGO_PROFILE_RELEASE_LTO="$lto" \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS="$codegen_units" \
    cargo build \
      --manifest-path "$root/Cargo.toml" \
      --release \
      --locked \
      -p bondry-server-bench
}

run_candidate() {
  local trial="$1"
  local optimization="$2"
  local lto="$3"
  local codegen_units="$4"
  local label="opt-$optimization-lto-$lto-cgu-$codegen_units"
  "$build_root/$label/release/bondry-server-bench" run \
    --revision "$revision" \
    --profile "$label" \
    --target "$target" \
    --warmup "$warmup_requests" \
    --requests "$measured_requests" \
    --connections "$connections" \
    > "$output_dir/trial-$trial-$label.json"
}

for profile in "${profiles[@]}"; do
  read -r optimization lto codegen_units <<< "$profile"
  build_candidate "$optimization" "$lto" "$codegen_units"
done

trial=0
for order in "${trial_orders[@]}"; do
  trial=$((trial + 1))
  IFS=';' read -r -a candidates <<< "$order"
  for candidate in "${candidates[@]}"; do
    read -r optimization lto codegen_units <<< "$candidate"
    run_candidate "$trial" "$optimization" "$lto" "$codegen_units"
  done
done
