#!/usr/bin/env bash

set -euo pipefail

workspace_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$workspace_root"

cargo build --release --locked \
  -p bondry-egress-e2e \
  --example egress-size-baseline \
  --example egress-size-http-tls

baseline_path=target/release/examples/egress-size-baseline
egress_path=target/release/examples/egress-size-http-tls
baseline_bytes=$(wc -c < "$baseline_path" | tr -d ' ')
egress_bytes=$(wc -c < "$egress_path" | tr -d ' ')
delta_bytes=$((egress_bytes - baseline_bytes))

printf 'baseline_bytes=%s\n' "$baseline_bytes"
printf 'egress_http_tls_bytes=%s\n' "$egress_bytes"
printf 'egress_http_tls_delta_bytes=%s\n' "$delta_bytes"

if [ "$delta_bytes" -gt 3145728 ]; then
  printf 'Rust webhook egress linked delta exceeds 3 MiB: %s bytes.\n' "$delta_bytes" >&2
  exit 1
fi
