#!/usr/bin/env bash

set -euo pipefail

workspace_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$workspace_root"

cargo build --release --locked \
  -p bondry-transport-net \
  --no-default-features \
  --features http,tls \
  --example transport-size-baseline \
  --example transport-size-http-tls

baseline_path=target/release/examples/transport-size-baseline
transport_path=target/release/examples/transport-size-http-tls
baseline_bytes=$(wc -c < "$baseline_path" | tr -d ' ')
transport_bytes=$(wc -c < "$transport_path" | tr -d ' ')
delta_bytes=$((transport_bytes - baseline_bytes))

printf 'baseline_bytes=%s\n' "$baseline_bytes"
printf 'http_tls_bytes=%s\n' "$transport_bytes"
printf 'http_tls_delta_bytes=%s\n' "$delta_bytes"
