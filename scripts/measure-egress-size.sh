#!/usr/bin/env bash

set -euo pipefail

workspace_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$workspace_root"
target_directory=${CARGO_TARGET_DIR:-"$workspace_root/target"}
if [[ "$target_directory" != /* ]]; then
  target_directory="$workspace_root/$target_directory"
fi

CARGO_PROFILE_RELEASE_STRIP=symbols cargo build --release --locked \
  -p bondry-egress-e2e \
  --example egress-size-baseline \
  --example egress-size-http-tls
CARGO_PROFILE_RELEASE_STRIP=symbols cargo build --release --locked \
  -p bondry-egress-mcp-e2e \
  --example egress-size-mcp-http

baseline_path="$target_directory/release/examples/egress-size-baseline"
webhook_path="$target_directory/release/examples/egress-size-http-tls"
mcp_path="$target_directory/release/examples/egress-size-mcp-http"
baseline_bytes=$(wc -c < "$baseline_path" | tr -d ' ')
webhook_bytes=$(wc -c < "$webhook_path" | tr -d ' ')
mcp_bytes=$(wc -c < "$mcp_path" | tr -d ' ')
webhook_delta_bytes=$((webhook_bytes - baseline_bytes))
mcp_delta_bytes=$((mcp_bytes - baseline_bytes))

printf 'baseline_bytes=%s\n' "$baseline_bytes"
printf 'egress_http_tls_bytes=%s\n' "$webhook_bytes"
printf 'egress_http_tls_delta_bytes=%s\n' "$webhook_delta_bytes"
printf 'egress_mcp_http_bytes=%s\n' "$mcp_bytes"
printf 'egress_mcp_http_delta_bytes=%s\n' "$mcp_delta_bytes"

if [ "$webhook_delta_bytes" -gt 3145728 ]; then
  printf 'Rust webhook egress linked delta exceeds 3 MiB: %s bytes.\n' "$webhook_delta_bytes" >&2
  exit 1
fi
if [ "$mcp_delta_bytes" -gt 3145728 ]; then
  printf 'Rust local MCP egress linked delta exceeds 3 MiB: %s bytes.\n' "$mcp_delta_bytes" >&2
  exit 1
fi
