#!/usr/bin/env bash

set -euo pipefail

if [[ "$#" -ne 2 ]]; then
  echo "usage: $0 <baseline-result.json> <current-result.json>" >&2
  exit 2
fi

readonly baseline="$1"
readonly current="$2"
readonly warning_percent="20"

if [[ ! -f "$baseline" || ! -f "$current" ]]; then
  echo "performance result file not found" >&2
  exit 1
fi

summary=""
for protocol in rest mcp; do
  baseline_p95="$(jq -r --arg protocol "$protocol" '.protocols[] | select(.protocol == $protocol) | .latency_ns_p95' "$baseline")"
  current_p95="$(jq -r --arg protocol "$protocol" '.protocols[] | select(.protocol == $protocol) | .latency_ns_p95' "$current")"
  baseline_throughput="$(jq -r --arg protocol "$protocol" '.protocols[] | select(.protocol == $protocol) | .throughput_requests_per_second' "$baseline")"
  current_throughput="$(jq -r --arg protocol "$protocol" '.protocols[] | select(.protocol == $protocol) | .throughput_requests_per_second' "$current")"
  p95_change="$(jq -nr --argjson old "$baseline_p95" --argjson new "$current_p95" '(($new / $old) - 1) * 100')"
  throughput_change="$(jq -nr --argjson old "$baseline_throughput" --argjson new "$current_throughput" '(($new / $old) - 1) * 100')"
  row="| $protocol | $baseline_p95 | $current_p95 | $(printf '%.2f' "$p95_change")% | $(printf '%.2f' "$throughput_change")% |"
  summary+="$row"$'\n'
  if jq -ne --argjson change "$p95_change" --argjson limit "$warning_percent" '$change > $limit' >/dev/null || \
    jq -ne --argjson change "$throughput_change" --argjson limit "$warning_percent" '$change < -$limit' >/dev/null
  then
    echo "::warning title=Performance smoke drift::$protocol p95 changed by $(printf '%.2f' "$p95_change")% and throughput changed by $(printf '%.2f' "$throughput_change")% against v0.1.2"
  fi
done

printf '%s\n' "Protocol 0.1.2-p95-ns current-p95-ns p95-change throughput-change"
printf '%s' "$summary"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### REST/MCP performance smoke"
    echo
    echo "| Protocol | 0.1.2 p95 (ns) | Current p95 (ns) | p95 change | Throughput change |"
    echo "| --- | ---: | ---: | ---: | ---: |"
    printf '%s' "$summary"
    echo
    echo "Shared-runner changes beyond 20% produce a warning, not a failure. The dedicated release gate remains 10%."
  } >> "$GITHUB_STEP_SUMMARY"
fi
