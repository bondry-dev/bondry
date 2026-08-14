#!/bin/bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
llvm_prefix=${LLVM19_PREFIX:-$(brew --prefix llvm@19)}
clang_version=$("$llvm_prefix/bin/clang" --version | head -n 1)
case "$clang_version" in
  *"clang version 19.1.7"*) ;;
  *)
    printf 'Expected LLVM 19.1.7, found: %s\n' "$clang_version" >&2
    exit 1
    ;;
esac

fuzzer_runtime=$(find "$llvm_prefix/lib/clang" -path '*/lib/darwin/libclang_rt.fuzzer_osx.a' -print -quit)
if [[ -z "$fuzzer_runtime" ]]; then
  printf 'LLVM 19 libFuzzer runtime is unavailable\n' >&2
  exit 1
fi

swift build \
  --package-path "$repo_root/apple/Fuzz" \
  --product HTTPParserFuzz \
  --configuration release \
  --sanitize address \
  -Xswiftc -sanitize-coverage=edge,inline-8bit-counters,pc-table,indirect-calls \
  -Xlinker "$fuzzer_runtime" \
  -Xlinker -lc++

corpus=$(mktemp -d "${TMPDIR:-/tmp}/bondry-http-parser-fuzz.XXXXXX")
trap 'rm -rf "$corpus"' EXIT
index=0
while IFS= read -r encoded; do
  printf '%s' "$encoded" | openssl base64 -d -A > "$corpus/malformed-$index"
  index=$((index + 1))
done < <(jq -r '.vectors[].response_base64' "$repo_root/fixtures/transport-v1/malformed-http1.json")
printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok' > "$corpus/valid-content-length"
printf 'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n' \
  > "$corpus/valid-chunked"

artifact_dir=${BONDRY_FUZZ_ARTIFACT_DIR:-$repo_root/target/apple-fuzz-artifacts}
mkdir -p "$artifact_dir"
"$repo_root/apple/Fuzz/.build/release/HTTPParserFuzz" \
  "$corpus" \
  -artifact_prefix="$artifact_dir/" \
  -max_len=300000 \
  -rss_limit_mb=1024 \
  -max_total_time="${BONDRY_FUZZ_SECONDS:-60}"
