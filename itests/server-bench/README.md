# Server Performance Harness

This package measures the REST and MCP request paths over persistent HTTP/1.1
loopback connections. It is a comparative harness, not a product artifact.

Each protocol runs in a fresh server process. The harness warms the process,
resets server-only allocation counters, then records 50,000 requests over eight
connections by default. It reports p50/p95/p99 latency, throughput, current and
sampled peak RSS, allocation operations, and allocated bytes. Client allocations
are outside the measured server process.

The fixed REST request lists capabilities. The fixed MCP request calls
`tools/list`. Both use an empty capability service and the maximum existing
per-minute limit so the configured workload is admitted without changing the
0.1.2 server behavior.

Run the pinned v0.1.2 comparison:

```console
scripts/run-phase-0-performance.sh baseline
```

Run the 24-entry profile matrix (`z`/`s`/`2`/`3`, off/thin/fat LTO, and 1/16
codegen units):

```console
scripts/run-phase-0-performance.sh matrix
```

Results are written under `target/phase-0-performance/results` unless a second
argument names another directory. `BONDRY_BENCH_WARMUP`,
`BONDRY_BENCH_REQUESTS`, and `BONDRY_BENCH_CONNECTIONS` may shorten smoke runs;
published baselines always use the defaults.
