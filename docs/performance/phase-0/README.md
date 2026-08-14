# Phase 0 Performance Baseline

Recorded: 2026-08-15

This is the immutable REST/MCP baseline for the 0.2.0 generation. Raw results
are stored beside this document. The benchmark harness and reproduction command
live in [`itests/server-bench`](../../../itests/server-bench/README.md).

## Environment

| Item | Value |
| --- | --- |
| Baseline revision | `2e715e3` (v0.1.2) |
| Restructured revision | `22c223a` |
| Hardware | MacBook Pro (Mac16,5), Apple M4 Max, 16 cores, 128 GiB RAM |
| Operating system | macOS 15.7.3 (24G419) |
| Target | `aarch64-apple-darwin` |
| Compiler | `rustc 1.90.0 (1159e78c4 2025-09-14)` |
| Release profile | `opt-level=z`, fat LTO, one codegen unit, debuginfo stripped, unwind |
| Workload per protocol and trial | 5,000 warmup requests, 50,000 measured requests, eight persistent connections |

REST lists capabilities and MCP calls `tools/list`. Each protocol runs in a
fresh process. Allocation counters cover only the server process. RSS is
sampled externally every 25 ms. Three paired trials compare v0.1.2 and the
restructured code on the same host; percentage changes below are medians of
the three paired changes, which normalizes run-to-run host noise.

## v0.1.2 Comparison

| Metric | REST v0.1.2 | REST current | MCP v0.1.2 | MCP current |
| --- | ---: | ---: | ---: | ---: |
| Median p95 latency | 83.625 µs | 87.334 µs | 104.834 µs | 104.542 µs |
| Median paired p95 change | — | +0.60% | — | -0.08% |
| Median throughput | 131,643/s | 122,567/s | 95,289/s | 95,147/s |
| Median paired throughput change | — | -3.28% | — | -0.65% |
| Allocations per request | 10.00238 | 9.00240 | 42.00240 | 41.00238 |
| Allocated bytes per request | 11,225.57 | 9,801.89 | 14,572.64 | 12,636.96 |
| Median peak RSS | 5.50 MiB | 5.44 MiB | 5.81 MiB | 5.67 MiB |

Both protocol p95 results satisfy the `≤ +10%` regression budget. The
restructured dispatch removes one heap allocation per request and reduces
allocated bytes by 12.68% for REST and 13.28% for MCP. The instrumented harness
binary grows from 1,137,344 to 1,140,112 bytes (+0.24%); this comparative binary
is not an artifact-size ceiling probe.

## Profile Study

The full matrix covers four optimization levels, three LTO modes, and two
codegen-unit settings: 24 configurations total. Every matrix entry contains
100,000 measured requests across REST and MCP. The raw one-pass results are in
[`profile-matrix`](profile-matrix/).

Three profiles were retained as Phase 6 candidates and rerun three times:

| Candidate | Harness bytes | REST median p95 | MCP median p95 | REST median throughput | MCP median throughput |
| --- | ---: | ---: | ---: | ---: | ---: |
| `s/fat/1` | 1,110,448 | 81.958 µs | 86.875 µs | 134,990/s | 122,223/s |
| `s/fat/16` | 1,193,072 | 79.375 µs | 92.208 µs | 140,466/s | 112,144/s |
| `3/fat/16` | 1,435,664 | 82.333 µs | 89.084 µs | 130,181/s | 120,471/s |

`s/fat/1` is the compact candidate, `s/fat/16` is the balanced candidate, and
`3/fat/16` preserves the highest-optimization option. Phase 0 does not select a
shipping profile. Phase 6 must rerun these candidates in randomized order on
the complete artifacts and choose the fastest result that satisfies every size
ceiling. The current `z/fat/1` profile remains unchanged until then.

## CI Timing Baseline

A change confined to `bondry-server-bench` selects only that package. On the
pinned local machine, a cold-target `cargo test` plus Clippy took 12.44 seconds
(9.08 + 3.36); the same pair with a warm target took 0.22 seconds (0.10 + 0.12).
This excludes checkout and tool installation. The CI performance-smoke job
records the real hosted-runner duration and uploads its paired JSON reports on
each main-branch run.

## Raw Data

- [`baseline-trials`](baseline-trials/) contains all three paired v0.1.2 and
  current-profile trials.
- [`profile-matrix`](profile-matrix/) contains all 24 final matrix entries.
- [`candidate-trials`](candidate-trials/) contains three repeats of each
  shortlisted profile.

Shared CI compares v0.1.2 and the current revision on the same runner and emits
a non-blocking warning at 20% drift. That noisy-runner warning is not the release
budget; the dedicated performance gate remains 10%.
