# Phase 6 Release Profile

Recorded: 2026-08-15

Phase 6 reran the three candidates retained by the
[Phase 0 study](../phase-0/README.md) after the 0.2.0 feature set was complete.
Each server profile was built once and measured three times in this balanced
order:

1. `3/fat/16`, `s/fat/1`, `s/fat/16`
2. `s/fat/16`, `3/fat/16`, `s/fat/1`
3. `s/fat/1`, `s/fat/16`, `3/fat/16`

Each trial used 5,000 warmup requests, 50,000 measured requests, and eight
persistent connections per protocol. Values below are medians of the three
trials.

## Performance

| Candidate | Harness bytes | REST p95 | MCP p95 | REST throughput | MCP throughput |
| --- | ---: | ---: | ---: | ---: | ---: |
| `s/fat/1` | 1,188,336 | 75.375 µs | 81.125 µs | 146,206/s | 132,769/s |
| `s/fat/16` | 1,256,480 | 74.333 µs | 81.584 µs | 149,094/s | 130,666/s |
| `3/fat/16` | 1,511,600 | 74.459 µs | 78.459 µs | 152,744/s | 139,214/s |

All profiles held REST at 9.0024 allocations per request and MCP at 41.0024
allocations per request. `3/fat/16` delivered the highest median throughput for
both protocols and the lowest MCP p95. Its REST p95 was within 0.2% of the
lowest candidate result.

## Size Gates

Every candidate passed the Swift linked-size gates, the individual archive
ceilings, and the 250 MiB aggregate archive ceiling. None passed the 3 MiB Rust
MCP linked-delta gate.

| Candidate | Rust webhook delta | Rust MCP delta | MCP excess |
| --- | ---: | ---: | ---: |
| `s/fat/1` | 1,162,656 | 3,196,928 | 51,200 |
| `s/fat/16` | 1,245,616 | 3,296,640 | 150,912 |
| `3/fat/16` | 1,592,336 | 4,122,720 | 976,992 |

| Candidate | Runtime probe | Server probe | Egress delta | Ingress delta | Combined delta | Apple archives |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `s/fat/1` | 6,141,968 | 7,238,360 | 1,864,600 | 525,848 | 2,114,776 | 201,575,575 |
| `s/fat/16` | 6,929,472 | 8,264,760 | 2,084,648 | 612,136 | 2,390,744 | 245,373,076 |
| `3/fat/16` | 7,674,192 | 9,143,416 | 2,072,664 | 655,320 | 2,390,760 | 253,266,421 |

The selected `z/fat/1` profile produces Rust webhook and MCP linked deltas of
983,504 and 2,394,864 bytes. The measurement scripts resolve
`CARGO_TARGET_DIR` so isolated candidate builds cannot accidentally measure a
stale default-target binary.

## v0.1.2 Release Gate

Three paired runs compared the selected profile with the pinned v0.1.2
baseline. The median paired changes remain inside the 10% p95 regression
budget:

| Protocol | p95 change | Throughput change |
| --- | ---: | ---: |
| REST | +0.29% | -0.75% |
| MCP | -1.33% | -0.03% |

## Selection

The three shortlisted profiles trade acceptable Apple artifact growth for a
Rust MCP linked-size regression beyond the release ceiling. The 0.2.0 release
therefore retains `opt-level=z`, fat LTO, and one codegen unit. It satisfies all
size and performance gates across the complete REST, MCP, egress, ingress, and
Apple distribution surface.

Raw server reports are stored in [`candidate-trials`](candidate-trials/) and
[`baseline-trials`](baseline-trials/). Reproduce the candidate trials with:

```sh
scripts/run-phase-6-performance.sh
```
