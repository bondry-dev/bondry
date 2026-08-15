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

Every candidate passed the 3 MiB Rust linked-delta gates, the Swift linked-size
gates, the individual archive ceilings, and the 250 MiB aggregate archive
ceiling.

| Candidate | Runtime probe | Server probe | Egress delta | Ingress delta | Combined delta | Apple archives |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `s/fat/1` | 6,141,968 | 7,238,360 | 1,864,600 | 525,848 | 2,114,776 | 201,575,575 |
| `s/fat/16` | 6,929,472 | 8,264,760 | 2,084,648 | 612,136 | 2,390,744 | 245,373,076 |
| `3/fat/16` | 7,674,192 | 9,143,416 | 2,072,664 | 655,320 | 2,390,760 | 253,266,421 |

The selected profile retains 8,877,579 bytes below the aggregate archive
ceiling and 714,416 bytes below the runtime-only executable ceiling. Its egress
archive is 24,206,594 bytes and its ingress archive is 5,645,612 bytes, below
their 40 MiB and 30 MiB ceilings.

## v0.1.2 Release Gate

Three paired runs compared the selected profile with the pinned v0.1.2
baseline. The median paired changes remain inside the 10% p95 regression
budget:

| Protocol | p95 change | Throughput change |
| --- | ---: | ---: |
| REST | +1.85% | +2.39% |
| MCP | -16.75% | +28.57% |

## Selection

The 0.2.0 release profile is `opt-level=3`, fat LTO, and 16 codegen units. It is
the fastest eligible candidate across the complete REST, MCP, egress, ingress,
and Apple distribution surface.

Raw server reports are stored in [`candidate-trials`](candidate-trials/) and
[`baseline-trials`](baseline-trials/). Reproduce the candidate trials with:

```sh
scripts/run-phase-6-performance.sh
```
