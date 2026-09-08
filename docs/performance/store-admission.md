# Store admission performance

Delivery and webhook deduplication admissions previously aggregated every retained record to enforce quotas. Their expiration queries also scanned retained history when nothing had expired. Schema 7 adds persisted record and charged-byte counters maintained by transactional triggers, a partial delivery expiration index, and a partial deduplication index on state and expiration time. Migration initializes each counter once; subsequent admissions use a primary-key lookup. Cleanup work grows with eligible expired records rather than all retained records.

The regression test traces every executed statement in an actual admission, including its transaction, cleanup, quota lookup, insertion, and counter triggers. With unexpired terminal history in both tables, the bundled SQLCipher development build produced:

| Retained records per table | Delivery admission VM steps | Deduplication admission VM steps |
| --- | ---: | ---: |
| 2,000 | 212 | 186 |
| 20,000 | 212 | 186 |

The test bounds VM instructions, not elapsed time. It seeds both tables through their accounting triggers and verifies the counters against full aggregates after measurement. It catches either a quota aggregate or an expiration scan returning to the admission path.

Before the change, isolated aggregate and no-op cleanup statements showed the following average times across ten warmed executions against an in-memory SQLCipher 4.14.0 database in a development build:

| Retained records | Delivery aggregate | Delivery cleanup | Deduplication aggregate | Deduplication cleanup |
| --- | ---: | ---: | ---: | ---: |
| 1,000 | 0.116 ms | 0.133 ms | 0.091 ms | 0.194 ms |
| 100,000 | 7.865 ms | 8.680 ms | 7.172 ms | 16.172 ms |
| 1,000,000 | 82.342 ms | 93.052 ms | 75.681 ms | 171.530 ms |

These timings illustrate retained-history scaling; they are not release-build, durable-disk, or end-to-end latency measurements. The fixture charged 512 bytes per delivery record and 110 bytes per deduplication record, within the configurable limits. The counter lookup and indexed no-op cleanup used 12, 12, and 15 VM steps respectively regardless of retained-row count. Exact VM totals can change with SQLite versions.

Reproduce the deterministic scaling check and run the quota, lifecycle, migration, rollback, corruption, and independent-connection regressions with:

```sh
cargo test -p bondry-store-sqlcipher admission_work_stays_bounded_as_retained_history_grows -- --nocapture
cargo test -p bondry-store-sqlcipher
```
