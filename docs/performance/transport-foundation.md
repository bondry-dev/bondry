# Transport foundation size measurement

Phase 1T records the linked contribution of `bondry-transport-net` with the
`http,tls` features enabled. Both probes include the same Tokio
`current_thread` runtime. The transport probe also initializes the platform
certificate verifier and drives a bounded HTTPS request future, so the linker
retains the HTTP, TLS, and connection-policy paths.

## Phase 1T measurement

| Field | Value |
| --- | ---: |
| Date | 2026-08-15 |
| Host | Apple M4 Max, arm64, macOS 15.7.3 |
| Rust | 1.90.0 (`aarch64-apple-darwin`) |
| Profile | `release`: `opt-level=z`, fat LTO, 1 codegen unit, stripped debuginfo |
| Baseline probe | 398,752 bytes |
| HTTP + TLS probe | 1,700,336 bytes |
| Linked delta | 1,301,584 bytes (1.24 MiB) |

Reproduce the measurement from the workspace root:

```console
scripts/measure-transport-size.sh
```

This is an implementation contribution measurement, not the Phase 2 egress
artifact ceiling. Phase 2 must measure its complete linked artifact against
the accepted egress budget.
