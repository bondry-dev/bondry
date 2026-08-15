# Phase 2 egress artifact measurements

These measurements were captured on 2026-08-15 from a clean Release artifact
build using Rust 1.90.0, Swift 6.2.3, Xcode 26.2, and arm64 macOS 15.7.3. The
build used `SOURCE_DATE_EPOCH=946684800 apple/scripts/build-xcframework.sh`.

| Metric | Measurement | Ceiling | Result |
| --- | ---: | ---: | --- |
| Rust webhook egress linked delta | 1,836,304 bytes | 3 MiB | Pass |
| Runtime probe executable | 5,430,048 bytes | 8 MiB | Pass |
| Local-server probe executable | 6,398,520 bytes | 16 MiB | Pass |
| Egress linked delta over runtime probe | 1,363,480 bytes | 6 MiB | Pass |
| `BondryEgress` XCFramework archive | 36,007,943 bytes | 40 MiB | Pass |
| Aggregate Apple archive download | 194,614,894 bytes | 250 MiB | Pass |

The aggregate consists of `BondryRuntime` at 77,487,288 bytes,
`BondryLocalServer` at 81,119,663 bytes, and `BondryEgress` at 36,007,943
bytes. It remains above the non-blocking 180 MiB optimization target. SwiftPM
download-path behavior and the fixed-runner RSS gate remain release checks;
this record does not claim results for either metric.

Reproduce the Rust measurement with `scripts/measure-egress-size.sh`. Its
baseline is a minimal Rust host, and the measured probe retains the egress
core, scheduler, URL-template webhook kind, and HTTP/TLS transport by
constructing and admitting a delivery through the complete profile.
