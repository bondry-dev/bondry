# Swift HTTP chunk parsing

Measured on arm64 macOS with Swift 6.2.4 and `swiftc -O` on 2026-09-08.
The probe decodes 65,536 one-byte chunks ten times per trial and checks the
resulting body. Results are medians of three alternating before/after trials.
The baseline is `4771f30`.

| Receive size | Before | After | Time reduction |
| --- | ---: | ---: | ---: |
| 16 KiB (network receive limit) | 223.5 ms | 166.1 ms | 25.7% |
| Entire response | 2,062.2 ms | 163.4 ms | 92.1% |

The parser now advances a cursor through complete chunks and removes consumed
bytes once per receive call. Previously, each chunk shifted the remaining
buffer. The whole-response case illustrates the scaling behavior; it is not
the normal network receive size. These are parser measurements, not end-to-end
HTTP throughput claims.

Run from the repository root on macOS:

```sh
swiftc -O -parse-as-library -package-name BondryApple \
  apple/Sources/BondryApple/*.swift apple/Benchmarks/HTTPParserProbe.swift \
  -o /tmp/bondry-http-parser-probe
/tmp/bondry-http-parser-probe
rm /tmp/bondry-http-parser-probe
```

`HTTPResponseParserTests` covers every split point in a multi-chunk response,
many small chunks, malformed framing after accepted chunks, and body limits
across receives. Existing transport tests cover shared malformed fixtures,
informational responses, redirects, and fixed-length responses.
