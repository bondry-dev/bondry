# TLS Ingress Size Profile

Recorded: 2026-08-27

Adding TLS 1.3 termination to the REST-only Apple product produced these release measurements:

| Measurement | Result | Ceiling |
| --- | ---: | ---: |
| REST-only linked delta | 3,226,368 bytes | 6 MiB |
| BondryRESTServer archive | 97,019,547 bytes | 110 MiB |
| Aggregate Apple archives | 274,838,657 bytes | 300 MiB |

The linked application remains inside the existing 6 MiB REST-only budget. The aggregate archive budget increased from 250 MiB to 300 MiB because each release archive carries every supported Apple architecture, while normal consumers link only the selected product and dead-strip unused code. A new 110 MiB REST-only archive ceiling bounds future TLS growth independently of the aggregate limit.
