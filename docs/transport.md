# Outbound transport foundation

`bondry-transport` defines runtime-neutral HTTP, WebSocket, and local
byte-stream contracts. It does not open sockets or own an executor.
`bondry-transport-net` provides the default Rust HTTP, TLS, and Unix-domain
socket implementations and uses the caller's Tokio executor.

## Network policy

HTTPS is required for public peers. Cleartext HTTP is allowed for an actual
loopback peer, regardless of the hostname spelling. RFC 1918 and IPv6 ULA
peers require explicit route opt-in. Link-local peers additionally require an
explicit interface scope. Other cleartext peers are rejected.

Authorization uses the endpoint of the established connection, not the URL
text or an earlier DNS result. The connected port must also match the target.
Policy is checked before application bytes are sent. Redirects are denied in
0.2.0.

Per-route DER trust anchors add roots to platform verification. They do not
disable hostname matching, certificate validity checks, EKU checks, or chain
validation. Connection evidence returned with a response contains no request
or response payload.

## Rust implementation features

`bondry-transport-net` defaults to `http,tls` and exposes these independent
features:

| Feature | Contents |
| --- | --- |
| `http` | one-shot Hyper HTTP/1.1 client |
| `tls` | rustls with platform certificate verification; implies `http` |
| `unix-socket` | Unix socket ownership, mode, and peer-credential checks |

An HTTP-only build does not link rustls. WebSocket and named-pipe
implementations are reserved and do not ship in 0.2.0.

## Apple implementation

`BondryAppleHTTPTransport` uses URLSession for HTTPS. A task delegate rejects
automatic redirects, and optional anchors are added through Security.framework
trust evaluation. Cleartext HTTP uses Network.framework without a proxy: after
`NWConnection` reaches `ready`, Bondry reads the effective remote endpoint,
checks policy, and only then writes a request. Its HTTP/1.1 response parser is
bounded to the shared endpoint, header, body, and deadline limits.

Apple does not provide a local byte-stream implementation in this phase.
