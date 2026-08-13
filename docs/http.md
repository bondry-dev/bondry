# Local HTTP

`bondry-http` provides one reusable HTTP/1.1 runtime for local protocol adapters. REST and MCP can be installed independently as adapters while sharing transport authentication, origin validation, rate limiting, body bounds, timeouts, connection limits, and shutdown ownership.

## Security Defaults

`ServerConfiguration::new` binds to `127.0.0.1` on port zero, which asks the operating system to choose a free port. It rejects every request carrying an `Origin` header unless the exact serialized HTTP or HTTPS origin is configured. The default limits are:

- 1 MiB decoded request bodies
- 64 request headers in a 32 KiB parser buffer
- 64 concurrent connections
- 120 authenticated requests per principal per minute
- 30 rejected authentication attempts per peer address per minute
- 5 seconds to read headers
- 30 seconds for authentication, body collection, and adapter handling
- 2 seconds for graceful shutdown

HTTP keep-alive is disabled so an idle client cannot retain a connection slot indefinitely. Responses receive `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` unless an adapter already supplied those headers.

## Authentication

Authentication is an explicit configuration choice. `Authentication::bearer` uses `AuthManager`; `BearerAuthenticator` accepts another `BearerTokenVerifier`; and applications with passkeys, security keys, or another scheme can implement `HttpAuthenticator`.

Authenticators receive the method, URI, headers, and connected peer address without the request body. They return only a `Principal`. Before protocol dispatch, Bondry removes common credential headers and asks a custom authenticator to remove any additional credential-bearing headers it consumed. Raw credentials never enter a REST or MCP adapter.

`Authentication::disabled` remains available for users who deliberately do not want tokens. It requires an explicit principal so grants and audit history still identify the unauthenticated interface. Disabled authentication is safe by default only on loopback.

## Network Exposure

This runtime does not terminate TLS. Any non-loopback bind requires `allowing_cleartext_network`, and disabled authentication on a non-loopback bind additionally requires `allowing_unauthenticated_network`. These acknowledgements make the risk visible in host code; they do not encrypt traffic or make an untrusted network safe.

Hosts should keep the default loopback bind. If network access is required, a host should place Bondry behind a trusted TLS terminator or provide a future secure transport implementation instead of transmitting bearer credentials over cleartext HTTP.

## Rate Limiting

Authenticated requests use an independent sliding window for each principal. Rejected authentication attempts use a separate sliding window for each peer IP address, limiting credential guessing without forcing all valid local clients to share one quota. Rate-limited responses include `Retry-After`.

## Adapter Boundary

The runtime selects an enabled adapter by path before authentication. A disabled or unknown route therefore remains a `404` rather than presenting an authentication challenge. Once authenticated, the adapter receives a bounded in-memory body, the authenticated principal, and the peer address. Protocol parsing, method handling, content negotiation, and error mapping remain adapter responsibilities.
