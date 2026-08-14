# Implementation Limits

This is an informational snapshot of pre-existing `v0.1.2` bounds. It keeps
internal allocation choices and fixed ABI capacities visible during the 0.2.0
workspace migration. Public behavior remains defined by the owning APIs and
protocol documentation.

## HTTP runtime

| Bound | `v0.1.2` value |
| --- | --- |
| Body buffer preallocation | At most 64 KiB before incremental growth |
| Connection lifetime | Header deadline + request deadline + 5 seconds |
| Rate-limit window | 60 seconds |
| Invocation identifier entropy | 16 random bytes |

The public HTTP defaults and configurable ceilings are documented in
[Local HTTP](http.md). HTTP/1.1 keep-alive is enabled, while the derived
connection lifetime prevents an idle connection from retaining a slot
indefinitely.

## Core and authentication

| Bound | `v0.1.2` value |
| --- | --- |
| Portable identifier | 128 UTF-8 bytes |
| Capability summary | 256 UTF-8 bytes |
| Encoded capability input schema | 65,536 bytes |
| Client display name | 128 UTF-8 bytes |
| Token label | 128 UTF-8 bytes |
| Token identifier entropy | 16 random bytes |
| Token secret | 32 random bytes |

## Protocol metadata

| Bound | `v0.1.2` value |
| --- | --- |
| MCP implementation name | 128 UTF-8 bytes |
| MCP implementation title | 256 UTF-8 bytes |
| MCP implementation version | 64 UTF-8 bytes |

## Persistence

| Bound | `v0.1.2` value |
| --- | --- |
| SQLCipher database key | Exactly 32 bytes |
| Audit events returned by one store query | 1–1,000 |

## C ABI

| Bound | `v0.1.2` value |
| --- | --- |
| Runtime JSON input or output payload | 1 MiB |
| Local-server configuration JSON | 65,536 bytes |
| Local-server runtime query attempts | 4 |
| Initial local-server discovery buffer | 4,096 bytes, growing to the 1 MiB runtime JSON ceiling |
| Textual server address buffer | 46 bytes including the terminator |
| Identifier record buffer | 129 bytes including the terminator |
| Label record buffer | 129 bytes including the terminator |
| Issued-token record buffer | 100 bytes including the terminator |
| Audit-detail record buffer | 129 bytes including the terminator |
| Capability-summary record buffer | 257 bytes including the terminator |

These capacities are part of the versioned C layouts or defensive
implementation behavior. Changing a C record capacity requires a new ABI
shape; changing another bound requires its owning API and tests to be reviewed
for observable behavior.
