# MCP Adapter

`bondry-mcp` exposes authorized Bondry capabilities as MCP tools at the exact `/mcp` path. It runs on `bondry-http`, so authentication, origin checks, rate limits, body limits, credential removal, and server lifecycle are shared with the REST adapter.

The adapter identifier defaults to `mcp`. A tool is visible and invocable only when policy grants the authenticated principal that exact adapter and capability combination.

## Protocol Versions

MCP `2026-07-28` is the primary protocol. It is stateless and does not use initialization or session identifiers. Every POST must include:

- `MCP-Protocol-Version: 2026-07-28`
- `Mcp-Method` matching the JSON-RPC method
- `Mcp-Name` matching `params.name` for `tools/call`
- request `_meta` containing the matching protocol version and a client-capabilities object

`Mcp-Name` accepts the protocol's Base64 sentinel form for values that cannot be represented directly as an HTTP field value. Duplicated, missing, malformed, or mismatched routing headers fail before dispatch.

The adapter implements `server/discover`, `tools/list`, and `tools/call`. Every successful modern result declares `resultType: "complete"` and includes server implementation metadata. Discovery and tool lists use `ttlMs: 0` with `cacheScope: "private"` because authorization changes must be observed immediately and results are specific to the authenticated principal.

MCP `2025-11-25` remains available for legacy clients. A headerless `initialize` request enters the legacy path and negotiates that version. Subsequent requests must send `MCP-Protocol-Version: 2025-11-25`. The legacy path supports `ping`, `tools/list`, and `tools/call` without modern routing headers or per-request metadata.

## HTTP Contract

The endpoint accepts POST only. Requests must have exactly one JSON `Content-Type` and must advertise both `application/json` and `text/event-stream` in `Accept`. Responses are currently complete JSON responses; the adapter does not produce SSE streams.

The shared HTTP runtime authenticates the request and removes credential-bearing headers before the adapter receives it. The adapter does not implement MCP OAuth discovery or protected-resource metadata. Hosts that expose the endpoint beyond loopback must provide an appropriate secure transport and authentication deployment.

Modern requests use transport-aware status codes for header mismatch, unsupported versions, invalid requests, and unknown methods. Legacy application-level JSON-RPC errors retain an HTTP `200` response where required for compatibility.

## Tool Mapping

Capabilities retain their Bondry identifier, summary, JSON Schema 2020-12 input contract, and read-only effect hint. Tool order is deterministic. Optional `x-mcp-header` annotations are removed recursively because Bondry does not let a capability define unvalidated transport headers.

The dispatcher performs exact authorization and input validation before executing the host handler. Missing and unauthorized tools both return `Unknown tool`. Successful calls return JSON as text and structured content, plus an invocation identifier for audit correlation. Handler failures return a generic message and may include only the handler's stable error code.

Legacy structured content is emitted only for JSON objects. Modern structured content may contain any JSON value.

## Current Scope

The adapter always completes a tool call in one response. It does not yet implement SSE response streams, multi-round-trip responses, elicitation, sampling, subscriptions, or OAuth discovery. None of those capabilities are advertised.
