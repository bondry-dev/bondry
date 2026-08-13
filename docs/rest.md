# REST Adapter

`bondry-rest` exposes authorized Bondry capabilities through a generic, versioned JSON API. It runs on `bondry-http`, so authentication, origin checks, rate limits, body limits, credential redaction, and server lifecycle remain shared with other HTTP adapters.

The adapter identifier defaults to `rest`. A capability is visible and invocable only when policy grants the authenticated principal that exact adapter and capability combination.

## Routes

| Method | Path | Behavior |
| --- | --- | --- |
| `GET` | `/api/v1` | Returns links to version-one resources |
| `GET` | `/api/v1/capabilities` | Lists authorized capability descriptors |
| `GET` | `/api/v1/capabilities/{capabilityId}` | Returns one authorized descriptor |
| `POST` | `/api/v1/capabilities/{capabilityId}` | Validates and invokes one capability |

Capability descriptors include the stable identifier, summary, effect, and JSON Schema 2020-12 input contract. Discovery fails closed when policy state is unavailable. Missing and unauthorized capabilities use the same `404 not_found` response.

## Invocation

A nonempty request body must have exactly one `Content-Type` header whose media type is `application/json`. An empty body is treated as an empty JSON object. The shared dispatcher performs exact authorization and schema validation before executing the host handler.

Successful invocations return the generated invocation identifier and the handler's JSON result:

```json
{
  "invocationId": "request_example",
  "result": {
    "charging": true
  }
}
```

The invocation identifier also appears in errors produced after dispatch begins so hosts can correlate responses with audit records. Handler failures expose only their stable, non-sensitive code.

## Error Mapping

| Status | Error | Meaning |
| --- | --- | --- |
| `400` | `invalid_json` | The request body is not valid JSON |
| `404` | `not_found` | The route, capability, or grant is absent |
| `405` | `method_not_allowed` | The route does not support the method |
| `415` | `unsupported_media_type` | A nonempty body is not declared as JSON |
| `422` | `invalid_input` | Input does not satisfy the capability schema |
| `422` | `capability_failed` | The host handler returned a stable failure code |
| `503` | `policy_unavailable` | Authorization state cannot be read safely |
| `503` | `audit_unavailable` | Required audit recording failed |
| `503` | `identifier_generation_unavailable` | Secure invocation identifier generation failed |

Authentication, request size, rate limit, origin, and timeout failures are produced by `bondry-http` before the adapter receives a request.
