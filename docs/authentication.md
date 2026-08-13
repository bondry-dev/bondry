# Authentication

Bondry separates credential verification from authorization. A valid token establishes an application principal but grants no capabilities by itself.

## Local Access Tokens

A local token contains a version marker, a 128-bit random public identifier, and a 256-bit random secret. Both random values come from the operating system's cryptographically secure random source.

Only the public identifier and a SHA-256 digest of the random secret are persisted. The complete token is returned once during issuance or rotation. Its Rust wrapper redacts debug output and zeroizes its owned string on drop.

SHA-256 is used here for a uniformly random 256-bit secret, not for a human-created password. Password-based credentials require a dedicated password-hashing design and are outside this token format.

Malformed, unknown, mismatched, expired, revoked, and disabled-client tokens all produce the same external rejection. Administrative APIs may expose lifecycle state to an authorized local user.

## Client State

Each client has a random principal identifier and can own multiple independently revocable tokens. Disabling a client immediately rejects all of its tokens. Rotation atomically revokes the selected token and stores its replacement.

Authentication returns a `PrincipalKind::Application` principal. The dispatch policy must still contain an explicit grant for that principal, adapter, and capability.
