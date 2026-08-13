# Authorization

Authentication establishes a principal but grants no automation capability. Bondry authorization is deny-by-default and matches one exact tuple:

```text
principal × adapter × capability
```

The adapter is part of the grant. Allowing a client to call `battery.status` through REST does not allow the same client to call it through MCP. Hosts should derive the available capability list from application-owned feature state, then let the user choose a subset for each client and adapter.

## Policy Implementations

`GrantPolicy` is an in-memory implementation for ephemeral hosts and tests. `StoredGrantPolicy` evaluates directly against a storage-neutral `GrantStore`. A storage read failure produces `PolicyUnavailable` and denies the invocation.

`bondry-store-sqlcipher` implements `GrantStore` with idempotent add and remove operations, exact lookup, and stable per-principal enumeration. Grants are encrypted with the rest of the database. Schema version two migrates an existing version-one authentication and audit database without deleting its clients, tokens, or events.

The C ABI and `BondrySQLCipher` expose grant administration but do not decide which capabilities an application may offer. That remains a host-owned decision so an automation setting can never enable a feature that the application itself has disabled.
