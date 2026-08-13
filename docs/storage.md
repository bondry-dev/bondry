# Storage

Bondry's core is storage-neutral. `AuthStore` defines transactional client and token lifecycle operations, `GrantStore` defines exact authorization state, and `AuditSink` defines invocation audit recording. A host application can implement these contracts using its existing persistence layer.

## Encrypted Reference Store

`bondry-store-sqlcipher` is an optional local reference implementation. It provides:

- Full-database SQLCipher encryption, including schema and indexes
- Atomic token rotation and crash-safe transactions
- Stable client and per-client token enumeration for administrative interfaces
- Idempotent exact grants scoped by principal, adapter, and capability
- Indexed recent and per-principal audit lookup
- Foreign-key and schema constraints
- A busy timeout for independent local connections
- WAL with full synchronous durability
- A bounded audit query API
- Transactional schema migrations that preserve authentication, grants, and audit history

The store has no plaintext open function. Opening it requires a 256-bit `DatabaseKey`. The key must be persisted separately in a platform-secure secret store. Apple hosts can use the `BondryApple` Keychain provider; other platforms should use their native credential facilities or a host-provided equivalent.

Apple builds use SQLCipher's CommonCrypto provider and link the system Security and CoreFoundation frameworks. Other platforms use the vendored OpenSSL provider so the reference store does not depend on a system OpenSSL installation.

Foreign-language hosts open and administer the reference store through the opaque handle in C ABI v1. Swift hosts use `BondrySQLCipher` to open the store with `DatabaseKeyMaterial` from `BondryApple` without persisting an intermediate key copy, then manage clients, tokens, authentication, and audit queries through native Swift models.

Losing the database key makes the database unrecoverable. Copying the key next to the database defeats the encryption boundary.

## File-System Defense

Encryption complements rather than replaces operating-system access control. Hosts should place the database in an app sandbox or protected app-group container and restrict its parent directory to the application. On Unix platforms the reference store creates and resets the main database file to mode `0600`.

The current API does not provide backup, restore, database-key rotation, or multi-process lifecycle coordination. Those controls must be designed before the backend is considered production-ready. The Apple provider intentionally has no public delete or regeneration operation because replacing a key without rekeying the database causes permanent data loss.

## Data Minimization

Access-token secrets, invocation payloads, and capability schemas are never persisted. The database contains token digests, client and token labels, lifecycle timestamps, exact authorization grants, capability identifiers, adapters, and audit outcomes. These fields remain sensitive metadata and are therefore encrypted at rest.
