# Storage

Bondry's core is storage-neutral. `AuthStore` defines transactional client and token lifecycle operations, while `AuditSink` defines invocation audit recording. A host application can implement either contract using its existing persistence layer.

## Encrypted Reference Store

`bondry-store-sqlcipher` is an optional local reference implementation. It provides:

- Full-database SQLCipher encryption, including schema and indexes
- Atomic token rotation and crash-safe transactions
- Indexed recent and per-principal audit lookup
- Foreign-key and schema constraints
- A busy timeout for independent local connections
- WAL with full synchronous durability
- A bounded audit query API

The store has no plaintext open function. Opening it requires a 256-bit `DatabaseKey`. The key must be persisted separately in a platform-secure secret store. Apple hosts should use Keychain; other platforms should use their native credential facilities or a host-provided equivalent.

Losing the database key makes the database unrecoverable. Copying the key next to the database defeats the encryption boundary.

## File-System Defense

Encryption complements rather than replaces operating-system access control. Hosts should place the database in an app sandbox or protected app-group container and restrict its parent directory to the application. On Unix platforms the reference store creates and resets the main database file to mode `0600`.

The current API does not provide backup, restore, key rotation, or multi-process lifecycle coordination. Those controls must be designed before the backend is considered production-ready.

## Data Minimization

Access-token secrets and invocation payloads are never persisted. The database contains token digests, client and token labels, lifecycle timestamps, authorization identities, capability identifiers, adapters, and audit outcomes. These fields remain sensitive metadata and are therefore encrypted at rest.
