# C ABI

`bondry-ffi` is the language-neutral boundary for embedding Bondry. The canonical public header is `bindings/c/include/bondry.h`.

## Version One

ABI v1 exposes encrypted-store lifecycle operations:

- `bondry_abi_version_v1`
- `bondry_store_open_v1`
- `bondry_store_check_v1`
- `bondry_store_close_v1`

It also exposes administrative operations without adding transport or application policy:

- Create, enumerate, enable, and disable authentication clients
- Issue, enumerate, rotate, and revoke independent client tokens
- Authenticate a bearer token into a non-secret application principal
- Add, remove, and enumerate exact principal-adapter-capability grants
- Query recent or per-principal audit metadata with a limit from 1 through 1,000

The store is an opaque handle. Foreign callers never allocate it, inspect its layout, or receive a Rust reference. Opening transfers one ownership unit to the caller, and closing consumes it. A non-null handle must be closed exactly once and must not be closed concurrently with another operation.

Paths cross the ABI as explicit-length UTF-8 bytes. Database keys must contain exactly 32 bytes. The open call copies the key into zeroizing Rust storage, initializes SQLCipher, and drops the temporary Rust key before returning.

Other strings also cross as explicit-length UTF-8 input. Result records have fixed capacities derived from the validated core limits, contain zero-terminated UTF-8 fields, and are written into caller-owned memory. Optional values use explicit presence fields instead of sentinel timestamps.

List calls use a two-call pattern. A null output with zero capacity reports the complete result count. Insufficient capacity returns `BONDRY_STATUS_BUFFER_TOO_SMALL`, writes no partial records, and reports the required count so the caller can retry. Audit queries remain bounded even during the count call.

Token issuance and rotation return the complete bearer token only once. The caller must call `bondry_issued_token_clear_v1` after deliberately copying or presenting it and must also clear any additional copies it creates. Authentication never retains the presented credential and maps all syntactically valid credential rejections to `BONDRY_STATUS_AUTHENTICATION_REJECTED`.

## Errors and Panics

Every function returns a stable integer status except the version query. Status values reveal safe administrative or storage categories but never Rust error text, SQL, paths, key material, or credential lookup details.

Rust unwinding is caught at each fallible ABI entry point and maps to `BONDRY_STATUS_INTERNAL_FAILURE`. Memory violations caused by dangling, undersized, or otherwise invalid foreign pointers cannot be recovered; pointer validity remains part of the C caller contract.

## Compatibility Rules

- Existing v1 function signatures and status values must not change.
- Existing status values must never be reused for another meaning.
- Compatible capabilities use new function names with the `_v1` suffix.
- A breaking ownership or representation change requires a new ABI version.

## Apple Bindings

`BondrySQLCipher` is the native Swift wrapper over ABI v1. It validates the linked ABI version, accepts only file URLs, maps every public status, closes its handle during deinitialization, and never exposes the opaque pointer. It provides Swift models for clients, non-secret token metadata, principals, exact capability grants, and audit events while transparently retrying list queries that grow between calls.

New token secrets remain in a private C record owned by shared Swift storage. The record is cleared when its last `BondryIssuedToken` value is released. Byte-oriented consumers can avoid a `String` copy with `withUnsafeSecretBytes`; `copySecret()` exists for callers that deliberately need one.

The source package does not commit a prebuilt Rust binary. Build the macOS static library with:

```sh
apple/scripts/build-rust-macos.sh
```

The same Rust crate has been compile-checked for `aarch64-apple-ios` and `aarch64-apple-ios-sim`. Packaging signed release artifacts as an XCFramework remains a separate distribution step.

## C Verification

The C smoke test compiles against only the public header and links the Rust static library:

```sh
clang -std=c11 -Wall -Wextra -Werror -mmacosx-version-min=13.0 \
  bindings/c/tests/store_smoke.c -I bindings/c/include \
  target/apple/macos/debug/libbondry_ffi.a -liconv \
  -o /tmp/bondry-store-smoke
/tmp/bondry-store-smoke /tmp/bondry-store-smoke.db
```
