# Apple Keychain

`BondryApple` provides the Apple-specific database-key boundary for `bondry-store-sqlcipher`. It is a separate Swift package so the portable Rust core does not depend on Security.framework.

## Protection Policy

The provider stores one 256-bit random value as a generic-password item with these properties:

- Data Protection Keychain is selected explicitly.
- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` prevents access while locked and prevents migration to another device.
- Keychain synchronization is disabled explicitly.
- Random bytes come from `SecRandomCopyBytes` and every status is checked.
- The service and account identify the item but are not treated as secrets.

The public API supports loading a key and atomically creating one when absent. It does not expose deletion or regeneration. An invalid stored key fails without replacement, and simultaneous creators converge on the item that Keychain accepted first.

## Host Integration

Add the package from the `apple` directory, then create one stable service and account pair for each encrypted database:

```swift
import BondryApple

let configuration = try KeychainDatabaseKeyConfiguration(
  service: "com.example.application.automation",
  account: "database-key"
)
let key = try KeychainDatabaseKeyProvider(configuration: configuration).loadOrCreate()
```

Use the separate `BondrySQLCipher` product to pass the key directly into the Rust encrypted store:

```swift
import BondrySQLCipher

let store = try BondryEncryptedStore.open(at: databaseURL, key: key)
try store.checkHealth()
```

The wrapper passes the bytes only for the duration of the open call. The host must not write them to defaults, logs, crash metadata, environment variables, or a file next to the database.

`DatabaseKeyMaterial` redacts its normal and debug descriptions. Swift's value semantics can still leave transient copies in process memory, so the provider does not claim memory protection after a successful read.

On macOS, a Data Protection Keychain caller must be code signed with an application-identifier entitlement. Xcode normally supplies it for an application target. A bare Swift Package test process does not have that entitlement and returns `missingKeychainEntitlement`.

Leave `accessGroup` unset for app-private storage. Set it only when multiple signed targets deliberately share the database key, and add the matching Keychain Sharing capability to every target. An unentitled access group fails closed.

## Verification

The regular test suite uses an in-memory Keychain boundary and never touches the user's Keychain:

```sh
swift test --package-path apple
```

The signed integration probe requires XcodeGen, a valid Apple development signing identity, the Rust static library, and the caller's team identifier:

```sh
apple/scripts/build-rust-macos.sh
cd apple/IntegrationTests/KeychainProbe
DEVELOPMENT_TEAM=YOUR_TEAM_ID xcodegen generate
xcodebuild -quiet -project KeychainProbe.xcodeproj \
  -scheme KeychainProbe -configuration Debug \
  -derivedDataPath DerivedData build
DerivedData/Build/Products/Debug/KeychainProbe.app/Contents/MacOS/KeychainProbe
```

The probe uses a random service name, opens a real encrypted Rust store through `BondrySQLCipher`, verifies that its file has no plaintext SQLite header, and removes both the Keychain item and database before exiting. Generated projects and build products are ignored by Git.
