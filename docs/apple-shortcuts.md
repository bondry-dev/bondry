# Apple Shortcuts

`BondryAppIntents` exposes registered Bondry capabilities to Apple Shortcuts without coupling application handlers to App Intents. It supports macOS 13 and iOS 16 or newer. Package-level App Intents discovery through `AppIntentsPackage` requires macOS 14 or iOS 17.

## Host Setup

Add `BondryAppIntents` to the application target. Include the package metadata from an application-owned `AppIntentsPackage`:

```swift
import AppIntents
import BondryAppIntents

@available(macOS 14.0, iOS 17.0, *)
struct MyAppIntentsPackage: AppIntentsPackage {
  static var includedPackages: [any AppIntentsPackage.Type] {
    [BondryAppIntentsPackage.self]
  }
}
```

After opening the encrypted store and registering application capabilities, create one stable local principal and register the runtime as an App Intents dependency:

```swift
let shortcutsPrincipal = BondryPrincipal(
  id: "shortcuts.local-user",
  kind: .system
)
let shortcutsRuntime = BondryShortcutsRuntime(
  store: store,
  principal: shortcutsPrincipal
)
shortcutsRuntime.register()

_ = try store.addGrant(
  principalID: shortcutsPrincipal.id,
  adapterID: BondryShortcutsRuntime.adapterID,
  capabilityID: "battery.read"
)
```

Keep the runtime's store alive for as long as Shortcuts can invoke the application. Use a stable principal identifier so grants and audit history remain attributable across launches.

## Generic Action

`BondryRunCapabilityIntent` contributes a generic **Run Automation Capability** action. Its capability picker discovers only capabilities that are both registered and explicitly granted to the configured principal for the `shortcuts` adapter. The action accepts JSON and returns JSON so the same capability contract can be reused by REST, MCP, and Shortcuts.

Discovery is not an authorization cache. Every invocation resolves the current capability, evaluates the current exact grant, validates its JSON Schema, and records the standard audit events. Removing a grant or unregistering a capability takes effect without rebuilding shortcuts.

The generic action uses `requiresAuthentication`. Applications with sensitive typed actions may define their own `AppIntent` and use `requiresLocalDeviceAuthentication` where the supported operating-system versions permit it.

## App Shortcuts and Siri Phrases

An application can optionally add an `AppShortcutsProvider` in its app target for a zero-setup Siri phrase:

```swift
import AppIntents
import BondryAppIntents

struct MyAppShortcuts: AppShortcutsProvider {
  static var appShortcuts: [AppShortcut] {
    AppShortcut(
      intent: BondryRunCapabilityIntent(),
      phrases: ["Run automation with \(.applicationName)"],
      shortTitle: "Run Automation",
      systemImageName: "bolt.horizontal"
    )
  }
}
```

The provider belongs in the app target because its phrases, title, and icon are application-specific static metadata. The reusable intent, entity, query, and runtime remain in Bondry. The generic action is available in the Shortcuts editor without an `AppShortcutsProvider`.

Applications can also define typed intents with static, localized parameters and call `BondryShortcutsRuntime.invoke` from `perform()`. That keeps application-facing vocabulary in the host while reusing Bondry authorization, validation, dispatch, and auditing.

## Security Boundary

Shortcuts does not present a Bondry bearer token. The host asserts a local system principal because App Intents is an operating-system-controlled invocation path. Trusted-principal dispatch bypasses only credential authentication; it does not bypass grants, input validation, auditing, or handler isolation.

The principal identifies the configured local Shortcuts context rather than an individual shortcut or another application. Use REST or MCP with independent client tokens when per-client revocation and attribution are required.
