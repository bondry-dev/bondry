// swift-tools-version: 6.2

import PackageDescription

#if os(Linux)
  let package = Package(
    name: "Bondry",
    products: [
      .library(name: "Bondry", targets: ["Bondry"]),
      .library(name: "BondryCredentials", targets: ["BondryCredentials"]),
      .library(name: "BondryRESTServer", targets: ["BondryRESTServer"]),
    ],
    targets: [
      .systemLibrary(
        name: "CBondryRuntime",
        path: "linux/Sources/CBondryRuntime",
        pkgConfig: "bondry-runtime"
      ),
      .systemLibrary(
        name: "CBondryCredentials",
        path: "linux/Sources/CBondryCredentials",
        pkgConfig: "bondry-credentials"
      ),
      .systemLibrary(
        name: "CBondryRESTServer",
        path: "linux/Sources/CBondryRESTServer",
        pkgConfig: "bondry-rest-server"
      ),
      .target(
        name: "Bondry",
        dependencies: ["CBondryRuntime"],
        path: "apple/Sources/Bondry"
      ),
      .target(
        name: "BondryCredentials",
        dependencies: ["CBondryCredentials"],
        path: "apple/Sources/BondryCredentials"
      ),
      .target(
        name: "BondryRESTServer",
        dependencies: ["Bondry", "CBondryRESTServer"],
        path: "apple/Sources/BondryRESTServer"
      ),
      .testTarget(
        name: "BondryRuntimeLinuxTests",
        dependencies: ["Bondry"],
        path: "linux/Tests/BondryRuntimeLinuxTests"
      ),
      .testTarget(
        name: "BondryCredentialsLinuxTests",
        dependencies: ["BondryCredentials"],
        path: "linux/Tests/BondryCredentialsLinuxTests"
      ),
      .testTarget(
        name: "BondryRESTServerLinuxTests",
        dependencies: ["Bondry", "BondryRESTServer"],
        path: "linux/Tests/BondryRESTServerLinuxTests"
      ),
    ]
  )
#else
  let bondryVersion = "__BONDRY_VERSION__"
  let releaseBaseURL =
    "https://github.com/bondry-dev/bondry/releases/download/v\(bondryVersion)"

  let package = Package(
    name: "Bondry",
    platforms: [
      .macOS(.v13),
      .iOS(.v16),
    ],
    products: [
      .library(name: "Bondry", targets: ["Bondry"]),
      .library(name: "BondryApple", targets: ["BondryApple"]),
      .library(name: "BondryAppIntents", targets: ["BondryAppIntents"]),
      .library(name: "BondryLocalServer", targets: ["BondryLocalServer"]),
      .library(name: "BondryRESTServer", targets: ["BondryRESTServer"]),
      .library(name: "BondryEgress", targets: ["BondryEgress"]),
      .library(name: "BondryWebhookIngress", targets: ["BondryWebhookIngress"]),
    ],
    targets: [
      .binaryTarget(
        name: "CBondryRuntime",
        url: "\(releaseBaseURL)/BondryRuntime.xcframework.zip",
        checksum: "__BONDRY_RUNTIME_CHECKSUM__"
      ),
      .binaryTarget(
        name: "CBondryLocalServer",
        url: "\(releaseBaseURL)/BondryLocalServer.xcframework.zip",
        checksum: "__BONDRY_LOCAL_SERVER_CHECKSUM__"
      ),
      .binaryTarget(
        name: "CBondryRESTServer",
        url: "\(releaseBaseURL)/BondryRESTServer.xcframework.zip",
        checksum: "__BONDRY_REST_SERVER_CHECKSUM__"
      ),
      .binaryTarget(
        name: "CBondryEgress",
        url: "\(releaseBaseURL)/BondryEgress.xcframework.zip",
        checksum: "__BONDRY_EGRESS_CHECKSUM__"
      ),
      .binaryTarget(
        name: "CBondryWebhookIngress",
        url: "\(releaseBaseURL)/BondryWebhookIngress.xcframework.zip",
        checksum: "__BONDRY_WEBHOOK_INGRESS_CHECKSUM__"
      ),
      .target(
        name: "BondryApple",
        path: "apple/Sources/BondryApple",
        linkerSettings: [.linkedFramework("Security")]
      ),
      .target(
        name: "Bondry",
        dependencies: ["BondryApple", "CBondryRuntime"],
        path: "apple/Sources/Bondry",
        linkerSettings: [
          .linkedFramework("CoreFoundation"),
          .linkedFramework("Security"),
          .linkedLibrary("iconv"),
        ]
      ),
      .target(
        name: "BondryLocalServer",
        dependencies: ["Bondry", "CBondryLocalServer"],
        path: "apple/Sources/BondryLocalServer"
      ),
      .target(
        name: "BondryRESTServer",
        dependencies: ["Bondry", "CBondryRESTServer"],
        path: "apple/Sources/BondryRESTServer"
      ),
      .target(
        name: "BondryEgress",
        dependencies: ["Bondry", "BondryApple", "CBondryEgress"],
        path: "apple/Sources/BondryEgress"
      ),
      .target(
        name: "BondryWebhookIngress",
        dependencies: [
          "Bondry", "BondryApple", "BondryLocalServer", "CBondryWebhookIngress",
        ],
        path: "apple/Sources/BondryWebhookIngress"
      ),
      .target(
        name: "BondryAppIntents",
        dependencies: ["Bondry"],
        path: "apple/Sources/BondryAppIntents",
        linkerSettings: [.linkedFramework("AppIntents")]
      ),
    ]
  )
#endif
