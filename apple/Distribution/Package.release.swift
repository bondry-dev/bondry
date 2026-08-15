// swift-tools-version: 6.2

import PackageDescription

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
