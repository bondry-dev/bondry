// swift-tools-version: 6.2

import PackageDescription

let bondryVersion = "0.2.1"
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
      checksum: "273f8949283a7f1b4288b8b74280e873c5440fc17b09aa47995f47319f1e21ab"
    ),
    .binaryTarget(
      name: "CBondryLocalServer",
      url: "\(releaseBaseURL)/BondryLocalServer.xcframework.zip",
      checksum: "a4e72ff50b095bd38716cb49abb6823d23cc418328f2c3ed82bb5becb62b4643"
    ),
    .binaryTarget(
      name: "CBondryRESTServer",
      url: "\(releaseBaseURL)/BondryRESTServer.xcframework.zip",
      checksum: "b77cd6e3617644da88590a0723dd12c58bb8ebb0fe064df49a0a688158e90303"
    ),
    .binaryTarget(
      name: "CBondryEgress",
      url: "\(releaseBaseURL)/BondryEgress.xcframework.zip",
      checksum: "1ec1aff2b241671344619752a72430955c26bfba630ce8c44f97362a3149e69c"
    ),
    .binaryTarget(
      name: "CBondryWebhookIngress",
      url: "\(releaseBaseURL)/BondryWebhookIngress.xcframework.zip",
      checksum: "3b95e7193e7ca8d68386445b6602ffff9050050bf103bd33ead09c93875f2c73"
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
