// swift-tools-version: 6.2

import PackageDescription

let bondryVersion = "0.2.0"
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
      checksum: "9d848465892c2d00d3b6f1f38034cc90b966361bfb0b1cbe1e36b567af65dbf4"
    ),
    .binaryTarget(
      name: "CBondryLocalServer",
      url: "\(releaseBaseURL)/BondryLocalServer.xcframework.zip",
      checksum: "ff73300b28195ec542f403e7ed96c349e3aaca06fac1fd8158b6db60b077875e"
    ),
    .binaryTarget(
      name: "CBondryEgress",
      url: "\(releaseBaseURL)/BondryEgress.xcframework.zip",
      checksum: "3e2a0a47724971d573c07e8d5279a6b4633871c8164924f762e7e023a6a75328"
    ),
    .binaryTarget(
      name: "CBondryWebhookIngress",
      url: "\(releaseBaseURL)/BondryWebhookIngress.xcframework.zip",
      checksum: "c940be1ff5b7247d0f8a6960bd8fb06d2f7c38e25432062d03da06961335ce6b"
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
