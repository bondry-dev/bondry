// swift-tools-version: 6.2

import PackageDescription

let package = Package(
  name: "BondryApple",
  platforms: [
    .macOS(.v13),
    .iOS(.v16),
  ],
  products: [
    .library(name: "Bondry", targets: ["Bondry"]),
    .library(name: "BondryApple", targets: ["BondryApple"]),
    .library(name: "BondryAppIntents", targets: ["BondryAppIntents"]),
    .library(name: "BondryLocalServer", targets: ["BondryLocalServer"]),
  ],
  targets: [
    .target(
      name: "CBondryRuntime",
      publicHeadersPath: "include"
    ),
    .target(
      name: "CBondryLocalServer",
      publicHeadersPath: "include"
    ),
    .target(
      name: "BondryApple",
      linkerSettings: [.linkedFramework("Security")]
    ),
    .target(
      name: "Bondry",
      dependencies: ["BondryApple", "CBondryRuntime"],
      linkerSettings: [
        .linkedFramework("CoreFoundation"),
        .linkedFramework("Security"),
        .linkedLibrary("iconv"),
      ]
    ),
    .target(
      name: "BondryLocalServer",
      dependencies: ["Bondry", "CBondryLocalServer"]
    ),
    .target(
      name: "BondryAppIntents",
      dependencies: ["Bondry"],
      linkerSettings: [.linkedFramework("AppIntents")]
    ),
    .target(
      name: "CBondryTestSupport",
      dependencies: ["CBondryRuntime", "CBondryLocalServer"],
      path: "Tests/CBondryTestSupport",
      publicHeadersPath: "include"
    ),
    .testTarget(
      name: "BondryAppleTests",
      dependencies: ["BondryApple"]
    ),
    .testTarget(
      name: "BondryTests",
      dependencies: ["Bondry", "CBondryTestSupport"]
    ),
    .testTarget(
      name: "BondryLocalServerTests",
      dependencies: [
        "Bondry",
        "BondryApple",
        "BondryLocalServer",
        "CBondryLocalServer",
        "CBondryTestSupport",
      ]
    ),
    .testTarget(
      name: "BondryAppIntentsTests",
      dependencies: ["BondryAppIntents", "Bondry", "CBondryTestSupport"]
    ),
  ]
)
