// swift-tools-version: 6.2

import PackageDescription

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
  ],
  targets: [
    .target(
      name: "CBondryRuntime",
      path: "apple/Sources/CBondryRuntime",
      publicHeadersPath: "include"
    ),
    .target(
      name: "CBondryLocalServer",
      path: "apple/Sources/CBondryLocalServer",
      publicHeadersPath: "include"
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
      name: "BondryAppIntents",
      dependencies: ["Bondry"],
      path: "apple/Sources/BondryAppIntents",
      linkerSettings: [.linkedFramework("AppIntents")]
    ),
  ]
)
