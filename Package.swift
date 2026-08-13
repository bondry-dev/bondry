// swift-tools-version: 6.2

import PackageDescription

let bondryVersion = "0.1.0"
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
  ],
  targets: [
    .binaryTarget(
      name: "CBondryRuntime",
      url: "\(releaseBaseURL)/BondryRuntime.xcframework.zip",
      checksum: "f276fcba7bf7db076f84809f9433567db1886a5d96d5080b83bb9394ddf6f4c9"
    ),
    .binaryTarget(
      name: "CBondryLocalServer",
      url: "\(releaseBaseURL)/BondryLocalServer.xcframework.zip",
      checksum: "79458fd84b624d65ccad7b1c9d3019f6c38701b56dd57f99f46e6a42102044c2"
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
