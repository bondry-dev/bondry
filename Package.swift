// swift-tools-version: 6.2

import PackageDescription

let bondryVersion = "0.1.2"
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
      checksum: "2a012c863be39b24312fcad9f0379035169c79bed17d1e68ca5b83211e37580e"
    ),
    .binaryTarget(
      name: "CBondryLocalServer",
      url: "\(releaseBaseURL)/BondryLocalServer.xcframework.zip",
      checksum: "4e388f2fb06aa784eaa11167c1ac263eff2a76131db87332a09ba2e1b5826ea7"
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
