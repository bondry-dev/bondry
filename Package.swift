// swift-tools-version: 6.2

import PackageDescription

let bondryVersion = "0.0.1"
let bondryArtifactURL =
  "https://github.com/bondry-dev/bondry/releases/download/v\(bondryVersion)/BondryFFI.xcframework.zip"

let package = Package(
  name: "Bondry",
  platforms: [
    .macOS(.v13),
    .iOS(.v16),
  ],
  products: [
    .library(name: "BondryApple", targets: ["BondryApple"]),
    .library(name: "BondryAppIntents", targets: ["BondryAppIntents"]),
    .library(name: "BondrySQLCipher", targets: ["BondrySQLCipher"]),
  ],
  targets: [
    .binaryTarget(
      name: "BondryFFI",
      url: bondryArtifactURL,
      checksum: "2963916fd4ed0a8d029779ead6e0b41cfdaf12e1a246425ecb826d4be662bfde"
    ),
    .target(
      name: "BondryApple",
      path: "apple/Sources/BondryApple",
      linkerSettings: [.linkedFramework("Security")]
    ),
    .target(
      name: "BondrySQLCipher",
      dependencies: ["BondryApple", "BondryFFI"],
      path: "apple/Sources/BondrySQLCipher",
      linkerSettings: [
        .linkedFramework("CoreFoundation"),
        .linkedFramework("Security"),
        .linkedLibrary("iconv"),
      ]
    ),
    .target(
      name: "BondryAppIntents",
      dependencies: ["BondrySQLCipher"],
      path: "apple/Sources/BondryAppIntents",
      linkerSettings: [.linkedFramework("AppIntents")]
    ),
  ]
)
