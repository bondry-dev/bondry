// swift-tools-version: 6.2

import PackageDescription

let bondryVersion = "__BONDRY_VERSION__"
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
      checksum: "__BONDRY_CHECKSUM__"
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
