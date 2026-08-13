// swift-tools-version: 6.2

import PackageDescription

let package = Package(
  name: "BondryApple",
  platforms: [
    .macOS(.v13),
    .iOS(.v16),
  ],
  products: [
    .library(name: "BondryApple", targets: ["BondryApple"]),
    .library(name: "BondrySQLCipher", targets: ["BondrySQLCipher"]),
  ],
  targets: [
    .target(
      name: "CBondry",
      publicHeadersPath: "include"
    ),
    .target(
      name: "BondryApple",
      linkerSettings: [.linkedFramework("Security")]
    ),
    .target(
      name: "BondrySQLCipher",
      dependencies: ["BondryApple", "CBondry"]
    ),
    .target(
      name: "CBondryTestSupport",
      dependencies: ["CBondry"],
      path: "Tests/CBondryTestSupport",
      publicHeadersPath: "include"
    ),
    .testTarget(
      name: "BondryAppleTests",
      dependencies: ["BondryApple"]
    ),
    .testTarget(
      name: "BondrySQLCipherTests",
      dependencies: ["BondrySQLCipher", "CBondryTestSupport"]
    ),
  ]
)
