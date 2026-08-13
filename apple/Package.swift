// swift-tools-version: 6.2

import PackageDescription

let package = Package(
  name: "BondryApple",
  platforms: [
    .macOS(.v13),
    .iOS(.v16),
  ],
  products: [
    .library(name: "BondryApple", targets: ["BondryApple"])
  ],
  targets: [
    .target(
      name: "BondryApple",
      linkerSettings: [.linkedFramework("Security")]
    ),
    .testTarget(
      name: "BondryAppleTests",
      dependencies: ["BondryApple"]
    ),
  ]
)
