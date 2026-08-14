// swift-tools-version: 6.2

import PackageDescription

let package = Package(
  name: "BondryAppleFuzz",
  platforms: [.macOS(.v13)],
  products: [
    .executable(name: "HTTPParserFuzz", targets: ["HTTPParserFuzz"])
  ],
  dependencies: [
    .package(path: "..")
  ],
  targets: [
    .target(
      name: "HTTPParserFuzzHarness",
      dependencies: [
        .product(name: "BondryApple", package: "apple")
      ]
    ),
    .executableTarget(
      name: "HTTPParserFuzz",
      dependencies: ["HTTPParserFuzzHarness"]
    ),
  ]
)
