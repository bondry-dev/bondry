// swift-tools-version: 6.2

import PackageDescription

#if os(Linux)
  let package = Package(
    name: "Bondry",
    products: [
      .library(name: "Bondry", targets: ["Bondry"]),
      .library(name: "BondryCredentials", targets: ["BondryCredentials"]),
      .library(name: "BondryRESTServer", targets: ["BondryRESTServer"]),
    ],
    targets: [
      .systemLibrary(
        name: "CBondryRuntime",
        path: "linux/Sources/CBondryRuntime",
        pkgConfig: "bondry-runtime"
      ),
      .systemLibrary(
        name: "CBondryCredentials",
        path: "linux/Sources/CBondryCredentials",
        pkgConfig: "bondry-credentials"
      ),
      .systemLibrary(
        name: "CBondryRESTServer",
        path: "linux/Sources/CBondryRESTServer",
        pkgConfig: "bondry-rest-server"
      ),
      .target(
        name: "Bondry",
        dependencies: ["CBondryRuntime"],
        path: "apple/Sources/Bondry"
      ),
      .target(
        name: "BondryCredentials",
        dependencies: ["CBondryCredentials"],
        path: "apple/Sources/BondryCredentials"
      ),
      .target(
        name: "BondryRESTServer",
        dependencies: ["Bondry", "CBondryRESTServer"],
        path: "apple/Sources/BondryRESTServer"
      ),
      .testTarget(
        name: "BondryRuntimeLinuxTests",
        dependencies: ["Bondry"],
        path: "linux/Tests/BondryRuntimeLinuxTests"
      ),
      .testTarget(
        name: "BondryCredentialsLinuxTests",
        dependencies: ["BondryCredentials"],
        path: "linux/Tests/BondryCredentialsLinuxTests"
      ),
      .testTarget(
        name: "BondryRESTServerLinuxTests",
        dependencies: ["Bondry", "BondryRESTServer"],
        path: "linux/Tests/BondryRESTServerLinuxTests"
      ),
    ]
  )
#else
  let bondryVersion = "0.3.1"
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
      .library(name: "BondryRESTServer", targets: ["BondryRESTServer"]),
      .library(name: "BondryEgress", targets: ["BondryEgress"]),
      .library(name: "BondryWebhookIngress", targets: ["BondryWebhookIngress"]),
    ],
    targets: [
      .binaryTarget(
        name: "CBondryRuntime",
        url: "\(releaseBaseURL)/BondryRuntime.xcframework.zip",
        checksum: "4c8e094e0479d012a61dd2854e1f4763d6fbbbe5e2a819e6ba08529ffe6c52df"
      ),
      .binaryTarget(
        name: "CBondryLocalServer",
        url: "\(releaseBaseURL)/BondryLocalServer.xcframework.zip",
        checksum: "9031a440c4892d900631346cd8222d8c7fd62165b230609b94a68e6ed78950a6"
      ),
      .binaryTarget(
        name: "CBondryRESTServer",
        url: "\(releaseBaseURL)/BondryRESTServer.xcframework.zip",
        checksum: "87b0cf902f6549cda8c23fc0058b71099b0e7d8801fd25e357a8ad99250ffe2c"
      ),
      .binaryTarget(
        name: "CBondryEgress",
        url: "\(releaseBaseURL)/BondryEgress.xcframework.zip",
        checksum: "1c4c04ce02c26f2b410e73631d8748cda95d827d0c1c0b7c72cee36cbb1be5ea"
      ),
      .binaryTarget(
        name: "CBondryWebhookIngress",
        url: "\(releaseBaseURL)/BondryWebhookIngress.xcframework.zip",
        checksum: "4fcf8132052b5cb7fcaa6b0f5e2923f5f5944e93db7daaaf0ebbe7a9592e5783"
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
        name: "BondryRESTServer",
        dependencies: ["Bondry", "CBondryRESTServer"],
        path: "apple/Sources/BondryRESTServer"
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
#endif
