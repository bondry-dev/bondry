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
  let bondryVersion = "0.3.0"
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
        checksum: "78640d852628e7826eb5be0b65245087da9c34caeb488f4b337f5d196cfbf4ba"
      ),
      .binaryTarget(
        name: "CBondryLocalServer",
        url: "\(releaseBaseURL)/BondryLocalServer.xcframework.zip",
        checksum: "5aff885f9a33c8e1d69416eac057afcec819960e59e48d6727410cffd4c27517"
      ),
      .binaryTarget(
        name: "CBondryRESTServer",
        url: "\(releaseBaseURL)/BondryRESTServer.xcframework.zip",
        checksum: "71c3cf3ce4101370ac061d1b7380ac37091be798dcdc89bf6f120a85f3e067ac"
      ),
      .binaryTarget(
        name: "CBondryEgress",
        url: "\(releaseBaseURL)/BondryEgress.xcframework.zip",
        checksum: "86b326a227986728ba4976387844985d504ceaed559a67e01ed2fda494d0285a"
      ),
      .binaryTarget(
        name: "CBondryWebhookIngress",
        url: "\(releaseBaseURL)/BondryWebhookIngress.xcframework.zip",
        checksum: "49f8e46eeab71d0d455f8eb2181c04d68314b18b45184a5769a7f8a639a3acec"
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
