// swift-tools-version: 6.0
import PackageDescription

// Root manifest so consumers can depend on this monorepo directly:
//   .package(url: "https://github.com/caesar-team/caesar-app.git", from: "0.1.0")
// SwiftPM has no subdirectory syntax for remote deps, but a root manifest whose targets
// point into SDKs/ achieves the same thing without a second repository.
let package = Package(
    name: "caesar-app",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [.library(name: "CaesarLinkKit", targets: ["CaesarLinkKit"])],
    dependencies: [
        .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.11.0")
    ],
    targets: [
        .target(
            name: "CaesarLinkKit",
            dependencies: [.product(name: "Clibsodium", package: "swift-sodium")],
            path: "SDKs/caesar-link-swift/Sources/CaesarLinkKit"
        ),
        .testTarget(
            name: "CaesarLinkKitTests",
            dependencies: ["CaesarLinkKit"],
            path: "SDKs/caesar-link-swift/Tests/CaesarLinkKitTests"
        ),
    ]
)
