// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "CaesarLinkKit",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "CaesarLinkKit", targets: ["CaesarLinkKit"])
    ],
    dependencies: [
        // Only the raw C library product — we call crypto_pwhash_scryptsalsa208sha256_ll
        // directly and skip the Sodium Swift wrapper entirely.
        .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.11.0")
    ],
    targets: [
        .target(
            name: "CaesarLinkKit",
            dependencies: [.product(name: "Clibsodium", package: "swift-sodium")]
        ),
        // No bundled resources: the vector tests read packages/link-sdk/vectors/v2.json
        // straight out of the monorepo, so regenerated vectors can never silently drift
        // away from this implementation.
        .testTarget(name: "CaesarLinkKitTests", dependencies: ["CaesarLinkKit"]),
    ]
)
