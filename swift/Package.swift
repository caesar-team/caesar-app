// swift-tools-version:5.9
import Foundation
import PackageDescription

// Статическая библиотека Rust лежит вне пакета, поэтому путь до неё считается
// от манифеста, а не задаётся относительным флагом: `swift test` и `swift build`
// запускаются с разными рабочими каталогами.
let workspaceRoot = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .path
let rustStaticLib = "\(workspaceRoot)/target/release/libcaesar_core_ffi.a"

let package = Package(
    name: "CaesarCore",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "CaesarCore", targets: ["CaesarCore"])
    ],
    targets: [
        // Заголовок и module map кладёт `generate-bindings.sh`; в репозитории
        // из этого таргета лежит только пустой `shim.c`.
        .target(
            name: "CaesarCoreFFI",
            linkerSettings: [
                // Архив передаётся путём, а не парой `-L`/`-l`: с `-l` линковщик
                // macOS предпочёл бы соседний `.dylib`, и тесты собирались бы,
                // но падали в рантайме без выставленного rpath.
                .unsafeFlags([rustStaticLib])
            ]
        ),
        .target(name: "CaesarCore", dependencies: ["CaesarCoreFFI"]),
        .testTarget(name: "CaesarCoreVectorsTests", dependencies: ["CaesarCore"]),
    ]
)
