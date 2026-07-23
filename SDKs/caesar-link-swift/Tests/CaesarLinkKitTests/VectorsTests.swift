import XCTest

@testable import CaesarLinkKit

/// Cross-implementation proof: these blobs were sealed by the TypeScript SDK. If Swift
/// opens them byte-for-byte, the two implementations speak the same protocol.
///
/// The vectors are read from `packages/link-sdk/vectors/v2.json` in this monorepo rather
/// than from a bundled copy — regenerating them upstream fails this test immediately
/// instead of letting the two SDKs drift apart unnoticed.
final class VectorsTests: XCTestCase {
    private struct VectorsFile: Decodable {
        let version: Int
        let vectors: [Vector]
    }

    private struct Vector: Decodable {
        let name: String
        let password: String?
        let fragment: String
        let kdf: KdfMeta?
        let blob: Blob
        let expected: Expected

        struct Blob: Decodable {
            let ciphertext: String
            let iv: String
        }

        struct ExpectedFile: Decodable {
            let name: String
            let mime: String
            let data: String
        }

        struct Expected: Decodable {
            let type: String
            let data: String?
            let files: [ExpectedFile]?
        }
    }

    /// Canonical location of the vectors, relative to the monorepo root.
    private static let vectorsPath = "packages/link-sdk/vectors/v2.json"

    /// Walks up from this source file until it finds the monorepo root. Searching for the
    /// file rather than counting `../` keeps the test working if the package moves.
    private func vectorsURL() throws -> URL {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let candidate = dir.appendingPathComponent(Self.vectorsPath)
            if FileManager.default.fileExists(atPath: candidate.path) { return candidate }
            dir = dir.deletingLastPathComponent()
        }
        throw XCTSkip("\(Self.vectorsPath) not found — package checked out outside the monorepo")
    }

    private func loadVectors() throws -> VectorsFile {
        try JSONDecoder().decode(VectorsFile.self, from: Data(contentsOf: try vectorsURL()))
    }

    func testVectorsFileIsVersion2() throws {
        XCTAssertEqual(try loadVectors().version, Envelope.version)
    }

    /// Every vector — `k.` and `p.` alike. Password vectors exercise scrypt via libsodium.
    func testOpensEveryVector() throws {
        let file = try loadVectors()
        XCTAssertFalse(file.vectors.isEmpty)

        for vector in file.vectors {
            let blob = SealedBlob(
                ciphertext: try Base64URL.decode(vector.blob.ciphertext),
                iv: try Base64URL.decode(vector.blob.iv)
            )
            let payload = try Share.open(
                blob: blob,
                fragment: vector.fragment,
                password: vector.password,
                kdf: vector.kdf
            )

            switch (payload, vector.expected.type) {
            case (.text(let data), "text"):
                let expected = try Base64URL.decode(try XCTUnwrap(vector.expected.data))
                XCTAssertEqual(data, expected, "text mismatch in vector \(vector.name)")

            case (.files(let files), "file"):
                let expected = try XCTUnwrap(vector.expected.files)
                XCTAssertEqual(files.count, expected.count, "file count in vector \(vector.name)")
                for (actual, want) in zip(files, expected) {
                    XCTAssertEqual(actual.name, want.name, "name in vector \(vector.name)")
                    XCTAssertEqual(actual.mime, want.mime, "mime in vector \(vector.name)")
                    XCTAssertEqual(
                        actual.data,
                        try Base64URL.decode(want.data),
                        "bytes in vector \(vector.name)"
                    )
                }

            default:
                XCTFail("payload/expected type mismatch in vector \(vector.name)")
            }
        }
    }

    /// The multi-file vector is the one that proves envelope **v2** specifically:
    /// v1 could only carry a single file.
    func testMultiFileVectorPreservesOrder() throws {
        let file = try loadVectors()
        let vector = try XCTUnwrap(file.vectors.first { $0.name == "file-multi" })
        let blob = SealedBlob(
            ciphertext: try Base64URL.decode(vector.blob.ciphertext),
            iv: try Base64URL.decode(vector.blob.iv)
        )
        guard case .files(let files) = try Share.open(blob: blob, fragment: vector.fragment) else {
            return XCTFail("expected a file payload")
        }
        XCTAssertEqual(files.map(\.name), ["one.txt", "two.bin"])
        XCTAssertEqual(files[0].data, Data("one".utf8))
        XCTAssertEqual(files[1].data, Data([254, 255]))
    }

    /// The `p.` vector: proves our scrypt (libsodium `_ll`) derives the exact same KEK as
    /// the TypeScript `@noble/hashes` scrypt for identical N/r/p/salt.
    func testPasswordVectorUnwrapsViaScrypt() throws {
        let file = try loadVectors()
        let vector = try XCTUnwrap(file.vectors.first { $0.password != nil })
        let blob = SealedBlob(
            ciphertext: try Base64URL.decode(vector.blob.ciphertext),
            iv: try Base64URL.decode(vector.blob.iv)
        )
        guard
            case .text(let data) = try Share.open(
                blob: blob,
                fragment: vector.fragment,
                password: vector.password,
                kdf: vector.kdf
            )
        else {
            return XCTFail("expected a text payload")
        }
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "guarded")
    }

    func testPasswordVectorRejectsWrongPassword() throws {
        let file = try loadVectors()
        let vector = try XCTUnwrap(file.vectors.first { $0.password != nil })
        let blob = SealedBlob(
            ciphertext: try Base64URL.decode(vector.blob.ciphertext),
            iv: try Base64URL.decode(vector.blob.iv)
        )
        XCTAssertThrowsError(
            try Share.open(blob: blob, fragment: vector.fragment, password: "nope", kdf: vector.kdf)
        ) { XCTAssertEqual($0 as? LinkError, .wrongPassword) }
    }

    func testPasswordShareWithoutPasswordIsRefused() throws {
        let file = try loadVectors()
        let vector = try XCTUnwrap(file.vectors.first { $0.password != nil })
        let blob = SealedBlob(
            ciphertext: try Base64URL.decode(vector.blob.ciphertext),
            iv: try Base64URL.decode(vector.blob.iv)
        )
        XCTAssertThrowsError(try Share.open(blob: blob, fragment: vector.fragment)) {
            XCTAssertEqual($0 as? LinkError, .passwordRequired)
        }
    }
}
