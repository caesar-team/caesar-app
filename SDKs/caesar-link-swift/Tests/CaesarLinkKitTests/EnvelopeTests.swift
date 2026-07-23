import CryptoKit
import XCTest

@testable import CaesarLinkKit

final class EnvelopeTests: XCTestCase {
    func testTextRoundtripPreservesUnicode() throws {
        let bundle = try Share.create(.text("привет 🔗 transcription"))
        guard case .text(let data) = try Share.open(blob: bundle.blob, fragment: bundle.fragment)
        else {
            return XCTFail("expected text payload")
        }
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "привет 🔗 transcription")
    }

    func testMultiFileRoundtripPreservesOrderAndBytes() throws {
        let payload = SharePayload.files([
            SharedFile(name: "a.txt", mime: "text/plain", data: Data([0, 1])),
            SharedFile(name: "b.bin", mime: "application/octet-stream", data: Data([254, 255])),
            SharedFile(name: "картинка.png", mime: "image/png", data: Data([137, 80])),
        ])
        let bundle = try Share.create(payload)
        XCTAssertEqual(try Share.open(blob: bundle.blob, fragment: bundle.fragment), payload)
    }

    func testSealedBlobLayoutMatchesWebCrypto() throws {
        // WebCrypto appends the 16-byte GCM tag to the ciphertext; the IV is 12 bytes.
        let plaintext = Data("hello".utf8)
        let bundle = try Share.create(.text(plaintext))
        XCTAssertEqual(bundle.blob.iv.count, 12)
        XCTAssertGreaterThan(bundle.blob.ciphertext.count, 16)
    }

    func testWrongKeyFails() throws {
        let bundle = try Share.create(.text("secret"))
        let otherKey = Fragment.encodeKey(SymmetricKey(size: .bits256))
        XCTAssertThrowsError(try Share.open(blob: bundle.blob, fragment: otherKey)) { error in
            XCTAssertEqual(error as? LinkError, .decryptionFailed)
        }
    }

    func testTamperedCiphertextFails() throws {
        let bundle = try Share.create(.text("secret"))
        var tampered = bundle.blob
        tampered.ciphertext[tampered.ciphertext.startIndex] ^= 0xFF
        XCTAssertThrowsError(try Share.open(blob: tampered, fragment: bundle.fragment)) { error in
            XCTAssertEqual(error as? LinkError, .decryptionFailed)
        }
    }

    func testRejectsWrongEnvelopeVersion() throws {
        let dek = SymmetricKey(size: .bits256)
        let bogus = Data(#"{"v":99,"type":"text","data":""}"#.utf8)
        var iv = Data(count: 12)
        iv[0] = 7
        let box = try AES.GCM.seal(bogus, using: dek, nonce: try AES.GCM.Nonce(data: iv))
        let blob = SealedBlob(ciphertext: box.ciphertext + box.tag, iv: iv)
        XCTAssertThrowsError(try Envelope.open(blob, dek: dek)) { error in
            XCTAssertEqual(error as? LinkError, .unsupportedVersion(99))
        }
    }

    func testFragmentRejectsShortKey() {
        XCTAssertThrowsError(try Fragment.decodeKey("k.\(Base64URL.encode(Data([1, 2, 3])))"))
    }

    func testPasswordRoundtrip() throws {
        let bundle = try Share.create(.text("guarded transcription"), password: "hunter2")
        XCTAssertTrue(bundle.fragment.hasPrefix("p."))
        let kdf = try XCTUnwrap(bundle.kdf)
        XCTAssertEqual(kdf.kdf, "scrypt")
        XCTAssertEqual(kdf.dkLen, 32)

        guard
            case .text(let data) = try Share.open(
                blob: bundle.blob,
                fragment: bundle.fragment,
                password: "hunter2",
                kdf: kdf
            )
        else {
            return XCTFail("expected text payload")
        }
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "guarded transcription")
    }

    func testPasswordRoundtripRejectsWrongPassword() throws {
        let bundle = try Share.create(.text("guarded"), password: "hunter2")
        XCTAssertThrowsError(
            try Share.open(
                blob: bundle.blob,
                fragment: bundle.fragment,
                password: "wrong",
                kdf: bundle.kdf
            )
        ) { XCTAssertEqual($0 as? LinkError, .wrongPassword) }
    }

    func testKeyModeShareCarriesNoKdf() throws {
        let bundle = try Share.create(.text("open"))
        XCTAssertTrue(bundle.fragment.hasPrefix("k."))
        XCTAssertNil(bundle.kdf)
    }

    /// The server is untrusted: hostile KDF parameters must be refused before we allocate.
    func testHostileKdfParametersAreRejected() throws {
        let salt = Base64URL.encode(Data(repeating: 0, count: 16))
        let cases: [(String, KdfMeta)] = [
            ("N not a power of two", KdfMeta(salt: salt, n: 16383, r: 8, p: 1, dkLen: 32)),
            ("N above ceiling", KdfMeta(salt: salt, n: 1 << 21, r: 8, p: 1, dkLen: 32)),
            ("memory blow-up", KdfMeta(salt: salt, n: 1 << 20, r: 32, p: 1, dkLen: 32)),
            ("bad dkLen", KdfMeta(salt: salt, n: 16384, r: 8, p: 1, dkLen: 16)),
            ("unknown kdf", KdfMeta(kdf: "argon2", salt: salt, n: 16384, r: 8, p: 1, dkLen: 32)),
        ]
        for (label, kdf) in cases {
            XCTAssertThrowsError(try kdf.validate(), "should reject: \(label)")
        }
    }

    func testHonestDefaultKdfValidates() throws {
        let kdf = KdfMeta(
            salt: Base64URL.encode(Data(repeating: 0, count: 16)),
            n: Fragment.defaultN,
            r: Fragment.defaultR,
            p: Fragment.defaultP,
            dkLen: 32
        )
        XCTAssertNoThrow(try kdf.validate())
    }

    func testShareURLRoundtrip() throws {
        let url = ShareURL.build(baseURL: "https://link.bshk.app/", id: "abc123", fragment: "k.xyz")
        XCTAssertEqual(url, "https://link.bshk.app/s/abc123#k.xyz")
        let parsed = try ShareURL.parse(url)
        XCTAssertEqual(parsed.id, "abc123")
        XCTAssertEqual(parsed.fragment, "k.xyz")
    }

    func testShareURLWithoutFragmentThrows() {
        XCTAssertThrowsError(try ShareURL.parse("https://link.bshk.app/s/abc123"))
    }

    func testBase64URLIsUnpaddedAndURLSafe() throws {
        let data = Data([251, 255, 190, 0])
        let encoded = Base64URL.encode(data)
        XCTAssertFalse(encoded.contains("="))
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertEqual(try Base64URL.decode(encoded), data)
    }
}
