import CryptoKit
import Foundation

/// One attachment. Name and mime travel *inside* the ciphertext — the server never sees them.
public struct SharedFile: Equatable, Sendable {
    public var name: String
    public var mime: String
    public var data: Data

    public init(name: String, mime: String, data: Data) {
        self.name = name
        self.mime = mime
        self.data = data
    }
}

/// What a share carries. Mirrors the TS SDK's discriminated union.
public enum SharePayload: Equatable, Sendable {
    case text(Data)
    case files([SharedFile])

    public static func text(_ string: String) -> SharePayload {
        .text(Data(string.utf8))
    }
}

/// The only thing uploaded: AES-GCM ciphertext plus the public IV.
public struct SealedBlob: Equatable, Sendable {
    /// Ciphertext with the 16-byte GCM tag **appended** — byte-for-byte what WebCrypto emits.
    public var ciphertext: Data
    /// 12-byte nonce. Public: stored server-side as share metadata.
    public var iv: Data

    public init(ciphertext: Data, iv: Data) {
        self.ciphertext = ciphertext
        self.iv = iv
    }
}

/// Envelope v2: a JSON document sealed under the DEK.
///
/// ```text
/// text : {"v":2,"type":"text","data":"<base64url>"}
/// file : {"v":2,"type":"file","files":[{"name":…,"mime":…,"data":"<base64url>"}]}
/// ```
public enum Envelope {
    public static let version = 2

    /// AES-GCM tag length. CryptoKit keeps the tag separate; WebCrypto appends it to the
    /// ciphertext, so we concatenate on seal and split on open to stay wire-compatible.
    private static let tagLength = 16
    private static let ivLength = 12

    private struct WireFile: Codable {
        let name: String
        let mime: String
        let data: String
    }

    private struct Wire: Codable {
        let v: Int
        let type: String
        // Optionals are omitted by Swift's synthesized encoder, matching the TS wire.
        let data: String?
        let files: [WireFile]?
    }

    public static func seal(_ payload: SharePayload, dek: SymmetricKey) throws -> SealedBlob {
        let wire: Wire
        switch payload {
        case .text(let bytes):
            wire = Wire(v: version, type: "text", data: Base64URL.encode(bytes), files: nil)
        case .files(let files):
            wire = Wire(
                v: version,
                type: "file",
                data: nil,
                files: files.map {
                    WireFile(name: $0.name, mime: $0.mime, data: Base64URL.encode($0.data))
                }
            )
        }

        let plaintext = try JSONEncoder().encode(wire)
        var ivBytes = Data(count: ivLength)
        ivBytes.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            _ = SecRandomCopyBytes(kSecRandomDefault, ivLength, base)
        }
        let nonce = try AES.GCM.Nonce(data: ivBytes)
        let box = try AES.GCM.seal(plaintext, using: dek, nonce: nonce)
        return SealedBlob(ciphertext: box.ciphertext + box.tag, iv: ivBytes)
    }

    public static func open(_ blob: SealedBlob, dek: SymmetricKey) throws -> SharePayload {
        guard blob.ciphertext.count > tagLength else {
            throw LinkError.malformed("ciphertext shorter than the GCM tag")
        }
        let split = blob.ciphertext.count - tagLength
        let body = Data(blob.ciphertext.prefix(split))
        let tag = Data(blob.ciphertext.suffix(tagLength))

        let plaintext: Data
        do {
            let nonce = try AES.GCM.Nonce(data: blob.iv)
            let box = try AES.GCM.SealedBox(nonce: nonce, ciphertext: body, tag: tag)
            plaintext = try AES.GCM.open(box, using: dek)
        } catch {
            throw LinkError.decryptionFailed
        }

        let wire: Wire
        do {
            wire = try JSONDecoder().decode(Wire.self, from: plaintext)
        } catch {
            throw LinkError.malformed("envelope is not valid JSON")
        }
        guard wire.v == version else { throw LinkError.unsupportedVersion(wire.v) }

        switch wire.type {
        case "text":
            guard let data = wire.data else {
                throw LinkError.malformed("missing data field")
            }
            return .text(try Base64URL.decode(data))
        case "file":
            guard let files = wire.files else {
                throw LinkError.malformed("missing files field")
            }
            return .files(
                try files.map {
                    SharedFile(name: $0.name, mime: $0.mime, data: try Base64URL.decode($0.data))
                }
            )
        default:
            throw LinkError.malformed("unknown type \"\(wire.type)\"")
        }
    }
}
