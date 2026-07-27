import Foundation

/// scrypt parameters for a password-protected share. Stored server-side and handed to the
/// recipient alongside the ciphertext.
public struct KdfMeta: Codable, Equatable, Sendable {
    public let kdf: String
    /// base64url, 16 bytes.
    public let salt: String
    public let n: Int
    public let r: Int
    public let p: Int
    public let dkLen: Int

    private enum CodingKeys: String, CodingKey {
        case kdf, salt
        case n = "N"
        case r, p, dkLen
    }

    public init(kdf: String = "scrypt", salt: String, n: Int, r: Int, p: Int, dkLen: Int = 32) {
        self.kdf = kdf
        self.salt = salt
        self.n = n
        self.r = r
        self.p = p
        self.dkLen = dkLen
    }

    /// Absolute ceiling on the cost parameter N (must also be a power of two).
    static let maxN = 1 << 20
    /// Ceiling on scrypt's working set, ≈ 128 · N · r bytes.
    ///
    /// The server is untrusted in this model: a crafted KdfMeta could pick individually
    /// in-range but hostile factors (N=2²⁰ with r=32 ≈ 4 GiB) and exhaust memory before any
    /// decryption happens. Bounding the *product* caps it at 1 GiB while leaving the honest
    /// default (N=2¹⁷, r=8 ≈ 128 MiB) plenty of room. Mirrors the TypeScript SDK exactly.
    static let maxMemoryBytes = 1 << 30

    /// Fails fast on hostile or unsupported parameters rather than trying to derive.
    func validate() throws {
        guard kdf == "scrypt" else { throw LinkError.malformed("unsupported KDF: \(kdf)") }
        guard dkLen == Fragment.dekLength else {
            throw LinkError.malformed("unsupported scrypt dkLen: \(dkLen)")
        }
        guard n >= 2, n <= Self.maxN, (n & (n - 1)) == 0 else {
            throw LinkError.malformed("scrypt N out of bounds: \(n)")
        }
        guard r >= 1, r <= 32 else { throw LinkError.malformed("scrypt r out of bounds: \(r)") }
        guard p >= 1, p <= 16 else { throw LinkError.malformed("scrypt p out of bounds: \(p)") }
        guard 128 * n * r <= Self.maxMemoryBytes else {
            throw LinkError.malformed("scrypt cost too high: N=\(n) r=\(r)")
        }
    }
}
