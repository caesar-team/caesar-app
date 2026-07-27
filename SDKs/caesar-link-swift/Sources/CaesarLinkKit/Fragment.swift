import CryptoKit
import Foundation

/// The URL `#fragment` — the zero-knowledge half of a share. Browsers never send it to a
/// server, which is exactly why the key lives there.
///
/// - `k.<base64url(dek)>` — the raw 32-byte data key.
/// - `p.<base64url(iv ‖ wrappedDek)>` — the key sealed under a scrypt-derived KEK; the
///   password travels out of band and the KDF parameters come from the share's metadata.
public enum Fragment {
    public static let dekLength = 32
    static let saltLength = 16
    static let ivLength = 12
    static let gcmTagLength = 16
    static let wrappedDekLength = dekLength + gcmTagLength

    public static let defaultN = 1 << 17
    public static let defaultR = 8
    public static let defaultP = 1

    public enum Decoded {
        case key(SymmetricKey)
        /// `iv ‖ ciphertext(dek)`, still sealed — needs the password and the KDF metadata.
        case passwordWrapped(Data)
    }

    public static func encodeKey(_ dek: SymmetricKey) -> String {
        let raw = dek.withUnsafeBytes { Data($0) }
        return "k.\(Base64URL.encode(raw))"
    }

    public static func decode(_ fragment: String) throws -> Decoded {
        guard let dot = fragment.firstIndex(of: ".") else {
            throw LinkError.malformed("fragment is missing its mode prefix")
        }
        let mode = String(fragment[fragment.startIndex..<dot])
        let body = try Base64URL.decode(String(fragment[fragment.index(after: dot)...]))

        switch mode {
        case "k":
            guard body.count == dekLength else {
                throw LinkError.malformed("data key must be \(dekLength) bytes, got \(body.count)")
            }
            return .key(SymmetricKey(data: body))
        case "p":
            guard body.count == ivLength + wrappedDekLength else {
                throw LinkError.malformed("wrapped key must be \(ivLength + wrappedDekLength) bytes")
            }
            return .passwordWrapped(body)
        default:
            throw LinkError.unsupportedFragmentMode(mode)
        }
    }

    /// Convenience for link-only shares. Throws on `p.` fragments, which need a password.
    public static func decodeKey(_ fragment: String) throws -> SymmetricKey {
        guard case .key(let dek) = try decode(fragment) else {
            throw LinkError.passwordRequired
        }
        return dek
    }

    static func deriveKek(password: String, kdf: KdfMeta) throws -> SymmetricKey {
        try kdf.validate()
        let salt = try Base64URL.decode(kdf.salt)
        let raw = try Scrypt.derive(
            password: password,
            salt: salt,
            n: UInt64(kdf.n),
            r: UInt32(kdf.r),
            p: UInt32(kdf.p),
            length: kdf.dkLen
        )
        return SymmetricKey(data: raw)
    }

    /// Seals `dek` under a fresh scrypt-derived KEK, returning the `p.` fragment plus the
    /// KDF metadata the server must store for the recipient.
    public static func encodePassword(
        _ dek: SymmetricKey,
        password: String,
        n: Int = defaultN,
        r: Int = defaultR,
        p: Int = defaultP
    ) throws -> (fragment: String, kdf: KdfMeta) {
        var salt = Data(count: saltLength)
        salt.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            _ = SecRandomCopyBytes(kSecRandomDefault, saltLength, base)
        }
        let kdf = KdfMeta(salt: Base64URL.encode(salt), n: n, r: r, p: p, dkLen: dekLength)
        let kek = try deriveKek(password: password, kdf: kdf)

        var iv = Data(count: ivLength)
        iv.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return }
            _ = SecRandomCopyBytes(kSecRandomDefault, ivLength, base)
        }
        let rawDek = dek.withUnsafeBytes { Data($0) }
        let box = try AES.GCM.seal(rawDek, using: kek, nonce: try AES.GCM.Nonce(data: iv))
        let body = iv + box.ciphertext + box.tag
        return ("p.\(Base64URL.encode(body))", kdf)
    }

    /// Reverses `encodePassword`. Throws `.wrongPassword` when the KEK does not unwrap.
    public static func unwrapPassword(
        _ wrapped: Data,
        password: String,
        kdf: KdfMeta
    ) throws -> SymmetricKey {
        let kek = try deriveKek(password: password, kdf: kdf)
        let iv = Data(wrapped.prefix(ivLength))
        let sealed = Data(wrapped.dropFirst(ivLength))
        let ciphertext = Data(sealed.prefix(sealed.count - gcmTagLength))
        let tag = Data(sealed.suffix(gcmTagLength))
        do {
            let box = try AES.GCM.SealedBox(
                nonce: try AES.GCM.Nonce(data: iv),
                ciphertext: ciphertext,
                tag: tag
            )
            return SymmetricKey(data: try AES.GCM.open(box, using: kek))
        } catch {
            throw LinkError.wrongPassword
        }
    }
}
