import CryptoKit
import Foundation

/// A sealed share, ready to upload. `blob` goes to the server; `fragment` must not.
/// `kdf` is non-nil only for password-protected shares and *must* be stored server-side —
/// the recipient cannot derive the key without it.
public struct ShareBundle: Sendable {
    public let blob: SealedBlob
    public let fragment: String
    public let kdf: KdfMeta?
}

public enum Share {
    /// Generates a fresh 256-bit data key and seals the payload under it.
    ///
    /// Without a password the key is handed back inline as a `k.` fragment — whoever has the
    /// link can read the secret. With a password the key is wrapped under a scrypt-derived
    /// KEK (`p.` fragment), so the link alone is useless; send the password separately.
    public static func create(_ payload: SharePayload, password: String? = nil) throws -> ShareBundle {
        let dek = SymmetricKey(size: .bits256)
        let blob = try Envelope.seal(payload, dek: dek)
        guard let password else {
            return ShareBundle(blob: blob, fragment: Fragment.encodeKey(dek), kdf: nil)
        }
        let (fragment, kdf) = try Fragment.encodePassword(dek, password: password)
        return ShareBundle(blob: blob, fragment: fragment, kdf: kdf)
    }

    public static func open(
        blob: SealedBlob,
        fragment: String,
        password: String? = nil,
        kdf: KdfMeta? = nil
    ) throws -> SharePayload {
        let dek: SymmetricKey
        switch try Fragment.decode(fragment) {
        case .key(let key):
            dek = key
        case .passwordWrapped(let wrapped):
            guard let password else { throw LinkError.passwordRequired }
            guard let kdf else { throw LinkError.missingKdf }
            dek = try Fragment.unwrapPassword(wrapped, password: password, kdf: kdf)
        }
        return try Envelope.open(blob, dek: dek)
    }
}

/// `<baseURL>/s/<id>#<fragment>`
public enum ShareURL {
    public static func build(baseURL: String, id: String, fragment: String) -> String {
        let base = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL
        return "\(base)/s/\(id)#\(fragment)"
    }

    public static func parse(_ url: String) throws -> (id: String, fragment: String) {
        guard let parsed = URLComponents(string: url) else {
            throw LinkError.malformed("not a URL: \(url)")
        }
        guard let fragment = parsed.fragment, !fragment.isEmpty else {
            throw LinkError.malformed("share URL has no fragment")
        }
        let segments = parsed.path.split(separator: "/").map(String.init)
        guard let sIndex = segments.firstIndex(of: "s"), sIndex + 1 < segments.count else {
            throw LinkError.malformed("share URL has no /s/<id> path")
        }
        return (segments[sIndex + 1], fragment)
    }
}
