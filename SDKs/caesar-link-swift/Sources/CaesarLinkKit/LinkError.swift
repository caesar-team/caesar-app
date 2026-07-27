import Foundation

public enum LinkError: Error, Equatable {
    /// Structurally invalid input (bad base64url, missing envelope field, hostile KDF params…).
    case malformed(String)
    /// Envelope version we do not speak. The Swift kit implements v2.
    case unsupportedVersion(Int)
    /// AES-GCM authentication failed: wrong key, or the ciphertext was tampered with.
    case decryptionFailed
    /// A `p.` share was opened without a password.
    case passwordRequired
    /// The password did not unwrap the data key.
    case wrongPassword
    /// A `p.` share was opened without the server-side KDF metadata.
    case missingKdf
    /// Fragment mode we do not recognise.
    case unsupportedFragmentMode(String)
    /// Non-2xx from the Link server.
    case server(status: Int, body: String)
}

extension LinkError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .malformed(let what): "Malformed Link data: \(what)"
        case .unsupportedVersion(let v): "Unsupported envelope version: \(v) (this kit speaks v\(Envelope.version))"
        case .decryptionFailed: "Decryption failed — wrong key or tampered ciphertext"
        case .passwordRequired: "This link is password-protected"
        case .wrongPassword: "Wrong password"
        case .missingKdf: "Password-protected share is missing its KDF metadata"
        case .unsupportedFragmentMode(let mode): "Unsupported fragment mode: \(mode)"
        case .server(let status, let body): "Link server returned \(status): \(body)"
        }
    }
}
