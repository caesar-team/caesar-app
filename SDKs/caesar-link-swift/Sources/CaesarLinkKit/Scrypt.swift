import Clibsodium
import Foundation

/// libsodium must be initialised once before use. Idempotent and thread-safe;
/// a Swift `let` gives us the once-only semantics for free.
private let sodiumInitialised: Bool = sodium_init() >= 0

/// scrypt (RFC 7914) via libsodium's low-level entry point, which takes N/r/p explicitly.
/// The high-level `crypto_pwhash_scryptsalsa208sha256` API is *not* usable here: it derives
/// its own cost from opslimit/memlimit, but our parameters are dictated by the share's KDF
/// metadata and must match the TypeScript SDK bit-for-bit.
enum Scrypt {
    static func derive(
        password: String,
        salt: Data,
        n: UInt64,
        r: UInt32,
        p: UInt32,
        length: Int
    ) throws -> Data {
        guard sodiumInitialised else {
            throw LinkError.malformed("libsodium failed to initialise")
        }
        let passwordBytes = Data(password.utf8)
        guard !salt.isEmpty else { throw LinkError.malformed("scrypt salt is empty") }
        guard !passwordBytes.isEmpty else { throw LinkError.malformed("password is empty") }
        guard length > 0 else { throw LinkError.malformed("scrypt dkLen must be positive") }

        var output = Data(count: length)
        let status: Int32 = output.withUnsafeMutableBytes { outRaw -> Int32 in
            guard let out = outRaw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return -1
            }
            return passwordBytes.withUnsafeBytes { pwRaw -> Int32 in
                guard let pw = pwRaw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return -1
                }
                return salt.withUnsafeBytes { saltRaw -> Int32 in
                    guard let st = saltRaw.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                        return -1
                    }
                    return crypto_pwhash_scryptsalsa208sha256_ll(
                        pw, passwordBytes.count,
                        st, salt.count,
                        n, r, p,
                        out, length
                    )
                }
            }
        }
        guard status == 0 else {
            throw LinkError.malformed("scrypt failed for N=\(n) r=\(r) p=\(p)")
        }
        return output
    }
}
