import Foundation

/// base64url (RFC 4648 §5), unpadded — the wire encoding used everywhere in the Link protocol.
public enum Base64URL {
    public static func encode(_ data: Data) -> String {
        var s = data.base64EncodedString()
        s = s.replacingOccurrences(of: "+", with: "-")
        s = s.replacingOccurrences(of: "/", with: "_")
        while s.hasSuffix("=") { s.removeLast() }
        return s
    }

    public static func decode(_ string: String) throws -> Data {
        var s = string.replacingOccurrences(of: "-", with: "+")
        s = s.replacingOccurrences(of: "_", with: "/")
        switch s.count % 4 {
        case 0: break
        case 2: s += "=="
        case 3: s += "="
        default: throw LinkError.malformed("invalid base64url length")
        }
        guard let data = Data(base64Encoded: s) else {
            throw LinkError.malformed("invalid base64url")
        }
        return data
    }
}
