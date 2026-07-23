import Foundation

public struct CreatedShare: Sendable {
    public let id: String
    /// Lets the creator revoke the share before it expires.
    public let deleteToken: String
    /// The full share URL, key included in the fragment. This is the only copy of the key.
    public let url: String
}

/// Talks to a Link server (`/api/shares`). All encryption happens before anything is sent:
/// the server only ever receives ciphertext plus the public IV.
public struct LinkClient {
    public let baseURL: URL
    private let session: URLSession

    public init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
    }

    /// Seals `payload` locally, uploads the ciphertext and returns the shareable URL.
    ///
    /// - Parameters:
    ///   - ttlSeconds: lifetime; the server clamps it to its configured maximum.
    ///   - views: how many times it may be opened. `nil` means unlimited; `1` self-destructs.
    ///   - password: when set, the key is wrapped under a scrypt-derived KEK and the link
    ///     alone cannot open the secret — deliver the password over a separate channel.
    public func createShare(
        _ payload: SharePayload,
        ttlSeconds: Int,
        views: Int? = 1,
        password: String? = nil
    ) async throws -> CreatedShare {
        let bundle = try Share.create(payload, password: password)

        struct MetaBody: Encodable {
            let iv: String
            let kdf: KdfMeta?
        }
        let metaData = try JSONEncoder().encode(
            MetaBody(iv: Base64URL.encode(bundle.blob.iv), kdf: bundle.kdf)
        )
        let meta = String(decoding: metaData, as: UTF8.self)

        var fields: [(name: String, value: String)] = [
            ("meta", meta),
            ("ttl", String(ttlSeconds)),
        ]
        // An empty `views` means unlimited, matching the server's parser.
        fields.append(("views", views.map(String.init) ?? ""))

        let boundary = "caesar-\(UUID().uuidString)"
        let body = Self.multipartBody(
            boundary: boundary,
            fields: fields,
            file: (name: "blob", filename: "blob.bin", data: bundle.blob.ciphertext)
        )

        var request = URLRequest(url: baseURL.appendingPathComponent("api/shares"))
        request.httpMethod = "POST"
        request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        request.httpBody = body

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw LinkError.server(status: -1, body: "no HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            throw LinkError.server(status: http.statusCode, body: String(decoding: data, as: UTF8.self))
        }

        struct CreateResponse: Decodable {
            let id: String
            let deleteToken: String
        }
        let decoded: CreateResponse
        do {
            decoded = try JSONDecoder().decode(CreateResponse.self, from: data)
        } catch {
            throw LinkError.malformed("unexpected create response")
        }

        return CreatedShare(
            id: decoded.id,
            deleteToken: decoded.deleteToken,
            url: ShareURL.build(
                baseURL: baseURL.absoluteString,
                id: decoded.id,
                fragment: bundle.fragment
            )
        )
    }

    /// Fetches and decrypts a share. **Consumes a view** — the server decrements on blob read.
    public func openShare(url: String, password: String? = nil) async throws -> SharePayload {
        let (id, fragment) = try ShareURL.parse(url)

        struct MetaResponse: Decodable {
            struct Meta: Decodable {
                let iv: String
                let kdf: KdfMeta?
            }
            let meta: Meta
        }
        let metaData = try await get("api/shares/\(id)")
        let meta: MetaResponse
        do {
            meta = try JSONDecoder().decode(MetaResponse.self, from: metaData)
        } catch {
            throw LinkError.malformed("unexpected meta response")
        }

        let ciphertext = try await get("api/shares/\(id)/blob")
        let blob = SealedBlob(ciphertext: ciphertext, iv: try Base64URL.decode(meta.meta.iv))
        return try Share.open(
            blob: blob,
            fragment: fragment,
            password: password,
            kdf: meta.meta.kdf
        )
    }

    private func get(_ path: String) async throws -> Data {
        let (data, response) = try await session.data(from: baseURL.appendingPathComponent(path))
        guard let http = response as? HTTPURLResponse else {
            throw LinkError.server(status: -1, body: "no HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            throw LinkError.server(status: http.statusCode, body: String(decoding: data, as: UTF8.self))
        }
        return data
    }

    private static func multipartBody(
        boundary: String,
        fields: [(name: String, value: String)],
        file: (name: String, filename: String, data: Data)
    ) -> Data {
        var body = Data()
        func append(_ string: String) { body.append(Data(string.utf8)) }

        for field in fields {
            append("--\(boundary)\r\n")
            append("Content-Disposition: form-data; name=\"\(field.name)\"\r\n\r\n")
            append("\(field.value)\r\n")
        }

        append("--\(boundary)\r\n")
        append(
            "Content-Disposition: form-data; name=\"\(file.name)\"; filename=\"\(file.filename)\"\r\n"
        )
        append("Content-Type: application/octet-stream\r\n\r\n")
        body.append(file.data)
        append("\r\n--\(boundary)--\r\n")
        return body
    }
}
