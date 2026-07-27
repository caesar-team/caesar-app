/// Ворота CI №1 для Swift: расхождение с Rust ломает билд.
///
/// Раннер намеренно читает тот же `protocol/vectors.json`, что и раннеры на Rust
/// и TypeScript. Отдельного набора ожиданий для Swift не существует — в этом
/// весь смысл: файл ожиданий, написанный под реализацию, подтверждает только
/// сам себя.
///
/// Половина случаев — отрицательные, и каждый проверяет не «отказано», а
/// «отказано именно этим вариантом ошибки». Имя варианта приезжает типизированным
/// (`ErrorCode`) и разворачивается в строку через `errorCodeName` — сравнивать
/// текст сообщения нельзя, он не пинуется файлом.
///
/// # Чего здесь нет и почему
///
/// Раннер на Rust сверяет конверты байт-в-байт через `aead::seal_with_nonce`, а
/// пары X25519 строит из пинованных секретов через `UserKeyPair::from_secret`.
/// Обе двери в UniFFI намеренно не выведены (см.
/// `crates/caesar-core-uniffi/src/lib.rs`), поэтому здесь конверты проверяются в
/// сторону расшифровки: `open()` обязан вернуть ровно тот `paddedPlaintext`,
/// который файл публикует рядом с конвертом. Это ловит другой AAD, другой
/// порядок полей и другую раскладку паддинга — всё, кроме выбора nonce, который
/// в этом направлении задан входом.
import Foundation
import XCTest

@testable import CaesarCore

private let vectors: JSONValue = {
    let url = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()  // CaesarCoreVectorsTests
        .deletingLastPathComponent()  // Tests
        .deletingLastPathComponent()  // swift
        .deletingLastPathComponent()  // корень воркспейса
        .appendingPathComponent("protocol/vectors.json")
    guard let data = try? Data(contentsOf: url),
          let raw = try? JSONSerialization.jsonObject(with: data)
    else {
        // Нечитаемый файл векторов — не «нет тестов», а сломанные ворота.
        fatalError("cannot read \(url.path)")
    }
    return JSONValue(raw)
}()

private let utf8Encoder = { (text: String) in Data(text.utf8) }

/// Отрицательный случай: отказ обязателен, и именно с заявленным вариантом.
///
/// Имя случая едет в обе стороны сравнения — иначе провал показывает только
/// «userKeyMismatch != DecryptionFailed», не говоря, какой случай упал.
private func expectRejected(
    _ entry: JSONValue,
    file: StaticString = #filePath,
    line: UInt = #line,
    _ run: () throws -> Any
) throws {
    let name = try entry.text("name")
    let expected = try entry.text("error")
    do {
        _ = try run()
        XCTFail("case \(name) was accepted", file: file, line: line)
    } catch let CoreError.Failed(code, _) {
        XCTAssertEqual(
            "\(name): \(errorCodeName(code: code))",
            "\(name): \(expected)",
            file: file, line: line
        )
    }
}

// ── Константы ───────────────────────────────────────────────────────────────

final class ConstantsTests: XCTestCase {
    func testEveryPinnedConstantMatches() throws {
        let declared = try vectors.section("constants")
        // `Mirror`, а не перечисление полей руками: константа, добавленная в
        // запись и забытая здесь, иначе не проверялась бы никем.
        let mirror = Mirror(reflecting: constants())
        var checked = 0

        for child in mirror.children {
            guard let key = child.label else { continue }
            let expected = try declared.child(key).described
            XCTAssertEqual("\(key)=\(child.value)", "\(key)=\(expected)")
            checked += 1
        }
        XCTAssertEqual(checked, 25)

        // Пустая соль — не «поле забыли»: HKDF для auth и wrap зовётся без соли.
        XCTAssertEqual(try declared.text("hkdfSaltAuth"), "")
        XCTAssertEqual(try declared.text("hkdfSaltWrap"), "")
    }

    func testEnvelopeLayoutMatches() throws {
        let layout = try vectors.section("envelope", "layout")
        let header = envelopeHeader()
        let c = constants()

        XCTAssertEqual(hex(header), try layout.text("header"))
        XCTAssertEqual(try layout.num("headerOffset"), 0)
        XCTAssertEqual(try layout.num("nonceOffset"), Int(c.headerLen))
        XCTAssertEqual(
            try layout.num("ciphertextOffset"),
            Int(c.headerLen) + Int(c.nonceLen)
        )

        // AAD — нормативное поле: реализация, передавшая в AEAD пустой AAD,
        // получит другой тег при всём остальном верном, и разойдётся с
        // векторами только здесь.
        XCTAssertEqual(try layout.text("aad"), hex(header))
        XCTAssertTrue(try layout.flag("aadIsHeader"))
    }
}

// ── KDF ─────────────────────────────────────────────────────────────────────

final class KdfTests: XCTestCase {
    func testKnownAnswerMatches() throws {
        let entry = try vectors.section("kdf", "knownAnswer")
        let master = try deriveMasterKey(
            password: entry.text("password"),
            encodedParams: entry.bytes("encodedParams")
        )

        XCTAssertEqual(hex(master), try entry.text("masterKey"))
        XCTAssertEqual(hex(try authKey(masterKey: master)), try entry.text("authKey"))
        XCTAssertEqual(
            hex(try keyEncryptionKey(masterKey: master)),
            try entry.text("keyEncryptionKey")
        )
    }

    func testParameterEncodingRoundTripsAndIsUsed() throws {
        var derived = 0

        for entry in try vectors.cases("kdf", "paramsEncoding") {
            let name = try entry.text("name")
            let encoded = try entry.bytes("encoded")
            let params = try decodeKdfParams(encoded: encoded)

            XCTAssertEqual("\(name).mCost=\(params.mCost)", "\(name).mCost=\(try entry.num("mCost"))")
            XCTAssertEqual(Int(params.tCost), try entry.num("tCost"))
            XCTAssertEqual(Int(params.pCost), try entry.num("pCost"))
            XCTAssertEqual(hex(params.salt), try entry.text("salt"))
            XCTAssertEqual(hex(params.reencoded), hex(encoded))

            // Разбор и переупаковка ничего не говорят о том, что клиент на этих
            // параметрах СЧИТАЕТ: реализация, зашившая свои умолчания и
            // игнорирующая присланные сервером параметры, проходит всё выше
            // целиком.
            //
            // `deriveSafe: false` — не «пропустить случай», а запрет: `atCeiling`
            // просит у Argon2id 4 ГиБ. Отсутствие флага — ошибка (её бросает
            // `flag`), а не «не надо».
            if try entry.flag("deriveSafe") {
                let master = try deriveMasterKey(
                    password: entry.text("password"), encodedParams: encoded
                )
                XCTAssertEqual("\(name): \(hex(master))", "\(name): \(try entry.text("masterKey"))")
                derived += 1
            } else {
                XCTAssertEqual(
                    "\(name) pins a master key: \(entry.has("masterKey"))",
                    "\(name) pins a master key: false"
                )
            }
        }
        // Один набор параметров — то же самое, что ни одного: он неотличим от
        // зашитых умолчаний.
        XCTAssertGreaterThan(derived, 1)
    }

    func testPasswordIsNormalizedToNfc() throws {
        // Без нормализации «é», набранное как U+0065 U+0301, даёт другой
        // мастер-ключ, чем «é» как U+00E9: хранилище, созданное в Swift, не
        // открывается в браузере, а тесты каждой платформы зелёные.
        let entry = try vectors.section("kdf", "passwordNormalization")
        let params = try entry.bytes("encodedParams")
        XCTAssertEqual(try entry.text("intendedForm"), "NFC")

        for (form, utf8Field) in [
            ("passwordNfc", "passwordNfcUtf8"), ("passwordNfd", "passwordNfdUtf8"),
        ] {
            // Сначала — что в файле лежит именно то, что заявлено: редактор или
            // git-фильтр, нормализовавший файл сам, обесценил бы весь случай.
            let password = try entry.text(form)
            XCTAssertEqual(
                "\(form): \(hex(utf8Encoder(password)))",
                "\(form): \(try entry.text(utf8Field))"
            )

            let master = try deriveMasterKey(password: password, encodedParams: params)
            XCTAssertEqual("\(form): \(hex(master))", "\(form): \(try entry.text("masterKey"))")
        }

        XCTAssertNotEqual(
            try entry.text("passwordNfcUtf8"), try entry.text("passwordNfdUtf8")
        )
    }

    func testOutOfRangeAndMalformedParametersAreRejected() throws {
        for entry in try vectors.cases("kdf", "invalid") {
            try expectRejected(entry) { try decodeKdfParams(encoded: entry.bytes("encoded")) }
        }
    }
}

// ── Конверты ────────────────────────────────────────────────────────────────

final class EnvelopeTests: XCTestCase {
    func testEveryValidEnvelopeOpensToItsPinnedPlaintext() throws {
        let header = envelopeHeader()
        let c = constants()
        let nonceEnd = Int(c.headerLen) + Int(c.nonceLen)

        for entry in try vectors.cases("envelope", "valid") {
            let name = try entry.text("name")
            let envelope = try entry.bytes("envelope")

            XCTAssertEqual(
                "\(name).length=\(envelope.count)",
                "\(name).length=\(try entry.num("envelopeLength"))"
            )
            XCTAssertEqual(hex(envelope.prefix(Int(c.headerLen))), hex(header))
            XCTAssertEqual(
                hex(envelope[Int(c.headerLen)..<nonceEnd]), try entry.text("nonce")
            )

            let plaintext = try open(key: entry.bytes("key"), envelope: envelope)
            XCTAssertEqual("\(name): \(hex(plaintext))", "\(name): \(try entry.text("plaintext"))")
        }
    }

    func testEveryInvalidEnvelopeIsRejectedWithItsPinnedError() throws {
        for entry in try vectors.cases("envelope", "invalid") {
            try expectRejected(entry) {
                try open(key: entry.bytes("key"), envelope: entry.bytes("envelope"))
            }
        }
    }

    func testAnEnvelopeSealedInSwiftOpensInSwift() throws {
        let key = try vectors.cases("envelope", "valid")[0].bytes("key")
        let plaintext = utf8Encoder("round trip — Ж 🔐")
        let sealed = try seal(key: key, plaintext: plaintext)

        XCTAssertEqual(hex(try open(key: key, envelope: sealed)), hex(plaintext))
        // Nonce берётся из CSPRNG: два запечатывания одного и того же не совпадают.
        XCTAssertNotEqual(hex(try seal(key: key, plaintext: plaintext)), hex(sealed))
    }
}

// ── Обёртывание ключей ──────────────────────────────────────────────────────

final class KeyWrappingTests: XCTestCase {
    func testWrappedUserKeyUnwrapsAndVerifies() throws {
        let kek = try vectors.section("keyWrapping").bytes("keyEncryptionKey")
        let entry = try vectors.section("keyWrapping", "userKey")

        let pair = try unwrapUserKeyVerified(
            kek: kek, wrapped: entry.bytes("wrapped"), expectedPublic: entry.bytes("public")
        )
        XCTAssertEqual(hex(pair.publicBytes()), try entry.text("public"))

        // Приватная половина через границу не выведена, но обёртка — обычный
        // конверт над ней, и в этом направлении её видно. Проверка не
        // декоративная: реализация, завернувшая ключ с другим AAD или в другом
        // порядке полей, расходится именно здесь.
        XCTAssertEqual(
            hex(try open(key: kek, envelope: entry.bytes("wrapped"))),
            try entry.text("secret")
        )
    }

    func testWrappedVaultKeyUnwrapsToItsPinnedPlaintext() throws {
        let kek = try vectors.section("keyWrapping").bytes("keyEncryptionKey")
        let entry = try vectors.section("keyWrapping", "vaultKey")

        XCTAssertEqual(
            hex(try unwrapVaultKey(kek: kek, wrapped: entry.bytes("wrapped"))),
            try entry.text("plaintext")
        )
        XCTAssertEqual(
            hex(try open(key: kek, envelope: entry.bytes("wrapped"))),
            try entry.text("plaintext")
        )
    }

    func testInvalidWrappingsAreRejected() throws {
        // `rolledBackUserKey` — единственный случай во всём файле, который тег
        // Poly1305 пропускает: запись честная, просто устаревшая.
        for entry in try vectors.cases("keyWrapping", "invalid") {
            try expectRejected(entry) {
                let kek = try entry.bytes("keyEncryptionKey")
                let wrapped = try entry.bytes("wrapped")
                return entry.has("expectedPublic")
                    ? try unwrapUserKeyVerified(
                        kek: kek, wrapped: wrapped, expectedPublic: entry.bytes("expectedPublic"))
                    : try unwrapVaultKey(kek: kek, wrapped: wrapped)
            }
        }
    }

    func testFreshlyGeneratedPairWrapsAndUnwraps() throws {
        let kek = try vectors.section("keyWrapping").bytes("keyEncryptionKey")
        let pair = try UserKeyPair.generate()
        let restored = try unwrapUserKeyVerified(
            kek: kek,
            wrapped: try wrapUserKey(kek: kek, userKey: pair),
            expectedPublic: pair.publicBytes()
        )
        XCTAssertEqual(hex(restored.publicBytes()), hex(pair.publicBytes()))
    }
}

// ── Разделение хранилища через X25519 ───────────────────────────────────────

/// Единственный способ добраться до пинованного получателя без `from_secret`.
///
/// Секрет `x25519.sealVaultKeyFor.recipientSecret` — тот же самый, что лежит
/// завёрнутым в `keyWrapping.userKey`, поэтому пару можно РАЗВЕРНУТЬ вместо
/// того, чтобы строить из голых байт. Совпадение секретов проверяется явно: если
/// генератор векторов их когда-нибудь разведёт, тесты ниже обязаны упасть, а не
/// начать молча проверять другую пару.
private func bridgedRecipient() throws -> (pair: UserKeyPair, secret: String) {
    let kek = try vectors.section("keyWrapping").bytes("keyEncryptionKey")
    let entry = try vectors.section("keyWrapping", "userKey")
    return (
        try unwrapUserKeyVerified(
            kek: kek, wrapped: entry.bytes("wrapped"), expectedPublic: entry.bytes("public")
        ),
        try entry.text("secret")
    )
}

final class X25519Tests: XCTestCase {
    func testBridgedRecipientIsTheOneTheVectorsPin() throws {
        let (pair, secret) = try bridgedRecipient()
        let entry = try vectors.section("x25519", "sealVaultKeyFor")
        XCTAssertEqual(secret, try entry.text("recipientSecret"))
        XCTAssertEqual(hex(pair.publicBytes()), try entry.text("recipientPublic"))
    }

    func testPublicHalvesMatchWhereTheSecretIsReachable() throws {
        let (pair, secret) = try bridgedRecipient()
        var unreachable: [String] = []

        for entry in try vectors.cases("x25519", "keyPairs") {
            guard try entry.text("secret") == secret else {
                unreachable.append(try entry.text("name"))
                continue
            }
            XCTAssertEqual(hex(pair.publicBytes()), try entry.text("public"))
        }
        // Остальные пары строятся из голых пинованных секретов, то есть требуют
        // `UserKeyPair::from_secret` — двери, которой в UniFFI намеренно нет. Их
        // держит раннер на Rust; здесь пропуск учтён явно, чтобы он не расползся.
        XCTAssertEqual(unreachable, ["rfc7748Alice"])
    }

    func testPinnedSharedRecordOpensToItsVaultKey() throws {
        let (pair, _) = try bridgedRecipient()
        let entry = try vectors.section("x25519", "sealVaultKeyFor")
        let sealed = try entry.bytes("sealed")
        let ephemeralLen = try entry.num("ephemeralPublicLen")

        XCTAssertEqual(hex(sealed.prefix(ephemeralLen)), try entry.text("ephemeralPublic"))
        XCTAssertEqual(
            hex(try openVaultKeyFor(recipient: pair, sealed: sealed)),
            try entry.text("vaultKey")
        )
    }

    func testDegenerateRecipientKeysAreRejected() throws {
        let vaultKey = Data(repeating: 0x07, count: 32)
        for entry in try vectors.cases("x25519", "invalidRecipients") {
            try expectRejected(entry) {
                try sealVaultKeyFor(
                    recipientPublic: entry.bytes("recipientPublic"), vaultKey: vaultKey
                )
            }
        }
    }

    func testInvalidSharedRecordsAreRejected() throws {
        let (pair, secret) = try bridgedRecipient()
        var unreachable: [String] = []
        var checked = 0

        for entry in try vectors.cases("x25519", "invalidSealed") {
            guard try entry.text("recipientSecret") == secret else {
                unreachable.append(try entry.text("name"))
                continue
            }
            try expectRejected(entry) {
                try openVaultKeyFor(recipient: pair, sealed: entry.bytes("sealed"))
            }
            checked += 1
        }
        // `wrongRecipient` пинует ЧУЖОЙ секрет получателя: подставить вместо
        // него свежесгенерированную пару — значит проверить другое утверждение.
        XCTAssertEqual(unreachable, ["wrongRecipient"])
        XCTAssertEqual(checked, 2)
    }

    func testARecordSealedInSwiftOpensForItsRecipient() throws {
        let recipient = try UserKeyPair.generate()
        let vaultKey = Data(repeating: 0x2a, count: 32)
        let sealed = try sealVaultKeyFor(
            recipientPublic: recipient.publicBytes(), vaultKey: vaultKey
        )
        XCTAssertEqual(
            hex(try openVaultKeyFor(recipient: recipient, sealed: sealed)), hex(vaultKey)
        )
    }
}

// ── Emergency Kit ───────────────────────────────────────────────────────────

final class EmergencyKitTests: XCTestCase {
    func testDeclaredLayoutIsTheOneTheEncoderProduces() throws {
        let layout = try vectors.section("emergencyKit", "layout")
        let alphabet = try layout.text("alphabet")
        let symbols = try layout.num("symbols")
        let groups = try layout.num("groups")
        let groupSize = try layout.num("groupSize")

        XCTAssertEqual(alphabet.count, 32)
        for excluded in ["I", "L", "O", "U"] {
            XCTAssertEqual(
                "\(excluded) in alphabet: \(alphabet.contains(excluded))",
                "\(excluded) in alphabet: false"
            )
        }
        XCTAssertEqual(groups * groupSize, symbols)

        let printed = try formatEmergencyKit(recoveryKey: Data(repeating: 0x5a, count: 32))
        let body = printed.filter { $0 != "-" }
        XCTAssertEqual(body.count, symbols)
        XCTAssertEqual(printed.count, symbols + groups - 1)
        for symbol in body {
            XCTAssertEqual(
                "\(symbol) in alphabet: \(alphabet.contains(symbol))",
                "\(symbol) in alphabet: true"
            )
        }

        // Подстановки: заявлено «I и L читаются как 1, O как 0» — значит, набор,
        // где каждая цифра заменена на свою букву, обязан разобраться в тот же ключ.
        let expected = hex(try parseEmergencyKit(input: printed))
        let substitutions = try layout.section("substitutions")
        XCTAssertFalse(substitutions.keys.isEmpty)
        for letter in substitutions.keys {
            let digit = try substitutions.text(letter)
            let substituted = printed.replacingOccurrences(of: digit, with: letter)
            let parsed = hex(try parseEmergencyKit(input: substituted))
            XCTAssertEqual("\(letter)->\(digit): \(parsed)", "\(letter)->\(digit): \(expected)")
        }
    }

    func testFormattingMatchesTheVectors() throws {
        for entry in try vectors.cases("emergencyKit", "formatted") {
            let name = try entry.text("name")
            let printed = try formatEmergencyKit(recoveryKey: entry.bytes("key"))
            XCTAssertEqual("\(name): \(printed)", "\(name): \(try entry.text("formatted"))")
            XCTAssertEqual(printed.count, try entry.num("printedLength"))
        }
    }

    func testHumanInputFromTheVectorsIsAccepted() throws {
        // Подстановка Крокфорда, нижний регистр и разделители — не украшения:
        // реализация, написанная по одному алфавиту, отвергнет ровно эти входы,
        // а человек с верной распечаткой в руках останется без хранилища.
        for entry in try vectors.cases("emergencyKit", "accepted") {
            let name = try entry.text("name")
            let parsed = try parseEmergencyKit(input: entry.text("input"))
            XCTAssertEqual("\(name): \(hex(parsed))", "\(name): \(try entry.text("key"))")
        }
    }

    func testInvalidInputIsRejectedWithItsPinnedError() throws {
        for entry in try vectors.cases("emergencyKit", "rejected") {
            try expectRejected(entry) { try parseEmergencyKit(input: entry.text("input")) }
        }
    }
}

// ── Айтемы ──────────────────────────────────────────────────────────────────

final class ItemTests: XCTestCase {
    private func vaultKey() throws -> Data {
        try vectors.section("item").bytes("vaultKey")
    }

    func testEveryValidItemOpensToItsPinnedJsonAndPadding() throws {
        let key = try vaultKey()
        let lenPrefixLen = try vectors.section("item", "padding").num("lenPrefixLen")

        for entry in try vectors.cases("item", "valid") {
            let name = try entry.text("name")
            let envelope = try entry.bytes("envelope")

            XCTAssertEqual(
                "\(name): \(try openItem(envelope: envelope, vaultKey: key))",
                "\(name): \(try entry.text("plaintextJson"))"
            )

            // Раскладка паддинга: `declaredLength(u32 LE) || json || zeros`.
            // `open()` отдаёт ровно то, что лежит под тегом, — на этом держится
            // вся проверка формата, которую иначе делал бы `seal_with_nonce`.
            let padded = try open(key: key, envelope: envelope)
            XCTAssertEqual(hex(padded), try entry.text("paddedPlaintext"))
            XCTAssertEqual(padded.count, try entry.num("paddedLength"))
            XCTAssertEqual(envelope.count, try entry.num("envelopeLength"))

            let declared = padded.prefix(lenPrefixLen).reversed().reduce(0) { $0 << 8 | Int($1) }
            XCTAssertEqual(declared, try entry.num("jsonLength"))
            XCTAssertEqual(
                hex(padded[lenPrefixLen..<(lenPrefixLen + declared)]),
                hex(utf8Encoder(try entry.text("plaintextJson")))
            )
            for tail in padded[(lenPrefixLen + declared)...] {
                XCTAssertEqual("\(name) padding tail: \(tail)", "\(name) padding tail: 0")
            }
        }
    }

    func testPaddingBucketsMatchTheVectors() throws {
        let key = try vaultKey()

        for entry in try vectors.cases("item", "bucketBoundaries") {
            let name = try entry.text("name")
            XCTAssertEqual(try entry.text("kind"), "secureNote")

            // Форма — та же, что у `ItemSecret::new(SecureNote, title)`: только
            // `v`, `kind` и `title`, остальные поля пропускаются при
            // сериализации. Строка собирается вручную, а не через
            // `JSONSerialization`: последний не обещает порядок ключей, а длина
            // пинуется файлом.
            let filler = String(repeating: "x", count: try entry.num("titleFiller"))
            let json = "{\"v\":1,\"kind\":\"secureNote\",\"title\":\"\(filler)\"}"
            XCTAssertEqual(
                "\(name) json: \(utf8Encoder(json).count)",
                "\(name) json: \(try entry.num("jsonLength"))"
            )
            let envelope = try sealItem(itemJson: json, vaultKey: key)
            XCTAssertEqual(
                "\(name) envelope: \(envelope.count)",
                "\(name) envelope: \(try entry.num("envelopeLength"))"
            )
        }
    }

    func testEveryInvalidItemIsRejectedWithItsPinnedError() throws {
        let key = try vaultKey()

        for entry in try vectors.cases("item", "invalid") {
            let name = try entry.text("name")
            // Отрицательный случай публикует и `paddedPlaintext`: непроверенный,
            // он разъезжается с конвертом молча, и файл начинает объяснять не тот
            // отказ, который проверяет. Сами конверты здесь валидны — ломается
            // разбор после расшифровки.
            let padded = try open(key: key, envelope: entry.bytes("envelope"))
            XCTAssertEqual("\(name): \(hex(padded))", "\(name): \(try entry.text("paddedPlaintext"))")
            try expectRejected(entry) {
                try openItem(envelope: entry.bytes("envelope"), vaultKey: key)
            }
        }
    }

    func testAnItemSealedInSwiftOpensInSwift() throws {
        let key = try vaultKey()
        let json = try vectors.cases("item", "valid")[0].text("plaintextJson")
        XCTAssertEqual(
            try openItem(envelope: try sealItem(itemJson: json, vaultKey: key), vaultKey: key),
            json
        )
    }
}
