#![forbid(unsafe_code)]

//! Порождает `protocol/vectors.json` из фиксированных входов.
//!
//! Запуск: `cargo run -p caesar-core --bin gen-vectors > protocol/vectors.json`
//!
//! # Детерминированность — требование, а не удобство
//!
//! Ворота CI №1 сравнивают вывод этого бинарника с файлом в репозитории
//! (`gen-vectors | diff -u protocol/vectors.json -`). Любой недетерминизм
//! ломает сборку на каждом коммите, поэтому источники случайности —
//! nonce конверта и эфемерный ключ X25519 — передаются снаружи через
//! `aead::seal_with_nonce` и `vault::seal_vault_key_for_with_randomness`.
//! Оба помечены `#[doc(hidden)]` и запрещены в рабочем коде.
//!
//! # Половина векторов — отрицательные
//!
//! Файл из одних счастливых путей пропускает снисходительную реализацию:
//! она примет всё подряд и пройдёт ворота. Каждый случай в списках `invalid`
//! несёт имя варианта `Error`, который обязана вернуть любая реализация.
//!
//! Отрицательные случаи, которые здесь построены вручную (порченый паддинг,
//! чужая версия конверта, испорченная контрольная сумма), — это заодно
//! независимое изложение формата: генератор пишет их не тем кодом, которым
//! читает раннер, и расхождение видно сразу.

use caesar_core::envelope::{HEADER, HEADER_LEN, MIN_ENVELOPE_LEN, NONCE_LEN, TAG_LEN};
use caesar_core::kdf::{
    auth_key, derive_master_key, key_encryption_key, KdfParams, KDF_ALGO_ARGON2ID, KDF_PARAMS_LEN,
    KDF_VERSION, MAX_M_COST, MAX_P_COST, MAX_T_COST, MIN_M_COST, MIN_P_COST, MIN_T_COST, SALT_LEN,
};
use caesar_core::keys::{RecoveryKey, VaultKey};
use caesar_core::model::{ItemKind, ItemSecret};
use caesar_core::vault::{self, UserKeyPair, EPHEMERAL_PUBLIC_LEN};
use caesar_core::{aead, recovery, Error, ITEM_SCHEMA_VERSION, PROTOCOL_VERSION, SUITE_ID};
use serde_json::{json, Map, Value};

/// Пароль известного ответа. Закреплён в Task 4 тестом `known_answer_vector`.
const PASSWORD: &str = "correct horse battery staple";

/// Известный ответ Argon2id + HKDF. Генератор обязан выдать ровно это.
const KNOWN_MK: &str = "5cea1d57f950121fbc7a6d90279d7612482cf65ea98cacf40dc8c22b92f9461f";
const KNOWN_AK: &str = "0b5632f94cac1cccdbc0d74954cd38603bf83c7f6a5c078d07e2601b016a282c";
const KNOWN_KEK: &str = "404992526283a87b4d58771fb7b71fdd90135a27688fdf632812c750b9a34252";

/// Ключ хранилища всех векторов.
const VAULT_KEY: [u8; 32] = [0x07; 32];

/// Приватный ключ участника, на которого шифруется ключ хранилища.
const RECIPIENT_SECRET: [u8; 32] = [0x03; 32];

/// Эфемерный ключ расшаренной записи. Настоящий берётся из CSPRNG.
const EPHEMERAL_SECRET: [u8; 32] = [0x11; 32];

/// Наименьший бакет паддинга и ширина префикса длины — независимое изложение
/// `model.rs`. Совпадение проверяет раннер: он открывает эти же конверты
/// рабочим кодом.
const MIN_BUCKET: usize = 512;
const LEN_PREFIX_LEN: usize = 4;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Nonce вектора. Каждому сообщению — свой: повторный nonce под одним ключом
/// раскрыл бы оба открытых текста, и файл векторов не должен показывать такой
/// пример даже там, где открытые тексты и так напечатаны рядом.
fn nonce(tag: u8) -> [u8; NONCE_LEN] {
    [tag; NONCE_LEN]
}

fn bucket_for(len: usize) -> usize {
    len.max(MIN_BUCKET).next_power_of_two()
}

/// Строит `len(u32 LE) || json || zeros` — раскладку `pad_item` из `model.rs`,
/// изложенную здесь заново. Нужна и для отрицательных случаев: рабочий путь
/// порченого паддинга не порождает по определению.
fn pad_json(json: &[u8]) -> Vec<u8> {
    let mut padded = vec![0u8; bucket_for(LEN_PREFIX_LEN + json.len())];
    let prefix = u32::try_from(json.len()).expect("vector payloads are far below 4 GiB");
    padded[..LEN_PREFIX_LEN].copy_from_slice(&prefix.to_le_bytes());
    padded[LEN_PREFIX_LEN..LEN_PREFIX_LEN + json.len()].copy_from_slice(json);
    padded
}

/// Раскладка закодированных параметров, изложенная здесь заново:
/// `version(1) || algo(1) || m_cost || t_cost || p_cost (все u32 LE) || salt(16)`.
fn encode_params(m_cost: u32, t_cost: u32, p_cost: u32, salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let mut out = Vec::with_capacity(KDF_PARAMS_LEN);
    out.push(KDF_VERSION);
    out.push(KDF_ALGO_ARGON2ID);
    out.extend_from_slice(&m_cost.to_le_bytes());
    out.extend_from_slice(&t_cost.to_le_bytes());
    out.extend_from_slice(&p_cost.to_le_bytes());
    out.extend_from_slice(salt);
    out
}

/// `KdfParams` помечен `#[non_exhaustive]`, а бинарник — отдельный крейт, как
/// и раннер в `tests/`. Оба обязаны идти через `KdfParams::decode()`, и это
/// правильнее литерала: путь векторов проходит через валидирующую точку входа,
/// а сама раскладка байт при этом закрепляется независимо от `encode()`.
fn params_at(m_cost: u32, t_cost: u32, p_cost: u32, salt: [u8; SALT_LEN]) -> KdfParams {
    let encoded = encode_params(m_cost, t_cost, p_cost, &salt);
    let params = KdfParams::decode(&encoded).expect("vector parameters are in range");
    assert_eq!(
        params.encode(),
        encoded,
        "KdfParams encoding disagrees with the layout stated in this generator"
    );
    params
}

/// Закодированные параметры с подменённым полем — вход, который `decode`
/// обязан отвергнуть. Собирается правкой байтов, а не конструктором: `KdfParams`
/// с такими значениями не должен существовать даже на мгновение.
fn encoded_with(base: &KdfParams, offset: usize, value: u32) -> Vec<u8> {
    let mut encoded = base.encode();
    encoded[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    encoded
}

fn case(name: &str, fields: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    map.insert("name".into(), json!(name));
    for (key, value) in fields {
        map.insert(key.into(), value);
    }
    Value::Object(map)
}

fn main() {
    let out = json!({
        "generatedBy": "caesar-core gen-vectors",
        "readMe": [
            "Порождается `cargo run -p caesar-core --bin gen-vectors`. Не править руками.",
            "Все байтовые поля — hex в нижнем регистре без разделителей.",
            "Списки `invalid` обязаны отвергаться: `error` — имя варианта Error.",
            "Конверты воспроизводимы байт-в-байт при данном `nonce`; реализация,",
            "которая не умеет задавать nonce, обязана хотя бы открыть их и сверить",
            "открытый текст."
        ],
        "constants": constants(),
        "kdf": kdf_section(),
        "envelope": envelope_section(),
        "keyWrapping": key_wrapping_section(),
        "x25519": x25519_section(),
        "emergencyKit": emergency_kit_section(),
        "item": item_section(),
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&out).expect("vectors are plain JSON values")
    );
}

fn constants() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "suiteId": SUITE_ID,
        "itemSchemaVersion": ITEM_SCHEMA_VERSION,
        "kdfVersion": KDF_VERSION,
        "kdfAlgoArgon2id": KDF_ALGO_ARGON2ID,
        "kdfParamsLen": KDF_PARAMS_LEN,
        "saltLen": SALT_LEN,
        "headerLen": HEADER_LEN,
        "nonceLen": NONCE_LEN,
        "tagLen": TAG_LEN,
        "minEnvelopeLen": MIN_ENVELOPE_LEN,
        "ephemeralPublicLen": EPHEMERAL_PUBLIC_LEN,
        "minBucket": MIN_BUCKET,
        "lenPrefixLen": LEN_PREFIX_LEN,
        "minMCost": MIN_M_COST,
        "minTCost": MIN_T_COST,
        "minPCost": MIN_P_COST,
        "maxMCost": MAX_M_COST,
        "maxTCost": MAX_T_COST,
        "maxPCost": MAX_P_COST,
        "hkdfInfoAuth": "caesar/auth/v1",
        "hkdfInfoWrap": "caesar/wrap/v1",
        "hkdfInfoShare": "caesar/share/v1",
    })
}

fn kdf_section() -> Value {
    let params = params_at(65536, 3, 4, [0x5A; SALT_LEN]);
    let mk = derive_master_key(PASSWORD, &params).expect("pinned params are in range");
    let ak = auth_key(&mk);
    let kek = key_encryption_key(&mk);

    // Расхождение здесь означает смену алгоритма, версии Argon2, порядка байт
    // соли или домена HKDF. Молча переписать вектор нельзя: он уже закреплён
    // тестом `known_answer_vector` и уйдёт в Swift, Kotlin и TypeScript.
    assert_eq!(hex(mk.as_bytes()), KNOWN_MK, "master key regressed");
    assert_eq!(hex(ak.as_bytes()), KNOWN_AK, "auth key regressed");
    assert_eq!(
        hex(kek.as_bytes()),
        KNOWN_KEK,
        "key encryption key regressed"
    );

    // Смещения полей в закодированных параметрах: версия, алгоритм, затем три
    // `u32` little-endian и соль.
    let (m_at, t_at, p_at) = (2, 6, 10);
    let floor_and_ceiling = vec![
        case(
            "mCostBelowFloor",
            vec![
                ("encoded", json!(hex(&encoded_with(&params, m_at, 8)))),
                ("error", json!("KdfParamsOutOfRange")),
            ],
        ),
        case(
            "tCostBelowFloor",
            vec![
                (
                    "encoded",
                    json!(hex(&encoded_with(&params, t_at, MIN_T_COST - 1))),
                ),
                ("error", json!("KdfParamsOutOfRange")),
            ],
        ),
        case(
            "pCostBelowFloor",
            vec![
                (
                    "encoded",
                    json!(hex(&encoded_with(&params, p_at, MIN_P_COST - 1))),
                ),
                ("error", json!("KdfParamsOutOfRange")),
            ],
        ),
        case(
            "mCostAboveCeiling",
            vec![
                (
                    "encoded",
                    json!(hex(&encoded_with(&params, m_at, MAX_M_COST + 1))),
                ),
                ("error", json!("KdfParamsOutOfRange")),
            ],
        ),
        case(
            "mCostMaxU32",
            vec![
                (
                    "encoded",
                    json!(hex(&encoded_with(&params, m_at, u32::MAX))),
                ),
                ("error", json!("KdfParamsOutOfRange")),
                (
                    "why",
                    json!("аллокация ~4 ТиБ: без проверки это abort, а не Err"),
                ),
            ],
        ),
        case(
            "tCostAboveCeiling",
            vec![
                (
                    "encoded",
                    json!(hex(&encoded_with(&params, t_at, MAX_T_COST + 1))),
                ),
                ("error", json!("KdfParamsOutOfRange")),
            ],
        ),
        case(
            "pCostAboveCeiling",
            vec![
                (
                    "encoded",
                    json!(hex(&encoded_with(&params, p_at, MAX_P_COST + 1))),
                ),
                ("error", json!("KdfParamsOutOfRange")),
            ],
        ),
    ];

    let mut unknown_version = params.encode();
    unknown_version[0] = 7;
    let mut unknown_algo = params.encode();
    unknown_algo[1] = 9;
    let mut truncated = params.encode();
    truncated.pop();

    let mut invalid = floor_and_ceiling;
    invalid.extend([
        case(
            "unknownKdfVersion",
            vec![
                ("encoded", json!(hex(&unknown_version))),
                ("error", json!("UnsupportedVersion")),
            ],
        ),
        case(
            "unknownKdfAlgorithm",
            vec![
                ("encoded", json!(hex(&unknown_algo))),
                ("error", json!("UnsupportedSuite")),
            ],
        ),
        case(
            "truncatedParams",
            vec![
                ("encoded", json!(hex(&truncated))),
                ("error", json!("Truncated")),
            ],
        ),
    ]);

    for entry in &invalid {
        let encoded = decode_hex(entry["encoded"].as_str().expect("encoded is a hex string"));
        assert!(
            KdfParams::decode(&encoded).is_err(),
            "invalid kdf case {} was accepted",
            entry["name"]
        );
    }

    // Границы принимаются: пол и потолок — включительные. Вывод ключа на них не
    // запускается (4 ГиБ памяти), проверяется только `decode`.
    let at_floor = params_at(MIN_M_COST, MIN_T_COST, MIN_P_COST, [0x00; SALT_LEN]);
    let at_ceiling = params_at(MAX_M_COST, MAX_T_COST, MAX_P_COST, [0xFF; SALT_LEN]);

    json!({
        "knownAnswer": {
            "password": PASSWORD,
            "mCost": params.m_cost,
            "tCost": params.t_cost,
            "pCost": params.p_cost,
            "salt": hex(&params.salt),
            "encodedParams": hex(&params.encode()),
            "masterKey": hex(mk.as_bytes()),
            "authKey": hex(ak.as_bytes()),
            "keyEncryptionKey": hex(kek.as_bytes()),
        },
        "paramsEncoding": [
            encoded_params_case("pinned", &params),
            // Три разных значения подряд: перепутанный порядок полей или
            // big-endian видно сразу, чего вектор 65536/3/4 не показывает.
            encoded_params_case("distinctFields", &params_at(20480, 5, 2, sequential_salt())),
            encoded_params_case("atFloor", &at_floor),
            encoded_params_case("atCeiling", &at_ceiling),
        ],
        "invalid": invalid,
    })
}

fn sequential_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    for (index, byte) in salt.iter_mut().enumerate() {
        *byte = index as u8;
    }
    salt
}

fn encoded_params_case(name: &str, params: &KdfParams) -> Value {
    case(
        name,
        vec![
            ("mCost", json!(params.m_cost)),
            ("tCost", json!(params.t_cost)),
            ("pCost", json!(params.p_cost)),
            ("salt", json!(hex(&params.salt))),
            ("encoded", json!(hex(&params.encode()))),
        ],
    )
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("generated hex"))
        .collect()
}

fn envelope_section() -> Value {
    let kek_bytes = decode_hex(KNOWN_KEK);
    let kek: [u8; 32] = kek_bytes.try_into().expect("KEK is 32 bytes");
    let user_key = UserKeyPair::from_secret(RECIPIENT_SECRET);

    let sealed_vault_key = aead::seal_with_nonce(&kek, &nonce(0xA1), &VAULT_KEY)
        .expect("sealing 32 bytes cannot overflow the counter");
    let sealed_user_key = aead::seal_with_nonce(&kek, &nonce(0xA2), user_key.secret_bytes())
        .expect("sealing 32 bytes cannot overflow the counter");
    let empty = aead::seal_with_nonce(&kek, &nonce(0xA3), b"")
        .expect("sealing nothing cannot overflow the counter");
    assert_eq!(empty.len(), MIN_ENVELOPE_LEN);

    let mut unknown_version = sealed_vault_key.clone();
    unknown_version[0] = 2;
    let mut unknown_suite = sealed_vault_key.clone();
    unknown_suite[1] = 2;
    let mut truncated = sealed_vault_key.clone();
    truncated.truncate(MIN_ENVELOPE_LEN - 1);
    let mut tampered_tag = sealed_vault_key.clone();
    let last = tampered_tag.len() - 1;
    tampered_tag[last] ^= 1;
    let mut tampered_nonce = sealed_vault_key.clone();
    tampered_nonce[HEADER_LEN] ^= 1;

    let invalid = vec![
        case(
            "unknownProtocolVersion",
            vec![
                ("key", json!(hex(&kek))),
                ("envelope", json!(hex(&unknown_version))),
                ("error", json!("UnsupportedVersion")),
                (
                    "why",
                    json!("клиент обязан отказаться, а не гадать о раскладке"),
                ),
            ],
        ),
        case(
            "unknownSuite",
            vec![
                ("key", json!(hex(&kek))),
                ("envelope", json!(hex(&unknown_suite))),
                ("error", json!("UnsupportedSuite")),
            ],
        ),
        case(
            "truncatedEnvelope",
            vec![
                ("key", json!(hex(&kek))),
                ("envelope", json!(hex(&truncated))),
                ("error", json!("Truncated")),
            ],
        ),
        case(
            "tamperedTag",
            vec![
                ("key", json!(hex(&kek))),
                ("envelope", json!(hex(&tampered_tag))),
                ("error", json!("DecryptionFailed")),
            ],
        ),
        case(
            "tamperedNonce",
            vec![
                ("key", json!(hex(&kek))),
                ("envelope", json!(hex(&tampered_nonce))),
                ("error", json!("DecryptionFailed")),
                ("why", json!("nonce не покрыт AAD — только тегом")),
            ],
        ),
        case(
            "wrongKey",
            vec![
                ("key", json!(hex(&[0x2B; 32]))),
                ("envelope", json!(hex(&sealed_vault_key))),
                ("error", json!("DecryptionFailed")),
            ],
        ),
    ];

    for entry in &invalid {
        let key: [u8; 32] = decode_hex(entry["key"].as_str().expect("key is hex"))
            .try_into()
            .expect("key is 32 bytes");
        let envelope = decode_hex(entry["envelope"].as_str().expect("envelope is hex"));
        assert!(
            aead::open(&key, &envelope).is_err(),
            "invalid envelope case {} was accepted",
            entry["name"]
        );
    }

    json!({
        "layout": {
            "description": "version(1) || suiteId(1) || nonce(24) || ciphertext+tag(16..)",
            "header": hex(&HEADER),
            "headerOffset": 0,
            "nonceOffset": HEADER_LEN,
            "ciphertextOffset": HEADER_LEN + NONCE_LEN,
            "aad": hex(&HEADER),
            "aadIsHeader": true,
        },
        "valid": [
            envelope_case("vaultKeyWrappedWithKek", &kek, &nonce(0xA1), &VAULT_KEY, &sealed_vault_key),
            envelope_case("userKeyWrappedWithKek", &kek, &nonce(0xA2), user_key.secret_bytes(), &sealed_user_key),
            envelope_case("emptyPlaintext", &kek, &nonce(0xA3), b"", &empty),
        ],
        "invalid": invalid,
    })
}

fn envelope_case(
    name: &str,
    key: &[u8; 32],
    nonce_bytes: &[u8; NONCE_LEN],
    plaintext: &[u8],
    envelope: &[u8],
) -> Value {
    case(
        name,
        vec![
            ("key", json!(hex(key))),
            ("nonce", json!(hex(nonce_bytes))),
            ("plaintext", json!(hex(plaintext))),
            ("envelope", json!(hex(envelope))),
            ("envelopeLength", json!(envelope.len())),
        ],
    )
}

/// Обёртка UK и VK ключом обёртки — и два отказа, которых больше нигде нет.
///
/// `UserKeyMismatch` не поймать ни тегом, ни длиной: откат к прошлой, честно
/// завёрнутой записи `encryptedUserKey` проходит Poly1305 чисто. Отличает
/// актуальную личность от устаревшей только сверка с опубликованным `UK_pub`,
/// и реализация, зовущая `unwrap_user_key` вместо `unwrap_user_key_verified`,
/// без этого вектора выглядит рабочей.
fn key_wrapping_section() -> Value {
    let kek: [u8; 32] = decode_hex(KNOWN_KEK).try_into().expect("KEK is 32 bytes");
    let user_key = UserKeyPair::from_secret(RECIPIENT_SECRET);
    let other_key = UserKeyPair::from_secret([0x04; 32]);

    let wrapped_user_key = aead::seal_with_nonce(&kek, &nonce(0xA2), user_key.secret_bytes())
        .expect("sealing 32 bytes cannot overflow the counter");
    let wrapped_vault_key = aead::seal_with_nonce(&kek, &nonce(0xA1), &VAULT_KEY)
        .expect("sealing 32 bytes cannot overflow the counter");
    // Обёрнутое значение не той длины: клиент другой платформы, завернувший
    // усечённый ключ. Тег сходится — ключ обёртки настоящий.
    let wrapped_short = aead::seal_with_nonce(&kek, &nonce(0xA4), &[0u8; 31])
        .expect("sealing 31 bytes cannot overflow the counter");

    let invalid = vec![
        case(
            "rolledBackUserKey",
            vec![
                ("keyEncryptionKey", json!(hex(&kek))),
                ("wrapped", json!(hex(&wrapped_user_key))),
                ("expectedPublic", json!(hex(other_key.public_bytes()))),
                ("error", json!("UserKeyMismatch")),
                (
                    "why",
                    json!("откат к прошлой записи проходит Poly1305 чисто"),
                ),
            ],
        ),
        case(
            "wrappedKeyWrongLength",
            vec![
                ("keyEncryptionKey", json!(hex(&kek))),
                ("wrapped", json!(hex(&wrapped_short))),
                ("error", json!("InvalidKeyLength")),
            ],
        ),
    ];

    assert_eq!(
        vault::unwrap_user_key_verified(
            &caesar_core::KeyEncryptionKey::from_bytes(kek),
            &wrapped_user_key,
            other_key.public_bytes(),
        )
        .unwrap_err(),
        Error::UserKeyMismatch
    );
    assert!(matches!(
        vault::unwrap_vault_key(
            &caesar_core::KeyEncryptionKey::from_bytes(kek),
            &wrapped_short,
        ),
        Err(Error::InvalidKeyLength { got: 31, .. })
    ));

    json!({
        "keyEncryptionKey": hex(&kek),
        "userKey": {
            "secret": hex(&RECIPIENT_SECRET),
            "public": hex(user_key.public_bytes()),
            "nonce": hex(&nonce(0xA2)),
            "wrapped": hex(&wrapped_user_key),
        },
        "vaultKey": {
            "plaintext": hex(&VAULT_KEY),
            "nonce": hex(&nonce(0xA1)),
            "wrapped": hex(&wrapped_vault_key),
        },
        "invalid": invalid,
    })
}

fn x25519_section() -> Value {
    let recipient = UserKeyPair::from_secret(RECIPIENT_SECRET);
    let vault_key = VaultKey::from_bytes(VAULT_KEY);

    let sealed = vault::seal_vault_key_for_with_randomness(
        recipient.public_bytes(),
        &vault_key,
        &EPHEMERAL_SECRET,
        &nonce(0xB1),
    )
    .expect("the pinned recipient key has large order");

    // Точки малого порядка: X25519 даёт с ними нулевой общий секрет, обе
    // половины соли HKDF при этом публичны и лежат в самой записи, поэтому VK
    // выводится из неё кем угодно. Список — классический набор из libsodium.
    let degenerate = [
        ("allZeros", [0u8; 32].to_vec()),
        (
            "one",
            decode_hex("0100000000000000000000000000000000000000000000000000000000000000"),
        ),
        (
            "orderEightA",
            decode_hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        ),
        (
            "orderEightB",
            decode_hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        ),
        (
            "pMinusOne",
            decode_hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ),
    ];

    let degenerate_cases: Vec<Value> = degenerate
        .iter()
        .map(|(name, bytes)| {
            let public: [u8; 32] = bytes.as_slice().try_into().expect("32 bytes");
            let rejected = vault::seal_vault_key_for(&public, &vault_key);
            assert_eq!(
                rejected.unwrap_err(),
                Error::DegenerateRecipientKey,
                "low-order recipient key {name} was accepted"
            );
            case(
                name,
                vec![
                    ("recipientPublic", json!(hex(&public))),
                    ("error", json!("DegenerateRecipientKey")),
                ],
            )
        })
        .collect();

    let invalid_sealed = vec![
        case(
            "truncatedBelowEphemeralPublic",
            vec![
                ("recipientSecret", json!(hex(&RECIPIENT_SECRET))),
                ("sealed", json!(hex(&sealed[..EPHEMERAL_PUBLIC_LEN - 1]))),
                ("error", json!("Truncated")),
            ],
        ),
        case(
            "truncatedEnvelope",
            vec![
                ("recipientSecret", json!(hex(&RECIPIENT_SECRET))),
                (
                    "sealed",
                    json!(hex(&sealed[..EPHEMERAL_PUBLIC_LEN + MIN_ENVELOPE_LEN - 1])),
                ),
                ("error", json!("Truncated")),
            ],
        ),
        case(
            "wrongRecipient",
            vec![
                ("recipientSecret", json!(hex(&[0x04; 32]))),
                ("sealed", json!(hex(&sealed))),
                ("error", json!("DecryptionFailed")),
            ],
        ),
    ];

    for entry in &invalid_sealed {
        let secret = decode_hex(entry["recipientSecret"].as_str().expect("secret is hex"));
        let pair = UserKeyPair::try_from_slice(&secret).expect("32 bytes");
        let blob = decode_hex(entry["sealed"].as_str().expect("sealed is hex"));
        assert!(
            vault::open_vault_key_for(&pair, &blob).is_err(),
            "invalid shared record {} was accepted",
            entry["name"]
        );
    }

    json!({
        "keyPairs": [
            case("pinned", vec![
                ("secret", json!(hex(&RECIPIENT_SECRET))),
                ("public", json!(hex(recipient.public_bytes()))),
            ]),
            // RFC 7748 §6.1, ключ Алисы: не прогон этой же реализации, а
            // внешний вектор. Ловит потерянный клэмпинг и обратный порядок байт.
            rfc7748_alice(),
        ],
        "sealVaultKeyFor": {
            "layout": "ephemeralPublic(32) || Envelope",
            "ephemeralPublicLen": EPHEMERAL_PUBLIC_LEN,
            "hkdfSalt": "ephemeralPublic(32) || recipientPublic(32)",
            "hkdfInfo": "caesar/share/v1",
            "recipientSecret": hex(&RECIPIENT_SECRET),
            "recipientPublic": hex(recipient.public_bytes()),
            "ephemeralSecret": hex(&EPHEMERAL_SECRET),
            "ephemeralPublic": hex(&sealed[..EPHEMERAL_PUBLIC_LEN]),
            "nonce": hex(&nonce(0xB1)),
            "vaultKey": hex(&VAULT_KEY),
            "sealed": hex(&sealed),
        },
        "invalidRecipients": degenerate_cases,
        "invalidSealed": invalid_sealed,
    })
}

fn rfc7748_alice() -> Value {
    let secret = decode_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let pair = UserKeyPair::try_from_slice(&secret).expect("32 bytes");
    assert_eq!(
        hex(pair.public_bytes()),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        "X25519 base point multiplication regressed"
    );
    case(
        "rfc7748Alice",
        vec![
            ("secret", json!(hex(&secret))),
            ("public", json!(hex(pair.public_bytes()))),
            ("source", json!("RFC 7748 section 6.1")),
        ],
    )
}

fn emergency_kit_section() -> Value {
    let zero = RecoveryKey::from_bytes([0x00; 32]);
    let ones = RecoveryKey::from_bytes([0xFF; 32]);
    let sequential_bytes = {
        let mut key = [0u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        key
    };
    let sequential = RecoveryKey::from_bytes(sequential_bytes);

    let zero_kit = recovery::format_emergency_kit(&zero);
    let ones_kit = recovery::format_emergency_kit(&ones);
    let printed = recovery::format_emergency_kit(&sequential);
    let kit = printed.as_str();

    // Закреплено в Task 8. Расхождение — смена кодека Base32 или контрольной
    // суммы, то есть напечатанные на бумаге наборы перестают работать.
    assert_eq!(
        zero_kit.as_str(),
        "0000000-0000000-0000000-0000000-0000000-0000000-0000000-006CT3T"
    );
    assert_eq!(
        ones_kit.as_str(),
        "ZZZZZZZ-ZZZZZZZ-ZZZZZZZ-ZZZZZZZ-ZZZZZZZ-ZZZZZZZ-ZZZZZZZ-ZZTZ5GK"
    );

    // Подстановка Крокфорда: кодировщик не печатает I, L и O никогда, поэтому
    // во вводе они берутся ровно одним способом — человек (или OCR) так прочитал
    // 1 и 0 с бумаги. Реализация, написанная по алфавиту без подстановки, такой
    // ввод ОТВЕРГНЕТ, и без этого вектора ворота №1 этого не увидят.
    let mut substituted = String::with_capacity(kit.len());
    let mut ones_seen = 0usize;
    for symbol in kit.chars() {
        substituted.push(match symbol {
            '0' => 'O',
            '1' => {
                ones_seen += 1;
                if ones_seen % 2 == 1 {
                    'I'
                } else {
                    'L'
                }
            }
            other => other,
        });
    }
    assert!(
        substituted.contains('I') && substituted.contains('L') && substituted.contains('O'),
        "substitution case must exercise all three letters"
    );

    let lowercase = kit.to_lowercase();
    let spaced = kit.replace('-', "  ");
    let joined = kit.replace('-', "");
    // Дефис, который автозамена в документе превратила в тире.
    let em_dashed = kit.replace('-', "\u{2014}");

    let accepted = vec![
        parse_case("canonical", kit, &sequential_bytes),
        parse_case("lowercase", &lowercase, &sequential_bytes),
        parse_case("crockfordSubstitution", &substituted, &sequential_bytes),
        parse_case("spacesInsteadOfDashes", &spaced, &sequential_bytes),
        parse_case("noSeparators", &joined, &sequential_bytes),
        parse_case("unicodeDashes", &em_dashed, &sequential_bytes),
    ];

    // Опечатка в последнем символе меняет напечатанную контрольную сумму.
    let mut bad_checksum: Vec<char> = kit.chars().collect();
    let last = bad_checksum.len() - 1;
    bad_checksum[last] = if bad_checksum[last] == 'Z' { 'Y' } else { 'Z' };
    let bad_checksum: String = bad_checksum.into_iter().collect();
    assert_eq!(
        recovery::parse_emergency_kit(&bad_checksum).unwrap_err(),
        Error::EmergencyKitChecksumMismatch,
        "a mistyped symbol must be distinguishable from a foreign key"
    );

    // `U` исключена Crockford'ом намеренно и замены ей не задано — в отличие от
    // I, L и O её обязаны отвергнуть.
    let letter_u = format!("U{}", &kit[1..]);
    let too_short = kit[..kit.len() - 1].to_string();
    let too_long = format!("{kit}Z");
    let non_latin = kit.replacen('0', "\u{041E}", 1);

    let rejected = vec![
        reject_case(
            "badChecksum",
            &bad_checksum,
            "EmergencyKitChecksumMismatch",
            Some("один символ набран неверно — это не «чужой ключ»"),
        ),
        reject_case(
            "letterU",
            &letter_u,
            "InvalidEmergencyKit",
            Some("U исключена из алфавита и не подставляется"),
        ),
        reject_case("tooFewSymbols", &too_short, "InvalidEmergencyKit", None),
        reject_case("tooManySymbols", &too_long, "InvalidEmergencyKit", None),
        reject_case(
            "nonLatinLookalike",
            &non_latin,
            "InvalidEmergencyKit",
            Some("кириллическая О вместо нуля"),
        ),
    ];

    for entry in &accepted {
        let input = entry["input"].as_str().expect("input is a string");
        let parsed = recovery::parse_emergency_kit(input).expect("accepted case must parse");
        assert_eq!(
            hex(parsed.as_bytes()),
            entry["key"].as_str().expect("key is hex"),
            "accepted kit case {} decoded to the wrong key",
            entry["name"]
        );
    }
    for entry in &rejected {
        assert!(
            recovery::parse_emergency_kit(entry["input"].as_str().expect("input is a string"))
                .is_err(),
            "rejected kit case {} was accepted",
            entry["name"]
        );
    }

    json!({
        "layout": {
            "alphabet": "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
            "symbols": 56,
            "groups": 8,
            "groupSize": 7,
            "payload": "key(32) || sha256(key)[..3]",
            "substitutions": { "I": "1", "L": "1", "O": "0" },
            "excluded": "U (исключена Crockford'ом, замены нет)",
        },
        "formatted": [
            format_case("allZeros", zero.as_bytes(), zero_kit.as_str()),
            format_case("allOnes", ones.as_bytes(), ones_kit.as_str()),
            format_case("sequential", &sequential_bytes, kit),
        ],
        "accepted": accepted,
        "rejected": rejected,
    })
}

fn format_case(name: &str, key: &[u8; 32], printed: &str) -> Value {
    case(
        name,
        vec![
            ("key", json!(hex(key))),
            ("formatted", json!(printed)),
            ("printedLength", json!(printed.chars().count())),
        ],
    )
}

fn parse_case(name: &str, input: &str, key: &[u8; 32]) -> Value {
    case(
        name,
        vec![("input", json!(input)), ("key", json!(hex(key)))],
    )
}

fn reject_case(name: &str, input: &str, error: &str, why: Option<&str>) -> Value {
    let mut fields = vec![("input", json!(input)), ("error", json!(error))];
    if let Some(why) = why {
        fields.push(("why", json!(why)));
    }
    case(name, fields)
}

/// Заголовок заметки, дающий JSON ровно `target` байт.
fn note_with_json_len(target: usize) -> (usize, ItemSecret) {
    let base = serde_json::to_vec(&ItemSecret::new(ItemKind::SecureNote, ""))
        .expect("an item is plain JSON")
        .len();
    let filler = target - base;
    let item = ItemSecret::new(ItemKind::SecureNote, "x".repeat(filler));
    assert_eq!(
        serde_json::to_vec(&item)
            .expect("an item is plain JSON")
            .len(),
        target
    );
    (filler, item)
}

fn item_section() -> Value {
    let vault_key = VaultKey::from_bytes(VAULT_KEY);

    let mut item = ItemSecret::new(ItemKind::Login, "Northwind Bank");
    item.username = Some("a.kern".into());
    item.password = Some("t7-Quarry-Ledger-49".into());
    item.totp_uri = Some("otpauth://totp/x".into());
    item.website = Some("northwind.example".into());
    item.notes = Some("branch 12".into());
    item.tags = vec!["finance".into(), "2fa".into()];

    let plaintext_json = serde_json::to_string(&item).expect("an item is plain JSON");
    let padded = pad_json(plaintext_json.as_bytes());
    let sealed = aead::seal_with_nonce(&VAULT_KEY, &nonce(0xC1), &padded)
        .expect("a padded item fits the ChaCha20 counter");

    let note = ItemSecret::new(ItemKind::SecureNote, "shed code");
    let note_json = serde_json::to_string(&note).expect("an item is plain JSON");
    let note_padded = pad_json(note_json.as_bytes());
    let note_sealed = aead::seal_with_nonce(&VAULT_KEY, &nonce(0xC2), &note_padded)
        .expect("a padded item fits the ChaCha20 counter");

    // Границы бакетов вокруг MIN_BUCKET и следующей степени двойки. Раннер
    // строит эти же айтемы сам: печатать тысячу символов заголовка в файл
    // векторов незачем, а длина проверяется и так.
    let boundaries: Vec<Value> = [
        MIN_BUCKET - LEN_PREFIX_LEN - 1,
        MIN_BUCKET - LEN_PREFIX_LEN,
        MIN_BUCKET - LEN_PREFIX_LEN + 1,
        2 * MIN_BUCKET - LEN_PREFIX_LEN,
        2 * MIN_BUCKET - LEN_PREFIX_LEN + 1,
    ]
    .into_iter()
    .map(|json_len| {
        let (filler, item) = note_with_json_len(json_len);
        let padded_len = bucket_for(LEN_PREFIX_LEN + json_len);
        // Раскладка бакетов здесь изложена заново; сверка с рабочим кодом —
        // вот она, на длине настоящего конверта.
        assert_eq!(
            caesar_core::seal_item(&item, &vault_key)
                .expect("a padded item fits the ChaCha20 counter")
                .len(),
            MIN_ENVELOPE_LEN + padded_len
        );
        case(
            &format!("json{json_len}"),
            vec![
                ("kind", json!("secureNote")),
                ("titleFiller", json!(filler)),
                ("jsonLength", json!(json_len)),
                ("paddedLength", json!(padded_len)),
                ("envelopeLength", json!(MIN_ENVELOPE_LEN + padded_len)),
            ],
        )
    })
    .collect();
    // Смысл списка — что граница проходит там, где заявлено: 512 и 1024 должны
    // встретиться оба, иначе вектор ничего не разделяет.
    assert!(boundaries
        .iter()
        .any(|entry| entry["paddedLength"] == json!(MIN_BUCKET)));
    assert!(boundaries
        .iter()
        .any(|entry| entry["paddedLength"] == json!(2 * MIN_BUCKET)));

    let unknown_field =
        br#"{"v":1,"kind":"login","title":"Northwind Bank","attachmentRef":"blob-1"}"#;
    let future_schema =
        br#"{"v":2,"kind":"login","title":"Northwind Bank","attachmentRef":"blob-1"}"#;

    // Длина не бакет: писатель другой платформы, дополняющий до кратного 16 или
    // не дополняющий вовсе. Тег Poly1305 такое не ловит — ключ-то настоящий.
    let not_a_bucket = {
        let mut padded = pad_json(note_json.as_bytes());
        padded.resize(600, 0);
        assert_ne!(padded.len(), bucket_for(padded.len()));
        padded
    };
    // Заявленная длина больше, чем вмещает бакет.
    let declared_too_long = {
        let mut padded = pad_json(note_json.as_bytes());
        padded[..LEN_PREFIX_LEN].copy_from_slice(&1000u32.to_le_bytes());
        padded
    };
    // Хвост не нулевой: PKCS#7 или случайная добивка чужой реализации.
    let dirty_tail = {
        let mut padded = pad_json(note_json.as_bytes());
        let last = padded.len() - 1;
        padded[last] = 0x07;
        padded
    };

    let invalid = vec![
        item_reject_case(
            "unknownField",
            &vault_key,
            &nonce(0xD1),
            &pad_json(unknown_field),
            "MalformedPlaintext",
            "deny_unknown_fields: поле из будущей версии нельзя молча потерять",
        ),
        item_reject_case(
            "futureSchemaVersion",
            &vault_key,
            &nonce(0xD2),
            &pad_json(future_schema),
            "UnsupportedItemSchema",
            "номер версии не редактируется: иначе перекос версий неотличим от порчи",
        ),
        item_reject_case(
            "paddedLengthIsNotABucket",
            &vault_key,
            &nonce(0xD3),
            &not_a_bucket,
            "MalformedPlaintext",
            "600 байт — не степень двойки не меньше 512",
        ),
        item_reject_case(
            "declaredLengthExceedsBucket",
            &vault_key,
            &nonce(0xD4),
            &declared_too_long,
            "MalformedPlaintext",
            "префикс длины указывает за пределы бакета",
        ),
        item_reject_case(
            "paddingTailIsNotZero",
            &vault_key,
            &nonce(0xD5),
            &dirty_tail,
            "MalformedPlaintext",
            "чужая реализация дополнила PKCS#7 или случайными байтами",
        ),
    ];

    for entry in &invalid {
        let envelope = decode_hex(entry["envelope"].as_str().expect("envelope is hex"));
        assert!(
            caesar_core::open_item(&envelope, &vault_key).is_err(),
            "invalid item case {} was accepted",
            entry["name"]
        );
    }

    json!({
        "padding": {
            "layout": "declaredLength(u32 LE) || json || zeros",
            "lenPrefixLen": LEN_PREFIX_LEN,
            "minBucket": MIN_BUCKET,
            "rule": "наименьшая степень двойки не меньше minBucket, вмещающая 4 + len(json)",
        },
        "vaultKey": hex(&VAULT_KEY),
        "valid": [
            item_case("fullLogin", &nonce(0xC1), &plaintext_json, &padded, &sealed),
            item_case("secureNote", &nonce(0xC2), &note_json, &note_padded, &note_sealed),
        ],
        "bucketBoundaries": boundaries,
        "invalid": invalid,
    })
}

fn item_case(
    name: &str,
    nonce_bytes: &[u8; NONCE_LEN],
    plaintext_json: &str,
    padded: &[u8],
    sealed: &[u8],
) -> Value {
    case(
        name,
        vec![
            ("nonce", json!(hex(nonce_bytes))),
            ("plaintextJson", json!(plaintext_json)),
            ("jsonLength", json!(plaintext_json.len())),
            ("paddedPlaintext", json!(hex(padded))),
            ("paddedLength", json!(padded.len())),
            ("envelope", json!(hex(sealed))),
            ("envelopeLength", json!(sealed.len())),
        ],
    )
}

fn item_reject_case(
    name: &str,
    vault_key: &VaultKey,
    nonce_bytes: &[u8; NONCE_LEN],
    padded: &[u8],
    error: &str,
    why: &str,
) -> Value {
    let sealed = aead::seal_with_nonce(vault_key.as_bytes(), nonce_bytes, padded)
        .expect("a padded item fits the ChaCha20 counter");
    case(
        name,
        vec![
            ("nonce", json!(hex(nonce_bytes))),
            ("paddedPlaintext", json!(hex(padded))),
            ("envelope", json!(hex(&sealed))),
            ("error", json!(error)),
            ("why", json!(why)),
        ],
    )
}
