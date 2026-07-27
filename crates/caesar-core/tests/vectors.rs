//! Ворота CI №1 для Rust: расхождение с `protocol/vectors.json` ломает билд.
//!
//! Раннер живёт в `tests/`, то есть в отдельном крейте, и намеренно ходит теми
//! же путями, что и биндинги: `KdfParams` помечен `#[non_exhaustive]`, поэтому
//! параметры приходят только через `KdfParams::decode()` из байт файла.
//!
//! Половина случаев — отрицательные. Файл из одних счастливых путей пропускает
//! снисходительную реализацию: она примет всё подряд и пройдёт ворота.

use caesar_core::kdf::{auth_key, derive_master_key, key_encryption_key, KdfParams};
use caesar_core::keys::{RecoveryKey, VaultKey};
use caesar_core::model::{ItemKind, ItemSecret};
use caesar_core::vault::{self, UserKeyPair};
use caesar_core::{aead, recovery, Error};
use serde_json::Value;

fn vectors() -> Value {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/vectors.json"
    ))
    .expect("run: cargo run -p caesar-core --bin gen-vectors > protocol/vectors.json");
    serde_json::from_str(&raw).expect("vectors.json is valid JSON")
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("field {key} is missing or not a string in {value}"))
}

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(text(value, key)).expect("byte fields are hex")
}

fn key32(value: &Value, key: &str) -> [u8; 32] {
    bytes(value, key)
        .try_into()
        .unwrap_or_else(|_| panic!("field {key} is not 32 bytes"))
}

fn nonce24(value: &Value, key: &str) -> [u8; 24] {
    bytes(value, key)
        .try_into()
        .unwrap_or_else(|_| panic!("field {key} is not 24 bytes"))
}

fn number(value: &Value, key: &str) -> usize {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("field {key} is missing or not a number in {value}")) as usize
}

fn cases<'a>(value: &'a Value, path: &[&str]) -> &'a Vec<Value> {
    let mut node = value;
    for step in path {
        node = &node[*step];
    }
    let list = node
        .as_array()
        .unwrap_or_else(|| panic!("{} is not an array", path.join(".")));
    assert!(!list.is_empty(), "{} is empty", path.join("."));
    list
}

/// Имя варианта `Error` — контракт файла векторов для всех четырёх языков.
///
/// Wildcard обязателен: `Error` помечен `#[non_exhaustive]`, а из другого
/// крейта это значит, что match без него не скомпилируется. Новый вариант
/// приедет сюда как `"Unknown"` и уронит первый же отрицательный случай,
/// который его ожидает, — это лучше, чем молча его принять.
fn error_name(err: &Error) -> &'static str {
    match err {
        Error::UnsupportedVersion { .. } => "UnsupportedVersion",
        Error::UnsupportedSuite { .. } => "UnsupportedSuite",
        Error::Truncated { .. } => "Truncated",
        Error::DecryptionFailed => "DecryptionFailed",
        Error::PlaintextTooLarge => "PlaintextTooLarge",
        Error::KeyDerivation(_) => "KeyDerivation",
        Error::MalformedPlaintext(_) => "MalformedPlaintext",
        Error::UnsupportedItemSchema { .. } => "UnsupportedItemSchema",
        Error::InvalidKeyLength { .. } => "InvalidKeyLength",
        Error::InvalidEmergencyKit(_) => "InvalidEmergencyKit",
        Error::EmergencyKitChecksumMismatch => "EmergencyKitChecksumMismatch",
        Error::RandomSourceUnavailable => "RandomSourceUnavailable",
        Error::UserKeyMismatch => "UserKeyMismatch",
        Error::DegenerateRecipientKey => "DegenerateRecipientKey",
        Error::KdfParamsOutOfRange { .. } => "KdfParamsOutOfRange",
        _ => "Unknown",
    }
}

/// Отрицательный случай: отказ обязателен, и именно с заявленным вариантом.
///
/// Проверять только `is_err()` было бы мало: «слишком слабые параметры» и
/// «обрезанный вход» — разные диагнозы, и реализация, схлопнувшая их в один,
/// оставляет пользователя без единственной подсказки, что делать дальше.
fn assert_rejected<T: std::fmt::Debug>(entry: &Value, outcome: Result<T, Error>) {
    let name = text(entry, "name");
    let expected = text(entry, "error");
    match outcome {
        Ok(value) => panic!("case {name} was accepted: {value:?}"),
        Err(err) => assert_eq!(error_name(&err), expected, "case {name} failed differently"),
    }
}

#[test]
fn protocol_constants_match_vectors() {
    let v = vectors();
    let c = &v["constants"];
    assert_eq!(
        number(c, "protocolVersion") as u8,
        caesar_core::PROTOCOL_VERSION
    );
    assert_eq!(number(c, "suiteId") as u8, caesar_core::SUITE_ID);
    assert_eq!(
        number(c, "itemSchemaVersion") as u8,
        caesar_core::ITEM_SCHEMA_VERSION
    );
    assert_eq!(number(c, "kdfVersion") as u8, caesar_core::kdf::KDF_VERSION);
    assert_eq!(
        number(c, "kdfAlgoArgon2id") as u8,
        caesar_core::kdf::KDF_ALGO_ARGON2ID
    );
    assert_eq!(number(c, "kdfParamsLen"), caesar_core::kdf::KDF_PARAMS_LEN);
    assert_eq!(number(c, "saltLen"), caesar_core::kdf::SALT_LEN);
    assert_eq!(number(c, "headerLen"), caesar_core::envelope::HEADER_LEN);
    assert_eq!(number(c, "nonceLen"), caesar_core::envelope::NONCE_LEN);
    assert_eq!(number(c, "tagLen"), caesar_core::envelope::TAG_LEN);
    assert_eq!(
        number(c, "minEnvelopeLen"),
        caesar_core::envelope::MIN_ENVELOPE_LEN
    );
    assert_eq!(
        number(c, "ephemeralPublicLen"),
        caesar_core::vault::EPHEMERAL_PUBLIC_LEN
    );
    assert_eq!(number(c, "minMCost") as u32, caesar_core::kdf::MIN_M_COST);
    assert_eq!(number(c, "minTCost") as u32, caesar_core::kdf::MIN_T_COST);
    assert_eq!(number(c, "minPCost") as u32, caesar_core::kdf::MIN_P_COST);
    assert_eq!(number(c, "maxMCost") as u32, caesar_core::kdf::MAX_M_COST);
    assert_eq!(number(c, "maxTCost") as u32, caesar_core::kdf::MAX_T_COST);
    assert_eq!(number(c, "maxPCost") as u32, caesar_core::kdf::MAX_P_COST);
}

#[test]
fn kdf_known_answer_matches_vectors() {
    let v = vectors();
    let entry = &v["kdf"]["knownAnswer"];
    let params = KdfParams::decode(&bytes(entry, "encodedParams")).expect("pinned params decode");
    let mk =
        derive_master_key(text(entry, "password"), &params).expect("pinned params are in range");

    assert_eq!(hex::encode(mk.as_bytes()), text(entry, "masterKey"));
    assert_eq!(
        hex::encode(auth_key(&mk).as_bytes()),
        text(entry, "authKey")
    );
    assert_eq!(
        hex::encode(key_encryption_key(&mk).as_bytes()),
        text(entry, "keyEncryptionKey")
    );
}

#[test]
fn kdf_params_encoding_matches_vectors() {
    let v = vectors();
    for entry in cases(&v, &["kdf", "paramsEncoding"]) {
        let encoded = bytes(entry, "encoded");
        let params = KdfParams::decode(&encoded)
            .unwrap_or_else(|e| panic!("case {} rejected: {e}", text(entry, "name")));

        assert_eq!(params.m_cost as usize, number(entry, "mCost"));
        assert_eq!(params.t_cost as usize, number(entry, "tCost"));
        assert_eq!(params.p_cost as usize, number(entry, "pCost"));
        assert_eq!(hex::encode(params.salt), text(entry, "salt"));
        assert_eq!(
            params.encode(),
            encoded,
            "re-encoding is not byte-identical"
        );
    }
}

#[test]
fn kdf_rejects_out_of_range_and_malformed_params() {
    let v = vectors();
    for entry in cases(&v, &["kdf", "invalid"]) {
        assert_rejected(entry, KdfParams::decode(&bytes(entry, "encoded")));
    }
}

#[test]
fn envelope_layout_matches_vectors() {
    let v = vectors();
    let layout = &v["envelope"]["layout"];
    let header = bytes(layout, "header");
    assert_eq!(header, caesar_core::envelope::HEADER);
    assert_eq!(number(layout, "headerOffset"), 0);
    assert_eq!(
        number(layout, "nonceOffset"),
        caesar_core::envelope::HEADER_LEN
    );
    assert_eq!(
        number(layout, "ciphertextOffset"),
        caesar_core::envelope::HEADER_LEN + caesar_core::envelope::NONCE_LEN
    );

    for entry in cases(&v, &["envelope", "valid"]) {
        let name = text(entry, "name");
        let key = key32(entry, "key");
        let nonce = nonce24(entry, "nonce");
        let envelope = bytes(entry, "envelope");
        let plaintext = bytes(entry, "plaintext");

        assert_eq!(envelope.len(), number(entry, "envelopeLength"), "{name}");
        assert_eq!(&envelope[..2], &header[..], "{name} header");
        assert_eq!(&envelope[2..26], &nonce[..], "{name} nonce at offset 2");
        assert_eq!(
            &aead::open(&key, &envelope).expect("vector envelope must open")[..],
            &plaintext[..],
            "{name} plaintext"
        );
        // Байт-в-байт, а не только «открывается»: иначе вектор пропустил бы
        // реализацию с другим AAD или другим порядком полей конверта.
        // `seal_with_nonce` — та же дверь, через которую векторы порождались.
        assert_eq!(
            aead::seal_with_nonce(&key, &nonce, &plaintext).expect("sealing a vector payload"),
            envelope,
            "{name} is not reproducible byte for byte"
        );
    }
}

#[test]
fn envelope_rejects_invalid_vectors() {
    let v = vectors();
    for entry in cases(&v, &["envelope", "invalid"]) {
        let key = key32(entry, "key");
        assert_rejected(entry, aead::open(&key, &bytes(entry, "envelope")));
    }
}

#[test]
fn key_wrapping_matches_vectors() {
    let v = vectors();
    let section = &v["keyWrapping"];
    let kek = caesar_core::KeyEncryptionKey::from_bytes(key32(section, "keyEncryptionKey"));

    let user_entry = &section["userKey"];
    let user_key = vault::unwrap_user_key_verified(
        &kek,
        &bytes(user_entry, "wrapped"),
        &key32(user_entry, "public"),
    )
    .expect("the wrapped user key must unwrap");
    assert_eq!(
        hex::encode(user_key.secret_bytes()),
        text(user_entry, "secret")
    );

    let vault_entry = &section["vaultKey"];
    let vault_key = vault::unwrap_vault_key(&kek, &bytes(vault_entry, "wrapped"))
        .expect("the wrapped vault key must unwrap");
    assert_eq!(
        hex::encode(vault_key.as_bytes()),
        text(vault_entry, "plaintext")
    );
}

#[test]
fn key_wrapping_rejects_invalid_vectors() {
    // `rolledBackUserKey` — единственный случай во всём файле, который тег
    // Poly1305 пропускает: запись честная, просто устаревшая.
    let v = vectors();
    for entry in cases(&v, &["keyWrapping", "invalid"]) {
        let kek = caesar_core::KeyEncryptionKey::from_bytes(key32(entry, "keyEncryptionKey"));
        let wrapped = bytes(entry, "wrapped");
        match entry.get("expectedPublic") {
            Some(_) => assert_rejected(
                entry,
                vault::unwrap_user_key_verified(&kek, &wrapped, &key32(entry, "expectedPublic")),
            ),
            None => assert_rejected(entry, vault::unwrap_vault_key(&kek, &wrapped)),
        }
    }
}

#[test]
fn x25519_key_pairs_match_vectors() {
    let v = vectors();
    for entry in cases(&v, &["x25519", "keyPairs"]) {
        let pair = UserKeyPair::from_secret(key32(entry, "secret"));
        assert_eq!(
            hex::encode(pair.public_bytes()),
            text(entry, "public"),
            "case {}",
            text(entry, "name")
        );
    }
}

#[test]
fn sealed_vault_key_matches_vectors() {
    let v = vectors();
    let entry = &v["x25519"]["sealVaultKeyFor"];
    let recipient = UserKeyPair::from_secret(key32(entry, "recipientSecret"));
    let sealed = bytes(entry, "sealed");
    let ephemeral_len = number(entry, "ephemeralPublicLen");

    assert_eq!(
        hex::encode(recipient.public_bytes()),
        text(entry, "recipientPublic")
    );
    assert_eq!(
        hex::encode(&sealed[..ephemeral_len]),
        text(entry, "ephemeralPublic"),
        "the record starts with the ephemeral public key"
    );

    let vault_key =
        vault::open_vault_key_for(&recipient, &sealed).expect("vector record must open");
    assert_eq!(hex::encode(vault_key.as_bytes()), text(entry, "vaultKey"));

    assert_eq!(
        vault::seal_vault_key_for_with_randomness(
            recipient.public_bytes(),
            &vault_key,
            &key32(entry, "ephemeralSecret"),
            &nonce24(entry, "nonce"),
        )
        .expect("the pinned recipient key has large order"),
        sealed,
        "the shared record is not reproducible byte for byte"
    );
}

#[test]
fn degenerate_recipient_keys_are_rejected() {
    let v = vectors();
    let vault_key = VaultKey::from_bytes([0x07; 32]);
    for entry in cases(&v, &["x25519", "invalidRecipients"]) {
        let public = key32(entry, "recipientPublic");
        assert_rejected(entry, vault::seal_vault_key_for(&public, &vault_key));
    }
}

#[test]
fn sealed_vault_key_rejects_invalid_vectors() {
    let v = vectors();
    for entry in cases(&v, &["x25519", "invalidSealed"]) {
        let recipient = UserKeyPair::from_secret(key32(entry, "recipientSecret"));
        assert_rejected(
            entry,
            vault::open_vault_key_for(&recipient, &bytes(entry, "sealed")),
        );
    }
}

#[test]
fn emergency_kit_formatting_matches_vectors() {
    let v = vectors();
    for entry in cases(&v, &["emergencyKit", "formatted"]) {
        let key = RecoveryKey::from_bytes(key32(entry, "key"));
        let printed = recovery::format_emergency_kit(&key);
        assert_eq!(
            printed.as_str(),
            text(entry, "formatted"),
            "case {}",
            text(entry, "name")
        );
        assert_eq!(printed.chars().count(), number(entry, "printedLength"));
    }
}

#[test]
fn emergency_kit_accepts_human_input_from_vectors() {
    // Подстановка Крокфорда, нижний регистр и разделители — не украшения:
    // реализация, написанная по одному алфавиту, отвергнет ровно эти входы,
    // а человек с верной распечаткой в руках останется без хранилища.
    let v = vectors();
    for entry in cases(&v, &["emergencyKit", "accepted"]) {
        let name = text(entry, "name");
        let parsed = recovery::parse_emergency_kit(text(entry, "input"))
            .unwrap_or_else(|e| panic!("case {name} was rejected: {e}"));
        assert_eq!(hex::encode(parsed.as_bytes()), text(entry, "key"), "{name}");
    }
}

#[test]
fn emergency_kit_rejects_invalid_vectors() {
    let v = vectors();
    for entry in cases(&v, &["emergencyKit", "rejected"]) {
        assert_rejected(entry, recovery::parse_emergency_kit(text(entry, "input")));
    }
}

#[test]
fn item_envelopes_match_vectors() {
    let v = vectors();
    let vault_key = VaultKey::from_bytes(key32(&v["item"], "vaultKey"));

    for entry in cases(&v, &["item", "valid"]) {
        let name = text(entry, "name");
        let envelope = bytes(entry, "envelope");
        let padded = bytes(entry, "paddedPlaintext");

        let item = caesar_core::open_item(&envelope, &vault_key)
            .unwrap_or_else(|e| panic!("case {name} failed to open: {e}"));
        assert_eq!(
            serde_json::to_string(&item).expect("an item is plain JSON"),
            text(entry, "plaintextJson"),
            "{name} plaintext"
        );

        // Раскладка паддинга: `declaredLength(u32 LE) || json || zeros`.
        assert_eq!(padded.len(), number(entry, "paddedLength"), "{name} bucket");
        let declared = u32::from_le_bytes(padded[..4].try_into().expect("bucket is long enough"));
        assert_eq!(
            declared as usize,
            number(entry, "jsonLength"),
            "{name} prefix"
        );
        assert_eq!(
            &padded[4..4 + declared as usize],
            text(entry, "plaintextJson").as_bytes(),
            "{name} json body"
        );
        assert!(
            padded[4 + declared as usize..].iter().all(|&b| b == 0),
            "{name} padding tail must be zero"
        );

        assert_eq!(
            aead::seal_with_nonce(vault_key.as_bytes(), &nonce24(entry, "nonce"), &padded)
                .expect("sealing a vector payload"),
            envelope,
            "{name} is not reproducible byte for byte"
        );
    }
}

#[test]
fn item_padding_buckets_match_vectors() {
    let v = vectors();
    let vault_key = VaultKey::from_bytes(key32(&v["item"], "vaultKey"));

    for entry in cases(&v, &["item", "bucketBoundaries"]) {
        let name = text(entry, "name");
        assert_eq!(text(entry, "kind"), "secureNote");
        let item = ItemSecret::new(
            ItemKind::SecureNote,
            "x".repeat(number(entry, "titleFiller")),
        );

        assert_eq!(
            serde_json::to_vec(&item)
                .expect("an item is plain JSON")
                .len(),
            number(entry, "jsonLength"),
            "{name} json length"
        );
        assert_eq!(
            caesar_core::seal_item(&item, &vault_key)
                .expect("a padded item fits the counter")
                .len(),
            number(entry, "envelopeLength"),
            "{name} envelope length"
        );
    }
}

#[test]
fn item_rejects_invalid_vectors() {
    let v = vectors();
    let vault_key = VaultKey::from_bytes(key32(&v["item"], "vaultKey"));
    for entry in cases(&v, &["item", "invalid"]) {
        assert_rejected(
            entry,
            caesar_core::open_item(&bytes(entry, "envelope"), &vault_key),
        );
    }
}
