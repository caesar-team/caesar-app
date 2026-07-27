//! WASM-обёртка над `caesar-core`. Логики здесь нет — только маршалинг.
//!
//! # Чего здесь намеренно нет
//!
//! Крейт не экспортирует `aead::seal_with_nonce`,
//! `vault::seal_vault_key_for_with_randomness`, `UserKeyPair::from_secret`,
//! `UserKeyPair::try_from_slice` и `UserKeyPair::secret_bytes`. Первые две
//! существуют только ради побайтовой воспроизводимости `protocol/vectors.json`
//! и в руках вызывающего означают повторно использованный nonce, то есть полную
//! потерю конфиденциальности XChaCha20-Poly1305. Остальные три отдают наружу
//! приватную половину личности пользователя или принимают её без единственной
//! проверки, которую даёт `unwrap_user_key_verified`.
//!
//! Взамен наружу выведены `generate()` и функции разворачивания: получить
//! [`UserKeyPair`] в JS можно ровно двумя способами — сгенерировать новую пару
//! или развернуть уже завёрнутую под KEK. Приватный ключ при этом не пересекает
//! границу ни разу.
//!
//! # `unsafe`
//!
//! В отличие от `caesar-core`, здесь нет `#![forbid(unsafe_code)]`: макрос
//! `#[wasm_bindgen]` разворачивается в `unsafe impl` и `unsafe extern "C"`,
//! и запрет уронил бы сборку на сгенерированном коде, а не на нашем. Своего
//! `unsafe` в этом файле нет ни одного; запрет в ядре остаётся на месте.

use caesar_core::kdf::KdfParams;
use caesar_core::keys::{KeyEncryptionKey, MasterKey, RecoveryKey, VaultKey};
use caesar_core::model::ItemSecret;
use caesar_core::{aead, kdf, model, recovery, vault, Error};
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// # Граница гарантии zeroize
///
/// Ядро отдаёт секреты в `Zeroizing<T>`: буфер затирается при выходе из
/// области видимости. Через границу wasm-bindgen этот тип не проходит — ни
/// `Zeroizing<Vec<u8>>`, ни `Zeroizing<String>` не реализуют нужные трейты, и
/// попытка вернуть их наружу не компилируется. Значит, копию всё равно делать
/// придётся, и вопрос только в том, где.
///
/// Здесь. Это единственное место во всём крейте, где секрет копируется из
/// затираемого буфера в обычный, и дальше за его судьбу отвечает уже
/// сборщик мусора JS, который ничего не затирает. Оригинал по-прежнему
/// зачищается на выходе из функции, копия — нет. Разбросанные по каждой
/// обёртке `.to_vec()` дали бы ровно тот же результат, но проверять пришлось бы
/// каждую; здесь достаточно проверить, что никто не завёл второй такой модуль.
mod declassify {
    use zeroize::Zeroizing;

    pub fn bytes(secret: Zeroizing<Vec<u8>>) -> Vec<u8> {
        secret.to_vec()
    }

    pub fn string(secret: Zeroizing<String>) -> String {
        String::from(secret.as_str())
    }
}

/// Имя варианта `Error` — контракт `protocol/vectors.json` для всех четырёх
/// языков. Раннер на Rust излагает то же соответствие у себя; это намеренное
/// повторение, а не забытый общий модуль: одна таблица, из которой обе стороны
/// читают, проверяла бы сама себя.
///
/// Wildcard обязателен: `Error` помечен `#[non_exhaustive]`. Новый вариант
/// приедет сюда как `"Unknown"` и уронит первый же отрицательный случай.
fn error_code(err: &Error) -> &'static str {
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

/// Ошибка ядра приезжает в JS обычным `Error`, у которого `name` — имя
/// варианта, а `message` — текст ядра. Отдельного типа-обёртки нет: `throw`
/// не-`Error` объектом ломает и стектрейсы, и `instanceof` на стороне JS.
fn js_err(err: Error) -> JsValue {
    let js = js_sys::Error::new(&err.to_string());
    js.set_name(error_code(&err));
    js.into()
}

/// Ошибка сериализации JSON — не ошибка протокола, своего варианта в `Error`
/// у неё нет, и подмешивать её в таблицу выше было бы ложью.
fn js_serde_err(err: impl std::fmt::Display) -> JsValue {
    let js = js_sys::Error::new(&err.to_string());
    js.set_name("SerializationFailed");
    js.into()
}

/// Проверка длины живёт в ядре — здесь только маппинг ошибки.
///
/// `VaultKey` выбран произвольно: `try_from_slice` порождается одним макросом
/// для всех пяти секретных типов, и проверка у них побайтово одна и та же.
fn key32(bytes: &[u8]) -> Result<[u8; 32], JsValue> {
    Ok(*VaultKey::try_from_slice(bytes).map_err(js_err)?.as_bytes())
}

// ── Константы ───────────────────────────────────────────────────────────────

/// Константы протокола одним объектом.
///
/// Именно объект, а не два десятка отдельных функций: раннер векторов сверяет
/// весь блок `constants` целиком, и по одному экспорту на константу — это
/// двадцать пять почти одинаковых обёрток, каждую из которых можно забыть.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Constants {
    protocol_version: u8,
    suite_id: u8,
    item_schema_version: u8,
    kdf_version: u8,
    kdf_algo_argon2id: u8,
    kdf_params_len: usize,
    salt_len: usize,
    header_len: usize,
    nonce_len: usize,
    tag_len: usize,
    min_envelope_len: usize,
    ephemeral_public_len: usize,
    min_m_cost: u32,
    min_t_cost: u32,
    min_p_cost: u32,
    max_m_cost: u32,
    max_t_cost: u32,
    max_p_cost: u32,
    argon2_version: u32,
    argon2_version_hex: String,
    argon2_output_len: usize,
    hkdf_output_len: usize,
    hkdf_info_auth: String,
    hkdf_info_wrap: String,
    hkdf_info_share: String,
}

#[wasm_bindgen]
pub fn constants() -> Result<JsValue, JsValue> {
    let c = Constants {
        protocol_version: caesar_core::PROTOCOL_VERSION,
        suite_id: caesar_core::SUITE_ID,
        item_schema_version: caesar_core::ITEM_SCHEMA_VERSION,
        kdf_version: kdf::KDF_VERSION,
        kdf_algo_argon2id: kdf::KDF_ALGO_ARGON2ID,
        kdf_params_len: kdf::KDF_PARAMS_LEN,
        salt_len: kdf::SALT_LEN,
        header_len: caesar_core::envelope::HEADER_LEN,
        nonce_len: caesar_core::envelope::NONCE_LEN,
        tag_len: caesar_core::envelope::TAG_LEN,
        min_envelope_len: caesar_core::envelope::MIN_ENVELOPE_LEN,
        ephemeral_public_len: vault::EPHEMERAL_PUBLIC_LEN,
        min_m_cost: kdf::MIN_M_COST,
        min_t_cost: kdf::MIN_T_COST,
        min_p_cost: kdf::MIN_P_COST,
        max_m_cost: kdf::MAX_M_COST,
        max_t_cost: kdf::MAX_T_COST,
        max_p_cost: kdf::MAX_P_COST,
        argon2_version: kdf::ARGON2_VERSION_NUMBER,
        argon2_version_hex: format!("0x{:02x}", kdf::ARGON2_VERSION_NUMBER),
        argon2_output_len: kdf::DERIVED_KEY_LEN,
        hkdf_output_len: kdf::DERIVED_KEY_LEN,
        // Домены HKDF — ASCII-байты; из ядра они приходят как `&[u8]`.
        hkdf_info_auth: String::from_utf8_lossy(kdf::INFO_AUTH).into_owned(),
        hkdf_info_wrap: String::from_utf8_lossy(kdf::INFO_WRAP).into_owned(),
        hkdf_info_share: String::from_utf8_lossy(vault::INFO_SHARE).into_owned(),
    };
    serde_wasm_bindgen::to_value(&c).map_err(js_serde_err)
}

/// Заголовок конверта: он же AAD. Отдельно от [`constants`], потому что это
/// байты, а не число, и раннер сверяет его с префиксом каждого конверта.
#[wasm_bindgen(js_name = envelopeHeader)]
pub fn envelope_header() -> Vec<u8> {
    caesar_core::envelope::HEADER.to_vec()
}

// ── KDF ─────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DecodedKdfParams {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: Vec<u8>,
    /// Результат обратной упаковки. Кодек обязан быть побайтово обратимым, и
    /// проверить это можно только сравнив с тем, что подали на вход.
    reencoded: Vec<u8>,
}

/// Разбирает закодированные параметры KDF. Отказывает ровно там же, где ядро.
#[wasm_bindgen(js_name = decodeKdfParams)]
pub fn decode_kdf_params(encoded: &[u8]) -> Result<JsValue, JsValue> {
    let params = KdfParams::decode(encoded).map_err(js_err)?;
    let decoded = DecodedKdfParams {
        m_cost: params.m_cost,
        t_cost: params.t_cost,
        p_cost: params.p_cost,
        salt: params.salt.to_vec(),
        reencoded: params.encode(),
    };
    serde_wasm_bindgen::to_value(&decoded).map_err(js_serde_err)
}

/// Выводит мастер-ключ из пароля.
///
/// Параметры принимаются только закодированными: `KdfParams` помечен
/// `#[non_exhaustive]`, собрать его снаружи ядра нельзя, и это единственная
/// дверь — та же, через которую ходят биндинги и раннер векторов. Пароль
/// нормализуется в NFC внутри ядра.
#[wasm_bindgen(js_name = deriveMasterKey)]
pub fn derive_master_key(password: &str, encoded_params: &[u8]) -> Result<Vec<u8>, JsValue> {
    let params = KdfParams::decode(encoded_params).map_err(js_err)?;
    let master = kdf::derive_master_key(password, &params).map_err(js_err)?;
    Ok(master.as_bytes().to_vec())
}

#[wasm_bindgen(js_name = authKey)]
pub fn auth_key(master_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let master = MasterKey::from_bytes(key32(master_key)?);
    Ok(kdf::auth_key(&master).as_bytes().to_vec())
}

#[wasm_bindgen(js_name = keyEncryptionKey)]
pub fn key_encryption_key(master_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let master = MasterKey::from_bytes(key32(master_key)?);
    Ok(kdf::key_encryption_key(&master).as_bytes().to_vec())
}

// ── Конверты ────────────────────────────────────────────────────────────────

#[wasm_bindgen]
pub fn seal(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsValue> {
    aead::seal(&key32(key)?, plaintext).map_err(js_err)
}

#[wasm_bindgen]
pub fn open(key: &[u8], envelope: &[u8]) -> Result<Vec<u8>, JsValue> {
    let plaintext = aead::open(&key32(key)?, envelope).map_err(js_err)?;
    Ok(declassify::bytes(plaintext))
}

// ── Айтемы ──────────────────────────────────────────────────────────────────

/// Сериализует айтем из JSON, дополняет до бакета и шифрует.
#[wasm_bindgen(js_name = sealItem)]
pub fn seal_item(item_json: &str, vault_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let item: ItemSecret = serde_json::from_str(item_json).map_err(js_serde_err)?;
    model::seal_item(&item, &VaultKey::from_bytes(key32(vault_key)?)).map_err(js_err)
}

/// Расшифровывает айтем и отдаёт его каноническим JSON.
#[wasm_bindgen(js_name = openItem)]
pub fn open_item(envelope: &[u8], vault_key: &[u8]) -> Result<String, JsValue> {
    let item =
        model::open_item(envelope, &VaultKey::from_bytes(key32(vault_key)?)).map_err(js_err)?;
    serde_json::to_string(&item).map_err(js_serde_err)
}

// ── Emergency Kit ───────────────────────────────────────────────────────────

#[wasm_bindgen(js_name = formatEmergencyKit)]
pub fn format_emergency_kit(recovery_key: &[u8]) -> Result<String, JsValue> {
    let printed = recovery::format_emergency_kit(&RecoveryKey::from_bytes(key32(recovery_key)?));
    Ok(declassify::string(printed))
}

#[wasm_bindgen(js_name = parseEmergencyKit)]
pub fn parse_emergency_kit(input: &str) -> Result<Vec<u8>, JsValue> {
    let key = recovery::parse_emergency_kit(input).map_err(js_err)?;
    Ok(key.as_bytes().to_vec())
}

// ── Обёртывание ключей ──────────────────────────────────────────────────────

/// Пара ключей пользователя. Непрозрачна для JS: приватная половина не
/// пересекает границу ни в одном направлении.
///
/// Получить её можно только [`UserKeyPair::generate`], [`unwrap_user_key`] или
/// [`unwrap_user_key_verified`]. Конструктора из байт нет намеренно: он принял
/// бы любые 32 байта (после клэмпинга X25519 валидны все) и потому не отличает
/// актуальную личность от подставленной.
#[wasm_bindgen]
pub struct UserKeyPair(vault::UserKeyPair);

#[wasm_bindgen]
impl UserKeyPair {
    /// Генерирует новую пару из системного CSPRNG.
    pub fn generate() -> Result<UserKeyPair, JsValue> {
        vault::UserKeyPair::generate()
            .map(UserKeyPair)
            .map_err(js_err)
    }

    /// Публичная половина. Секрета наружу нет — см. документацию типа.
    #[wasm_bindgen(js_name = publicBytes)]
    pub fn public_bytes(&self) -> Vec<u8> {
        self.0.public_bytes().to_vec()
    }
}

#[wasm_bindgen(js_name = wrapUserKey)]
pub fn wrap_user_key(kek: &[u8], user_key: &UserKeyPair) -> Result<Vec<u8>, JsValue> {
    vault::wrap_user_key(&KeyEncryptionKey::from_bytes(key32(kek)?), &user_key.0).map_err(js_err)
}

/// Разворачивает пару без сверки с опубликованной публичной половиной.
///
/// Годится там, где `UK_pub` неоткуда взять. Везде, где он приходит с сервера,
/// нужен [`unwrap_user_key_verified`]: тег Poly1305 ловит порчу, но не откат на
/// прошлую, честно завёрнутую запись.
#[wasm_bindgen(js_name = unwrapUserKey)]
pub fn unwrap_user_key(kek: &[u8], wrapped: &[u8]) -> Result<UserKeyPair, JsValue> {
    vault::unwrap_user_key(&KeyEncryptionKey::from_bytes(key32(kek)?), wrapped)
        .map(UserKeyPair)
        .map_err(js_err)
}

#[wasm_bindgen(js_name = unwrapUserKeyVerified)]
pub fn unwrap_user_key_verified(
    kek: &[u8],
    wrapped: &[u8],
    expected_public: &[u8],
) -> Result<UserKeyPair, JsValue> {
    // Длина публичного ключа проверяется ядром — второй копии проверки нет.
    let expected = vault::public_key_from_slice(expected_public).map_err(js_err)?;
    vault::unwrap_user_key_verified(
        &KeyEncryptionKey::from_bytes(key32(kek)?),
        wrapped,
        &expected,
    )
    .map(UserKeyPair)
    .map_err(js_err)
}

#[wasm_bindgen(js_name = wrapVaultKey)]
pub fn wrap_vault_key(kek: &[u8], vault_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    vault::wrap_vault_key(
        &KeyEncryptionKey::from_bytes(key32(kek)?),
        &VaultKey::from_bytes(key32(vault_key)?),
    )
    .map_err(js_err)
}

#[wasm_bindgen(js_name = unwrapVaultKey)]
pub fn unwrap_vault_key(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, JsValue> {
    let key = vault::unwrap_vault_key(&KeyEncryptionKey::from_bytes(key32(kek)?), wrapped)
        .map_err(js_err)?;
    Ok(key.as_bytes().to_vec())
}

// ── Разделение хранилища через X25519 ───────────────────────────────────────

/// Шифрует ключ хранилища на публичный ключ участника.
///
/// Эфемерный ключ и nonce берутся из CSPRNG внутри ядра: версия с внешней
/// случайностью существует только для генератора векторов и наружу не выведена.
#[wasm_bindgen(js_name = sealVaultKeyFor)]
pub fn seal_vault_key_for(recipient_public: &[u8], vault_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let recipient = vault::public_key_from_slice(recipient_public).map_err(js_err)?;
    vault::seal_vault_key_for(&recipient, &VaultKey::from_bytes(key32(vault_key)?)).map_err(js_err)
}

#[wasm_bindgen(js_name = openVaultKeyFor)]
pub fn open_vault_key_for(recipient: &UserKeyPair, sealed: &[u8]) -> Result<Vec<u8>, JsValue> {
    let key = vault::open_vault_key_for(&recipient.0, sealed).map_err(js_err)?;
    Ok(key.as_bytes().to_vec())
}
