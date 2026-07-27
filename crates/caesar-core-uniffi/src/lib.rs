//! UniFFI-обёртка над `caesar-core`. Логики здесь нет — только маршалинг.
//!
//! Крейт отдельный по той же причине, что и `caesar-core-wasm`: макросы UniFFI
//! разворачиваются в `unsafe extern "C"`, а ядро стоит под
//! `#![forbid(unsafe_code)]`. Своего `unsafe` в этом файле нет ни одного;
//! запрет в ядре остаётся на месте.
//!
//! # Чего здесь намеренно нет
//!
//! Тот же список, что и в WASM: не экспортируются `aead::seal_with_nonce`,
//! `vault::seal_vault_key_for_with_randomness`, `UserKeyPair::from_secret`,
//! `UserKeyPair::try_from_slice` и `UserKeyPair::secret_bytes`. Первые две
//! существуют только ради побайтовой воспроизводимости `protocol/vectors.json`
//! и в руках вызывающего означают повторно использованный nonce, то есть полную
//! потерю конфиденциальности XChaCha20-Poly1305. Остальные три отдают наружу
//! приватную половину личности пользователя или принимают её без единственной
//! проверки, которую даёт `unwrap_user_key_verified`.
//!
//! Получить [`UserKeyPair`] в Swift можно ровно двумя способами — сгенерировать
//! новую пару или развернуть уже завёрнутую под KEK. Приватный ключ при этом не
//! пересекает границу ни разу.

use caesar_core::kdf::KdfParams;
use caesar_core::keys::{KeyEncryptionKey, MasterKey, RecoveryKey, VaultKey};
use caesar_core::model::ItemSecret;
use caesar_core::{aead, kdf, model, recovery, vault, Error};
use std::sync::Arc;

uniffi::setup_scaffolding!();

/// # Граница гарантии zeroize
///
/// Ядро отдаёт секреты в `Zeroizing<T>`: буфер затирается при выходе из области
/// видимости. Через границу UniFFI этот тип не проходит — ни `Zeroizing<Vec<u8>>`,
/// ни `Zeroizing<String>` не реализуют `Lower`/`Lift`, и попытка вернуть их
/// наружу не компилируется. Значит, копию всё равно делать придётся, и вопрос
/// только в том, где.
///
/// Здесь. Это единственное место во всём крейте, где секрет копируется из
/// затираемого буфера в обычный, и дальше за его судьбу отвечает уже ARC Swift
/// (или GC на JVM), который ничего не затирает. Оригинал по-прежнему зачищается
/// на выходе из функции, копия — нет. Разбросанные по каждой обёртке `.to_vec()`
/// дали бы ровно тот же результат, но проверять пришлось бы каждую; здесь
/// достаточно проверить, что никто не завёл второй такой модуль.
///
/// Модуль-близнец живёт в `crates/caesar-core-wasm/src/lib.rs`: у каждой границы
/// своя, потому что граница у них разная. Третьей быть не должно.
mod declassify {
    use zeroize::Zeroizing;

    pub fn bytes(secret: Zeroizing<Vec<u8>>) -> Vec<u8> {
        secret.to_vec()
    }

    pub fn string(secret: Zeroizing<String>) -> String {
        String::from(secret.as_str())
    }
}

// ── Ошибки ──────────────────────────────────────────────────────────────────

/// Имя варианта `Error` — контракт `protocol/vectors.json` для всех четырёх
/// языков. Раннеры на Rust и в WASM излагают то же соответствие у себя; это
/// намеренное повторение, а не забытый общий модуль: одна таблица, из которой
/// обе стороны читают, проверяла бы сама себя.
///
/// Отдельный тип, а не строка: хост-приложению в M6′ нужен `switch` с проверкой
/// полноты, а не сравнение литералов. Имя варианта для сверки с файлом векторов
/// отдаёт [`error_code_name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ErrorCode {
    UnsupportedVersion,
    UnsupportedSuite,
    Truncated,
    DecryptionFailed,
    PlaintextTooLarge,
    KeyDerivation,
    MalformedPlaintext,
    UnsupportedItemSchema,
    InvalidKeyLength,
    InvalidEmergencyKit,
    EmergencyKitChecksumMismatch,
    RandomSourceUnavailable,
    UserKeyMismatch,
    DegenerateRecipientKey,
    KdfParamsOutOfRange,
    /// Ошибка сериализации JSON — не ошибка протокола, своего варианта в `Error`
    /// у неё нет, и подмешивать её к вариантам ядра было бы ложью.
    SerializationFailed,
    /// `Error` помечен `#[non_exhaustive]`, поэтому wildcard в маппинге
    /// обязателен. Новый вариант ядра приедет сюда и уронит первый же
    /// отрицательный случай — молча пройти он не может.
    Unknown,
}

/// Имя варианта строкой — ровно то, что пинует `protocol/vectors.json`.
///
/// Источник имени — `Debug` самого варианта: все они unit-подобные, так что
/// вторая таблица «вариант → строка» была бы копией объявления выше, которая
/// расходится с ним молча.
#[uniffi::export]
pub fn error_code_name(code: ErrorCode) -> String {
    format!("{code:?}")
}

/// Ошибка ядра для хоста: машиночитаемый код плюс человекочитаемый текст.
///
/// Один вариант, а не пятнадцать: код — уже перечисление, и дублировать его
/// формой самой ошибки значит завести два места, где список вариантов надо
/// держать в синхроне.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("{code:?}: {message}")]
    Failed { code: ErrorCode, message: String },
}

impl From<Error> for CoreError {
    fn from(err: Error) -> Self {
        let code = match err {
            Error::UnsupportedVersion { .. } => ErrorCode::UnsupportedVersion,
            Error::UnsupportedSuite { .. } => ErrorCode::UnsupportedSuite,
            Error::Truncated { .. } => ErrorCode::Truncated,
            Error::DecryptionFailed => ErrorCode::DecryptionFailed,
            Error::PlaintextTooLarge => ErrorCode::PlaintextTooLarge,
            Error::KeyDerivation(_) => ErrorCode::KeyDerivation,
            Error::MalformedPlaintext(_) => ErrorCode::MalformedPlaintext,
            Error::UnsupportedItemSchema { .. } => ErrorCode::UnsupportedItemSchema,
            Error::InvalidKeyLength { .. } => ErrorCode::InvalidKeyLength,
            Error::InvalidEmergencyKit(_) => ErrorCode::InvalidEmergencyKit,
            Error::EmergencyKitChecksumMismatch => ErrorCode::EmergencyKitChecksumMismatch,
            Error::RandomSourceUnavailable => ErrorCode::RandomSourceUnavailable,
            Error::UserKeyMismatch => ErrorCode::UserKeyMismatch,
            Error::DegenerateRecipientKey => ErrorCode::DegenerateRecipientKey,
            Error::KdfParamsOutOfRange { .. } => ErrorCode::KdfParamsOutOfRange,
            _ => ErrorCode::Unknown,
        };
        Self::Failed {
            code,
            message: err.to_string(),
        }
    }
}

fn serde_err(err: impl std::fmt::Display) -> CoreError {
    CoreError::Failed {
        code: ErrorCode::SerializationFailed,
        message: err.to_string(),
    }
}

type FfiResult<T> = std::result::Result<T, CoreError>;

/// Проверка длины живёт в ядре — здесь только маппинг ошибки.
///
/// `VaultKey` выбран произвольно: `try_from_slice` порождается одним макросом
/// для всех пяти секретных типов, и проверка у них побайтово одна и та же.
fn key32(bytes: &[u8]) -> FfiResult<[u8; 32]> {
    Ok(*VaultKey::try_from_slice(bytes)?.as_bytes())
}

// ── Константы ───────────────────────────────────────────────────────────────

/// Константы протокола одной записью.
///
/// Именно запись, а не два десятка отдельных функций: раннер векторов сверяет
/// весь блок `constants` целиком (в Swift — через `Mirror`), и по одному
/// экспорту на константу — это двадцать пять почти одинаковых обёрток, каждую из
/// которых можно забыть.
///
/// Длины — `u32`, а не `usize`: последний не пересекает границу UniFFI.
#[derive(uniffi::Record)]
pub struct Constants {
    pub protocol_version: u8,
    pub suite_id: u8,
    pub item_schema_version: u8,
    pub kdf_version: u8,
    pub kdf_algo_argon2id: u8,
    pub kdf_params_len: u32,
    pub salt_len: u32,
    pub header_len: u32,
    pub nonce_len: u32,
    pub tag_len: u32,
    pub min_envelope_len: u32,
    pub ephemeral_public_len: u32,
    pub min_m_cost: u32,
    pub min_t_cost: u32,
    pub min_p_cost: u32,
    pub max_m_cost: u32,
    pub max_t_cost: u32,
    pub max_p_cost: u32,
    pub argon2_version: u32,
    pub argon2_version_hex: String,
    pub argon2_output_len: u32,
    pub hkdf_output_len: u32,
    pub hkdf_info_auth: String,
    pub hkdf_info_wrap: String,
    pub hkdf_info_share: String,
}

#[uniffi::export]
pub fn constants() -> Constants {
    Constants {
        protocol_version: caesar_core::PROTOCOL_VERSION,
        suite_id: caesar_core::SUITE_ID,
        item_schema_version: caesar_core::ITEM_SCHEMA_VERSION,
        kdf_version: kdf::KDF_VERSION,
        kdf_algo_argon2id: kdf::KDF_ALGO_ARGON2ID,
        kdf_params_len: kdf::KDF_PARAMS_LEN as u32,
        salt_len: kdf::SALT_LEN as u32,
        header_len: caesar_core::envelope::HEADER_LEN as u32,
        nonce_len: caesar_core::envelope::NONCE_LEN as u32,
        tag_len: caesar_core::envelope::TAG_LEN as u32,
        min_envelope_len: caesar_core::envelope::MIN_ENVELOPE_LEN as u32,
        ephemeral_public_len: vault::EPHEMERAL_PUBLIC_LEN as u32,
        min_m_cost: kdf::MIN_M_COST,
        min_t_cost: kdf::MIN_T_COST,
        min_p_cost: kdf::MIN_P_COST,
        max_m_cost: kdf::MAX_M_COST,
        max_t_cost: kdf::MAX_T_COST,
        max_p_cost: kdf::MAX_P_COST,
        argon2_version: kdf::ARGON2_VERSION_NUMBER,
        argon2_version_hex: format!("0x{:02x}", kdf::ARGON2_VERSION_NUMBER),
        argon2_output_len: kdf::DERIVED_KEY_LEN as u32,
        hkdf_output_len: kdf::DERIVED_KEY_LEN as u32,
        // Домены HKDF — ASCII-байты; из ядра они приходят как `&[u8]`.
        hkdf_info_auth: String::from_utf8_lossy(kdf::INFO_AUTH).into_owned(),
        hkdf_info_wrap: String::from_utf8_lossy(kdf::INFO_WRAP).into_owned(),
        hkdf_info_share: String::from_utf8_lossy(vault::INFO_SHARE).into_owned(),
    }
}

/// Заголовок конверта: он же AAD. Отдельно от [`constants`], потому что это
/// байты, а не число, и раннер сверяет его с префиксом каждого конверта.
#[uniffi::export]
pub fn envelope_header() -> Vec<u8> {
    caesar_core::envelope::HEADER.to_vec()
}

// ── KDF ─────────────────────────────────────────────────────────────────────

#[derive(uniffi::Record)]
pub struct DecodedKdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: Vec<u8>,
    /// Результат обратной упаковки. Кодек обязан быть побайтово обратимым, и
    /// проверить это можно только сравнив с тем, что подали на вход.
    pub reencoded: Vec<u8>,
}

/// Разбирает закодированные параметры KDF. Отказывает ровно там же, где ядро.
#[uniffi::export]
pub fn decode_kdf_params(encoded: Vec<u8>) -> FfiResult<DecodedKdfParams> {
    let params = KdfParams::decode(&encoded)?;
    Ok(DecodedKdfParams {
        m_cost: params.m_cost,
        t_cost: params.t_cost,
        p_cost: params.p_cost,
        salt: params.salt.to_vec(),
        reencoded: params.encode(),
    })
}

/// Выводит мастер-ключ из пароля.
///
/// Параметры принимаются только закодированными: `KdfParams` помечен
/// `#[non_exhaustive]`, собрать его снаружи ядра нельзя, и это единственная
/// дверь — та же, через которую ходят остальные биндинги и раннер векторов.
/// Пароль нормализуется в NFC внутри ядра.
#[uniffi::export]
pub fn derive_master_key(password: String, encoded_params: Vec<u8>) -> FfiResult<Vec<u8>> {
    let params = KdfParams::decode(&encoded_params)?;
    Ok(kdf::derive_master_key(&password, &params)?
        .as_bytes()
        .to_vec())
}

#[uniffi::export]
pub fn auth_key(master_key: Vec<u8>) -> FfiResult<Vec<u8>> {
    let master = MasterKey::from_bytes(key32(&master_key)?);
    Ok(kdf::auth_key(&master).as_bytes().to_vec())
}

#[uniffi::export]
pub fn key_encryption_key(master_key: Vec<u8>) -> FfiResult<Vec<u8>> {
    let master = MasterKey::from_bytes(key32(&master_key)?);
    Ok(kdf::key_encryption_key(&master).as_bytes().to_vec())
}

// ── Конверты ────────────────────────────────────────────────────────────────

#[uniffi::export]
pub fn seal(key: Vec<u8>, plaintext: Vec<u8>) -> FfiResult<Vec<u8>> {
    Ok(aead::seal(&key32(&key)?, &plaintext)?)
}

#[uniffi::export]
pub fn open(key: Vec<u8>, envelope: Vec<u8>) -> FfiResult<Vec<u8>> {
    let plaintext = aead::open(&key32(&key)?, &envelope)?;
    Ok(declassify::bytes(plaintext))
}

// ── Айтемы ──────────────────────────────────────────────────────────────────

/// Сериализует айтем из JSON, дополняет до бакета и шифрует.
#[uniffi::export]
pub fn seal_item(item_json: String, vault_key: Vec<u8>) -> FfiResult<Vec<u8>> {
    let item: ItemSecret = serde_json::from_str(&item_json).map_err(serde_err)?;
    Ok(model::seal_item(
        &item,
        &VaultKey::from_bytes(key32(&vault_key)?),
    )?)
}

/// Расшифровывает айтем и отдаёт его каноническим JSON.
#[uniffi::export]
pub fn open_item(envelope: Vec<u8>, vault_key: Vec<u8>) -> FfiResult<String> {
    let item = model::open_item(&envelope, &VaultKey::from_bytes(key32(&vault_key)?))?;
    serde_json::to_string(&item).map_err(serde_err)
}

// ── Emergency Kit ───────────────────────────────────────────────────────────

#[uniffi::export]
pub fn format_emergency_kit(recovery_key: Vec<u8>) -> FfiResult<String> {
    let printed = recovery::format_emergency_kit(&RecoveryKey::from_bytes(key32(&recovery_key)?));
    Ok(declassify::string(printed))
}

#[uniffi::export]
pub fn parse_emergency_kit(input: String) -> FfiResult<Vec<u8>> {
    Ok(recovery::parse_emergency_kit(&input)?.as_bytes().to_vec())
}

// ── Обёртывание ключей ──────────────────────────────────────────────────────

/// Пара ключей пользователя. Непрозрачна для хоста: приватная половина не
/// пересекает границу ни в одном направлении.
///
/// Получить её можно только [`UserKeyPair::generate`], [`unwrap_user_key`] или
/// [`unwrap_user_key_verified`]. Конструктора из байт нет намеренно: он принял
/// бы любые 32 байта (после клэмпинга X25519 валидны все) и потому не отличает
/// актуальную личность от подставленной.
#[derive(uniffi::Object)]
pub struct UserKeyPair(vault::UserKeyPair);

#[uniffi::export]
impl UserKeyPair {
    /// Генерирует новую пару из системного CSPRNG.
    #[uniffi::constructor]
    pub fn generate() -> FfiResult<Arc<Self>> {
        Ok(Arc::new(Self(vault::UserKeyPair::generate()?)))
    }

    /// Публичная половина. Секрета наружу нет — см. документацию типа.
    pub fn public_bytes(&self) -> Vec<u8> {
        self.0.public_bytes().to_vec()
    }
}

#[uniffi::export]
pub fn wrap_user_key(kek: Vec<u8>, user_key: Arc<UserKeyPair>) -> FfiResult<Vec<u8>> {
    Ok(vault::wrap_user_key(
        &KeyEncryptionKey::from_bytes(key32(&kek)?),
        &user_key.0,
    )?)
}

/// Разворачивает пару без сверки с опубликованной публичной половиной.
///
/// Годится там, где `UK_pub` неоткуда взять. Везде, где он приходит с сервера,
/// нужен [`unwrap_user_key_verified`]: тег Poly1305 ловит порчу, но не откат на
/// прошлую, честно завёрнутую запись.
#[uniffi::export]
pub fn unwrap_user_key(kek: Vec<u8>, wrapped: Vec<u8>) -> FfiResult<Arc<UserKeyPair>> {
    let pair = vault::unwrap_user_key(&KeyEncryptionKey::from_bytes(key32(&kek)?), &wrapped)?;
    Ok(Arc::new(UserKeyPair(pair)))
}

#[uniffi::export]
pub fn unwrap_user_key_verified(
    kek: Vec<u8>,
    wrapped: Vec<u8>,
    expected_public: Vec<u8>,
) -> FfiResult<Arc<UserKeyPair>> {
    // Длина публичного ключа проверяется ядром — второй копии проверки нет.
    let expected = vault::public_key_from_slice(&expected_public)?;
    let pair = vault::unwrap_user_key_verified(
        &KeyEncryptionKey::from_bytes(key32(&kek)?),
        &wrapped,
        &expected,
    )?;
    Ok(Arc::new(UserKeyPair(pair)))
}

#[uniffi::export]
pub fn wrap_vault_key(kek: Vec<u8>, vault_key: Vec<u8>) -> FfiResult<Vec<u8>> {
    Ok(vault::wrap_vault_key(
        &KeyEncryptionKey::from_bytes(key32(&kek)?),
        &VaultKey::from_bytes(key32(&vault_key)?),
    )?)
}

#[uniffi::export]
pub fn unwrap_vault_key(kek: Vec<u8>, wrapped: Vec<u8>) -> FfiResult<Vec<u8>> {
    let key = vault::unwrap_vault_key(&KeyEncryptionKey::from_bytes(key32(&kek)?), &wrapped)?;
    Ok(key.as_bytes().to_vec())
}

// ── Разделение хранилища через X25519 ───────────────────────────────────────

/// Шифрует ключ хранилища на публичный ключ участника.
///
/// Эфемерный ключ и nonce берутся из CSPRNG внутри ядра: версия с внешней
/// случайностью существует только для генератора векторов и наружу не выведена.
#[uniffi::export]
pub fn seal_vault_key_for(recipient_public: Vec<u8>, vault_key: Vec<u8>) -> FfiResult<Vec<u8>> {
    let recipient = vault::public_key_from_slice(&recipient_public)?;
    Ok(vault::seal_vault_key_for(
        &recipient,
        &VaultKey::from_bytes(key32(&vault_key)?),
    )?)
}

#[uniffi::export]
pub fn open_vault_key_for(recipient: Arc<UserKeyPair>, sealed: Vec<u8>) -> FfiResult<Vec<u8>> {
    let key = vault::open_vault_key_for(&recipient.0, &sealed)?;
    Ok(key.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Имя, которое видит Swift, — это имя варианта ядра, а не текст ошибки.
    #[test]
    fn error_codes_carry_the_core_variant_name() {
        let err: CoreError = Error::UserKeyMismatch.into();
        let CoreError::Failed { code, message } = err;
        assert_eq!(error_code_name(code), "UserKeyMismatch");
        assert_eq!(message, Error::UserKeyMismatch.to_string());
    }

    /// Пол/потолок Argon2id отказывают до аллокации — иначе хост-приложение
    /// умирает в `handle_alloc_error`, а не получает `Err`.
    #[test]
    fn out_of_range_params_surface_their_code() {
        let mut encoded = vec![0u8; kdf::KDF_PARAMS_LEN];
        encoded[0] = kdf::KDF_VERSION;
        encoded[1] = kdf::KDF_ALGO_ARGON2ID;
        let Err(CoreError::Failed { code, .. }) = decode_kdf_params(encoded) else {
            panic!("all-zero parameters were accepted");
        };
        assert_eq!(error_code_name(code), "KdfParamsOutOfRange");
    }
}
