use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Конверт создан версией протокола, которую этот клиент не понимает.
    /// Клиент обязан отказаться, а не пытаться разобрать конверт.
    #[error("unsupported protocol version: {found} (this build supports {supported})")]
    UnsupportedVersion { found: u8, supported: u8 },

    #[error("unsupported cipher suite: {found} (this build supports {supported})")]
    UnsupportedSuite { found: u8, supported: u8 },

    #[error("envelope is truncated: got {got} bytes, need at least {need}")]
    Truncated { got: usize, need: usize },

    #[error("decryption failed: wrong key or tampered ciphertext")]
    DecryptionFailed,

    /// Открытый текст длиннее, чем адресует счётчик блоков ChaCha20 (~256 ГиБ).
    /// Недостижимо для реальных данных Caesar, но паниковать нельзя: под
    /// UniFFI это унесло бы хост-приложение целиком.
    #[error("plaintext too large to encrypt")]
    PlaintextTooLarge,

    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("malformed plaintext: {0}")]
    MalformedPlaintext(String),

    #[error("invalid key length: got {got} bytes, expected {expected}")]
    InvalidKeyLength { got: usize, expected: usize },

    #[error("invalid emergency kit: {0}")]
    InvalidEmergencyKit(String),

    #[error("no secure random source available")]
    RandomSourceUnavailable,

    /// Развёрнутый приватный ключ пользователя не сходится с опубликованным
    /// `UK_pub`. После клэмпинга любые 32 байта — валидный секрет X25519,
    /// поэтому порчу ловит тег Poly1305, а откат её переживает: враждебный
    /// сервер отдаёт прошлую, честно завёрнутую запись `encryptedUserKey`,
    /// и без этой сверки клиент молча принял бы устаревшую личность.
    #[error("unwrapped user key does not match the published public key")]
    UserKeyMismatch,

    /// Параметры KDF вне вкомпилированного диапазона: слишком слабые (сервер
    /// пытается получить брутфорсимый `auth_key`) либо слишком тяжёлые
    /// (аллокация на терабайты или счёт на десятки суток).
    #[error("kdf parameters out of the compiled-in range: m={m_cost}, t={t_cost}, p={p_cost}")]
    KdfParamsOutOfRange {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    },
}

/// Redacts detail derived from decrypted plaintext unless `debug-errors` is on.
///
/// serde error messages name vault fields, so they must not reach host logs
/// in release builds of a zero-knowledge product.
pub fn redact_plaintext_detail(detail: impl std::fmt::Display) -> String {
    if cfg!(feature = "debug-errors") {
        detail.to_string()
    } else {
        "redacted (build with the debug-errors feature for detail)".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(feature = "debug-errors"))]
    #[test]
    fn default_build_redacts_plaintext_detail() {
        let detail = "unknown field `totpSecret`, expected one of `login`, `password`";
        let redacted = redact_plaintext_detail(detail);

        assert!(!redacted.contains("totpSecret"));
        assert!(!redacted.contains("password"));
        assert_eq!(
            redacted,
            "redacted (build with the debug-errors feature for detail)"
        );
    }

    #[cfg(feature = "debug-errors")]
    #[test]
    fn debug_errors_build_keeps_plaintext_detail() {
        assert_eq!(
            redact_plaintext_detail("unknown field `totpSecret`"),
            "unknown field `totpSecret`"
        );
    }
}
