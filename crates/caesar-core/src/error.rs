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
