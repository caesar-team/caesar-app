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
}
