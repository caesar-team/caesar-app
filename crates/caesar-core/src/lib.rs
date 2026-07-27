#![forbid(unsafe_code)]

//! Caesar core: единственная реализация криптографии Caesar.
//!
//! Крейт не содержит сети, хранилища и UI. Все функции — от байтов к байтам.

pub mod aead;
pub mod envelope;
pub mod error;
pub mod kdf;
pub mod keys;
pub mod vault;

pub use aead::{open, seal};
pub use error::{Error, Result};
pub use kdf::{auth_key, derive_master_key, key_encryption_key, KdfParams};
pub use keys::{AuthKey, KeyEncryptionKey, MasterKey, RecoveryKey, VaultKey};
pub use vault::{unwrap_user_key, unwrap_vault_key, wrap_user_key, wrap_vault_key, UserKeyPair};

/// Версия формата конверта. Меняется только при смене формата шифрования.
pub const PROTOCOL_VERSION: u8 = 1;

/// Идентификатор криптографической сюиты: Argon2id + XChaCha20-Poly1305 + X25519.
pub const SUITE_ID: u8 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_constants_are_pinned() {
        // Эти значения попадают в каждый конверт на диске и у пользователей.
        // Изменение любого из них — ломающее изменение формата.
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(SUITE_ID, 1);
    }
}
