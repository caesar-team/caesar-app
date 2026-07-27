#![forbid(unsafe_code)]

//! Caesar core: единственная реализация криптографии Caesar.
//!
//! Крейт не содержит сети, хранилища и UI. Все функции — от байтов к байтам.

pub mod error;

pub use error::{Error, Result};

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
