use zeroize::{Zeroize, ZeroizeOnDrop};

/// Объявляет 32-байтный ключ, который зачищается при выходе из области видимости.
///
/// Каждый вызов создаёт отдельный тип, а не псевдоним: система типов не даст
/// передать `AuthKey` туда, где ожидается `KeyEncryptionKey`, хотя оба — 32 байта.
macro_rules! secret_key {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Генерирует ключ из системного CSPRNG.
            pub fn generate() -> Self {
                use rand_core::{OsRng, RngCore};
                let mut bytes = [0u8; 32];
                OsRng.fill_bytes(&mut bytes);
                Self(bytes)
            }
        }

        // Ключи никогда не попадают в логи.
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

secret_key!(
    MasterKey,
    "Выводится из мастер-пароля. Не покидает устройство."
);
secret_key!(AuthKey, "Уходит на сервер как пароль Better Auth.");
secret_key!(
    KeyEncryptionKey,
    "Оборачивает UK и VK. Не покидает устройство."
);
secret_key!(VaultKey, "Шифрует айтемы одного хранилища.");
secret_key!(
    RecoveryKey,
    "Второй путь обёртки UK и VK. Печатается в Emergency Kit."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_differ() {
        let a = VaultKey::generate();
        let b = VaultKey::generate();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn debug_output_hides_key_material() {
        let key = MasterKey::from_bytes([0x42; 32]);
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "MasterKey([redacted])");
        assert!(!rendered.contains("42"));
    }

    #[test]
    fn round_trips_through_bytes() {
        let bytes = [7u8; 32];
        assert_eq!(KeyEncryptionKey::from_bytes(bytes).as_bytes(), &bytes);
    }
}
