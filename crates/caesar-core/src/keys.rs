use zeroize::{Zeroize, ZeroizeOnDrop};

/// Объявляет 32-байтный ключ, который зачищается при выходе из области видимости.
///
/// Каждый вызов создаёт отдельный тип, а не псевдоним. Это не средство защиты,
/// а страховка от перепутанных аргументов: компилятор не даст передать `AuthKey`
/// туда, где ожидается `KeyEncryptionKey`, хотя оба — 32 байта. Гарантию того,
/// что из `AuthKey` нельзя получить `KeyEncryptionKey`, даёт доменное разделение
/// в HKDF (задача 4), а не система типов.
macro_rules! secret_key {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Строит ключ из среза произвольной длины. Единственная точка проверки
            /// длины: биндинги в задачах 11 и 13 переиспользуют её вместо своих копий.
            pub fn try_from_slice(bytes: &[u8]) -> crate::Result<Self> {
                let bytes: [u8; 32] =
                    bytes
                        .try_into()
                        .map_err(|_| crate::Error::InvalidKeyLength {
                            got: bytes.len(),
                            expected: 32,
                        })?;
                Ok(Self(bytes))
            }

            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Генерирует ключ из системного CSPRNG.
            pub fn generate() -> crate::Result<Self> {
                use rand_core::{OsRng, RngCore};
                let mut key = Self([0u8; 32]);
                OsRng
                    .try_fill_bytes(&mut key.0)
                    .map_err(|_| crate::Error::RandomSourceUnavailable)?;
                Ok(key)
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

    fn _assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn generated_keys_differ() {
        let a = VaultKey::generate().unwrap();
        let b = VaultKey::generate().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn debug_output_hides_key_material() {
        macro_rules! assert_redacted {
            ($ty:ident) => {{
                let key = $ty::from_bytes([0x42; 32]);
                let rendered = format!("{key:?}");
                assert_eq!(rendered, concat!(stringify!($ty), "([redacted])"));
                assert!(!rendered.contains("42"));
            }};
        }

        assert_redacted!(MasterKey);
        assert_redacted!(AuthKey);
        assert_redacted!(KeyEncryptionKey);
        assert_redacted!(VaultKey);
        assert_redacted!(RecoveryKey);
    }

    #[test]
    fn all_key_types_zeroize_on_drop() {
        _assert_zeroize_on_drop::<MasterKey>();
        _assert_zeroize_on_drop::<AuthKey>();
        _assert_zeroize_on_drop::<KeyEncryptionKey>();
        _assert_zeroize_on_drop::<VaultKey>();
        _assert_zeroize_on_drop::<RecoveryKey>();
    }

    #[test]
    fn round_trips_through_bytes() {
        let bytes = [7u8; 32];
        assert_eq!(KeyEncryptionKey::from_bytes(bytes).as_bytes(), &bytes);
    }

    #[test]
    fn try_from_slice_accepts_exact_length() {
        let bytes = [9u8; 32];
        let key = AuthKey::try_from_slice(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn try_from_slice_rejects_wrong_length() {
        let err = AuthKey::try_from_slice(&[0u8; 16]).unwrap_err();
        assert_eq!(
            err,
            crate::Error::InvalidKeyLength {
                got: 16,
                expected: 32
            }
        );
    }
}
