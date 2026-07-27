use crate::aead;
use crate::keys::{KeyEncryptionKey, VaultKey};
use crate::{Error, Result};
use zeroize::ZeroizeOnDrop;

/// Пара ключей пользователя. Долгоживущая личность: именно она делает
/// командный доступ возможным без раскрытия VK серверу.
///
/// Приватный ключ хранится сырыми байтами, а не как `StaticSecret`: обёртка
/// нужна только на время скалярного умножения, а на диск и в биндинги уходят
/// именно 32 байта. `ZeroizeOnDrop` затирает их; публичный ключ пропущен —
/// он не секрет и нужен в `Debug`.
#[derive(ZeroizeOnDrop)]
pub struct UserKeyPair {
    secret: [u8; 32],
    #[zeroize(skip)]
    public: [u8; 32],
}

/// Выводит публичную половину X25519. Единственное место, где приватный ключ
/// вообще попадает в `StaticSecret`.
///
/// `StaticSecret` реализует `ZeroizeOnDrop` не безусловно, а под фичей
/// `zeroize` крейта: она приходит из его default-фич и потому явно закреплена в
/// корневом `Cargo.toml`. Без неё клэмпнутая копия ключа осталась бы на стеке.
fn public_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};

    let sk = StaticSecret::from(*secret);
    PublicKey::from(&sk).to_bytes()
}

impl UserKeyPair {
    /// Генерирует пару из системного CSPRNG.
    ///
    /// Отказ CSPRNG — это `Err`, а не паника: под wasm и UniFFI паника уносит
    /// весь модуль или хост-приложение. Та же схема, что в `keys.rs` и `kdf.rs`.
    pub fn generate() -> Result<Self> {
        use rand_core::{OsRng, RngCore};

        // Выход CSPRNG пишется сразу в итоговую структуру, без промежуточного
        // буфера: копировать нечего, значит и нечему пережить возврат. Та же
        // форма, что у `generate()` в `keys.rs`.
        let mut kp = Self {
            secret: [0u8; 32],
            public: [0u8; 32],
        };
        OsRng
            .try_fill_bytes(&mut kp.secret)
            .map_err(|_| Error::RandomSourceUnavailable)?;
        kp.public = public_from_secret(&kp.secret);
        Ok(kp)
    }

    /// Восстанавливает пару по приватному ключу. Публичный всегда выводится
    /// заново, а не принимается снаружи: пара, у которой половинки не сходятся,
    /// не должна существовать.
    ///
    /// # Не для биндингов
    ///
    /// Принимает произвольные 32 байта и не может отличить ключ от мусора:
    /// `from_secret([0u8; 32])` даёт валидную пару, которую воспроизведёт кто
    /// угодно, и сообщить об этом наружу нечем — тип возврата без ошибки.
    /// Внутри крейта это нужно (генератор векторов задачи 10). Биндинги задач
    /// 11 и 13 обязаны выставлять только `generate()` и `unwrap_user_key()`;
    /// ни `from_secret`, ни `try_from_slice` через UniFFI или wasm-bindgen не
    /// экспортируются.
    pub fn from_secret(secret: [u8; 32]) -> Self {
        let public = public_from_secret(&secret);
        Self { secret, public }
    }

    /// Строит пару из среза произвольной длины. Единственная точка проверки
    /// длины: `unwrap_user_key` и биндинги задач 11 и 13 ходят сюда, а не
    /// заводят свои копии. Зеркалит `try_from_slice` из `keys.rs`.
    ///
    /// Наружу не экспортируется по тем же причинам, что и [`Self::from_secret`].
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        let secret: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidKeyLength {
            got: bytes.len(),
            expected: 32,
        })?;
        Ok(Self::from_secret(secret))
    }

    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

// Приватный ключ никогда не попадает в логи. Публичный печатается целиком:
// это идентификатор участника, по нему и различают пары в отладке.
impl std::fmt::Debug for UserKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserKeyPair { public: ")?;
        for byte in &self.public {
            write!(f, "{byte:02x}")?;
        }
        f.write_str(", secret: [redacted] }")
    }
}

/// Оборачивает приватный ключ пользователя ключом обёртки.
pub fn wrap_user_key(kek: &KeyEncryptionKey, user_key: &UserKeyPair) -> Result<Vec<u8>> {
    aead::seal(kek.as_bytes(), user_key.secret_bytes())
}

pub fn unwrap_user_key(kek: &KeyEncryptionKey, wrapped: &[u8]) -> Result<UserKeyPair> {
    // `aead::open` отдаёт `Zeroizing`, поэтому расшифрованный приватный ключ
    // затирается, даже если проверка длины ниже провалится.
    let secret = aead::open(kek.as_bytes(), wrapped)?;
    UserKeyPair::try_from_slice(&secret)
}

/// Оборачивает ключ хранилища. Один vault даёт одну такую запись.
pub fn wrap_vault_key(kek: &KeyEncryptionKey, vault_key: &VaultKey) -> Result<Vec<u8>> {
    aead::seal(kek.as_bytes(), vault_key.as_bytes())
}

pub fn unwrap_vault_key(kek: &KeyEncryptionKey, wrapped: &[u8]) -> Result<VaultKey> {
    let raw = aead::open(kek.as_bytes(), wrapped)?;
    VaultKey::try_from_slice(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{derive_master_key, key_encryption_key, KdfParams, SALT_LEN};
    use std::collections::BTreeMap;

    fn kek_for(password: &str, salt: [u8; SALT_LEN]) -> KeyEncryptionKey {
        let params = KdfParams {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 4,
            salt,
        };
        key_encryption_key(&derive_master_key(password, &params).unwrap())
    }

    fn test_kek() -> KeyEncryptionKey {
        kek_for("pw", [0x5A; SALT_LEN])
    }

    fn _assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn user_key_pair_zeroizes_on_drop() {
        _assert_zeroize_on_drop::<UserKeyPair>();
    }

    #[test]
    fn public_key_is_derived_from_secret() {
        // Вектор из RFC 7748 §6.1 (ключ Алисы), а не прогон этой же реализации:
        // он ловит и потерянный клэмпинг, и перепутанный порядок байт, и
        // подмену X25519 на «публичный = приватный». Проверка «два вызова дали
        // одно и то же» ничего из этого не увидела бы.
        let secret =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap();
        let kp = UserKeyPair::try_from_slice(&secret).unwrap();
        assert_eq!(
            hex::encode(kp.public_bytes()),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(kp.secret_bytes()[..], secret[..]);
    }

    #[test]
    fn user_key_round_trips_through_wrapping() {
        let kek = test_kek();
        let kp = UserKeyPair::generate().unwrap();
        let wrapped = wrap_user_key(&kek, &kp).unwrap();
        let restored = unwrap_user_key(&kek, &wrapped).unwrap();
        assert_eq!(restored.secret_bytes(), kp.secret_bytes());
        assert_eq!(restored.public_bytes(), kp.public_bytes());
    }

    #[test]
    fn vault_key_round_trips_through_wrapping() {
        let kek = test_kek();
        let vk = VaultKey::generate().unwrap();
        let wrapped = wrap_vault_key(&kek, &vk).unwrap();
        assert_eq!(
            unwrap_vault_key(&kek, &wrapped).unwrap().as_bytes(),
            vk.as_bytes()
        );
    }

    #[test]
    fn unwrapping_with_the_wrong_kek_fails() {
        let wrapped = wrap_vault_key(&test_kek(), &VaultKey::generate().unwrap()).unwrap();
        let stranger = kek_for("other pw", [0x5A; SALT_LEN]);
        assert_eq!(
            unwrap_vault_key(&stranger, &wrapped).unwrap_err(),
            Error::DecryptionFailed
        );
    }

    #[test]
    fn unwrapping_rejects_a_payload_of_the_wrong_length() {
        // Тег сошёлся, но внутри не ключ: запись сделана сломанным писателем
        // или форматом другой версии. Молча взять первые 32 байта нельзя.
        let kek = test_kek();
        let wrapped = aead::seal(kek.as_bytes(), &[7u8; 16]).unwrap();
        assert_eq!(
            unwrap_vault_key(&kek, &wrapped).unwrap_err(),
            Error::InvalidKeyLength {
                got: 16,
                expected: 32
            }
        );
        assert_eq!(
            unwrap_user_key(&kek, &wrapped).unwrap_err(),
            Error::InvalidKeyLength {
                got: 16,
                expected: 32
            }
        );
    }

    #[test]
    fn wrapped_record_layout_is_pinned() {
        // Обёрнутая запись — конверт ровно над 32 байтами ключа, без длин,
        // padding и прочих полей. Эти байты лежат у пользователей на сервере:
        // любое изменение формы делает их нечитаемыми.
        //
        // 74 = 2 (заголовок) + 24 (nonce) + 32 (ключ) + 16 (тег). Литерал
        // намеренный: `MIN_ENVELOPE_LEN + 32` поехало бы следом за константой и
        // не заметило бы ровно ту правку, ради которой этот тест существует.
        // Не «упрощать», как и смещения в `envelope.rs`.
        let kek = test_kek();
        let uk = wrap_user_key(&kek, &UserKeyPair::generate().unwrap()).unwrap();
        let vk = wrap_vault_key(&kek, &VaultKey::generate().unwrap()).unwrap();
        assert_eq!(uk.len(), 74);
        assert_eq!(vk.len(), 74);
    }

    /// Модель серверного хранилища: имя записи → её байты.
    type Store = BTreeMap<&'static str, Vec<u8>>;

    /// Смена мастер-пароля так, как её обязан делать клиент: перевернуть
    /// только обёртки. Айтемы зашифрованы на VK, а VK при смене пароля не
    /// меняется — трогать их незачем.
    fn change_password(store: &Store, old: &KeyEncryptionKey, new: &KeyEncryptionKey) -> Store {
        let mut out = store.clone();
        let uk = unwrap_user_key(old, &store["wrapped_uk"]).unwrap();
        let vk = unwrap_vault_key(old, &store["wrapped_vk"]).unwrap();
        out.insert("wrapped_uk", wrap_user_key(new, &uk).unwrap());
        out.insert("wrapped_vk", wrap_vault_key(new, &vk).unwrap());
        out
    }

    #[test]
    fn password_change_rewraps_two_records_only() {
        // Ради этого свойства и существует развязка MK → KEK → {UK, VK}.
        // Тест — её исполняемая формулировка, поэтому проверяет не только
        // «ключи вернулись», но и то, что записей поменялось ровно две, а
        // старые шифротексты айтемов остались читаемыми байт в байт.
        let old_kek = kek_for("old pw", [0x5A; SALT_LEN]);
        let kp = UserKeyPair::generate().unwrap();
        let vk = VaultKey::generate().unwrap();

        let items: [&[u8]; 3] = [b"item one", b"item two", b"item three"];
        let mut before: Store = BTreeMap::new();
        before.insert("wrapped_uk", wrap_user_key(&old_kek, &kp).unwrap());
        before.insert("wrapped_vk", wrap_vault_key(&old_kek, &vk).unwrap());
        for (i, item) in items.iter().enumerate() {
            let name: &'static str = ["item_0", "item_1", "item_2"][i];
            before.insert(name, aead::seal(vk.as_bytes(), item).unwrap());
        }

        let new_kek = kek_for("new pw", [0x99; SALT_LEN]);
        let after = change_password(&before, &old_kek, &new_kek);

        // 1. Пароль действительно сменился: старый KEK больше не открывает
        //    перевёрнутые записи. Реализация, оставившая обёртки под старым
        //    KEK, провалится здесь.
        assert!(unwrap_user_key(&old_kek, &after["wrapped_uk"]).is_err());
        assert!(unwrap_vault_key(&old_kek, &after["wrapped_vk"]).is_err());

        // 2. Собственно свойство: изменились ровно две записи из пяти.
        //    Реализация, перешифровывающая айтемы, провалится здесь.
        let changed: Vec<&str> = before
            .keys()
            .filter(|name| before[*name] != after[*name])
            .copied()
            .collect();
        assert_eq!(changed, ["wrapped_uk", "wrapped_vk"]);
        assert_eq!(before.len(), after.len());

        // 3. И это не «поменялось две, а данные потерялись»: VK, добытый
        //    через новый пароль, открывает нетронутые шифротексты айтемов.
        let recovered_vk = unwrap_vault_key(&new_kek, &after["wrapped_vk"]).unwrap();
        assert_eq!(recovered_vk.as_bytes(), vk.as_bytes());
        for (i, item) in items.iter().enumerate() {
            let name = ["item_0", "item_1", "item_2"][i];
            assert_eq!(
                &aead::open(recovered_vk.as_bytes(), &after[name]).unwrap()[..],
                *item
            );
        }

        // 4. Личность пользователя пережила смену пароля: тот же публичный
        //    ключ X25519, значит расшаренные ему хранилища остались доступны.
        let recovered_uk = unwrap_user_key(&new_kek, &after["wrapped_uk"]).unwrap();
        assert_eq!(recovered_uk.secret_bytes(), kp.secret_bytes());
        assert_eq!(recovered_uk.public_bytes(), kp.public_bytes());
    }

    #[test]
    fn debug_output_hides_secret() {
        let kp = UserKeyPair::from_secret([1u8; 32]);
        let rendered = format!("{kp:?}");
        assert!(rendered.contains("[redacted]"));
        assert!(rendered.contains(&hex::encode(kp.public_bytes())));
        assert!(!rendered.contains(&hex::encode(kp.secret_bytes())));
    }
}
