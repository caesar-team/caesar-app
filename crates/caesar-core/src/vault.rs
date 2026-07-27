use crate::aead;
use crate::keys::{KeyEncryptionKey, VaultKey};
use crate::{Error, Result};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Длина эфемерного публичного ключа в префиксе расшаренной записи.
pub const EPHEMERAL_PUBLIC_LEN: usize = 32;

/// Домен HKDF для расшаривания ключа хранилища. Соседи — `caesar/auth/v1` и
/// `caesar/wrap/v1` в `kdf.rs`.
const INFO_SHARE: &[u8] = b"caesar/share/v1";

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

/// То же, что [`unwrap_user_key`], но дополнительно сверяет выведенную
/// публичную половину с той, что опубликована сервером.
///
/// `unwrap_user_key` больше проверить и не может: после клэмпинга любые 32
/// байта — валидный секрет X25519, и `from_secret` пересчитает согласованную
/// с ними публичную половину. Тег Poly1305 ловит порчу, но не откат: подстановка
/// прошлой, честно завёрнутой записи проходит его чисто. Сверка с `UK_pub` —
/// единственное, что отличает актуальную личность от устаревшей, поэтому
/// клиенты обязаны ходить сюда, а не в `unwrap_user_key`, везде, где `UK_pub`
/// приходит с сервера.
pub fn unwrap_user_key_verified(
    kek: &KeyEncryptionKey,
    wrapped: &[u8],
    expected_public: &[u8; 32],
) -> Result<UserKeyPair> {
    // Сравнение обычное, не константное по времени: обе стороны публичны.
    let user_key = unwrap_user_key(kek, wrapped)?;
    if user_key.public_bytes() != expected_public {
        return Err(Error::UserKeyMismatch);
    }
    Ok(user_key)
}

/// Оборачивает ключ хранилища. Один vault даёт одну такую запись.
pub fn wrap_vault_key(kek: &KeyEncryptionKey, vault_key: &VaultKey) -> Result<Vec<u8>> {
    aead::seal(kek.as_bytes(), vault_key.as_bytes())
}

pub fn unwrap_vault_key(kek: &KeyEncryptionKey, wrapped: &[u8]) -> Result<VaultKey> {
    let raw = aead::open(kek.as_bytes(), wrapped)?;
    VaultKey::try_from_slice(&raw)
}

/// Выводит симметричный ключ записи из общего секрета X25519.
///
/// Оба публичных ключа входят в соль. Публичный ключ получателя там не ради
/// красоты: сам по себе DH связывает шифротекст с адресатом только пока
/// эфемерный ключ имеет большой порядок. Точка малого порядка в префиксе даёт
/// нулевой общий секрет с *любым* приватным ключом, и без получателя в соли
/// одна такая запись открывалась бы всеми участниками сразу.
fn shared_key(
    shared_secret: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    // Соль — из двух публичных ключей, зачищать нечего.
    let mut salt = [0u8; 2 * EPHEMERAL_PUBLIC_LEN];
    salt[..EPHEMERAL_PUBLIC_LEN].copy_from_slice(ephemeral_public);
    salt[EPHEMERAL_PUBLIC_LEN..].copy_from_slice(recipient_public);

    // `Zeroizing`, а не голый `[u8; 32]`: массив — `Copy`, обычный локальный
    // остался бы на стеке после возврата. Та же форма, что у `expand` в `kdf.rs`.
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(INFO_SHARE, out.as_mut_slice())
        .expect("32 bytes is a valid HKDF output length");
    out
}

/// Шифрует ключ хранилища на публичный ключ участника.
///
/// Формат: `ephemeral_public(32) || Envelope`.
pub fn seal_vault_key_for(recipient_public: &[u8; 32], vault_key: &VaultKey) -> Result<Vec<u8>> {
    use rand_core::{OsRng, RngCore};
    use x25519_dalek::{PublicKey, StaticSecret};

    // Отказ CSPRNG — `Err`, а не паника, и не «сделать хоть что-нибудь»:
    // повторный эфемерный ключ повторяет и ключ записи. Та же схема, что в
    // `keys.rs`, `kdf.rs` и `aead.rs`.
    let mut ephemeral_secret = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(ephemeral_secret.as_mut_slice())
        .map_err(|_| Error::RandomSourceUnavailable)?;

    let ephemeral_public = public_from_secret(&ephemeral_secret);
    let shared =
        StaticSecret::from(*ephemeral_secret).diffie_hellman(&PublicKey::from(*recipient_public));
    let key = shared_key(shared.as_bytes(), &ephemeral_public, recipient_public);

    let envelope = aead::seal(&key, vault_key.as_bytes())?;
    let mut out = Vec::with_capacity(EPHEMERAL_PUBLIC_LEN + envelope.len());
    out.extend_from_slice(&ephemeral_public);
    out.extend_from_slice(&envelope);
    Ok(out)
}

/// Расшифровывает ключ хранилища приватным ключом получателя.
pub fn open_vault_key_for(recipient: &UserKeyPair, sealed: &[u8]) -> Result<VaultKey> {
    use x25519_dalek::{PublicKey, StaticSecret};

    // `first_chunk` отдаёт `&[u8; 32]` сразу: срез с последующим `try_into`
    // добавил бы преобразование, которое не может провалиться, и `unwrap`
    // поверх него.
    let ephemeral_public =
        *sealed
            .first_chunk::<EPHEMERAL_PUBLIC_LEN>()
            .ok_or(Error::Truncated {
                got: sealed.len(),
                need: EPHEMERAL_PUBLIC_LEN,
            })?;

    let shared = StaticSecret::from(*recipient.secret_bytes())
        .diffie_hellman(&PublicKey::from(ephemeral_public));
    let key = shared_key(
        shared.as_bytes(),
        &ephemeral_public,
        recipient.public_bytes(),
    );

    // `aead::open` отдаёт `Zeroizing`, поэтому расшифрованный ключ затирается,
    // даже если проверка длины ниже провалится.
    let raw = aead::open(&key, &sealed[EPHEMERAL_PUBLIC_LEN..])?;
    // Проверка длины — через try_from_slice, единственную точку в крейте.
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
    fn verified_unwrap_accepts_the_published_public_key() {
        let kek = test_kek();
        let kp = UserKeyPair::generate().unwrap();
        let wrapped = wrap_user_key(&kek, &kp).unwrap();
        let restored = unwrap_user_key_verified(&kek, &wrapped, kp.public_bytes()).unwrap();
        assert_eq!(restored.secret_bytes(), kp.secret_bytes());
    }

    #[test]
    fn verified_unwrap_rejects_a_rolled_back_record() {
        // Откат: сервер отдаёт прошлую, честно завёрнутую запись
        // `encryptedUserKey`. Тег Poly1305 сходится, длина верна, и без сверки
        // с опубликованным UK_pub клиент принял бы устаревшую личность — а
        // вместе с ней потерял бы все расшаренные на текущий UK_pub хранилища,
        // не получив ни одной ошибки, объясняющей почему.
        let kek = test_kek();
        let old = UserKeyPair::generate().unwrap();
        let current = UserKeyPair::generate().unwrap();
        let stale = wrap_user_key(&kek, &old).unwrap();

        assert_eq!(
            unwrap_user_key_verified(&kek, &stale, current.public_bytes()).unwrap_err(),
            Error::UserKeyMismatch
        );
        // Та же запись без сверки проходит молча — это и есть дыра, которую
        // закрывает `unwrap_user_key_verified`.
        assert!(unwrap_user_key(&kek, &stale).is_ok());
    }

    #[test]
    fn recipient_recovers_vault_key() {
        let recipient = UserKeyPair::generate().unwrap();
        let vk = VaultKey::generate().unwrap();
        let sealed = seal_vault_key_for(recipient.public_bytes(), &vk).unwrap();
        assert_eq!(
            open_vault_key_for(&recipient, &sealed).unwrap().as_bytes(),
            vk.as_bytes()
        );
    }

    #[test]
    fn other_user_cannot_open() {
        let recipient = UserKeyPair::generate().unwrap();
        let stranger = UserKeyPair::generate().unwrap();
        let sealed =
            seal_vault_key_for(recipient.public_bytes(), &VaultKey::generate().unwrap()).unwrap();
        assert_eq!(
            open_vault_key_for(&stranger, &sealed).unwrap_err(),
            Error::DecryptionFailed
        );
    }

    #[test]
    fn each_seal_uses_a_fresh_ephemeral_key() {
        let recipient = UserKeyPair::generate().unwrap();
        let vk = VaultKey::generate().unwrap();
        let a = seal_vault_key_for(recipient.public_bytes(), &vk).unwrap();
        let b = seal_vault_key_for(recipient.public_bytes(), &vk).unwrap();
        assert_ne!(
            &a[..EPHEMERAL_PUBLIC_LEN],
            &b[..EPHEMERAL_PUBLIC_LEN],
            "переиспользованный эфемерный ключ повторяет и nonce-независимый \
             ключ шифрования: две записи под одним ключом"
        );
    }

    #[test]
    fn open_rejects_a_blob_without_a_full_ephemeral_key() {
        // Слишком короткий вход не должен доезжать до `first_chunk`-less
        // индексации: 31 байт — это не «пустой конверт», а обрезанный префикс.
        let recipient = UserKeyPair::generate().unwrap();
        assert_eq!(
            open_vault_key_for(&recipient, &[0u8; 31]).unwrap_err(),
            Error::Truncated { got: 31, need: 32 }
        );
    }

    #[test]
    fn sealed_blob_layout_is_pinned() {
        // Эти байты лежат у пользователей на сервере: любое изменение формы
        // делает расшаренные хранилища неоткрываемыми.
        //
        // 106 = 32 (эфемерный публичный ключ) + 2 (заголовок) + 24 (nonce)
        //     + 32 (ключ хранилища) + 16 (тег). Литерал намеренный: выражение
        // из констант поехало бы следом за ними и не заметило бы ровно ту
        // правку, ради которой этот тест существует.
        let recipient = UserKeyPair::generate().unwrap();
        let sealed =
            seal_vault_key_for(recipient.public_bytes(), &VaultKey::generate().unwrap()).unwrap();
        assert_eq!(sealed.len(), 106);
        // Конверт идёт сразу за эфемерным ключом, а не перед ним: на смещении
        // 32 лежит его заголовок — версия протокола и идентификатор сюиты.
        assert_eq!(&sealed[32..34], &[1, 1]);
    }

    #[test]
    fn shared_key_binds_both_public_keys() {
        // Общий секрет один и тот же, меняется только соль. Реализация,
        // потерявшая любую из её половин, вернёт здесь одинаковые ключи.
        let ss = [0x11; 32];
        let base = *shared_key(&ss, &[0x22; 32], &[0x33; 32]);
        assert_ne!(*shared_key(&ss, &[0x99; 32], &[0x33; 32]), base);
        assert_ne!(*shared_key(&ss, &[0x22; 32], &[0x99; 32]), base);
    }

    #[test]
    fn shared_key_derivation_is_pinned() {
        // Снято с этой реализации и закреплено литералом. Тест не проверяет
        // криптографию — он держит форму вывода: строку домена INFO_SHARE и
        // порядок половин в соли (сначала эфемерный ключ, затем ключ
        // получателя). Перестановка соли или правка INFO_SHARE делают
        // нечитаемыми все уже расшаренные записи; без литерала такое
        // изменение прошло бы молча — все остальные тесты остаются зелёными,
        // потому что seal и open меняются вместе.
        assert_eq!(
            hex::encode(*shared_key(&[0x01; 32], &[0x02; 32], &[0x03; 32])),
            "1337fa98bc6ff6f271111ae6d42497a724e6cc4cac0366aaa89f7c16289b2436"
        );
    }

    /// Публичный ключ с u = 0. Точка малого порядка: X25519 даёт с ней
    /// вырожденный (нулевой) общий секрет для любого приватного ключа.
    const DEGENERATE_PUBLIC: [u8; 32] = [0u8; 32];

    #[test]
    fn a_degenerate_ephemeral_key_cannot_be_replayed_to_another_recipient() {
        use x25519_dalek::{PublicKey, StaticSecret};

        let alice = UserKeyPair::generate().unwrap();
        let bob = UserKeyPair::generate().unwrap();
        let vk = VaultKey::generate().unwrap();

        // Предпосылка, ради которой этот тест вообще возможен: с точкой малого
        // порядка в роли эфемерного ключа обмен Диффи-Хеллмана перестаёт
        // зависеть от получателя — у Алисы и Боба он даёт одни и те же нули.
        // Именно здесь сам по себе DH больше не связывает шифротекст с
        // адресатом, и единственное, что его связывает, — соль HKDF.
        let dh = |kp: &UserKeyPair| {
            *StaticSecret::from(*kp.secret_bytes())
                .diffie_hellman(&PublicKey::from(DEGENERATE_PUBLIC))
                .as_bytes()
        };
        assert_eq!(dh(&alice), [0u8; 32]);
        assert_eq!(dh(&bob), [0u8; 32]);

        // Враждебный отправитель собирает запись на Алису вручную.
        let key = shared_key(&[0u8; 32], &DEGENERATE_PUBLIC, alice.public_bytes());
        let mut blob = DEGENERATE_PUBLIC.to_vec();
        blob.extend_from_slice(&aead::seal(&key, vk.as_bytes()).unwrap());

        // Адресат её открывает — запись настоящая, а не заведомо битая.
        assert_eq!(
            open_vault_key_for(&alice, &blob).unwrap().as_bytes(),
            vk.as_bytes()
        );
        // А больше никто, и ровно потому, что публичный ключ получателя входит
        // в соль HKDF. Убрать его оттуда — и Боб выведет тот же ключ, что
        // Алиса: одна запись, переадресуемая любому участнику.
        assert_eq!(
            open_vault_key_for(&bob, &blob).unwrap_err(),
            Error::DecryptionFailed
        );
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
