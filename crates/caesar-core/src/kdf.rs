use crate::keys::{AuthKey, KeyEncryptionKey, MasterKey};
use crate::{Error, Result};
use argon2::Version;

pub const KDF_VERSION: u8 = 1;
pub const KDF_ALGO_ARGON2ID: u8 = 1;
pub const SALT_LEN: usize = 16;

/// Длина закодированных параметров: версия, алгоритм, три `u32` и соль.
/// Выводится из `SALT_LEN`, а не пишется числом: поднять соль до 32 байт
/// должно быть одной правкой, а не охотой за литералами в `decode`.
pub const KDF_PARAMS_LEN: usize = 2 + 3 * 4 + SALT_LEN;

const _: () = assert!(KDF_PARAMS_LEN == 2 + 12 + SALT_LEN);

/// Домены HKDF. Изменение любой строки делает существующие данные нечитаемыми.
///
/// `pub` не ради вызывающих, а ради `protocol/vectors.json`: генератор печатает
/// эти строки в файл векторов как документацию для Swift и TypeScript. Пока они
/// были литералами в генераторе, значение пинилось косвенно (через известный
/// ответ), а *подпись* могла разойтись с кодом — и файл вёз бы ложь ровно тем,
/// кому он адресован.
pub const INFO_AUTH: &[u8] = b"caesar/auth/v1";
pub const INFO_WRAP: &[u8] = b"caesar/wrap/v1";

/// Длина всего производного ключевого материала: выхода Argon2id и каждого
/// выхода HKDF. Один источник правды — иначе «32» живёт в четырёх местах.
pub const DERIVED_KEY_LEN: usize = 32;

/// Версия Argon2, попадающая в каждый выведенный ключ. `0x13` — это 19,
/// «Argon2 version 1.3»; версия 0x10 при тех же параметрах даёт другой ключ.
/// Константа выводится из самого значения, переданного в `Argon2::new`, а не
/// написана числом рядом с ним.
const ARGON2_VERSION: Version = Version::V0x13;
pub const ARGON2_VERSION_NUMBER: u32 = ARGON2_VERSION as u32;

/// Пол параметров Argon2id, вкомпилированный в клиента.
///
/// `KdfParams` приходят с сервера открытым текстом и не покрыты ничьей
/// аутентификацией — проверить тег нельзя, потому что для этого нужен ключ,
/// а ключ зависит от самих параметров. Враждебный сервер, приславший
/// `m_cost: 8`, получил бы `auth_key`, выведенный за миллисекунды и
/// брутфорсимый офлайн. Клиент обязан отказаться считать на таких параметрах.
pub const MIN_M_COST: u32 = 19 * 1024;
pub const MIN_T_COST: u32 = 2;
pub const MIN_P_COST: u32 = 1;

/// Потолок параметров. Защищает не только от враждебного сервера, но и от
/// собственной ошибки: миграция, записавшая m_cost в МиБ вместо КиБ, иначе
/// вешает каждого клиента навсегда и без диагностируемой ошибки.
///
/// `Params::new` из argon2 не спасает: там `MAX_M_COST == u32::MAX`. При
/// `m_cost = 0xFFFFFFFF` клиент пытается выделить ~4 ТиБ и умирает в
/// `handle_alloc_error` — это abort, а не `Err`: под wasm гибнет модуль, под
/// UniFFI — хост-приложение. `t_cost = 0xFFFFFFFF` вместо этого считает ~50
/// суток вообще без признаков ошибки.
pub const MAX_M_COST: u32 = 4 * 1024 * 1024; // 4 GiB
pub const MAX_T_COST: u32 = 16;
pub const MAX_P_COST: u32 = 16;

/// Параметры Argon2id. Хранятся на сервере открыто, один раз на пользователя.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; SALT_LEN],
}

impl KdfParams {
    /// Параметры по умолчанию: 64 MiB, 3 прохода, 4 потока.
    ///
    /// Отказ CSPRNG — это `Err`, а не паника: под wasm и UniFFI паника уносит
    /// весь модуль или хост-приложение. Та же схема, что в `keys.rs`.
    pub fn generate() -> Result<Self> {
        use rand_core::{OsRng, RngCore};
        let mut salt = [0u8; SALT_LEN];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|_| Error::RandomSourceUnavailable)?;
        Ok(Self {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 4,
            salt,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KDF_PARAMS_LEN);
        out.push(KDF_VERSION);
        out.push(KDF_ALGO_ARGON2ID);
        out.extend_from_slice(&self.m_cost.to_le_bytes());
        out.extend_from_slice(&self.t_cost.to_le_bytes());
        out.extend_from_slice(&self.p_cost.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KDF_PARAMS_LEN {
            return Err(Error::Truncated {
                got: bytes.len(),
                need: KDF_PARAMS_LEN,
            });
        }
        if bytes[0] != KDF_VERSION {
            return Err(Error::UnsupportedVersion {
                found: bytes[0],
                supported: KDF_VERSION,
            });
        }
        if bytes[1] != KDF_ALGO_ARGON2ID {
            return Err(Error::UnsupportedSuite {
                found: bytes[1],
                supported: KDF_ALGO_ARGON2ID,
            });
        }
        let u32_at = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        // `bytes[14..]` — ровно `SALT_LEN` байт по построению: длина уже
        // проверена выше, а `KDF_PARAMS_LEN` выведен из `SALT_LEN`.
        let params = Self {
            m_cost: u32_at(2),
            t_cost: u32_at(6),
            p_cost: u32_at(10),
            salt: bytes[14..].try_into().unwrap(),
        };
        params.validate()?;
        Ok(params)
    }

    /// Отвергает параметры вне вкомпилированного диапазона. Единственная точка
    /// проверки: `decode` и `derive_master_key` зовут её, а не свои копии.
    pub fn validate(&self) -> Result<()> {
        let too_weak =
            self.m_cost < MIN_M_COST || self.t_cost < MIN_T_COST || self.p_cost < MIN_P_COST;
        let too_heavy =
            self.m_cost > MAX_M_COST || self.t_cost > MAX_T_COST || self.p_cost > MAX_P_COST;
        if too_weak || too_heavy {
            return Err(Error::KdfParamsOutOfRange {
                m_cost: self.m_cost,
                t_cost: self.t_cost,
                p_cost: self.p_cost,
            });
        }
        Ok(())
    }
}

/// Выводит мастер-ключ из пароля. Единственное место, где пароль вообще виден.
///
/// Отказывается работать на параметрах вне диапазона: см. `MIN_M_COST`
/// и `MAX_M_COST`.
///
/// # Нормализация — обязанность ядра, а не вызывающего
///
/// Пароль приводится к NFC **здесь**, первым же шагом. `String` в Swift и
/// строка в JS хранят «é» и как U+00E9, и как U+0065 U+0301: пользователь
/// набирает один и тот же пароль, байты приходят разные, мастер-ключ выходит
/// разный — и хранилище, созданное на одной платформе, не открывается на
/// другой. Ошибка при этом не диагностируется ничем: клиент видит обычный
/// «неверный пароль», а CI зелёный, потому что каждая платформа согласована
/// сама с собой.
///
/// Нормализовать обязано ядро, а не четыре клиента: смысл этого крейта в том,
/// что расходиться им негде. **Вызывающие не должны нормализовать пароль сами** —
/// NFC идемпотентен, так что вреда не будет, но и пользы тоже, а забытая
/// нормализация у одного клиента вернула бы ровно ту поломку.
///
/// # Обязанность вызывающего
///
/// Пароль принимается как `&str` осознанно: строку JS или Swift всё равно
/// нельзя затереть, а `String` в сигнатуре лишь создавал бы иллюзию, что ядро
/// владеет буфером. Ядро **не может** зачистить память вызывающего — за время
/// жизни пароля отвечает вызывающий: держать его как можно короче и, если
/// платформа это позволяет (нативный буфер, `Vec<u8>`), затереть сразу после
/// вызова. Всё, что гарантирует ядро, — пароль не копируется наружу и не
/// попадает ни в одну ошибку.
pub fn derive_master_key(password: &str, params: &KdfParams) -> Result<MasterKey> {
    use argon2::{Algorithm, Argon2, Params};
    use unicode_normalization::UnicodeNormalization;
    use zeroize::Zeroizing;

    params.validate()?;

    // `Zeroizing`, а не голая `String`: нормализация — это вторая копия пароля
    // в куче, и оставлять её там было бы хуже, чем не нормализовать вовсе.
    // Копия делается всегда, в том числе когда вход уже в NFC: ветка «уже
    // нормализован» экономила бы одну аллокацию на вход пароля и добавляла
    // путь, который на ASCII-пароле никогда не исполняется, — а именно ASCII
    // и покрыт известным ответом.
    let normalized = Zeroizing::new(password.nfc().collect::<String>());

    // Ошибки argon2 не редактируются: они описывают только публичные
    // параметры с сервера — ни пароля, ни ключа, ни расшифрованного текста
    // в них нет. Редактирование сделало бы враждебный `m_cost` неотличимым
    // от любой другой поломки в поле.
    let argon_params = Params::new(
        params.m_cost,
        params.t_cost,
        params.p_cost,
        Some(DERIVED_KEY_LEN),
    )
    .map_err(|e| Error::KeyDerivation(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, ARGON2_VERSION, argon_params);

    // `[u8; 32]` — `Copy`: обычный локальный массив остался бы на стеке после
    // возврата, и `ZeroizeOnDrop` на `MasterKey` затирал бы только копию.
    let mut out = Zeroizing::new([0u8; DERIVED_KEY_LEN]);
    argon
        .hash_password_into(normalized.as_bytes(), &params.salt, out.as_mut_slice())
        .map_err(|e| Error::KeyDerivation(e.to_string()))?;
    Ok(MasterKey::from_bytes(*out))
}

/// HKDF-SHA256 без соли (RFC 5869: это `HashLen` нулевых байт), IKM —
/// мастер-ключ, выход — [`DERIVED_KEY_LEN`] байт. Разделяет домены только
/// `info`; раскладка закреплена в `constants` файла векторов.
fn expand(master: &MasterKey, info: &[u8]) -> zeroize::Zeroizing<[u8; DERIVED_KEY_LEN]> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use zeroize::Zeroizing;

    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    let mut out = Zeroizing::new([0u8; DERIVED_KEY_LEN]);
    hk.expand(info, out.as_mut_slice())
        .expect("32 bytes is a valid HKDF output length");
    out
}

/// Ключ аутентификации. Единственный производный ключ, который уходит на сервер.
pub fn auth_key(master: &MasterKey) -> AuthKey {
    AuthKey::from_bytes(*expand(master, INFO_AUTH))
}

/// Ключ обёртки. Не покидает устройство никогда.
pub fn key_encryption_key(master: &MasterKey) -> KeyEncryptionKey {
    KeyEncryptionKey::from_bytes(*expand(master, INFO_WRAP))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_params() -> KdfParams {
        // Продакшн-параметры с фиксированной солью. Ослабленных параметров
        // в тестах нет намеренно: обходного пути мимо пола существовать
        // не должно, иначе он рано или поздно попадёт в рабочий код.
        KdfParams {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 4,
            salt: [0x5A; SALT_LEN],
        }
    }

    #[test]
    fn rejects_weak_parameters() {
        let weak = KdfParams {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
            salt: [0x5A; SALT_LEN],
        };
        assert!(matches!(
            derive_master_key("pw", &weak),
            Err(Error::KdfParamsOutOfRange { .. })
        ));
    }

    #[test]
    fn rejects_absurd_parameters() {
        // Проверка обязана сработать ДО argon2: `m_cost = u32::MAX` — это не
        // `Err` из `Params::new`, а попытка выделить ~4 ТиБ и abort процесса,
        // а `t_cost = u32::MAX` — счёт на десятки суток.
        let huge_m = KdfParams {
            m_cost: u32::MAX,
            t_cost: 3,
            p_cost: 4,
            salt: [0x5A; SALT_LEN],
        };
        assert!(matches!(
            derive_master_key("pw", &huge_m),
            Err(Error::KdfParamsOutOfRange { .. })
        ));

        let huge_t = KdfParams {
            m_cost: 65536,
            t_cost: u32::MAX,
            p_cost: 4,
            salt: [0x5A; SALT_LEN],
        };
        assert!(matches!(
            derive_master_key("pw", &huge_t),
            Err(Error::KdfParamsOutOfRange { .. })
        ));

        let huge_p = KdfParams {
            m_cost: 65536,
            t_cost: 3,
            p_cost: u32::MAX,
            salt: [0x5A; SALT_LEN],
        };
        assert!(matches!(
            derive_master_key("pw", &huge_p),
            Err(Error::KdfParamsOutOfRange { .. })
        ));
    }

    #[test]
    fn decode_rejects_out_of_range_parameters() {
        // Единственный вход для байтов с сервера. Без проверки здесь
        // инвариант держался бы только тем, что каждый будущий вызов вывода
        // не забудет позвать `validate()`.
        let mut encoded = fixed_params().encode();
        encoded[2..6].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            KdfParams::decode(&encoded),
            Err(Error::KdfParamsOutOfRange { .. })
        ));

        let mut encoded = fixed_params().encode();
        encoded[2..6].copy_from_slice(&8u32.to_le_bytes());
        assert!(matches!(
            KdfParams::decode(&encoded),
            Err(Error::KdfParamsOutOfRange { .. })
        ));
    }

    #[test]
    fn generate_produces_valid_distinct_params() {
        let a = KdfParams::generate().unwrap();
        let b = KdfParams::generate().unwrap();
        a.validate().unwrap();
        assert_ne!(a.salt, b.salt);
    }

    #[test]
    fn derivation_is_deterministic() {
        let p = fixed_params();
        let a = derive_master_key("correct horse", &p).unwrap();
        let b = derive_master_key("correct horse", &p).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn nfc_and_nfd_spellings_of_a_password_agree() {
        // Один и тот же пароль с точки зрения пользователя, разные байты:
        // «é» как U+00E9 и как U+0065 U+0301. Swift и JS отдают то и другое в
        // зависимости от того, откуда строка приехала (клавиатура, буфер
        // обмена, файловая система macOS), поэтому без нормализации хранилище
        // просто не открылось бы на второй платформе — без единого признака
        // поломки, кроме «неверный пароль».
        let nfc = "caf\u{00E9} au lait";
        let nfd = "cafe\u{0301} au lait";
        assert_ne!(nfc.as_bytes(), nfd.as_bytes(), "test premise: bytes differ");

        let p = fixed_params();
        let a = derive_master_key(nfc, &p).unwrap();
        let b = derive_master_key(nfd, &p).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_salt_gives_different_key() {
        let mut p2 = fixed_params();
        p2.salt = [0x5B; SALT_LEN];
        let a = derive_master_key("correct horse", &fixed_params()).unwrap();
        let b = derive_master_key("correct horse", &p2).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn auth_key_and_kek_are_independent() {
        // Это и есть zero-knowledge: сервер знает AK и не может получить KEK.
        let mk = derive_master_key("correct horse", &fixed_params()).unwrap();
        assert_ne!(auth_key(&mk).as_bytes(), key_encryption_key(&mk).as_bytes());
    }

    #[test]
    fn kdf_constants_are_pinned() {
        // Домены HKDF попадают в каждый выведенный ключ у каждого пользователя.
        // Перепутать их местами — значит отправить на сервер ключ обёртки;
        // `auth_key_and_kek_are_independent` такую перестановку пропускает,
        // потому что ключи остаются разными. Пол и потолок пинуются здесь же:
        // сдвиг любого из них молча меняет то, какие параметры клиент примет.
        assert_eq!(INFO_AUTH, b"caesar/auth/v1");
        assert_eq!(INFO_WRAP, b"caesar/wrap/v1");

        // Версия Argon2 и длина выхода попадают в ключ ровно так же, как соль:
        // 0x10 вместо 0x13 или 64 байта вместо 32 дают другой мастер-ключ.
        assert_eq!(ARGON2_VERSION_NUMBER, 0x13);
        assert_eq!(DERIVED_KEY_LEN, 32);

        assert_eq!(MIN_M_COST, 19 * 1024);
        assert_eq!(MIN_T_COST, 2);
        assert_eq!(MIN_P_COST, 1);
        assert_eq!(MAX_M_COST, 4 * 1024 * 1024);
        assert_eq!(MAX_T_COST, 16);
        assert_eq!(MAX_P_COST, 16);
    }

    #[test]
    fn known_answer_vector() {
        // Единственный тест, который ловит смену алгоритма, версии Argon2,
        // порядка байт соли или доменов HKDF. Значения получены прогоном этого
        // же кода и зафиксированы: задача 10 переиспользует ровно их.
        let mk = derive_master_key("correct horse battery staple", &fixed_params()).unwrap();
        assert_eq!(
            hex::encode(mk.as_bytes()),
            "5cea1d57f950121fbc7a6d90279d7612482cf65ea98cacf40dc8c22b92f9461f"
        );
        assert_eq!(
            hex::encode(auth_key(&mk).as_bytes()),
            "0b5632f94cac1cccdbc0d74954cd38603bf83c7f6a5c078d07e2601b016a282c"
        );
        assert_eq!(
            hex::encode(key_encryption_key(&mk).as_bytes()),
            "404992526283a87b4d58771fb7b71fdd90135a27688fdf632812c750b9a34252"
        );
    }

    #[test]
    fn kdf_params_round_trip() {
        let p = KdfParams {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 4,
            salt: [0x11; SALT_LEN],
        };
        let encoded = p.encode();
        assert_eq!(encoded.len(), KDF_PARAMS_LEN);
        assert_eq!(KdfParams::decode(&encoded).unwrap(), p);
    }

    #[test]
    fn kdf_params_reject_unknown_version() {
        let mut encoded = fixed_params().encode();
        encoded[0] = 7;
        assert!(matches!(
            KdfParams::decode(&encoded),
            Err(Error::UnsupportedVersion { found: 7, .. })
        ));
    }
}
