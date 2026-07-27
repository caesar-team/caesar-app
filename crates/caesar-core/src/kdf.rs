use crate::error::redact_plaintext_detail;
use crate::keys::{AuthKey, KeyEncryptionKey, MasterKey};
use crate::{Error, Result};

pub const KDF_VERSION: u8 = 1;
pub const KDF_ALGO_ARGON2ID: u8 = 1;
pub const SALT_LEN: usize = 16;
pub const KDF_PARAMS_LEN: usize = 30;

/// Домены HKDF. Изменение любой строки делает существующие данные нечитаемыми.
const INFO_AUTH: &[u8] = b"caesar/auth/v1";
const INFO_WRAP: &[u8] = b"caesar/wrap/v1";

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

/// Параметры Argon2id. Хранятся на сервере открыто, один раз на пользователя.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; SALT_LEN],
}

impl KdfParams {
    /// Параметры по умолчанию: 64 MiB, 3 прохода, 4 потока.
    pub fn generate() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Self {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 4,
            salt,
        }
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
        Ok(Self {
            m_cost: u32_at(2),
            t_cost: u32_at(6),
            p_cost: u32_at(10),
            salt: bytes[14..30].try_into().unwrap(),
        })
    }

    /// Отвергает параметры ниже вкомпилированного пола.
    pub fn validate(&self) -> Result<()> {
        if self.m_cost < MIN_M_COST || self.t_cost < MIN_T_COST || self.p_cost < MIN_P_COST {
            return Err(Error::WeakKdfParams {
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
/// Отказывается работать на параметрах ниже пола: см. `MIN_M_COST`.
pub fn derive_master_key(password: &str, params: &KdfParams) -> Result<MasterKey> {
    use argon2::{Algorithm, Argon2, Params, Version};

    params.validate()?;

    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| Error::KeyDerivation(redact_plaintext_detail(e)))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), &params.salt, &mut out)
        .map_err(|e| Error::KeyDerivation(redact_plaintext_detail(e)))?;
    Ok(MasterKey::from_bytes(out))
}

fn expand(master: &MasterKey, info: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, master.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("32 bytes is a valid HKDF output length");
    out
}

/// Ключ аутентификации. Единственный производный ключ, который уходит на сервер.
pub fn auth_key(master: &MasterKey) -> AuthKey {
    AuthKey::from_bytes(expand(master, INFO_AUTH))
}

/// Ключ обёртки. Не покидает устройство никогда.
pub fn key_encryption_key(master: &MasterKey) -> KeyEncryptionKey {
    KeyEncryptionKey::from_bytes(expand(master, INFO_WRAP))
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
            Err(Error::WeakKdfParams { .. })
        ));
    }

    #[test]
    fn derivation_is_deterministic() {
        let p = fixed_params();
        let a = derive_master_key("correct horse", &p).unwrap();
        let b = derive_master_key("correct horse", &p).unwrap();
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
