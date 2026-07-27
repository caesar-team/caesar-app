use crate::envelope::{self, NONCE_LEN, TAG_LEN};
use crate::{Error, Result};
use zeroize::Zeroizing;

// Размеры конверта обязаны совпадать с тем, что реально выдаёт AEAD.
// Бамп зависимости, меняющий их, должен ломать сборку, а не молча
// порождать некорректные конверты.
const _: () = {
    // `Unsigned` берётся по цепочке ре-экспортов самого chacha20poly1305:
    // `chacha20poly1305::consts` — это только псевдонимы `U*` из typenum,
    // трейта там нет. Тянуть его из `sha2::digest` нельзя: тогда утверждение
    // о размерах AEAD начнёт зависеть от версии хеш-крейта.
    use chacha20poly1305::aead::generic_array::typenum::Unsigned;
    use chacha20poly1305::aead::AeadCore;
    use chacha20poly1305::XChaCha20Poly1305;
    assert!(<XChaCha20Poly1305 as AeadCore>::NonceSize::USIZE == NONCE_LEN);
    assert!(<XChaCha20Poly1305 as AeadCore>::TagSize::USIZE == TAG_LEN);
};

/// Шифрует данные ключом и упаковывает в конверт.
///
/// Заголовок конверта передаётся как AAD, поэтому подмена версии или сюиты
/// ломает проверку тега.
///
/// Возвращает `Err`, а не паникует, если системный CSPRNG недоступен: nonce
/// обязан быть свежим на каждый вызов, и «сделать хоть что-нибудь» тут хуже,
/// чем отказать.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    use rand_core::{OsRng, RngCore};

    // Повторный nonce XChaCha20 под тем же ключом раскрывает открытый текст,
    // поэтому единственный допустимый ответ на отказ CSPRNG — ошибка.
    // Та же схема, что в `keys.rs` и `kdf.rs`: под wasm и UniFFI паника
    // уносит весь модуль или хост-приложение.
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| Error::RandomSourceUnavailable)?;

    seal_with_nonce(key, &nonce_bytes, plaintext)
}

/// То же, что [`seal`], но с nonce от вызывающего.
///
/// # Только для генератора векторов
///
/// Существует ровно ради `src/bin/gen_vectors.rs`: `protocol/vectors.json`
/// обязан порождаться байт-в-байт одинаково на каждом прогоне, иначе ворота
/// CI №1 (`gen-vectors | diff protocol/vectors.json -`) падают на каждом
/// коммите, и единственный источник случайности в `seal` — nonce.
///
/// Повторный nonce под тем же ключом раскрывает открытый текст обоих
/// сообщений и подделывает теги: это не «менее безопасный вариант», а прямая
/// потеря конфиденциальности. Рабочий код обязан звать [`seal`].
///
/// Не экспортируется через UniFFI и wasm-bindgen — тот же список, что у
/// `UserKeyPair::from_secret` и [`crate::vault::seal_vault_key_for_with_randomness`].
/// `seal` реализован через неё, а не рядом с ней: два тела для одного формата
/// разъехались бы на версии 2.
#[doc(hidden)]
pub fn seal_with_nonce(
    key: &[u8; 32],
    nonce_bytes: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    // Заголовок берётся из `envelope::HEADER`, а не собирается заново:
    // два источника правды для одних и тех же байт разъедутся на версии 2,
    // и каждый конверт станет нерасшифровываемым своим же `open`.
    //
    // Зачищать здесь нечего: nonce не секрет, открытый текст только
    // заимствован, а свою копию ключа `cipher` затирает сам —
    // `ChaChaPoly1305` реализует `ZeroizeOnDrop`.
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &envelope::HEADER,
            },
        )
        // Единственный отказ XChaCha20-Poly1305 — длина открытого текста
        // за пределом счётчика ChaCha20 (~256 ГиБ). Под wasm32 это
        // недостижимо по построению (всё адресное пространство — 4 ГиБ), но
        // на 64-битных целях UniFFI (iOS, Android, десктоп) — нет, а `seal`
        // и так возвращает `Result`. Тот же довод, что и у `try_fill_bytes`
        // выше: паника здесь уносит модуль или хост-приложение.
        .map_err(|_| Error::PlaintextTooLarge)?;

    Ok(envelope::encode(nonce_bytes, &ciphertext))
}

/// Разбирает конверт и расшифровывает его.
///
/// В отличие от `seal`, здесь секрет — именно **возвращаемое** значение: это
/// приватный ключ X25519, ключ хранилища или JSON элемента с паролями и TOTP.
/// `RustCrypto` расшифровывает на месте в собственном `Vec` и отдаёт его как
/// есть, поэтому без обёртки открытый текст освобождался бы незатёртым.
/// `Zeroizing<Vec<u8>>` затирает и длину, и остаток ёмкости (16 байт из-под
/// срезанного тега), а `Deref` до `Vec<u8>` оставляет вызывающий код прежним.
pub fn open(key: &[u8; 32], envelope_bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    let parsed = envelope::decode(envelope_bytes)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(parsed.nonce),
            Payload {
                msg: parsed.ciphertext,
                aad: parsed.aad,
            },
        )
        .map(Zeroizing::new)
        // Причина отказа не уточняется намеренно: различать «не тот ключ» и
        // «подделанный шифротекст» — значит отвечать на вопросы атакующего.
        .map_err(|_| Error::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    // Смещения полей нужны только тестам: рабочий код всегда ходит в конверт
    // через `envelope::encode`/`decode`, а не по индексам.
    use crate::envelope::HEADER_LEN;
    use std::collections::HashSet;

    const KEY: [u8; 32] = [0x2A; 32];

    fn nonce_of(sealed: &[u8]) -> [u8; NONCE_LEN] {
        sealed[HEADER_LEN..HEADER_LEN + NONCE_LEN]
            .try_into()
            .expect("sealed envelope contains a full nonce")
    }

    #[test]
    fn round_trips() {
        let sealed = seal(&KEY, b"hunter2").unwrap();
        // Срез, а не сам `Zeroizing`: `PartialEq` у него только с себе
        // подобным, до `Vec<u8>` он доходит через `Deref`.
        assert_eq!(&open(&KEY, &sealed).unwrap()[..], b"hunter2");
    }

    #[test]
    fn nonce_differs_between_calls() {
        // Повторное использование nonce в XChaCha20 раскрывает открытый текст.
        //
        // Тест сравнивает именно поле nonce, а не конверты целиком: разные
        // конверты доказывали бы лишь то, что где-то есть отличие, и прошли бы
        // на реализации с фиксированным nonce и случайными байтами в другом
        // месте.
        //
        // Чего этот тест не доказывает: что nonce хватит энтропии. Несколько
        // выборок ничего не говорят о вероятности коллизии на миллионах
        // конвертов — счётчик или слабо засеянный RNG прошли бы его. Уникальность
        // держится на 24 случайных байтах из OsRng, а тест ловит регрессию
        // «nonce захардкожен или выведен из ключа/текста».
        const SAMPLES: usize = 64;
        let nonces: HashSet<[u8; NONCE_LEN]> = (0..SAMPLES)
            .map(|_| nonce_of(&seal(&KEY, b"same").unwrap()))
            .collect();
        assert_eq!(nonces.len(), SAMPLES);
    }

    #[test]
    fn seal_binds_the_envelope_header_as_aad() {
        // Проверяет, что в AAD ушёл именно заголовок, а не пусто. Через `open`
        // это не видно: сегодня подмену заголовка ловит `decode`, а не тег,
        // и `seal` с забытым AAD прошёл бы все остальные тесты.
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};

        let sealed = seal(&KEY, b"payload").unwrap();
        let nonce = nonce_of(&sealed);
        let ciphertext = &sealed[HEADER_LEN + NONCE_LEN..];
        let cipher = XChaCha20Poly1305::new(&KEY.into());

        assert!(cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &envelope::HEADER
                },
            )
            .is_ok());
        assert!(cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: b""
                },
            )
            .is_err());
    }

    #[test]
    fn seal_uses_the_same_aad_that_decode_reports() {
        // Сегодня оба источника — `envelope::HEADER`, так что равенство
        // выполняется по построению. Тест нужен на будущее: когда `decode`
        // научится принимать несколько версий, он станет отдавать в `aad`
        // заголовок конверта, а захардкоженный `HEADER` в `seal` обязан
        // переехать вместе с ним. Иначе `open` перестанет расшифровывать
        // свежие конверты, и ни один другой тест этого не покажет.
        let sealed = seal(&KEY, b"x").unwrap();
        assert_eq!(envelope::decode(&sealed).unwrap().aad, &envelope::HEADER);
    }

    #[test]
    fn seal_is_seal_with_nonce_plus_a_fresh_nonce() {
        // Векторы порождаются через `seal_with_nonce`, а пользователи получают
        // конверты из `seal`. Расхождение между ними сделало бы
        // `protocol/vectors.json` описанием формата, которого нет в продукте,
        // и ни один другой тест этого не увидел бы: обе функции самосогласованы.
        let sealed = seal(&KEY, b"payload").unwrap();
        let nonce = nonce_of(&sealed);
        assert_eq!(seal_with_nonce(&KEY, &nonce, b"payload").unwrap(), sealed);
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&KEY, b"secret").unwrap();
        assert_eq!(
            open(&[0x2B; 32], &sealed).unwrap_err(),
            Error::DecryptionFailed
        );
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut sealed = seal(&KEY, b"secret").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert_eq!(open(&KEY, &sealed).unwrap_err(), Error::DecryptionFailed);
    }

    #[test]
    fn tampered_nonce_fails() {
        // Nonce не покрыт ни AAD, ни проверками `decode` — только тегом.
        let mut sealed = seal(&KEY, b"secret").unwrap();
        sealed[HEADER_LEN] ^= 1;
        assert_eq!(open(&KEY, &sealed).unwrap_err(), Error::DecryptionFailed);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let sealed = seal(&KEY, b"").unwrap();
        assert_eq!(sealed.len(), envelope::MIN_ENVELOPE_LEN);
        assert!(open(&KEY, &sealed).unwrap().is_empty());
    }

    #[test]
    fn open_rejects_a_foreign_envelope_before_touching_the_cipher() {
        // Ошибки разбора конверта не схлопываются в `DecryptionFailed`:
        // «чужая версия» и «не тот ключ» — разные диагнозы в поле.
        let mut sealed = seal(&KEY, b"secret").unwrap();
        sealed[0] = 99;
        assert!(matches!(
            open(&KEY, &sealed).unwrap_err(),
            Error::UnsupportedVersion { found: 99, .. }
        ));
    }

    #[test]
    fn open_rejects_a_truncated_envelope() {
        // Слишком короткий вход не должен доезжать до `XNonce::from_slice`,
        // который на срезе не той длины паникует. Защита стоит в `decode`,
        // но со стороны `open` её ничто не удерживало.
        assert!(matches!(open(&KEY, &[1, 1]), Err(Error::Truncated { .. })));
    }
}
