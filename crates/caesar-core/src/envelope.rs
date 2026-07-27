use crate::{Error, Result, PROTOCOL_VERSION, SUITE_ID};

/// Длина заголовка: версия + сюита.
pub const HEADER_LEN: usize = 2;
/// Длина nonce XChaCha20.
pub const NONCE_LEN: usize = 24;
/// Длина тега Poly1305.
pub const TAG_LEN: usize = 16;
/// Минимальная длина конверта: заголовок + nonce + тег пустого текста.
pub const MIN_ENVELOPE_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;

/// Заголовок, который пишет `encode` и который передаётся в AEAD как AAD.
/// Единственный источник правды: `seal` в Task 5 обязан использовать его,
/// а не собирать массив заново.
pub const HEADER: [u8; HEADER_LEN] = [PROTOCOL_VERSION, SUITE_ID];

/// Разобранный конверт: заголовок проверен, части выделены.
///
/// Это заимствованное представление буфера: оно живёт ровно столько, сколько
/// живёт исходный срез, и не предназначено для пересечения языковой границы —
/// не помечайте его `#[uniffi::export]`.
///
/// `Debug` реализован вручную, чтобы тесты могли звать `unwrap_err()` на
/// `Result<ParsedEnvelope, _>`, но содержимое редактируется: шифротекст — не
/// открытый текст, однако производный `Debug` сделал бы любой агрегатор логов
/// новым непроверенным хранителем зашифрованных хранилищ пользователей.
/// Отлаживать всё равно нужно длины.
#[non_exhaustive]
pub struct ParsedEnvelope<'a> {
    pub nonce: &'a [u8; NONCE_LEN],
    pub ciphertext: &'a [u8],
    /// Заголовок целиком — он передаётся в AEAD как AAD.
    ///
    /// Сегодня заголовок всегда `[1, 1]`, и отказ при подмене даёт явная
    /// проверка в `decode`, а не тег. AAD существует ради версии 2: когда
    /// `decode` начнёт принимать несколько версий, тег будет привязывать
    /// шифротекст к тому заголовку, под которым он был запечатан.
    /// Проверки в `decode` удалять нельзя — они дают точную ошибку.
    pub aad: &'a [u8],
}

impl std::fmt::Debug for ParsedEnvelope<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedEnvelope")
            .field("nonce", &format_args!("[{} bytes]", NONCE_LEN))
            .field(
                "ciphertext",
                &format_args!("[{} bytes]", self.ciphertext.len()),
            )
            .field("aad", &self.aad)
            .finish()
    }
}

/// Собирает конверт из nonce и шифротекста.
///
/// Предусловие: `ciphertext` уже включает тег AEAD, то есть его длина не
/// меньше [`TAG_LEN`]. Конверт короче [`MIN_ENVELOPE_LEN`] его собственный
/// [`decode`] отвергнет как `Truncated`.
pub fn encode(nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Vec<u8> {
    debug_assert!(
        ciphertext.len() >= TAG_LEN,
        "ciphertext must include the AEAD tag"
    );
    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&HEADER);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out
}

/// Разбирает конверт. Отказывается при незнакомой версии или сюите.
pub fn decode(bytes: &[u8]) -> Result<ParsedEnvelope<'_>> {
    if bytes.len() < MIN_ENVELOPE_LEN {
        return Err(Error::Truncated {
            got: bytes.len(),
            need: MIN_ENVELOPE_LEN,
        });
    }
    if bytes[0] != PROTOCOL_VERSION {
        return Err(Error::UnsupportedVersion {
            found: bytes[0],
            supported: PROTOCOL_VERSION,
        });
    }
    if bytes[1] != SUITE_ID {
        return Err(Error::UnsupportedSuite {
            found: bytes[1],
            supported: SUITE_ID,
        });
    }
    let nonce = bytes[HEADER_LEN..HEADER_LEN + NONCE_LEN]
        .try_into()
        .expect("slice length checked above");
    Ok(ParsedEnvelope {
        nonce,
        ciphertext: &bytes[HEADER_LEN + NONCE_LEN..],
        aad: &bytes[..HEADER_LEN],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_header_then_nonce_then_ciphertext() {
        // Смещения 2 и 26 захардкожены намеренно: они закрепляют формат на
        // проводе независимо от констант. Если кто-то поменяет NONCE_LEN,
        // тест обязан упасть громко, а не молча поехать следом за константой.
        // Не «упрощать» до HEADER_LEN / HEADER_LEN + NONCE_LEN.
        let ciphertext = [7u8; TAG_LEN];
        let out = encode(&[0xAB; NONCE_LEN], &ciphertext);
        assert_eq!(out[0], PROTOCOL_VERSION);
        assert_eq!(out[1], SUITE_ID);
        assert_eq!(&out[2..26], &[0xAB; NONCE_LEN]);
        assert_eq!(&out[26..], &ciphertext);
    }

    #[test]
    fn round_trips() {
        let ciphertext = vec![9u8; TAG_LEN + 5];
        let encoded = encode(&[0x11; NONCE_LEN], &ciphertext);
        let parsed = decode(&encoded).unwrap();
        assert_eq!(parsed.nonce, &[0x11; NONCE_LEN]);
        assert_eq!(parsed.ciphertext, &ciphertext[..]);
        assert_eq!(parsed.aad, &[PROTOCOL_VERSION, SUITE_ID]);
    }

    #[test]
    fn rejects_unknown_version_instead_of_guessing() {
        let mut encoded = encode(&[0; NONCE_LEN], &[0; TAG_LEN]);
        encoded[0] = 99;
        assert_eq!(
            decode(&encoded).unwrap_err(),
            Error::UnsupportedVersion {
                found: 99,
                supported: PROTOCOL_VERSION
            }
        );
    }

    #[test]
    fn rejects_unknown_suite() {
        let mut encoded = encode(&[0; NONCE_LEN], &[0; TAG_LEN]);
        encoded[1] = 42;
        assert_eq!(
            decode(&encoded).unwrap_err(),
            Error::UnsupportedSuite {
                found: 42,
                supported: SUITE_ID
            }
        );
    }

    #[test]
    fn rejects_truncated_envelope() {
        assert!(matches!(
            decode(&[1, 1, 0, 0]),
            Err(Error::Truncated { .. })
        ));
    }

    #[test]
    fn accepts_exactly_minimum_length_as_empty_plaintext() {
        let encoded = encode(&[0; NONCE_LEN], &[0; TAG_LEN]);
        assert_eq!(encoded.len(), MIN_ENVELOPE_LEN);
        assert_eq!(decode(&encoded).unwrap().ciphertext.len(), TAG_LEN);
    }

    #[test]
    fn rejects_one_byte_below_minimum() {
        let mut encoded = encode(&[0; NONCE_LEN], &[0; TAG_LEN]);
        encoded.pop();
        assert_eq!(
            decode(&encoded).unwrap_err(),
            Error::Truncated {
                got: MIN_ENVELOPE_LEN - 1,
                need: MIN_ENVELOPE_LEN
            }
        );
    }
}
