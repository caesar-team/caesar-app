use crate::{Error, Result, PROTOCOL_VERSION, SUITE_ID};

/// Длина заголовка: версия + сюита.
pub const HEADER_LEN: usize = 2;
/// Длина nonce XChaCha20.
pub const NONCE_LEN: usize = 24;
/// Длина тега Poly1305.
pub const TAG_LEN: usize = 16;
/// Минимальная длина конверта: заголовок + nonce + тег пустого текста.
pub const MIN_ENVELOPE_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;

/// Разобранный конверт: заголовок проверен, части выделены.
///
/// `Debug` безопасен: внутри только nonce, шифротекст и заголовок —
/// ключей и открытого текста здесь нет.
#[derive(Debug)]
pub struct ParsedEnvelope<'a> {
    pub nonce: &'a [u8; NONCE_LEN],
    pub ciphertext: &'a [u8],
    /// Заголовок целиком — он передаётся в AEAD как AAD.
    pub aad: &'a [u8],
}

/// Собирает конверт из nonce и шифротекста.
pub fn encode(nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MIN_ENVELOPE_LEN + ciphertext.len());
    out.push(PROTOCOL_VERSION);
    out.push(SUITE_ID);
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
        let out = encode(&[0xAB; NONCE_LEN], &[1, 2, 3]);
        assert_eq!(out[0], PROTOCOL_VERSION);
        assert_eq!(out[1], SUITE_ID);
        assert_eq!(&out[2..26], &[0xAB; NONCE_LEN]);
        assert_eq!(&out[26..], &[1, 2, 3]);
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
}
