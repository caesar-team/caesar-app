use crate::keys::RecoveryKey;
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Алфавит Crockford Base32: без I, L, O, U — их путают при чтении с бумаги.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Символов в наборе, без разделителей.
const KIT_SYMBOLS: usize = 56;

/// Символов в группе. 56 = 8 групп по 7 — это и есть печатная раскладка.
const GROUP: usize = 7;

/// Длина напечатанного набора вместе с дефисами.
const PRINTED_LEN: usize = KIT_SYMBOLS + KIT_SYMBOLS / GROUP - 1;

/// Байт ключа восстановления.
const KEY_BYTES: usize = 32;

/// Байт контрольной суммы: первые три байта SHA-256 от ключа.
const CHECKSUM_BYTES: usize = 3;

/// Что именно кодируют символы набора: ключ, следом контрольная сумма.
const KIT_BYTES: usize = KEY_BYTES + CHECKSUM_BYTES;

/// Форматирует ключ восстановления для печати: 8 групп по 7 символов.
///
/// Возвращает `Zeroizing<String>`, а не `String`: напечатанный набор — это тот
/// же самый RK, только в другой записи, и по нему разворачиваются UK и VK.
/// Освободить его нетронутым — то же самое, что оставить в куче сам ключ.
/// Та же причина, по которой `aead::open` отдаёт `Zeroizing<Vec<u8>>`.
pub fn format_emergency_kit(key: &RecoveryKey) -> Zeroizing<String> {
    // 56 символов по 5 бит — это 280 бит, ключ занимает 256. Оставшиеся 24
    // несут контрольную сумму ключа, а не добивку: без неё опечатка в любом из
    // 51 несущего символа разбиралась бы как `Ok` с неверным ключом, и ошибка
    // всплывала бы позже тегом Poly1305 — неотличимо от испорченного конверта
    // или вообще чужой учётной записи. На единственном пути обратно в аккаунт
    // это разница между «проверьте набор» и глухим отказом расшифровки.
    //
    // Решение постоянное: набор печатают на бумагу, и с того момента смена
    // смысла этих 24 бит означала бы поддержку обеих кодировок навсегда.
    //
    // Ключ и сумма вместе дают 35 байт = ровно 280 бит, поэтому добивки в
    // потоке больше нет ни одного бита и каждый символ набора несущий.
    let mut payload = Zeroizing::new([0u8; KIT_BYTES]);
    payload[..KEY_BYTES].copy_from_slice(key.as_bytes());
    payload[KEY_BYTES..].copy_from_slice(&key_checksum(key.as_bytes()));

    let mut symbols = Zeroizing::new([ALPHABET[0]; KIT_SYMBOLS]);
    let mut acc: u32 = 0;
    let mut bits = 0u8;
    let mut next = 0usize;

    for &byte in payload.iter() {
        // Живыми в `acc` остаются младшие `bits` бит; всё, что выше, осталось
        // от прошлых итераций и отсекается маской `0x1f` при чтении.
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            symbols[next] = ALPHABET[((acc >> bits) & 0x1f) as usize];
            next += 1;
        }
    }

    // Ёмкость точная, поэтому `push` ни разу не перевыделяет буфер и не
    // оставляет в куче незатёртую копию набора.
    let mut printed = Zeroizing::new(String::with_capacity(PRINTED_LEN));
    for (index, &symbol) in symbols.iter().enumerate() {
        if index > 0 && index % GROUP == 0 {
            printed.push('-');
        }
        // `char::from(u8)` тотален, а алфавит — ASCII, поэтому ни проверки
        // UTF-8, ни `expect` здесь не нужны.
        printed.push(char::from(symbol));
    }
    printed
}

/// Разбирает напечатанный Emergency Kit. Дефисы, пробелы и регистр игнорируются.
///
/// Три причины отказа, и все три различимы вызывающим кодом: длина и алфавит
/// приходят как `InvalidEmergencyKit` с разным текстом, а несошедшаяся
/// контрольная сумма — отдельным вариантом `EmergencyKitChecksumMismatch`.
/// Последнее нужно биндингам, чтобы отличить «вы опечатались» от «этот ключ
/// не от этого хранилища»: набор синтаксически безупречен в обоих случаях.
pub fn parse_emergency_kit(input: &str) -> Result<RecoveryKey> {
    // Байты, а не символы: любой не-ASCII разворачивается в байты `>= 0x80`,
    // которых нет ни в алфавите, ни среди подстановок, поэтому пройти дальше
    // он не может ни при какой длине.
    let cleaned = Zeroizing::new(
        input
            .bytes()
            .filter(|b| !b.is_ascii_whitespace() && *b != b'-')
            .map(|b| b.to_ascii_uppercase())
            .collect::<Vec<u8>>(),
    );

    if cleaned.len() != KIT_SYMBOLS {
        return Err(Error::InvalidEmergencyKit(format!(
            "expected {KIT_SYMBOLS} symbols, got {}",
            cleaned.len()
        )));
    }

    let mut payload = Zeroizing::new([0u8; KIT_BYTES]);
    let mut acc: u32 = 0;
    let mut bits = 0u8;
    let mut next = 0usize;

    for &symbol in cleaned.iter() {
        acc = (acc << 5) | u32::from(symbol_value(symbol)?);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if next < payload.len() {
                payload[next] = (acc >> bits) as u8;
                next += 1;
            }
        }
    }

    let mut key = Zeroizing::new([0u8; KEY_BYTES]);
    key.copy_from_slice(&payload[..KEY_BYTES]);

    // Сумма считается от разобранного ключа и сверяется с напечатанной. Любая
    // опечатка в несущих символах меняет ключ, а с ним и сумму; опечатка в
    // хвосте меняет саму напечатанную сумму. Мимо проходит только совпадение
    // 24 бит — примерно один случай на 16.7 млн.
    let expected = key_checksum(&key);
    if payload[KEY_BYTES..] != expected[..] {
        return Err(Error::EmergencyKitChecksumMismatch);
    }

    Ok(RecoveryKey::from_bytes(*key))
}

/// Первые три байта SHA-256 от ключа — те самые 24 бита в хвосте набора.
///
/// Дайджест целиком не секрет: он однонаправлен, а его начало и так уходит на
/// бумагу, поэтому затирать его отдельно смысла нет.
fn key_checksum(key: &[u8; KEY_BYTES]) -> [u8; CHECKSUM_BYTES] {
    let digest = Sha256::digest(key);
    let mut checksum = [0u8; CHECKSUM_BYTES];
    checksum.copy_from_slice(&digest[..CHECKSUM_BYTES]);
    checksum
}

/// Переводит символ набора в его пятибитное значение. Вход уже приведён к
/// верхнему регистру вызывающим кодом.
///
/// Здесь же живёт подстановка Crockford: `I` и `L` читаются как `1`, `O` — как
/// `0`. Кодировщик этих букв не печатает никогда, поэтому во вводе они могут
/// взяться ровно одним способом: человек (или OCR) так прочитал цифру с бумаги.
/// Отвергать их значило бы показать «неверный символ» тому, кто держит в руках
/// верную распечатку, — а это последнее, что стоит между ним и потерянным
/// навсегда хранилищем. Риска подстановка не добавляет: она детерминирована и
/// не может превратить один валидный набор в другой валидный, а если человек и
/// правда ввёл не ту букву, это поймает контрольная сумма. `U` не
/// подставляется: Crockford исключил её из алфавита намеренно и замены ей не
/// задал.
fn symbol_value(symbol: u8) -> Result<u8> {
    let symbol = match symbol {
        b'I' | b'L' => b'1',
        b'O' => b'0',
        other => other,
    };

    ALPHABET
        .iter()
        .position(|&candidate| candidate == symbol)
        .map(|value| value as u8)
        .ok_or_else(|| {
            // Символ вне алфавита по определению не является частью ключа,
            // поэтому попадает в сообщение целиком: выдавать тут нечего.
            Error::InvalidEmergencyKit(format!("invalid symbol: {}", char::from(symbol)))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead;
    use crate::keys::VaultKey;

    /// SplitMix64. Нужен не как источник случайности, а как источник
    /// повторяемости: `Debug` у `RecoveryKey` редактирован, и упавший тест
    /// набор не покажет — воспроизводить придётся по номеру итерации.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next_key(&mut self) -> [u8; 32] {
            let mut key = [0u8; 32];
            for chunk in key.chunks_mut(8) {
                self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.0;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                chunk.copy_from_slice(&(z ^ (z >> 31)).to_le_bytes());
            }
            key
        }
    }

    fn round_trip(bytes: [u8; 32]) -> [u8; 32] {
        let printed = format_emergency_kit(&RecoveryKey::from_bytes(bytes));
        *parse_emergency_kit(&printed).unwrap().as_bytes()
    }

    /// `RecoveryKey` намеренно не сравнивается на равенство, поэтому
    /// `assert_eq!` по `Result` тут невозможен — вариант ошибки сверяется так.
    fn checksum_rejected(input: &str) -> bool {
        matches!(
            parse_emergency_kit(input),
            Err(Error::EmergencyKitChecksumMismatch)
        )
    }

    fn sequential_key() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index as u8;
        }
        bytes
    }

    #[test]
    fn round_trip_is_total_over_random_keys() {
        // Единственное свойство, ради которого существует модуль. Если формат и
        // разбор разойдутся хотя бы на одном входе, у этого пользователя
        // хранилище закрыто навсегда: на сервере нет ничего, что бы помогло.
        let mut rng = SplitMix64(0x0BADC0DE_DEADBEEF);
        for iteration in 0..10_000 {
            let bytes = rng.next_key();
            assert_eq!(round_trip(bytes), bytes, "iteration {iteration}");
        }
    }

    #[test]
    fn round_trip_survives_every_single_bit() {
        // Сдвиг битов на единицу в любую сторону теряет либо крайний бит, либо
        // сажает его не в тот байт. Ключ ровно с одним поднятым битом ловит это
        // на той позиции, где оно происходит, а не «где-то в 32 байтах».
        for bit in 0..256usize {
            let mut bytes = [0u8; 32];
            bytes[bit / 8] = 1 << (7 - bit % 8);
            assert_eq!(round_trip(bytes), bytes, "bit {bit}");
        }
    }

    #[test]
    fn printed_kit_matches_pinned_literals() {
        // Набор печатается на бумагу и живёт дольше любой версии клиента.
        // Литералы закреплены намеренно: пересчёт по тем же константам поехал
        // бы вместе с реализацией и не поймал бы ничего — а поймать надо ровно
        // одно, любое изменение раскладки бит. У человека с распечаткой нет
        // способа обновить её под новый кодек.
        //
        // Хвост каждого набора — контрольная сумма, первые 24 бита SHA-256 от
        // ключа: `66 68 7a` для нулевого, `af 96 13` для `0xFF`, `63 0d cd`
        // для последовательного.
        assert_eq!(
            &*format_emergency_kit(&RecoveryKey::from_bytes([0x00; 32])),
            "0000000-0000000-0000000-0000000-0000000-0000000-0000000-006CT3T"
        );
        assert_eq!(
            &*format_emergency_kit(&RecoveryKey::from_bytes([0xFF; 32])),
            "ZZZZZZZ-ZZZZZZZ-ZZZZZZZ-ZZZZZZZ-ZZZZZZZ-ZZZZZZZ-ZZZZZZZ-ZZTZ5GK"
        );
        assert_eq!(
            &*format_emergency_kit(&RecoveryKey::from_bytes(sequential_key())),
            "000G40R-40M30E2-09185GR-38E1W81-24GK2GA-HC5RR34-D1P70X3-RFP63ED"
        );
    }

    #[test]
    fn kit_is_grouped_for_reading() {
        let printed = format_emergency_kit(&RecoveryKey::from_bytes([0x5A; 32]));

        assert_eq!(printed.len(), 63);
        let groups: Vec<&str> = printed.split('-').collect();
        assert_eq!(groups.len(), 8);
        for group in groups {
            assert_eq!(group.len(), 7);
        }
    }

    #[test]
    fn every_single_symbol_typo_is_detected() {
        // До контрольной суммы опечатка в любом из 51 несущего символа давала
        // `Ok` с неверным ключом, а в четырёх последних — `Ok` с верным:
        // хвост был добивкой и в ключ не попадал. Теперь несущи все 56, и
        // проверяются здесь тоже все — и «рабочая» область, и бывшая добивка
        // (позиции 52..56, то есть группа 8).
        for bytes in [[0x00; 32], [0xFF; 32], sequential_key(), [0x5A; 32]] {
            let printed = format_emergency_kit(&RecoveryKey::from_bytes(bytes));
            let symbols: Vec<u8> = printed.bytes().filter(|b| *b != b'-').collect();
            assert_eq!(symbols.len(), KIT_SYMBOLS);

            for position in 0..KIT_SYMBOLS {
                for &replacement in ALPHABET.iter() {
                    if replacement == symbols[position] {
                        continue;
                    }
                    let mut typo = symbols.clone();
                    typo[position] = replacement;
                    let typo = String::from_utf8(typo).unwrap();

                    assert!(
                        checksum_rejected(&typo),
                        "position {position} typed as '{}' went undetected",
                        char::from(replacement)
                    );
                }
            }
        }
    }

    #[test]
    fn checksum_rejection_is_distinct_from_a_malformed_kit() {
        // Биндингам нужно развести два случая, синтаксически неотличимых:
        // «вы опечатались» и «этот ключ не от этого хранилища». Второй сюда не
        // доходит вовсе — он всплывает тегом Poly1305 при развёртывании.
        let printed = format_emergency_kit(&RecoveryKey::from_bytes([0x11; 32]));
        let mut symbols = printed.replace('-', "");
        symbols.replace_range(0..1, "Z");

        assert!(checksum_rejected(&symbols));
    }

    #[test]
    fn parsing_tolerates_human_formatting() {
        let bytes = [0x3C; 32];
        let printed = format_emergency_kit(&RecoveryKey::from_bytes(bytes));
        let messy = format!("  {}\n", printed.to_lowercase().replace('-', "  "));

        assert_eq!(parse_emergency_kit(&messy).unwrap().as_bytes(), &bytes);
    }

    #[test]
    fn parsing_substitutes_crockford_lookalikes() {
        // Тот случай, ради которого подстановка и заведена: человек переписал с
        // бумаги единицы как I и l, а нули — как O. Набор при этом верный, и
        // после подстановки обязан дать исходный ключ вместе с суммой.
        let bytes = sequential_key();
        let printed = format_emergency_kit(&RecoveryKey::from_bytes(bytes));
        assert!(
            printed.contains('0') && printed.contains('1'),
            "the fixture must exercise both substitutions: {}",
            &*printed
        );

        for (one, zero) in [("I", "O"), ("i", "o"), ("L", "O"), ("l", "o")] {
            let retyped = printed.replace('1', one).replace('0', zero);
            assert_eq!(
                parse_emergency_kit(&retyped).unwrap().as_bytes(),
                &bytes,
                "lookalikes {one}/{zero}"
            );
        }
    }

    /// Обе точки проверки возвращают один и тот же вариант ошибки, поэтому
    /// `matches!(.., InvalidEmergencyKit(_))` не отличает «плохой символ» от
    /// «плохая длина». Тесты ниже сверяют причину, иначе каждый из них
    /// проходил бы на отказе по чужому поводу.
    fn rejection_reason(input: &str) -> String {
        match parse_emergency_kit(input) {
            Err(Error::InvalidEmergencyKit(detail)) => detail,
            other => panic!("expected InvalidEmergencyKit, got {other:?}"),
        }
    }

    #[test]
    fn parsing_rejects_symbols_outside_the_alphabet() {
        // `U` выброшена Crockford'ом намеренно и замены не имеет — в отличие от
        // I, L и O она обязана оставаться ошибкой. Кириллическая `О` идёт сюда
        // же: от латинской она на бумаге неотличима, а в UTF-8 разворачивается
        // в два байта `>= 0x80`, до которых подстановке дела нет.
        let filler = "0".repeat(KIT_SYMBOLS - 2);
        let inputs = [
            "U".repeat(KIT_SYMBOLS),
            "$".repeat(KIT_SYMBOLS),
            format!("{filler}\u{041E}"),
        ];

        for input in inputs {
            // Длина ровно в один набор: иначе сработала бы проверка выше и тест
            // доказывал бы не то, что написано в его имени.
            assert_eq!(input.len(), KIT_SYMBOLS);
            let reason = rejection_reason(&input);
            assert!(
                reason.starts_with("invalid symbol"),
                "expected an alphabet rejection, got: {reason}"
            );
        }
    }

    #[test]
    fn parsing_rejects_wrong_length() {
        let printed = format_emergency_kit(&RecoveryKey::from_bytes([0x11; 32]));
        let symbols = printed.replace('-', "");
        let short = symbols[..KIT_SYMBOLS - 1].to_string();
        let long = format!("{symbols}7");

        for input in [short, long] {
            let reason = rejection_reason(&input);
            assert!(
                reason.starts_with("expected"),
                "expected a length rejection for {} symbols, got: {reason}",
                input.len()
            );
        }
    }

    #[test]
    fn recovery_key_survives_the_printed_kit() {
        // Весь механизм восстановления целиком: RK оборачивает те же ключи, что
        // и KEK, а между «напечатали» и «ввели заново» стоит только этот кодек.
        let recovery_key = RecoveryKey::generate().unwrap();
        let vault_key = VaultKey::generate().unwrap();
        let wrapped = aead::seal(recovery_key.as_bytes(), vault_key.as_bytes()).unwrap();

        let printed = format_emergency_kit(&recovery_key);
        let restored = parse_emergency_kit(&printed).unwrap();

        assert_eq!(
            &aead::open(restored.as_bytes(), &wrapped).unwrap()[..],
            &vault_key.as_bytes()[..]
        );
    }
}
