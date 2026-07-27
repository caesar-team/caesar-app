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

// `KIT_SYMBOLS` читается как настройка печатной раскладки, но несущий он.
// Уменьшить его — значит получить набор, который физически не вмещает ключ:
// `format` упал бы по индексу (громко и на месте), а вот `parse` вернул бы
// молча дополненный нулями ключ — ровно та тихая катастрофа, ради которой
// модуль и написан. Обе стороны кодека здесь же и закрепляются.
const _: () = assert!(KIT_SYMBOLS * 5 >= KEY_BYTES * 8);
const _: () = assert!(KIT_SYMBOLS * 5 == KIT_BYTES * 8);

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
    // это разница между «проверьте группу 4» и глухим отказом расшифровки.
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
    debug_assert_eq!(bits, 0, "kit encoding must not leave a partial symbol");

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

/// Разбирает напечатанный Emergency Kit. Разделители и регистр игнорируются.
///
/// Три причины отказа, и все три различимы вызывающим кодом: длина и алфавит
/// приходят как `InvalidEmergencyKit` с разным текстом, а несошедшаяся
/// контрольная сумма — отдельным вариантом `EmergencyKitChecksumMismatch`.
/// Последнее нужно биндингам, чтобы отличить «вы опечатались» от «этот ключ
/// не от этого хранилища»: набор синтаксически безупречен в обоих случаях.
pub fn parse_emergency_kit(input: &str) -> Result<RecoveryKey> {
    let cleaned = clean_symbols(input)?;

    let mut payload = Zeroizing::new([0u8; KIT_BYTES]);
    let mut acc: u32 = 0;
    let mut bits = 0u8;
    let mut next = 0usize;

    for (index, &symbol) in cleaned.iter().enumerate() {
        acc = (acc << 5) | u32::from(symbol_value(symbol, index)?);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            payload[next] = (acc >> bits) as u8;
            next += 1;
        }
    }
    // Страховка к константам выше: если набор перестанет вмещать ключ целиком,
    // сюда доедет частично заполненный `payload`, а не молчаливый нулевой хвост.
    debug_assert_eq!(next, payload.len(), "kit does not carry a full key");

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

/// Разделитель, который человек мог принести вместе с набором.
///
/// `is_ascii_whitespace` тут мало: набор, скопированный из документа, приезжает
/// с неразрывными пробелами и с дефисами, которые автозамена превратила в тире.
/// Без этого фильтра такой ввод отвергался бы по длине — «ожидалось 56
/// символов, получено 77», то есть формально верно и совершенно сбивающе с
/// толку для того, кто эти 56 символов только что пересчитал глазами.
fn is_separator(character: char) -> bool {
    character.is_whitespace()
        || character == '-'
        || matches!(character, '\u{2010}'..='\u{2015}' | '\u{2212}')
}

/// Вычищает разделители, приводит к верхнему регистру и проверяет длину.
fn clean_symbols(input: &str) -> Result<Zeroizing<Vec<u8>>> {
    // Ёмкость набирается сразу и не растёт никогда: за границей набора символы
    // только считаются. `collect` по итератору с `filter` так не умеет — там
    // нижняя граница `size_hint` равна нулю, и буфер растёт 8 → 16 → 32 → 64,
    // оставляя в куче три незатёртых куска начала ключа. То же самое сделал бы
    // и `extend` на входе длиннее набора. В wasm это особенно неприятно:
    // линейная память операционной системе не возвращается никогда.
    let mut cleaned = Zeroizing::new(Vec::with_capacity(KIT_SYMBOLS));
    let mut symbols = 0usize;

    for character in input.chars() {
        if is_separator(character) {
            continue;
        }
        if !character.is_ascii() {
            // Байтовый разбор показал бы здесь `Ð` — первый байт UTF-8 от
            // кириллической `О`. Человеку, который смотрит на свою же букву,
            // это сообщение не говорит ничего.
            return Err(Error::InvalidEmergencyKit(format!(
                "non-Latin character '{character}' in {}",
                symbol_location(symbols)
            )));
        }
        if symbols < KIT_SYMBOLS {
            // ASCII проверен строкой выше, поэтому приведение не усекает.
            cleaned.push(character.to_ascii_uppercase() as u8);
        }
        symbols += 1;
    }

    if symbols != KIT_SYMBOLS {
        return Err(Error::InvalidEmergencyKit(format!(
            "expected {KIT_SYMBOLS} symbols, got {symbols}"
        )));
    }

    Ok(cleaned)
}

/// Место символа в печатной раскладке — так, как его видит человек с листом.
fn symbol_location(index: usize) -> String {
    format!(
        "group {}, position {}",
        index / GROUP + 1,
        index % GROUP + 1
    )
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
fn symbol_value(symbol: u8, index: usize) -> Result<u8> {
    let substituted = match symbol {
        b'I' | b'L' => b'1',
        b'O' => b'0',
        other => other,
    };

    ALPHABET
        .iter()
        .position(|&candidate| candidate == substituted)
        .map(|value| value as u8)
        .ok_or_else(|| {
            // Символ вне алфавита по определению не является частью ключа,
            // поэтому попадает в сообщение целиком. Вместе с ним — место: на
            // последнем экране перед потерянным хранилищем «проверьте группу
            // 4» стоит дороже, чем «где-то среди 56 символов».
            Error::InvalidEmergencyKit(format!(
                "invalid symbol '{}' in {}",
                char::from(symbol),
                symbol_location(index)
            ))
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
    fn parsing_tolerates_unicode_separators() {
        // Набор, проехавший через текстовый редактор: дефисы стали тире, а
        // пробелы — неразрывными. Символы при этом человек переписал верно, и
        // отказывать ему не за что.
        let bytes = [0x3C; 32];
        let printed = format_emergency_kit(&RecoveryKey::from_bytes(bytes));

        for separator in [
            "\u{2010}", "\u{2011}", "\u{2012}", "\u{2013}", "\u{2014}", "\u{2015}", "\u{2212}",
            "\u{00A0}", "\u{2007}", "\u{3000}",
        ] {
            let retyped = printed.replace('-', separator);
            assert_eq!(
                parse_emergency_kit(&retyped).unwrap().as_bytes(),
                &bytes,
                "separator {separator:?}"
            );
        }
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
        // I, L и O она обязана оставаться ошибкой.
        let inputs = ["U".repeat(KIT_SYMBOLS), "$".repeat(KIT_SYMBOLS)];

        for input in inputs {
            // Длина ровно в один набор: иначе сработала бы проверка длины и
            // тест доказывал бы не то, что написано в его имени.
            assert_eq!(input.len(), KIT_SYMBOLS);
            let reason = rejection_reason(&input);
            assert!(
                reason.starts_with("invalid symbol"),
                "expected an alphabet rejection, got: {reason}"
            );
        }
    }

    #[test]
    fn parsing_names_the_position_of_a_bad_symbol() {
        // Сообщение читает человек, у которого этот набор — последнее, что
        // осталось от хранилища. «Неверный символ» без места отправляет его
        // перечитывать все 56.
        let mut symbols = "0".repeat(KIT_SYMBOLS);
        symbols.replace_range(23..24, "$");

        assert_eq!(
            rejection_reason(&symbols),
            "invalid symbol '$' in group 4, position 3"
        );
    }

    #[test]
    fn parsing_names_non_latin_characters() {
        // Кириллическая `О` от латинской на бумаге неотличима, а в UTF-8
        // разворачивается в два байта `>= 0x80`. Байтовый разбор показывал
        // здесь `Ð` — первый байт этой пары, то есть мусор вместо подсказки.
        let mut symbols = "0".repeat(KIT_SYMBOLS - 1);
        symbols.insert(8, '\u{041E}');

        assert_eq!(
            rejection_reason(&symbols),
            "non-Latin character 'О' in group 2, position 2"
        );
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
