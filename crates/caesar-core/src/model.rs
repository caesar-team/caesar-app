use crate::aead;
use crate::error::redact_plaintext_detail;
use crate::keys::VaultKey;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Версия схемы открытого текста. Независима от `PROTOCOL_VERSION`.
pub const ITEM_SCHEMA_VERSION: u8 = 1;

/// Длина префикса длины: `u32` little-endian.
const LEN_PREFIX_LEN: usize = 4;

/// Наименьший бакет паддинга.
///
/// Полный логин с паролем и TOTP укладывается примерно в 260 байт, заметка и
/// карта — меньше. 256 — первая степень двойки, которая накрывает подавляющее
/// большинство айтемов одним бакетом, то есть не даёт серверу развести типы по
/// размеру записи. Меньший минимум (128) вернул бы это различие, больший
/// удвоил бы хранение, ничего не скрыв дополнительно.
const MIN_BUCKET: usize = 256;

/// Строка, содержимое которой зачищается при выходе из области видимости.
///
/// `Zeroizing` не транзитивен: `aead::open` отдаёт зачищаемый буфер, но serde
/// строит из него свежие `String` вне всякой защиты, и пароль остаётся в куче
/// после дропа айтема. Обёртка возвращает гарантию содержимому полей.
///
/// Чего она не даёт: `String::zeroize` затирает текущую аллокацию, а промежуточные
/// перевыделения, которые serde делает при разборе, ей недоступны — это предел
/// зачистки в Rust, а не свойство этого типа.
///
/// Второе назначение — `Debug`. Производный `Debug` у `ItemSecret` напечатал бы
/// пароль в первый же лог хоста; здесь он редактируется, как у ключей.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretString([redacted])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ItemKind {
    Login,
    SecureNote,
    CreditCard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomField {
    pub label: SecretString,
    pub value: SecretString,
    #[serde(default)]
    pub hidden: bool,
}

/// Содержимое айтема. Сервер видит только его шифротекст.
///
/// `deny_unknown_fields` намеренно строг: клиент, встретивший поле из будущей
/// версии, обязан отказаться, а не молча его потерять при следующем сохранении.
///
/// `ZeroizeOnDrop` затирает все пользовательские строки и `v`. `kind` пропущен:
/// это безполевой перечислитель без собственной аллокации, и после дропа от него
/// остаётся байт дискриминанта, а не ключевой материал.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ItemSecret {
    pub v: u8,
    #[zeroize(skip)]
    pub kind: ItemKind,
    pub title: SecretString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<SecretString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_uri: Option<SecretString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<SecretString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<SecretString>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<SecretString>,
}

impl ItemSecret {
    pub fn new(kind: ItemKind, title: impl Into<String>) -> Self {
        Self {
            v: ITEM_SCHEMA_VERSION,
            kind,
            title: SecretString::new(title),
            username: None,
            password: None,
            totp_uri: None,
            website: None,
            notes: None,
            custom_fields: Vec::new(),
            tags: Vec::new(),
        }
    }
}

/// Единственная точка, где деталь из расшифрованного текста становится ошибкой.
///
/// Сообщения serde называют поля хранилища, а строка уходит через границу FFI
/// в логи хоста, поэтому деталь редактируется. Структурные отказы паддинга сюда
/// же: объявленная длина — это ровно та метаданная, которую паддинг и прячет.
fn malformed(detail: impl std::fmt::Display) -> Error {
    Error::MalformedPlaintext(redact_plaintext_detail(detail))
}

/// Бакет для полезной нагрузки в `len` байт: наименьшая степень двойки не
/// меньше [`MIN_BUCKET`], вмещающая её.
///
/// `None`, когда бакет не помещается в `usize`. На wasm32 это достижимо
/// быстрее, чем на 64-битных целях, и паникующий `next_power_of_two` там
/// унёс бы весь модуль.
fn bucket_for(len: usize) -> Option<usize> {
    len.max(MIN_BUCKET).checked_next_power_of_two()
}

/// Длина корректного открытого текста айтема.
///
/// Выражено через [`bucket_for`], чтобы у границ бакета был один источник
/// правды: писатель и читатель не могут разойтись в том, что считается бакетом.
fn is_bucket(len: usize) -> bool {
    bucket_for(len) == Some(len)
}

/// Дополняет JSON до границы бакета: `len(u32 LE) || json || zeros`.
///
/// Длина конверта равна `42 + len(plaintext)`, поэтому без паддинга размер
/// записи выдаёт серверу длину JSON, а с ней тип айтема, примерную длину пароля
/// и факт того, что пользователь её изменил.
fn pad(json: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    // Обе ветки — «айтем не адресуется форматом»: префикс шире `u32` либо бакет
    // шире `usize`. Отказ, а не паника и не молчаливое усечение до `as u32`.
    let prefix = u32::try_from(json.len()).map_err(|_| Error::PlaintextTooLarge)?;
    let total = LEN_PREFIX_LEN
        .checked_add(json.len())
        .and_then(bucket_for)
        .ok_or(Error::PlaintextTooLarge)?;

    let mut padded = Zeroizing::new(vec![0u8; total]);
    padded[..LEN_PREFIX_LEN].copy_from_slice(&prefix.to_le_bytes());
    padded[LEN_PREFIX_LEN..LEN_PREFIX_LEN + json.len()].copy_from_slice(json);
    Ok(padded)
}

/// Обрезает дополненный открытый текст по префиксу длины.
///
/// Отвергает буфер, длина которого не является бакетом, и префикс, выходящий за
/// его пределы. Оба случая означают писателя, разошедшегося с форматом: подделать
/// их снаружи нельзя без ключа хранилища, но клиент другой платформы — можно, и
/// сервер такого расхождения не увидит.
///
/// Содержимое хвоста не проверяется: формат объявляет его нулями, но чтение
/// опирается только на префикс.
fn unpad(padded: &[u8]) -> Result<&[u8]> {
    if !is_bucket(padded.len()) {
        return Err(malformed(format!(
            "padded plaintext is {} bytes, which is not a padding bucket",
            padded.len()
        )));
    }
    // Разрез безопасен: бакет не короче `MIN_BUCKET`.
    let (prefix, body) = padded.split_at(LEN_PREFIX_LEN);
    let declared = u32::from_le_bytes(
        prefix
            .try_into()
            .expect("bucket is at least MIN_BUCKET bytes long"),
    ) as usize;

    body.get(..declared).ok_or_else(|| {
        malformed(format!(
            "declared length {declared} exceeds the {} bytes the bucket holds",
            body.len()
        ))
    })
}

/// Сериализует айтем, дополняет до бакета и шифрует ключом хранилища.
pub fn seal_item(item: &ItemSecret, vault_key: &VaultKey) -> Result<Vec<u8>> {
    // Буфер serde содержит пароль в открытом виде — он обязан зачищаться так же,
    // как то, что возвращает `aead::open`.
    let json = Zeroizing::new(serde_json::to_vec(item).map_err(malformed)?);
    let padded = pad(&json)?;
    aead::seal(vault_key.as_bytes(), &padded)
}

/// Расшифровывает конверт, снимает паддинг и разбирает айтем.
pub fn open_item(sealed: &[u8], vault_key: &VaultKey) -> Result<ItemSecret> {
    let padded = aead::open(vault_key.as_bytes(), sealed)?;
    let json = unpad(&padded)?;
    serde_json::from_slice(json).map_err(malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    fn sample() -> ItemSecret {
        let mut item = ItemSecret::new(ItemKind::Login, "Northwind Bank");
        item.username = Some("a.kern".into());
        item.password = Some("t7-Quarry-Ledger-49".into());
        item.website = Some("northwind.example".into());
        item.tags = vec!["finance".into(), "2fa".into()];
        item
    }

    fn full_item() -> ItemSecret {
        let mut item = sample();
        item.totp_uri = Some("otpauth://totp/x".into());
        item.notes = Some("branch 12".into());
        item.custom_fields = vec![CustomField {
            label: "pin".into(),
            value: "4242".into(),
            hidden: true,
        }];
        item
    }

    #[test]
    fn item_round_trips() {
        let vk = VaultKey::generate().unwrap();
        let sealed = seal_item(&sample(), &vk).unwrap();
        assert_eq!(open_item(&sealed, &vk).unwrap(), sample());
    }

    #[test]
    fn item_larger_than_the_first_bucket_round_trips() {
        // Пересекает границу 256 → 512: путь с непустым хвостом нулей и
        // префиксом, который больше не совпадает с длиной буфера.
        let mut item = sample();
        item.notes = Some("x".repeat(600).into());
        let vk = VaultKey::generate().unwrap();
        let sealed = seal_item(&item, &vk).unwrap();
        assert_eq!(open_item(&sealed, &vk).unwrap(), item);
    }

    #[test]
    fn wrong_vault_key_fails() {
        let sealed = seal_item(&sample(), &VaultKey::generate().unwrap()).unwrap();
        assert_eq!(
            open_item(&sealed, &VaultKey::generate().unwrap()).unwrap_err(),
            Error::DecryptionFailed
        );
    }

    #[test]
    fn unknown_field_is_rejected_not_ignored() {
        // Клиент старой версии не должен молча терять данные новой.
        let vk = VaultKey::generate().unwrap();
        let seal_json = |json: &[u8]| aead::seal(vk.as_bytes(), &pad(json).unwrap()).unwrap();

        let known = br#"{"v":1,"kind":"login","title":"x"}"#;
        assert!(
            open_item(&seal_json(known), &vk).is_ok(),
            "control: the same document without the extra field must open"
        );

        assert!(matches!(
            open_item(&seal_json(UNKNOWN_FIELD_JSON), &vk),
            Err(Error::MalformedPlaintext(_))
        ));
    }

    #[test]
    fn unknown_field_inside_a_custom_field_is_rejected() {
        let vk = VaultKey::generate().unwrap();
        let json = br#"{"v":1,"kind":"login","title":"x","customFields":[{"label":"a","value":"b","futureField":true}]}"#;
        let sealed = aead::seal(vk.as_bytes(), &pad(json).unwrap()).unwrap();
        assert!(matches!(
            open_item(&sealed, &vk),
            Err(Error::MalformedPlaintext(_))
        ));
    }

    #[test]
    fn schema_version_is_pinned() {
        // Попадает в каждый сохранённый айтем: смена — ломающее изменение.
        assert_eq!(ITEM_SCHEMA_VERSION, 1);
        assert_eq!(ItemSecret::new(ItemKind::Login, "x").v, 1);
    }

    #[test]
    fn wire_format_is_pinned() {
        // Литерал, а не сборка из констант: имена полей, их порядок, camelCase
        // и имена вариантов `kind` — это формат на проводе, который обязаны
        // повторить Swift и TypeScript. Расхождение здесь сервер не поймает.
        assert_eq!(
            serde_json::to_string(&full_item()).unwrap(),
            r#"{"v":1,"kind":"login","title":"Northwind Bank","username":"a.kern","password":"t7-Quarry-Ledger-49","totpUri":"otpauth://totp/x","website":"northwind.example","notes":"branch 12","customFields":[{"label":"pin","value":"4242","hidden":true}],"tags":["finance","2fa"]}"#
        );
    }

    #[test]
    fn absent_optionals_are_omitted_from_the_wire() {
        assert_eq!(
            serde_json::to_string(&ItemSecret::new(ItemKind::SecureNote, "n")).unwrap(),
            r#"{"v":1,"kind":"secureNote","title":"n"}"#
        );
    }

    #[test]
    fn item_kind_names_are_pinned() {
        for (kind, expected) in [
            (ItemKind::Login, r#""login""#),
            (ItemKind::SecureNote, r#""secureNote""#),
            (ItemKind::CreditCard, r#""creditCard""#),
        ] {
            assert_eq!(serde_json::to_string(&kind).unwrap(), expected);
        }
    }

    #[test]
    fn padded_plaintext_layout_is_pinned() {
        let padded = pad(b"{}").unwrap();
        assert_eq!(padded.len(), 256);
        assert_eq!(&padded[..6], &[0x02, 0x00, 0x00, 0x00, b'{', b'}']);
        assert!(padded[6..].iter().all(|&b| b == 0));
    }

    #[test]
    fn buckets_are_powers_of_two_from_256() {
        assert_eq!(bucket_for(0), Some(256));
        assert_eq!(bucket_for(255), Some(256));
        assert_eq!(bucket_for(256), Some(256));
        assert_eq!(bucket_for(257), Some(512));
        assert_eq!(bucket_for(512), Some(512));
        assert_eq!(bucket_for(513), Some(1024));
        assert_eq!(bucket_for(4096), Some(4096));
        assert_eq!(bucket_for(4097), Some(8192));
        // Не паника: под UniFFI она унесла бы хост-приложение.
        assert_eq!(bucket_for(usize::MAX), None);
    }

    #[test]
    fn bucket_boundary_counts_the_length_prefix() {
        // Ровно те два размера, на которых видна забытая четвёрка префикса.
        assert_eq!(pad(&vec![b'x'; 252]).unwrap().len(), 256);
        assert_eq!(pad(&vec![b'x'; 253]).unwrap().len(), 512);
    }

    #[test]
    fn sealed_length_does_not_track_item_length() {
        // Ради этого и существует паддинг: без него длина конверта выдала бы
        // серверу длину пароля и факт её изменения при обновлении.
        let vk = VaultKey::generate().unwrap();
        let short = ItemSecret::new(ItemKind::SecureNote, "n");
        let mut long = ItemSecret::new(ItemKind::SecureNote, "n");
        long.notes = Some("x".repeat(150).into());

        let short_len = seal_item(&short, &vk).unwrap().len();
        assert_eq!(short_len, seal_item(&long, &vk).unwrap().len());
        // 42 байта конверта (2 заголовок + 24 nonce + 16 тег) поверх бакета 256.
        assert_eq!(short_len, 298);
    }

    #[test]
    fn unpad_rejects_a_length_prefix_past_the_buffer() {
        let mut padded = vec![0u8; 256];
        padded[..LEN_PREFIX_LEN].copy_from_slice(&253u32.to_le_bytes());
        assert!(matches!(unpad(&padded), Err(Error::MalformedPlaintext(_))));

        // Наибольший префикс, который бакет 256 действительно вмещает.
        padded[..LEN_PREFIX_LEN].copy_from_slice(&252u32.to_le_bytes());
        assert_eq!(unpad(&padded).unwrap().len(), 252);
    }

    #[test]
    fn unpad_rejects_a_plaintext_that_is_not_a_bucket() {
        // 0 и 4 заодно проверяют, что буфер короче префикса не доезжает до
        // разреза и не паникует.
        for len in [0usize, 4, 255, 257, 384, 511] {
            assert!(
                matches!(unpad(&vec![0u8; len]), Err(Error::MalformedPlaintext(_))),
                "length {len} must not pass as a bucket"
            );
        }
    }

    #[test]
    fn open_item_rejects_an_unpadded_plaintext() {
        // Клиент, который забыл паддинг, пишет `len || json` без хвоста. Без
        // проверки бакета такая запись разобралась бы молча, и расхождение
        // реализаций осталось бы незамеченным — сервер его не видит.
        let json = serde_json::to_vec(&sample()).unwrap();
        let mut plaintext = u32::try_from(json.len()).unwrap().to_le_bytes().to_vec();
        plaintext.extend_from_slice(&json);
        assert!(!is_bucket(plaintext.len()), "test premise: not a bucket");

        let vk = VaultKey::generate().unwrap();
        let sealed = aead::seal(vk.as_bytes(), &plaintext).unwrap();
        assert!(matches!(
            open_item(&sealed, &vk),
            Err(Error::MalformedPlaintext(_))
        ));
    }

    /// Возвращает деталь `MalformedPlaintext` для запечатанного открытого текста.
    fn malformed_detail_of(plaintext: &[u8]) -> String {
        let vk = VaultKey::generate().unwrap();
        let sealed = aead::seal(vk.as_bytes(), plaintext).unwrap();
        match open_item(&sealed, &vk) {
            Err(Error::MalformedPlaintext(detail)) => detail,
            other => panic!("expected MalformedPlaintext, got {other:?}"),
        }
    }

    const UNKNOWN_FIELD_JSON: &[u8] = br#"{"v":1,"kind":"login","title":"x","futureField":true}"#;

    #[cfg(not(feature = "debug-errors"))]
    #[test]
    fn malformed_plaintext_detail_is_redacted() {
        // Строка уходит через границу FFI в логи хоста. Сообщения serde называют
        // поля хранилища, а деталь паддинга — объявленную длину, то есть ровно ту
        // метаданную, которую паддинг и прячет.
        let from_serde = malformed_detail_of(&pad(UNKNOWN_FIELD_JSON).unwrap());
        assert!(
            !from_serde.contains("futureField"),
            "serde detail reached the caller: {from_serde}"
        );

        let unpadded = vec![0u8; 300];
        let from_padding = malformed_detail_of(&unpadded);
        assert!(
            !from_padding.contains(&unpadded.len().to_string()),
            "padding detail reached the caller: {from_padding}"
        );
    }

    #[cfg(feature = "debug-errors")]
    #[test]
    fn debug_errors_build_keeps_malformed_plaintext_detail() {
        // Парный тест: доказывает, что деталь проходит через
        // `redact_plaintext_detail`, а не заменена на константу.
        let detail = malformed_detail_of(&pad(UNKNOWN_FIELD_JSON).unwrap());
        assert!(detail.contains("futureField"), "{detail}");
    }

    #[test]
    fn item_secret_zeroizes_its_contents() {
        let mut item = full_item();
        item.zeroize();

        assert_eq!(item.title.as_str(), "");
        assert!(item.username.is_none());
        assert!(item.password.is_none());
        assert!(item.totp_uri.is_none());
        assert!(item.website.is_none());
        assert!(item.notes.is_none());
        assert!(item.custom_fields.is_empty());
        assert!(item.tags.is_empty());
    }

    #[test]
    fn secret_types_zeroize_on_drop() {
        // Тип-уровневое утверждение: без `ZeroizeOnDrop` это не скомпилируется.
        _assert_zeroize_on_drop::<SecretString>();
        _assert_zeroize_on_drop::<CustomField>();
        _assert_zeroize_on_drop::<ItemSecret>();
    }

    #[test]
    fn debug_output_hides_item_contents() {
        let rendered = format!("{:?}", full_item());
        for secret in [
            "Northwind Bank",
            "a.kern",
            "t7-Quarry-Ledger-49",
            "otpauth",
            "northwind.example",
            "branch 12",
            "4242",
            "finance",
        ] {
            assert!(
                !rendered.contains(secret),
                "Debug leaked {secret}: {rendered}"
            );
        }
        // Тип айтема остаётся: без него отладочный вывод бесполезен, а сервер
        // его и так не видит — он не покидает устройство иначе, чем через логи.
        assert!(rendered.contains("Login"));
    }
}
