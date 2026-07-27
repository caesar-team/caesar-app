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
/// Замеренные длины JSON реальных айтемов:
///
/// | айтем | байт JSON |
/// |---|---|
/// | голая защищённая заметка | 39 |
/// | минимальный логин без TOTP | 135 |
/// | карта с двумя своими полями | 220 |
/// | логин с паролем, TOTP и заметкой (`full_item` в тестах) | 266 |
/// | логин с полным `otpauth://` URI | 334 |
///
/// При минимуме 256 граница проходит по 252 байтам JSON — внутри разброса
/// обычного логина, и первые три строки попадают в один бакет, а последние две
/// в другой. Сервер при этом не узнаёт «заметка или логин», но узнаёт
/// «пустой или заполненный» и, что хуже, видит *переход*: добавление TOTP или
/// абзаца заметок сдвигает запись с 298 на 554 байта в конкретный день у
/// конкретного айтема. Ровно ту утечку паддинг и должен закрывать.
///
/// 512 накрывает все пять строк одним бакетом. Цена — 554 КиБ против 298 КиБ на
/// хранилище в 1000 айтемов; дизайн-документ закладывал «примерно двукратный
/// объём… то есть килобайты».
const MIN_BUCKET: usize = 512;

/// Строка, содержимое которой зачищается при выходе из области видимости.
///
/// `Zeroizing` не транзитивен: `aead::open` отдаёт зачищаемый буфер, но serde
/// строит из него свежие `String` вне всякой защиты, и пароль остаётся в куче
/// после дропа айтема. Обёртка возвращает гарантию содержимому полей.
///
/// Чего она не даёт: `String::zeroize` затирает текущую аллокацию этой строки и
/// только её. На пути чтения `serde_json` разбирает срез через `SliceRead`, у
/// которого есть внутренний `scratch: Vec<u8>`; любая строка со escape-
/// последовательностью (`"`, `\`, перевод строки) распаковывается туда, и этот
/// буфер дропается незачищенным. Достижимо обычными данными: заметка с кодами
/// восстановления по строкам или пароль со слэшем. Дотянуться до него из
/// безопасного Rust нельзя — это буфер внутри чужого крейта, и заменить его
/// можно только своим ридером. Путь записи такой оговорки не требует: там
/// промежуточного буфера больше нет, см. `pad_item`.
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
///
/// Вложения сюда не поедут: `bucket_for` прячет размер лишь с точностью до
/// двух раз, и на 10 МиБ такой бакет — часто уникальный отпечаток файла против
/// известного корпуса. Им нужна отдельная схема — нарезка на куски
/// фиксированного размера с потолком, вне `ItemSecret`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
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

/// Печатает только `v` и `kind`.
///
/// Производный `Debug` редактировал бы значения (это делает [`SecretString`]),
/// но сам скелет структуры выдаёт форму айтема: какие `Option` заполнены,
/// сколько тегов и своих полей, какие из них `hidden`. «У этого айтема есть
/// TOTP, три своих поля и два тега» — это метаданные хранилища, и через границу
/// FFI они уходят в логи хоста ровно так же, как ушло бы значение.
impl std::fmt::Debug for ItemSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ItemSecret")
            .field("v", &self.v)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
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

/// Счётчик байтов сериализации: пишет в никуда, не выделяя ничего.
struct ByteCounter(usize);

impl std::io::Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Сериализует айтем прямо в дополненный буфер: `len(u32 LE) || json || zeros`.
///
/// Длина конверта равна `42 + len(plaintext)`, поэтому без паддинга размер
/// записи выдаёт серверу длину JSON, а с ней тип айтема, примерную длину пароля
/// и факт того, что пользователь её изменил.
///
/// Длина JSON считается отдельным проходом [`ByteCounter`], чтобы буфер
/// выделялся сразу под бакет и ни разу не перевыделялся. Это не микро-
/// оптимизация, а требование зачистки: `serde_json::to_vec` начинает со 128
/// байт и удваивается, а каждое удвоение освобождает блок с куском JSON — то
/// есть с паролем. `Zeroizing` вокруг результата до брошенных блоков не
/// дотягивается: он видит только последнюю аллокацию. Реальный логин — 135–334
/// байта, так что срабатывало это практически на каждом айтеме.
fn pad_item(item: &ItemSecret) -> Result<Zeroizing<Vec<u8>>> {
    let mut counter = ByteCounter(0);
    serde_json::to_writer(&mut counter, item).map_err(malformed)?;
    let json_len = counter.0;

    // Обе ветки — «айтем не адресуется форматом»: префикс шире `u32` либо бакет
    // шире `usize`. Отказ, а не паника и не молчаливое усечение до `as u32`.
    let prefix = u32::try_from(json_len).map_err(|_| Error::PlaintextTooLarge)?;
    let total = LEN_PREFIX_LEN
        .checked_add(json_len)
        .and_then(bucket_for)
        .ok_or(Error::PlaintextTooLarge)?;

    let mut padded = Zeroizing::new(Vec::with_capacity(total));
    padded.extend_from_slice(&prefix.to_le_bytes());
    serde_json::to_writer(&mut *padded, item).map_err(malformed)?;
    // Второй проход обязан совпасть с первым: иначе буфер уже перевыделился, и
    // гарантия выше нарушена молча. Сериализация детерминирована, так что это
    // утверждение о коде, а не о данных.
    debug_assert_eq!(padded.len(), LEN_PREFIX_LEN + json_len);
    padded.resize(total, 0);
    Ok(padded)
}

/// Обрезает дополненный открытый текст по префиксу длины.
///
/// Отвергает буфер, длина которого не является бакетом, и префикс, выходящий за
/// его пределы. Оба случая означают писателя, разошедшегося с форматом: подделать
/// их снаружи нельзя без ключа хранилища, но клиент другой платформы — можно, и
/// сервер такого расхождения не увидит.
///
/// Хвост проверяется на нули по тому же доводу, что и длина. Скрытый канал тут
/// ни при чём: сервер не держит ключа, а кто может дописать хвост, тот и так
/// держит весь открытый текст. Проверка ловит расхождение реализаций — клиент
/// на Swift или TypeScript, дополняющий по PKCS#7 или случайными байтами, иначе
/// молча взаимодействовал бы с этим и разошёлся бы незаметно. Применять к
/// соседним решениям разные мерки для одной и той же угрозы нельзя.
///
/// Второй довод: непроверенный хвост — это ничейное место, которое будущая
/// версия начнёт использовать, а старые клиенты примут молча. Ровно тот отказ,
/// ради которого выбран `deny_unknown_fields`. Обратная сторона: любое
/// использование хвоста под данные теперь ломающее изменение формата.
/// Стоимость — один проход по бакету, то есть по паре килобайт.
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

    if declared > body.len() {
        return Err(malformed(format!(
            "declared length {declared} exceeds the {} bytes the bucket holds",
            body.len()
        )));
    }
    let (json, tail) = body.split_at(declared);

    if let Some(offset) = tail.iter().position(|&b| b != 0) {
        return Err(malformed(format!(
            "padding tail is not zero: byte {} of {}",
            offset,
            tail.len()
        )));
    }
    Ok(json)
}

/// Версия схемы, вытащенная из документа в обход строгого разбора.
///
/// Без `deny_unknown_fields` намеренно: смысл в том, чтобы прочитать `v` из
/// документа, который строгий разбор уже отверг.
#[derive(Deserialize)]
struct SchemaProbe {
    v: u8,
}

/// Различает «айтем из более новой версии схемы» и «мусор».
///
/// `deny_unknown_fields` обрывает разбор на первом незнакомом ключе, поэтому
/// прочитать `v` из отказавшего документа постфактум нельзя: если незнакомый
/// ключ шёл раньше `v`, serde до `v` не дошёл. Отсюда второй, снисходительный
/// проход ровно за `v`.
///
/// Номер версии уходит наружу нередактированным — в этом вся суть. Иначе
/// клиент, встретивший `attachmentRef` от более новой версии, сообщает
/// `MalformedPlaintext("redacted …")`, неотличимое от порчи данных, про айтем,
/// у которого пользователь не может прочитать даже заголовок. Сам номер не
/// секрет: он одинаков у всех айтемов этой версии формата.
///
/// Граница: документ с будущим `v`, который *успешно* разобрался (новая версия
/// только добавила необязательные поля, и в этом айтеме их нет), проходит как
/// обычный. Отказывать в нём было бы отказом от совместимого документа.
fn diagnose_plaintext(json: &[u8], err: serde_json::Error) -> Error {
    match serde_json::from_slice::<SchemaProbe>(json) {
        Ok(probe) if probe.v > ITEM_SCHEMA_VERSION => Error::UnsupportedItemSchema {
            found: probe.v,
            supported: ITEM_SCHEMA_VERSION,
        },
        _ => malformed(err),
    }
}

/// Сериализует айтем, дополняет до бакета и шифрует ключом хранилища.
pub fn seal_item(item: &ItemSecret, vault_key: &VaultKey) -> Result<Vec<u8>> {
    let padded = pad_item(item)?;
    aead::seal(vault_key.as_bytes(), &padded)
}

/// Расшифровывает конверт, снимает паддинг и разбирает айтем.
pub fn open_item(sealed: &[u8], vault_key: &VaultKey) -> Result<ItemSecret> {
    let padded = aead::open(vault_key.as_bytes(), sealed)?;
    let json = unpad(&padded)?;
    serde_json::from_slice(json).map_err(|err| diagnose_plaintext(json, err))
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

    /// Длина JSON защищённой заметки с пустым заголовком.
    const EMPTY_NOTE_JSON_LEN: usize = 38;

    /// Заметка, JSON которой длиной ровно `len` байт.
    fn note_with_json_len(len: usize) -> ItemSecret {
        let item = ItemSecret::new(ItemKind::SecureNote, "x".repeat(len - EMPTY_NOTE_JSON_LEN));
        assert_eq!(serde_json::to_vec(&item).unwrap().len(), len);
        item
    }

    /// Строит `len || json || zeros` для произвольного JSON.
    ///
    /// Тестам нужны документы, которые `ItemSecret` породить не умеет, а
    /// продакшн-путь сериализует только сам себя. Заодно это независимое
    /// изложение формата: расхождение с `pad_item` тесты увидят.
    fn pad_json(json: &[u8]) -> Vec<u8> {
        let total = bucket_for(LEN_PREFIX_LEN + json.len()).unwrap();
        let mut padded = vec![0u8; total];
        padded[..LEN_PREFIX_LEN].copy_from_slice(&u32::try_from(json.len()).unwrap().to_le_bytes());
        padded[LEN_PREFIX_LEN..LEN_PREFIX_LEN + json.len()].copy_from_slice(json);
        padded
    }

    #[test]
    fn item_round_trips() {
        let vk = VaultKey::generate().unwrap();
        let sealed = seal_item(&sample(), &vk).unwrap();
        assert_eq!(open_item(&sealed, &vk).unwrap(), sample());
    }

    #[test]
    fn item_larger_than_the_first_bucket_round_trips() {
        // Пересекает границу 512 → 1024: путь с непустым хвостом нулей и
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
        let seal_json = |json: &[u8]| aead::seal(vk.as_bytes(), &pad_json(json)).unwrap();

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
        let sealed = aead::seal(vk.as_bytes(), &pad_json(json)).unwrap();
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
        // Формат на проводе целиком, от продакшн-пути: префикс длины в LE,
        // затем JSON, затем нули до границы бакета.
        let json = br#"{"v":1,"kind":"secureNote","title":"n"}"#;
        let padded = pad_item(&ItemSecret::new(ItemKind::SecureNote, "n")).unwrap();
        assert_eq!(padded.len(), 512);
        assert_eq!(&padded[..LEN_PREFIX_LEN], &[0x27, 0x00, 0x00, 0x00]);
        assert_eq!(json.len(), 0x27);
        assert_eq!(&padded[LEN_PREFIX_LEN..LEN_PREFIX_LEN + json.len()], json);
        assert!(padded[LEN_PREFIX_LEN + json.len()..]
            .iter()
            .all(|&b| b == 0));
    }

    #[test]
    fn buckets_are_powers_of_two_from_512() {
        assert_eq!(bucket_for(0), Some(512));
        assert_eq!(bucket_for(511), Some(512));
        assert_eq!(bucket_for(512), Some(512));
        assert_eq!(bucket_for(513), Some(1024));
        assert_eq!(bucket_for(1024), Some(1024));
        assert_eq!(bucket_for(1025), Some(2048));
        assert_eq!(bucket_for(4096), Some(4096));
        assert_eq!(bucket_for(4097), Some(8192));
        // Не паника: под UniFFI она унесла бы хост-приложение.
        assert_eq!(bucket_for(usize::MAX), None);
    }

    #[test]
    fn a_populated_login_shares_a_bucket_with_a_bare_note() {
        // Ради этого поднят минимум: сервер не должен видеть переход
        // «заполнили TOTP и заметки» как скачок размера записи.
        for len in [39usize, 135, 220, 266, 334] {
            assert_eq!(
                pad_item(&note_with_json_len(len)).unwrap().len(),
                512,
                "JSON of {len} bytes must land in the first bucket"
            );
        }
        assert_eq!(serde_json::to_vec(&full_item()).unwrap().len(), 266);
    }

    #[test]
    fn bucket_boundary_counts_the_length_prefix() {
        // Ровно те два размера, на которых видна забытая четвёрка префикса:
        // 508 + 4 == 512, а 509 + 4 уже нет.
        assert_eq!(pad_item(&note_with_json_len(508)).unwrap().len(), 512);
        assert_eq!(pad_item(&note_with_json_len(509)).unwrap().len(), 1024);
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
        // 42 байта конверта (2 заголовок + 24 nonce + 16 тег) поверх бакета 512.
        assert_eq!(short_len, 554);
    }

    #[test]
    fn unpad_rejects_a_length_prefix_past_the_buffer() {
        let mut padded = vec![0u8; 512];
        padded[..LEN_PREFIX_LEN].copy_from_slice(&509u32.to_le_bytes());
        assert!(matches!(unpad(&padded), Err(Error::MalformedPlaintext(_))));

        // Наибольший префикс, который бакет 512 действительно вмещает.
        padded[..LEN_PREFIX_LEN].copy_from_slice(&508u32.to_le_bytes());
        assert_eq!(unpad(&padded).unwrap().len(), 508);
    }

    #[test]
    fn unpad_rejects_a_non_zero_padding_tail() {
        // Клиент другой платформы, дополняющий по PKCS#7 или случайными
        // байтами, взаимодействовал бы молча — сервер расхождения не видит.
        let json = br#"{"v":1,"kind":"secureNote","title":"n"}"#;
        let vk = VaultKey::generate().unwrap();

        let mut padded = pad_json(json);
        assert!(unpad(&padded).is_ok(), "control: the clean buffer opens");

        // Последний байт бакета: хвост проверяется целиком, а не первым байтом.
        *padded.last_mut().unwrap() = 0x07;
        assert!(matches!(unpad(&padded), Err(Error::MalformedPlaintext(_))));
        assert!(matches!(
            open_item(&aead::seal(vk.as_bytes(), &padded).unwrap(), &vk),
            Err(Error::MalformedPlaintext(_))
        ));

        // И сразу за JSON, а не только в конце.
        let mut padded = pad_json(json);
        padded[LEN_PREFIX_LEN + json.len()] = 0x01;
        assert!(matches!(unpad(&padded), Err(Error::MalformedPlaintext(_))));
    }

    #[test]
    fn unpad_rejects_a_plaintext_that_is_not_a_bucket() {
        // 0 и 4 заодно проверяют, что буфер короче префикса не доезжает до
        // разреза и не паникует.
        for len in [0usize, 4, 511, 513, 768, 1023] {
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

    #[test]
    fn a_newer_schema_version_is_named_not_reported_as_corruption() {
        // Незнакомый ключ стоит *до* `v`: строгий разбор обрывается на нём и до
        // `v` не доходит, поэтому диагноз обязан идти вторым проходом.
        let json = br#"{"attachmentRef":"blob-1","v":2,"kind":"login","title":"x"}"#;
        let vk = VaultKey::generate().unwrap();
        let sealed = aead::seal(vk.as_bytes(), &pad_json(json)).unwrap();

        let err = open_item(&sealed, &vk).unwrap_err();
        assert_eq!(
            err,
            Error::UnsupportedItemSchema {
                found: 2,
                supported: ITEM_SCHEMA_VERSION,
            }
        );
        // Номер версии — не секрет, и редактировать его нечего: без него
        // сообщение снова неотличимо от порчи данных.
        assert!(err.to_string().contains('2'), "{err}");
    }

    #[test]
    fn an_unknown_field_at_the_current_version_stays_malformed() {
        // Контроль: диагноз опирается на `v`, а не на сам факт отказа serde.
        let vk = VaultKey::generate().unwrap();
        let sealed = aead::seal(vk.as_bytes(), &pad_json(UNKNOWN_FIELD_JSON)).unwrap();
        assert!(matches!(
            open_item(&sealed, &vk),
            Err(Error::MalformedPlaintext(_))
        ));

        // И мусор, в котором `v` вовсе нет, тоже.
        let garbage = aead::seal(vk.as_bytes(), &pad_json(b"[1,2,3]")).unwrap();
        assert!(matches!(
            open_item(&garbage, &vk),
            Err(Error::MalformedPlaintext(_))
        ));
    }

    #[cfg(not(feature = "debug-errors"))]
    #[test]
    fn malformed_plaintext_detail_is_redacted() {
        // Строка уходит через границу FFI в логи хоста. Сообщения serde называют
        // поля хранилища, а деталь паддинга — объявленную длину, то есть ровно ту
        // метаданную, которую паддинг и прячет.
        let from_serde = malformed_detail_of(&pad_json(UNKNOWN_FIELD_JSON));
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

        // Смещение ненулевого байта в хвосте — тоже деталь открытого текста:
        // вместе с длиной бакета оно выдаёт длину JSON, которую паддинг прячет.
        let json_len = br#"{"v":1,"kind":"secureNote","title":"n"}"#.len();
        let mut tainted = pad_json(br#"{"v":1,"kind":"secureNote","title":"n"}"#);
        tainted[LEN_PREFIX_LEN + json_len] = 0x07;
        let from_tail = malformed_detail_of(&tainted);
        assert!(
            !from_tail.contains(&(tainted.len() - LEN_PREFIX_LEN - json_len).to_string()),
            "padding tail detail reached the caller: {from_tail}"
        );
    }

    #[cfg(feature = "debug-errors")]
    #[test]
    fn debug_errors_build_keeps_malformed_plaintext_detail() {
        // Парный тест: доказывает, что деталь проходит через
        // `redact_plaintext_detail`, а не заменена на константу.
        let detail = malformed_detail_of(&pad_json(UNKNOWN_FIELD_JSON));
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
        // Форма айтема — тоже метаданные: производный `Debug` печатал бы
        // `Some(...)` у заполненных полей, длину `tags`, длину `customFields` и
        // каждый флаг `hidden`. «Есть TOTP, три своих поля и два тега» уходит
        // через FFI в логи хоста ровно так же, как ушло бы значение.
        assert_eq!(rendered, "ItemSecret { v: 1, kind: Login, .. }");
    }
}
