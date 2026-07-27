# CaesarCore (Swift)

UniFFI-биндинги `caesar-core` и раннер векторов. Собственной криптографии здесь
нет: всё, что делает пакет, — маршалит байты в единственную реализацию, которая
живёт в `crates/caesar-core`.

```bash
./swift/generate-bindings.sh          # cargo + uniffi-bindgen -> Sources/
cd swift && swift test                # ворота CI №1 для Swift
```

Биндинги не коммитятся: они полностью выводятся из `crates/caesar-core-uniffi`,
и закоммиченная копия — это второй источник правды, который расходится молча.
Без `generate-bindings.sh` `swift test` падает на отсутствующем
`Sources/CaesarCore/CaesarCore.swift`.

`generate-bindings.sh` — единственная точка входа, и запускать `swift test`
после голого `cargo build --release` нельзя: SwiftPM не считает внешний архив
входом сборки, пересобранная `libcaesar_core_ffi.a` перелинковку не вызывает, и
тесты молча проверят прошлую версию ядра. Проверено сабатажем — с
`PROTOCOL_VERSION = 2` и без перегенерации все 27 тестов остались зелёными.
Поэтому скрипт сносит `swift/.build`.

## Раскладка

| Таргет | Что внутри |
| --- | --- |
| `CaesarCoreFFI` | сгенерированный `CaesarCoreFFI.h` + module map, линкует `target/release/libcaesar_core_ffi.a` |
| `CaesarCore` | сгенерированный `CaesarCore.swift` |
| `CaesarCoreVectorsTests` | раннер `protocol/vectors.json` |

Имена таргетов не произвольны: SwiftPM требует, чтобы имя модуля в module map
совпадало с именем C-таргета, поэтому `module_name`/`ffi_module_name` заданы в
`crates/caesar-core-uniffi/uniffi.toml`.

Архив подключается полным путём, а не парой `-L`/`-l`: с `-l` линковщик macOS
предпочёл бы соседний `.dylib`, и тесты собирались бы, но падали в рантайме без
выставленного rpath.

## Чего в API нет

`sealWithNonce` и `sealVaultKeyForWithRandomness` не экспортированы: они
существуют ради побайтовой воспроизводимости `protocol/vectors.json`, а в руках
вызывающего означают повторно использованный nonce. Из `UserKeyPair` наружу
выведены только `generate()` и `publicBytes()` — приватная половина не пересекает
границу ни в одном направлении.

Из-за этого раннер на Swift не может воспроизвести конверты байт-в-байт и не
покрывает `x25519.keyPairs` целиком: обе проверки требуют запрещённых дверей. Их
держит раннер на Rust, у которого доступ к ядру полный. Пропуски в раннере
перечислены явными списками (`unreachable`), чтобы они не расползались.

## Ошибки

Отказ приезжает как `CoreError.Failed(code:message:)`. Сверяется `code` — файл
векторов пинует имя варианта ядра, а не текст сообщения:

```swift
} catch let CoreError.Failed(code, _) {
    XCTAssertEqual(errorCodeName(code: code), "UnsupportedVersion")
}
```

`errorCodeName` живёт в Rust, потому что Swift печатает варианты в
lowerCamelCase, а файл — в UpperCamelCase ядра.

## Kotlin

`generate-bindings.sh` попутно кладёт Kotlin-биндинги в `bindings/kotlin`.
Раннера для них нет: он приедет в M6′ вместе с `apps/mobile`.
