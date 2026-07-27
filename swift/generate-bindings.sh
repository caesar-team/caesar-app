#!/usr/bin/env bash
#
# Собирает `caesar-core-uniffi` и раскладывает сгенерированные биндинги.
#
# Скрипт, а не `swift build`-плагин: плагин не умеет звать cargo без сетевой
# песочницы SwiftPM, а раскладка файлов всё равно нужна — UniFFI кладёт module
# map под именем модуля, а SwiftPM ищет его строго как `include/module.modulemap`.
#
# Swift-раннер macOS-only, поэтому библиотека ищется как `.dylib`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo build -p caesar-core-uniffi --release

LIB="target/release/libcaesar_core_ffi.dylib"
GEN="swift/.generated"
rm -rf "$GEN"

# SwiftPM не считает внешний архив входом сборки: пересобранная
# `libcaesar_core_ffi.a` сама по себе перелинковку не вызывает, и `swift test`
# молча проверил бы прошлую версию ядра — ворота, которые не срабатывают, хуже
# отсутствующих. Кэш сборки Swift сносится целиком, потому что дешевле (~15 с)
# и надёжнее, чем угадывать имена слинкованных продуктов.
rm -rf swift/.build

# Одна команда на язык, одна и та же библиотека: расхождение между Swift и
# Kotlin невозможно по построению.
for language in swift kotlin; do
  cargo run -q -p caesar-core-uniffi --bin uniffi-bindgen -- generate \
    --library "$LIB" --no-format --language "$language" --out-dir "$GEN/$language"
done

mkdir -p swift/Sources/CaesarCore swift/Sources/CaesarCoreFFI/include bindings
rm -rf bindings/kotlin
mv "$GEN/kotlin" bindings/kotlin
mv "$GEN/swift/CaesarCore.swift" swift/Sources/CaesarCore/CaesarCore.swift
mv "$GEN/swift/CaesarCoreFFI.h" swift/Sources/CaesarCoreFFI/include/CaesarCoreFFI.h
mv "$GEN/swift/CaesarCoreFFI.modulemap" swift/Sources/CaesarCoreFFI/include/module.modulemap
rm -rf "$GEN"

echo "swift  -> swift/Sources/{CaesarCore,CaesarCoreFFI}"
echo "kotlin -> bindings/kotlin (раннер приедет в M6′ вместе с apps/mobile)"
