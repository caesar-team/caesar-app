#!/usr/bin/env bash
#
# Ворота CI №2: у версии протокола ровно один источник правды.
#
# Второе объявление `PROTOCOL_VERSION` — это не дублирование строки, а два
# независимых числа, которые разъедутся при бампе формата: одно попадёт в
# заголовок конверта, другое — в проверку `decode`, и клиент начнёт отвергать
# собственные конверты. Компилятор такого не ловит: оба объявления валидны.
#
# Биндинги (`swift/Sources`, `bindings/`) не проверяются: они генерируются из
# ядра и переносят значение, а не задают его.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

matches=$(grep -rn --include='*.rs' -E '^[[:space:]]*(pub )?const PROTOCOL_VERSION: u8 = ' crates/ || true)
count=$(printf '%s' "$matches" | grep -c . || true)

if [ "$count" -ne 1 ]; then
  echo "FAIL: PROTOCOL_VERSION declared $count time(s), expected exactly 1"
  [ -n "$matches" ] && echo "$matches"
  exit 1
fi

echo "OK: single source of protocol version — ${matches%%:*}"
