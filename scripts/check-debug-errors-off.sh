#!/usr/bin/env bash
#
# Ворота CI: фича `debug-errors` выключена в том, что уезжает пользователю.
#
# `MalformedPlaintext` несёт сообщение serde, а оно называет поля хранилища
# («unknown field `totpSecret`»). Строка пересекает границу FFI и попадает в
# логи хоста, поэтому в релизе деталь редактируется. Редактирование стоит под
# `cfg!(feature = "debug-errors")` — вся защита нулевого знания в сообщениях об
# ошибках держится на одном флаге, который включается одной строкой в чужом
# манифесте и не ломает ни одного теста. Cargo объединяет фичи по всему графу:
# достаточно, чтобы фичу попросил ЛЮБОЙ участник воркспейса.
#
# Проверяются четыре поверхности, через которые фича может включиться, и
# поведение в релизной сборке — статика без поведения ловит не всё.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

FEATURE='debug-errors'
SELF='scripts/check-debug-errors-off.sh'
violations=0

# --- 1. Фича не входит в default ---------------------------------------------
defaults=$(cargo metadata --no-deps --format-version 1 --locked |
  jq -r '.packages[] | select(.name == "caesar-core") | .features.default[]?')

if printf '%s\n' "$defaults" | grep -qx "$FEATURE"; then
  echo "FAIL: caesar-core enables '$FEATURE' by default"
  violations=$((violations + 1))
fi

# --- 2. Ни один манифест её не просит ----------------------------------------
#
# В `crates/caesar-core/Cargo.toml` разрешено ровно объявление; всё остальное —
# просьба включить.
while IFS= read -r manifest; do
  hits=$(grep -nE "$FEATURE" "$manifest" || true)
  [ -z "$hits" ] && continue
  if [ "$manifest" = "./crates/caesar-core/Cargo.toml" ]; then
    hits=$(printf '%s\n' "$hits" | grep -vE ":[[:space:]]*${FEATURE}[[:space:]]*=[[:space:]]*\[\]" || true)
    [ -z "$hits" ] && continue
  fi
  echo "FAIL: $manifest requests '$FEATURE'"
  printf '%s\n' "$hits"
  violations=$((violations + 1))
done <<EOF
$(find . \( -name node_modules -o -name target -o -name .git -o -name .build \) -prune -o -name Cargo.toml -print)
EOF

# --- 3. Ни один скрипт сборки её не передаёт ---------------------------------
#
# `--features caesar-core/debug-errors`, `-F …` и то же самое внутри npm-скрипта
# или workflow: cargo не различает, откуда пришёл флаг. `--all-features` сюда же
# — он включает и эту.
#
# Ищется передача фичи, а не упоминание строки: сам workflow обязан называть
# ворота по имени, и запрет на слово сделал бы проверку требованием переименовать
# шаг. Свой файл исключается — он объясняет, что именно запрещает.
build_inputs=$(grep -rnE -- "(--features|-F)[^\"']*${FEATURE}|--all-features" \
  .gitea scripts package.json packages/*/package.json swift/*.sh 2>/dev/null |
  grep -v "^$SELF:" || true)

if [ -n "$build_inputs" ]; then
  echo "FAIL: a build input hands '$FEATURE' to cargo:"
  printf '%s\n' "$build_inputs"
  violations=$((violations + 1))
fi

# --- 4. Релизная сборка действительно редактирует ----------------------------
#
# Единственная проверка поведения, а не текста. Тест редактирования объявлен под
# `#[cfg(not(feature = "debug-errors"))]`: с включённой фичей он не отсутствует —
# он ИСЧЕЗАЕТ, и `cargo test` возвращает 0 с нулём выполненных тестов. Поэтому
# сверяется именно «1 passed», а не код возврата.
result=$(cargo test --release --locked -p caesar-core --lib -- \
  --exact error::tests::default_build_redacts_plaintext_detail 2>&1 |
  grep -E '^test result:' || true)

case "$result" in
*"1 passed"*) ;;
*)
  echo "FAIL: the release build does not redact plaintext detail"
  echo "  expected the redaction test to run and pass, got: ${result:-<no test result>}"
  violations=$((violations + 1))
  ;;
esac

[ "$violations" -gt 0 ] && exit 1

echo "OK: '$FEATURE' is off — release builds redact plaintext detail"
