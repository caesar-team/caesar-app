#!/usr/bin/env bash
#
# Ворота CI №4: сервер не линкует криптографическое ядро.
#
# Зависимость означает, что сервер способен расшифровывать данные пользователя,
# то есть zero-knowledge сломан не в теории, а в дереве зависимостей.
#
# Проверка обязана проходить и сейчас, когда `apps/server` ещё не существует, и
# позже, когда он появится: манифесты ищутся рекурсивно, отсутствие каталога —
# не ошибка. Молчаливое «нечего проверять» тоже недопустимо, поэтому в конце
# печатается, сколько манифестов реально просмотрено.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Ядро и все его обёртки. `@caesar/core-wasm` — тот же код через npm.
FORBIDDEN='caesar-core|caesar_core|@caesar/core-wasm'

violations=0
checked=0

if [ -d apps/server ]; then
  while IFS= read -r manifest; do
    checked=$((checked + 1))
    if grep -qE "$FORBIDDEN" "$manifest"; then
      echo "FAIL: $manifest depends on the crypto core"
      grep -nE "$FORBIDDEN" "$manifest"
      violations=$((violations + 1))
    fi
  done <<EOF
$(find apps/server \( -name node_modules -o -name target -o -name dist \) -prune -o \
    \( -name Cargo.toml -o -name package.json \) -print)
EOF
fi

if [ "$violations" -gt 0 ]; then
  echo
  echo "Сервер не должен иметь доступа к криптографическому ядру."
  exit 1
fi

if [ "$checked" -eq 0 ]; then
  echo "OK: apps/server does not exist yet, nothing to link against"
else
  echo "OK: $checked server manifest(s) checked, none depends on the crypto core"
fi
