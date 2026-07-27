#!/usr/bin/env bash
#
# Ворота CI: двери, которые обещаны закрытыми, действительно закрыты.
#
# В `aead.rs`, `vault.rs` и в обоих крейтах-биндингах написано, что четыре
# функции наружу не выходят. Это обещание в комментарии: `pub` они всё равно
# (иначе их не увидел бы генератор векторов), и добавить `#[wasm_bindgen]` или
# `#[uniffi::export]` над обёрткой — правка на одну строку, которую не завалит
# ни компилятор, ни один из 148 тестов. Здесь она заваливается.
#
#   seal_with_nonce, seal_vault_key_for_with_randomness
#       nonce и эфемерный ключ от вызывающего. Повторный nonce под тем же
#       ключом раскрывает открытый текст обоих сообщений и подделывает теги.
#       Существуют ровно ради побайтовой воспроизводимости vectors.json.
#
#   UserKeyPair::{from_secret, try_from_slice, secret_bytes}
#       принимают или отдают сырой приватный ключ X25519. `secret_bytes` —
#       главный: убрать его нельзя, на нём держится `wrap_user_key`, поэтому
#       кроме этой проверки поймать его экспорт негде.
#
# Проверяются только строки КОДА: сами эти имена обязаны упоминаться в доках
# биндингов (там объясняется, чего в API нет), и запрет на упоминание сделал бы
# ворота требованием удалить объяснение. Строка, начинающаяся с `//`, считается
# комментарием; вызов, приписанный в конец строки кода, — нет.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Печатает `file:line:code` для строк, которые не являются строчным комментарием.
code_matches() {
  pattern="$1"
  shift
  grep -rnE --include='*.rs' "$pattern" "$@" 2>/dev/null |
    awk '{ body = $0; sub(/^[^:]*:[0-9]+:/, "", body); if (body !~ /^[[:space:]]*\/\//) print }' ||
    true
}

violations=0

# --- Дверь 1: вызывающий задаёт nonce / эфемерный ключ -----------------------
#
# Четыре файла и ни одного больше: реализация (`aead.rs` — тело, `vault.rs` —
# вызов из `seal_vault_key_for`), генератор векторов и раннер векторов.
ALLOWED='^(crates/caesar-core/src/aead\.rs|crates/caesar-core/src/vault\.rs|crates/caesar-core/src/bin/gen_vectors\.rs|crates/caesar-core/tests/vectors\.rs):'

leaked=$(code_matches 'seal_with_nonce|seal_vault_key_for_with_randomness' crates |
  grep -vE "$ALLOWED" || true)

if [ -n "$leaked" ]; then
  echo "FAIL: nonce-controlling functions referenced outside the four allowed files:"
  echo "$leaked"
  echo "  allowed: crates/caesar-core/src/{aead,vault}.rs,"
  echo "           crates/caesar-core/src/bin/gen_vectors.rs,"
  echo "           crates/caesar-core/tests/vectors.rs"
  violations=$((violations + 1))
fi

# --- Дверь 2: приватная половина личности в биндингах ------------------------
#
# `try_from_slice` проверяется только с префиксом `UserKeyPair::`: тот же метод
# у `VaultKey` биндинги используют законно — это единственная точка проверки
# длины ключа во всём крейте.
BINDINGS='crates/caesar-core-wasm/src crates/caesar-core-uniffi/src'

# shellcheck disable=SC2086
leaked=$(code_matches 'from_secret|secret_bytes|UserKeyPair[[:space:]]*::[[:space:]]*try_from_slice' $BINDINGS || true)

if [ -n "$leaked" ]; then
  echo "FAIL: the private half of UserKeyPair is reachable from a binding crate:"
  echo "$leaked"
  echo "  bindings may expose only UserKeyPair::generate() and public_bytes()"
  violations=$((violations + 1))
fi

[ "$violations" -gt 0 ] && exit 1

echo "OK: nonce-controlling functions confined to the core; bindings expose no private key"
