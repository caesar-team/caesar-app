# @caesar/core-wasm

WASM-биндинги `caesar-core`. Собственной криптографии в пакете нет: всё, что он
делает, — маршалит байты в единственную реализацию, которая живёт в
`crates/caesar-core`.

```bash
bun run --filter @caesar/core-wasm build   # wasm-pack -> ./pkg
bun run --filter @caesar/core-wasm test    # ворота CI №1 для TypeScript
```

## Почему `--target nodejs`, а не `bundler`

Раннер векторов запускается `bun test`. Вывод `--target bundler` — ESM с
`import * as wasm from "./caesar_core_wasm_bg.wasm"`, и Bun 1.3 разрешает этот
импорт, но не поднимает модуль до конца: `wasm.__wbindgen_start` в момент
вызова ещё `undefined`, и пакет падает на первой же строке. `--target nodejs`
даёт CommonJS, который инстанцирует `.wasm` сам через `fs`, и работает в Bun
без оговорок.

Ворота обязаны исполнять тот же код, который поедет в приложение, поэтому смена
цели на `bundler` для Next.js — это добавить вторую сборку рядом, а не заменить
эту: непроверенный артефакт хуже отсутствующего.

## Чего в API нет

`sealWithNonce` и `sealVaultKeyForWithRandomness` не экспортированы: они
существуют ради побайтовой воспроизводимости `protocol/vectors.json`, а в руках
вызывающего означают повторно использованный nonce. Из `UserKeyPair` наружу
выведены только `generate()` и `publicBytes()` — приватная половина не
пересекает границу ни в одном направлении.

Из-за этого раннер на TypeScript не может воспроизвести конверты байт-в-байт и
не покрывает `x25519.keyPairs`: обе проверки требуют запрещённых дверей. Их
держит раннер на Rust, у которого доступ к ядру полный.
