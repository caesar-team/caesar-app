import { describe, expect, test } from "bun:test";
/**
 * Ворота CI №1 для WASM: расхождение с Rust ломает билд.
 *
 * Раннер намеренно читает тот же `protocol/vectors.json`, что и раннер на Rust.
 * Отдельного набора ожиданий для TypeScript не существует — в этом весь смысл:
 * файл ожиданий, написанный под реализацию, подтверждает только сам себя.
 *
 * Половина случаев — отрицательные, и каждый проверяет не «отказано», а
 * «отказано именно этим вариантом ошибки»: реализация, схлопнувшая «слабые
 * параметры» и «обрезанный вход» в один диагноз, оставляет пользователя без
 * единственной подсказки, что делать дальше.
 *
 * # Чего здесь нет и почему
 *
 * Раннер на Rust сверяет конверты байт-в-байт через `aead::seal_with_nonce`, а
 * пары X25519 строит из пинованных секретов через `UserKeyPair::from_secret`.
 * Обе двери в WASM намеренно не выведены (см. `crates/caesar-core-wasm/src/lib.rs`),
 * поэтому здесь конверты проверяются в сторону расшифровки: `open()` обязан
 * вернуть ровно тот `paddedPlaintext`, который файл публикует рядом с
 * конвертом. Это ловит другой AAD, другой порядок полей и другую раскладку
 * паддинга — всё, кроме выбора nonce, который в этом направлении задан входом.
 */
import { readFileSync } from "node:fs";
import * as core from "../pkg/caesar_core_wasm.js";

const VECTORS_PATH = new URL("../../../protocol/vectors.json", import.meta.url);

type JsonValue = string | number | boolean | null | JsonValue[] | JsonObject;
interface JsonObject {
  [key: string]: JsonValue;
}

const vectors: JsonObject = JSON.parse(readFileSync(VECTORS_PATH, "utf8")) as JsonObject;

/** Argon2id на продакшн-параметрах в WASM — это секунды, а не миллисекунды. */
const KDF_TIMEOUT_MS = 120_000;

// ── Доступ к файлу векторов ─────────────────────────────────────────────────

function object(value: JsonValue | undefined, what: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${what} is not an object`);
  }
  return value;
}

/** Спускается по пути и требует непустой массив: пустая секция ничего не ловит. */
function cases(...path: string[]): JsonObject[] {
  let node: JsonValue = vectors;
  for (const step of path) {
    node = object(node, path.join("."))[step];
  }
  if (!Array.isArray(node) || node.length === 0) {
    throw new Error(`${path.join(".")} is not a non-empty array`);
  }
  return node.map((entry, i) => object(entry, `${path.join(".")}[${i}]`));
}

function section(...path: string[]): JsonObject {
  let node: JsonValue = vectors;
  for (const step of path) {
    node = object(node, path.join("."))[step];
  }
  return object(node, path.join("."));
}

function text(entry: JsonObject, key: string): string {
  const value = entry[key];
  if (typeof value !== "string") {
    throw new Error(`field ${key} is missing or not a string`);
  }
  return value;
}

function num(entry: JsonObject, key: string): number {
  const value = entry[key];
  if (typeof value !== "number") {
    throw new Error(`field ${key} is missing or not a number`);
  }
  return value;
}

/**
 * Байтовые поля файла — строчный hex. Регистр проверяется, а не нормализуется:
 * файл, наполовину переехавший в верхний регистр, разошёлся бы с раннером на
 * Rust молча, потому что `hex::decode` принимает оба.
 */
function unhex(value: string): Uint8Array {
  if (!/^[0-9a-f]*$/.test(value) || value.length % 2 !== 0) {
    throw new Error(`not lowercase hex of even length: ${value.slice(0, 32)}`);
  }
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function bytes(entry: JsonObject, key: string): Uint8Array {
  return unhex(text(entry, key));
}

const utf8 = new TextEncoder();

/**
 * Отрицательный случай: отказ обязателен, и именно с заявленным вариантом.
 *
 * Имя варианта приезжает из ядра в `Error.name` — это контракт биндингов, а не
 * сообщение для человека: текст ошибки не пинуется файлом и меняться может.
 */
function expectRejected(entry: JsonObject, run: () => unknown): void {
  const name = text(entry, "name");
  const expected = text(entry, "error");

  let thrown: unknown;
  let accepted = false;
  try {
    run();
    accepted = true;
  } catch (err) {
    thrown = err;
  }

  if (accepted) {
    throw new Error(`case ${name} was accepted`);
  }
  if (!(thrown instanceof Error)) {
    throw new Error(`case ${name} threw a non-Error: ${String(thrown)}`);
  }
  // Имя случая едет в обе стороны сравнения — иначе провал показывает только
  // «UserKeyMismatch !== DecryptionFailed», не говоря, какой случай упал.
  expect(`${name}: ${thrown.name}`).toBe(`${name}: ${expected}`);
}

// ── Константы ───────────────────────────────────────────────────────────────

describe("protocol constants", () => {
  test("wasm agrees with the vectors on every pinned constant", () => {
    const declared = section("constants");
    const actual = core.constants() as Record<string, number | string>;

    for (const [key, value] of Object.entries(actual)) {
      expect(`${key}=${value}`).toBe(`${key}=${declared[key]}`);
    }

    // Пустая соль — не «поле забыли»: HKDF для auth и wrap зовётся без соли.
    expect(text(declared, "hkdfSaltAuth")).toBe("");
    expect(text(declared, "hkdfSaltWrap")).toBe("");
  });
});

describe("envelope layout", () => {
  test("header, offsets and AAD match the vectors", () => {
    const layout = section("envelope", "layout");
    const header = core.envelopeHeader();
    const constants = core.constants() as Record<string, number>;

    expect(hex(header)).toBe(text(layout, "header"));
    expect(num(layout, "headerOffset")).toBe(0);
    expect(num(layout, "nonceOffset")).toBe(constants.headerLen);
    expect(num(layout, "ciphertextOffset")).toBe(constants.headerLen + constants.nonceLen);

    // AAD — нормативное поле: реализация, передавшая в AEAD пустой AAD, получит
    // другой тег при всём остальном верном, и разойдётся с векторами только
    // здесь.
    expect(text(layout, "aad")).toBe(hex(header));
    expect(layout.aadIsHeader).toBe(true);
  });
});

// ── KDF ─────────────────────────────────────────────────────────────────────

describe("key derivation", () => {
  test(
    "known answer matches the vectors",
    () => {
      const entry = section("kdf", "knownAnswer");
      const params = bytes(entry, "encodedParams");
      const mk = core.deriveMasterKey(text(entry, "password"), params);

      expect(hex(mk)).toBe(text(entry, "masterKey"));
      expect(hex(core.authKey(mk))).toBe(text(entry, "authKey"));
      expect(hex(core.keyEncryptionKey(mk))).toBe(text(entry, "keyEncryptionKey"));
    },
    KDF_TIMEOUT_MS
  );

  test(
    "parameter encoding round-trips and is actually used",
    () => {
      let derived = 0;
      for (const entry of cases("kdf", "paramsEncoding")) {
        const name = text(entry, "name");
        const encoded = bytes(entry, "encoded");
        const params = core.decodeKdfParams(encoded) as {
          mCost: number;
          tCost: number;
          pCost: number;
          salt: Uint8Array;
          reencoded: Uint8Array;
        };

        expect(`${name}.mCost=${params.mCost}`).toBe(`${name}.mCost=${num(entry, "mCost")}`);
        expect(params.tCost).toBe(num(entry, "tCost"));
        expect(params.pCost).toBe(num(entry, "pCost"));
        expect(hex(params.salt)).toBe(text(entry, "salt"));
        expect(hex(params.reencoded)).toBe(hex(encoded));

        // Разбор и переупаковка ничего не говорят о том, что клиент на этих
        // параметрах СЧИТАЕТ: реализация, зашившая свои умолчания и
        // игнорирующая присланные сервером параметры, проходит всё выше целиком.
        //
        // `deriveSafe: false` — не «пропустить случай», а запрет: `atCeiling`
        // просит у Argon2id 4 ГиБ. Отсутствие флага — ошибка, а не «не надо».
        const safe = entry.deriveSafe;
        if (safe === true) {
          const mk = core.deriveMasterKey(text(entry, "password"), encoded);
          expect(`${name}: ${hex(mk)}`).toBe(`${name}: ${text(entry, "masterKey")}`);
          derived += 1;
        } else if (safe === false) {
          expect(`${name} pins a master key: ${"masterKey" in entry}`).toBe(
            `${name} pins a master key: false`
          );
        } else {
          throw new Error(`case ${name} has no deriveSafe flag`);
        }
      }
      // Один набор параметров — то же самое, что ни одного: он неотличим от
      // зашитых умолчаний.
      expect(derived).toBeGreaterThan(1);
    },
    KDF_TIMEOUT_MS
  );

  test(
    "password is normalized to NFC before hashing",
    () => {
      // Без нормализации «é», набранное как U+0065 U+0301, даёт другой
      // мастер-ключ, чем «é» как U+00E9: хранилище, созданное в Swift, не
      // открывается в браузере, а тесты каждой платформы зелёные.
      const entry = section("kdf", "passwordNormalization");
      const params = bytes(entry, "encodedParams");
      expect(text(entry, "intendedForm")).toBe("NFC");

      for (const [form, utf8Field] of [
        ["passwordNfc", "passwordNfcUtf8"],
        ["passwordNfd", "passwordNfdUtf8"],
      ] as const) {
        // Сначала — что в файле лежит именно то, что заявлено: редактор или
        // git-фильтр, нормализовавший файл сам, обесценил бы весь случай.
        const password = text(entry, form);
        expect(`${form}: ${hex(utf8.encode(password))}`).toBe(`${form}: ${text(entry, utf8Field)}`);

        const mk = core.deriveMasterKey(password, params);
        expect(`${form}: ${hex(mk)}`).toBe(`${form}: ${text(entry, "masterKey")}`);
      }

      expect(text(entry, "passwordNfcUtf8")).not.toBe(text(entry, "passwordNfdUtf8"));
    },
    KDF_TIMEOUT_MS
  );

  test("out-of-range and malformed parameters are rejected", () => {
    for (const entry of cases("kdf", "invalid")) {
      expectRejected(entry, () => core.decodeKdfParams(bytes(entry, "encoded")));
    }
  });
});

// ── Конверты ────────────────────────────────────────────────────────────────

describe("envelopes", () => {
  test("every valid envelope opens to its pinned plaintext", () => {
    const header = core.envelopeHeader();
    for (const entry of cases("envelope", "valid")) {
      const name = text(entry, "name");
      const envelope = bytes(entry, "envelope");

      expect(`${name}.length=${envelope.length}`).toBe(
        `${name}.length=${num(entry, "envelopeLength")}`
      );
      expect(hex(envelope.subarray(0, 2))).toBe(hex(header));
      expect(hex(envelope.subarray(2, 26))).toBe(text(entry, "nonce"));
      expect(`${name}: ${hex(core.open(bytes(entry, "key"), envelope))}`).toBe(
        `${name}: ${text(entry, "plaintext")}`
      );
    }
  });

  test("every invalid envelope is rejected with its pinned error", () => {
    for (const entry of cases("envelope", "invalid")) {
      expectRejected(entry, () => core.open(bytes(entry, "key"), bytes(entry, "envelope")));
    }
  });

  test("an envelope sealed in wasm opens in wasm", () => {
    const key = bytes(cases("envelope", "valid")[0], "key");
    const plaintext = utf8.encode("round trip — Ж 🔐");
    const sealed = core.seal(key, plaintext);
    expect(hex(core.open(key, sealed))).toBe(hex(plaintext));
    // Nonce берётся из CSPRNG: два запечатывания одного и того же не совпадают.
    expect(hex(core.seal(key, plaintext))).not.toBe(hex(sealed));
  });
});

// ── Обёртывание ключей ──────────────────────────────────────────────────────

describe("key wrapping", () => {
  test("the wrapped user key unwraps and verifies against its public half", () => {
    const kw = section("keyWrapping");
    const entry = section("keyWrapping", "userKey");
    const kek = bytes(kw, "keyEncryptionKey");

    const pair = core.unwrapUserKeyVerified(kek, bytes(entry, "wrapped"), bytes(entry, "public"));
    expect(hex(pair.publicBytes())).toBe(text(entry, "public"));

    // Приватная половина через границу не выведена, но обёртка — обычный
    // конверт над ней, и в этом направлении её видно. Проверка не декоративная:
    // реализация, завернувшая ключ с другим AAD или в другом порядке полей,
    // расходится именно здесь.
    expect(hex(core.open(kek, bytes(entry, "wrapped")))).toBe(text(entry, "secret"));
  });

  test("the wrapped vault key unwraps to its pinned plaintext", () => {
    const kw = section("keyWrapping");
    const entry = section("keyWrapping", "vaultKey");
    const kek = bytes(kw, "keyEncryptionKey");

    expect(hex(core.unwrapVaultKey(kek, bytes(entry, "wrapped")))).toBe(text(entry, "plaintext"));
    expect(hex(core.open(kek, bytes(entry, "wrapped")))).toBe(text(entry, "plaintext"));
  });

  test("invalid wrappings are rejected with their pinned errors", () => {
    // `rolledBackUserKey` — единственный случай во всём файле, который тег
    // Poly1305 пропускает: запись честная, просто устаревшая.
    for (const entry of cases("keyWrapping", "invalid")) {
      const kek = bytes(entry, "keyEncryptionKey");
      const wrapped = bytes(entry, "wrapped");
      expectRejected(entry, () =>
        "expectedPublic" in entry
          ? core.unwrapUserKeyVerified(kek, wrapped, bytes(entry, "expectedPublic"))
          : core.unwrapVaultKey(kek, wrapped)
      );
    }
  });

  test("a freshly generated pair wraps and unwraps", () => {
    const kek = bytes(section("keyWrapping"), "keyEncryptionKey");
    const pair = core.UserKeyPair.generate();
    const restored = core.unwrapUserKeyVerified(
      kek,
      core.wrapUserKey(kek, pair),
      pair.publicBytes()
    );
    expect(hex(restored.publicBytes())).toBe(hex(pair.publicBytes()));
  });
});

// ── Разделение хранилища через X25519 ───────────────────────────────────────

/**
 * Единственный способ добраться до пинованного получателя без `from_secret`.
 *
 * Секрет `x25519.sealVaultKeyFor.recipientSecret` — тот же самый, что лежит
 * завёрнутым в `keyWrapping.userKey`, поэтому пару можно РАЗВЕРНУТЬ вместо того,
 * чтобы строить из голых байт. Совпадение секретов проверяется явно: если
 * генератор векторов их когда-нибудь разведёт, тесты ниже обязаны упасть, а не
 * начать молча проверять другую пару.
 */
function bridgedRecipient(): { pair: core.UserKeyPair; secret: string } {
  const kw = section("keyWrapping");
  const entry = section("keyWrapping", "userKey");
  return {
    pair: core.unwrapUserKeyVerified(
      bytes(kw, "keyEncryptionKey"),
      bytes(entry, "wrapped"),
      bytes(entry, "public")
    ),
    secret: text(entry, "secret"),
  };
}

describe("x25519 vault sharing", () => {
  test("the bridged recipient is the one the vectors pin", () => {
    const { pair, secret } = bridgedRecipient();
    const seal = section("x25519", "sealVaultKeyFor");
    expect(secret).toBe(text(seal, "recipientSecret"));
    expect(hex(pair.publicBytes())).toBe(text(seal, "recipientPublic"));
  });

  test("public halves match the vectors where the secret is reachable", () => {
    const { pair, secret } = bridgedRecipient();
    const unreachable: string[] = [];
    for (const entry of cases("x25519", "keyPairs")) {
      if (text(entry, "secret") !== secret) {
        unreachable.push(text(entry, "name"));
        continue;
      }
      expect(hex(pair.publicBytes())).toBe(text(entry, "public"));
    }
    // Остальные пары строятся из голых пинованных секретов, то есть требуют
    // `UserKeyPair::from_secret` — двери, которой в WASM намеренно нет. Их
    // держит раннер на Rust; здесь пропуск учтён явно, чтобы он не расползся.
    expect(unreachable).toEqual(["rfc7748Alice"]);
  });

  test("the pinned shared record opens to its vault key", () => {
    const { pair } = bridgedRecipient();
    const entry = section("x25519", "sealVaultKeyFor");
    const sealed = bytes(entry, "sealed");
    const ephemeralLen = num(entry, "ephemeralPublicLen");

    expect(hex(sealed.subarray(0, ephemeralLen))).toBe(text(entry, "ephemeralPublic"));
    expect(hex(core.openVaultKeyFor(pair, sealed))).toBe(text(entry, "vaultKey"));
  });

  test("degenerate recipient keys are rejected", () => {
    const vaultKey = new Uint8Array(32).fill(0x07);
    for (const entry of cases("x25519", "invalidRecipients")) {
      expectRejected(entry, () => core.sealVaultKeyFor(bytes(entry, "recipientPublic"), vaultKey));
    }
  });

  test("invalid shared records are rejected with their pinned errors", () => {
    const { pair, secret } = bridgedRecipient();
    const unreachable: string[] = [];
    let checked = 0;
    for (const entry of cases("x25519", "invalidSealed")) {
      if (text(entry, "recipientSecret") !== secret) {
        unreachable.push(text(entry, "name"));
        continue;
      }
      expectRejected(entry, () => core.openVaultKeyFor(pair, bytes(entry, "sealed")));
      checked += 1;
    }
    // `wrongRecipient` пинует ЧУЖОЙ секрет получателя: подставить вместо него
    // свежесгенерированную пару — значит проверить другое утверждение.
    expect(unreachable).toEqual(["wrongRecipient"]);
    expect(checked).toBe(2);
  });

  test("a record sealed in wasm opens for its recipient", () => {
    const recipient = core.UserKeyPair.generate();
    const vaultKey = new Uint8Array(32).fill(0x2a);
    const sealed = core.sealVaultKeyFor(recipient.publicBytes(), vaultKey);
    expect(hex(core.openVaultKeyFor(recipient, sealed))).toBe(hex(vaultKey));
  });
});

// ── Emergency Kit ───────────────────────────────────────────────────────────

describe("emergency kit", () => {
  test("the declared layout is the one the encoder produces", () => {
    const layout = section("emergencyKit", "layout");
    const alphabet = text(layout, "alphabet");
    const symbols = num(layout, "symbols");
    const groups = num(layout, "groups");
    const groupSize = num(layout, "groupSize");

    expect([...alphabet].length).toBe(32);
    for (const excluded of ["I", "L", "O", "U"]) {
      expect(`${excluded} in alphabet: ${alphabet.includes(excluded)}`).toBe(
        `${excluded} in alphabet: false`
      );
    }
    expect(groups * groupSize).toBe(symbols);

    const printed = core.formatEmergencyKit(new Uint8Array(32).fill(0x5a));
    const body = [...printed].filter((c) => c !== "-").join("");
    expect([...body].length).toBe(symbols);
    expect([...printed].length).toBe(symbols + groups - 1);
    for (const symbol of body) {
      expect(`${symbol} in alphabet: ${alphabet.includes(symbol)}`).toBe(
        `${symbol} in alphabet: true`
      );
    }

    // Подстановки: заявлено «I и L читаются как 1, O как 0» — значит, набор,
    // где каждая цифра заменена на свою букву, обязан разобраться в тот же ключ.
    const expected = hex(core.parseEmergencyKit(printed));
    for (const [letter, digit] of Object.entries(
      section("emergencyKit", "layout", "substitutions")
    )) {
      if (typeof digit !== "string") {
        throw new Error(`substitution ${letter} is not a string`);
      }
      const substituted = printed.replaceAll(digit, letter);
      expect(`${letter}->${digit}: ${hex(core.parseEmergencyKit(substituted))}`).toBe(
        `${letter}->${digit}: ${expected}`
      );
    }
  });

  test("formatting matches the vectors", () => {
    for (const entry of cases("emergencyKit", "formatted")) {
      const name = text(entry, "name");
      const printed = core.formatEmergencyKit(bytes(entry, "key"));
      expect(`${name}: ${printed}`).toBe(`${name}: ${text(entry, "formatted")}`);
      expect([...printed].length).toBe(num(entry, "printedLength"));
    }
  });

  test("human input from the vectors is accepted", () => {
    // Подстановка Крокфорда, нижний регистр и разделители — не украшения:
    // реализация, написанная по одному алфавиту, отвергнет ровно эти входы, а
    // человек с верной распечаткой в руках останется без хранилища.
    for (const entry of cases("emergencyKit", "accepted")) {
      const name = text(entry, "name");
      const parsed = core.parseEmergencyKit(text(entry, "input"));
      expect(`${name}: ${hex(parsed)}`).toBe(`${name}: ${text(entry, "key")}`);
    }
  });

  test("invalid input is rejected with its pinned error", () => {
    for (const entry of cases("emergencyKit", "rejected")) {
      expectRejected(entry, () => core.parseEmergencyKit(text(entry, "input")));
    }
  });
});

// ── Айтемы ──────────────────────────────────────────────────────────────────

const ITEM_VAULT_KEY = (): Uint8Array => bytes(section("item"), "vaultKey");

describe("items", () => {
  test("every valid item opens to its pinned JSON and padding", () => {
    const vaultKey = ITEM_VAULT_KEY();

    for (const entry of cases("item", "valid")) {
      const name = text(entry, "name");
      const envelope = bytes(entry, "envelope");

      expect(`${name}: ${core.openItem(envelope, vaultKey)}`).toBe(
        `${name}: ${text(entry, "plaintextJson")}`
      );

      // Раскладка паддинга: `declaredLength(u32 LE) || json || zeros`.
      // `open()` отдаёт ровно то, что лежит под тегом, — на этом держится вся
      // проверка формата, которую иначе делал бы `seal_with_nonce`.
      const padded = core.open(vaultKey, envelope);
      expect(hex(padded)).toBe(text(entry, "paddedPlaintext"));
      expect(padded.length).toBe(num(entry, "paddedLength"));
      expect(envelope.length).toBe(num(entry, "envelopeLength"));

      const declared = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint32(
        0,
        true
      );
      expect(declared).toBe(num(entry, "jsonLength"));
      expect(hex(padded.subarray(4, 4 + declared))).toBe(
        hex(utf8.encode(text(entry, "plaintextJson")))
      );
      for (const tail of padded.subarray(4 + declared)) {
        expect(`${name} padding tail: ${tail}`).toBe(`${name} padding tail: 0`);
      }
    }
  });

  test("padding buckets match the vectors", () => {
    const vaultKey = ITEM_VAULT_KEY();

    for (const entry of cases("item", "bucketBoundaries")) {
      const name = text(entry, "name");
      expect(text(entry, "kind")).toBe("secureNote");

      // Форма — та же, что у `ItemSecret::new(SecureNote, title)`: только `v`,
      // `kind` и `title`, остальные поля пропускаются при сериализации. Длина
      // пинуется файлом, поэтому разошедшийся порядок полей или лишний пробел
      // здесь падает, а не проходит.
      const json = JSON.stringify({
        v: 1,
        kind: "secureNote",
        title: "x".repeat(num(entry, "titleFiller")),
      });
      expect(`${name} json: ${utf8.encode(json).length}`).toBe(
        `${name} json: ${num(entry, "jsonLength")}`
      );
      expect(`${name} envelope: ${core.sealItem(json, vaultKey).length}`).toBe(
        `${name} envelope: ${num(entry, "envelopeLength")}`
      );
    }
  });

  test("every invalid item is rejected with its pinned error", () => {
    const vaultKey = ITEM_VAULT_KEY();

    for (const entry of cases("item", "invalid")) {
      const name = text(entry, "name");
      // Отрицательный случай публикует и `paddedPlaintext`: непроверенный, он
      // разъезжается с конвертом молча, и файл начинает объяснять не тот отказ,
      // который проверяет. Сами конверты здесь валидны — ломается разбор
      // после расшифровки.
      expect(`${name}: ${hex(core.open(vaultKey, bytes(entry, "envelope")))}`).toBe(
        `${name}: ${text(entry, "paddedPlaintext")}`
      );
      expectRejected(entry, () => core.openItem(bytes(entry, "envelope"), vaultKey));
    }
  });

  test("an item sealed in wasm opens in wasm", () => {
    const vaultKey = ITEM_VAULT_KEY();
    const entry = cases("item", "valid")[0];
    const json = text(entry, "plaintextJson");
    expect(core.openItem(core.sealItem(json, vaultKey), vaultKey)).toBe(json);
  });
});
