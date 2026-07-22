/**
 * Minimal i18n: a flat key → string dictionary per language, with {n} interpolation.
 * Language is resolved once at boot (localStorage override → navigator → "en") and
 * exposed via t(). A change persists to localStorage and reloads the app.
 */
export type Lang = "en" | "ru";

const en: Record<string, string> = {
  "badge.encrypted": "End-to-end encrypted",
  "footer.zk": "Zero-knowledge: encrypted in your browser. We only ever store ciphertext.",

  "create.title": "Share a secret",
  "create.subtitle_1": "Encrypted in your browser before it ever leaves. The link ",
  "create.subtitle_is": "is",
  "create.subtitle_2": " the key.",
  "create.text": "Text",
  "create.file": "File",
  "create.text_placeholder": "Type or paste the message you want to share…",
  "create.text_hint": "Plain text · Markdown-safe",
  "create.expires": "Expires after",
  "create.exp_1h": "1 hour",
  "create.exp_24h": "24 hours",
  "create.exp_7d": "7 days",
  "create.exp_30d": "30 days",
  "create.views": "Views",
  "create.views_once": "Once",
  "create.views_number": "Number",
  "create.destroy_after": "Destroy after",
  "create.views_word": "views",
  "create.drag": "Drag a file here",
  "create.browse_1": "or ",
  "create.browse_link": "browse",
  "create.browse_2": " — it's encrypted before upload",
  "create.remove_file": "Remove file",
  "create.pw_title": "Protect with password",
  "create.pw_sub": "Adds a second key we never see",
  "create.pw_placeholder": "Enter or generate a password",
  "create.show": "Show",
  "create.hide": "Hide",
  "create.generate": "✦ Generate",
  "create.strength_1": "Weak",
  "create.strength_2": "Fair",
  "create.strength_3": "Strong",
  "create.submit": "Create secret link",
  "create.fragment_note_1": "The decryption key stays in the link's ",
  "create.fragment_note_2": " — it never reaches our servers.",
  "create.err_generic": "Something went wrong",

  "create.encrypting": "Encrypting…",
  "create.encrypting_sub":
    "Scrambling on your device with AES-256. Large files keep encrypting in the background — the page stays responsive.",
  "create.encrypted_pct": "{n}% encrypted",
  "create.uploading": "Uploading…",
  "create.uploading_sub": "Sending ciphertext only. The server can't read a byte of it.",
  "create.uploading_pct": "{n}% · ciphertext",

  "create.ready": "Your secret link is ready",
  "create.share_link": "Share link",
  "create.key_note": "The highlighted key lives only in the link.",
  "create.pw_separate": "Send the password separately",
  "create.copy": "Copy",
  "create.copied": "Copied",
  "create.pw_separate_note":
    "Never in the same message as the link — use a different channel (a call, another app).",
  "create.another": "Create another",

  "view.decrypting": "Decrypting…",
  "view.pw_required": "Password required",
  "view.pw_required_sub":
    "This secret is protected. Enter the password the sender shared with you.",
  "view.pw_wrong": "Incorrect password",
  "view.pw_wrong_sub": "That password didn't decrypt the secret.",
  "view.password": "Password",
  "view.unlock": "Unlock",
  "view.unlocking": "Unlocking…",
  "view.pw_hint": "Heads up: an incorrect password still counts as a view.",
  "view.pw_spent": "That attempt spent the only view. This link is now empty.",
  "view.gate_title": "This secret self-destructs after one view",
  "view.gate_sub":
    "Once you reveal it, it's permanently destroyed and this link stops working. Ready?",
  "view.reveal": "Reveal secret",
  "view.revealing": "Revealing…",
  "view.gate_note": "Nothing is decrypted until you tap Reveal — safe from link previews.",
  "view.decrypted": "Decrypted secret",
  "view.in_browser": "Decrypted in your browser",
  "view.copy_text": "Copy text",
  "view.copied": "✓ Copied",
  "view.destroyed": "This secret has now been destroyed and can't be opened again.",
  "view.file_ready": "Your file is ready",
  "view.download": "↓ Download file",
  "view.decrypted_suffix": "decrypted",
  "view.file_note": "The name came from inside the encrypted payload. This link is now spent.",
  "view.unavailable": "This link is no longer available",
  "view.unavailable_sub":
    "It may have expired, been viewed already, or never existed. For your privacy, we don't say which.",
  "view.create_own": "Create your own secret",
};

const ru: Record<string, string> = {
  "badge.encrypted": "Сквозное шифрование",
  "footer.zk": "Zero-knowledge: шифруется в вашем браузере. Мы храним только шифротекст.",

  "create.title": "Поделиться секретом",
  "create.subtitle_1": "Шифруется в браузере ещё до отправки. Ссылка ",
  "create.subtitle_is": "и есть",
  "create.subtitle_2": " ключ.",
  "create.text": "Текст",
  "create.file": "Файл",
  "create.text_placeholder": "Введите или вставьте сообщение, которым хотите поделиться…",
  "create.text_hint": "Обычный текст · безопасно для Markdown",
  "create.expires": "Истекает через",
  "create.exp_1h": "1 час",
  "create.exp_24h": "24 часа",
  "create.exp_7d": "7 дней",
  "create.exp_30d": "30 дней",
  "create.views": "Просмотры",
  "create.views_once": "Один раз",
  "create.views_number": "Число",
  "create.destroy_after": "Уничтожить после",
  "create.views_word": "просмотров",
  "create.drag": "Перетащите файл сюда",
  "create.browse_1": "или ",
  "create.browse_link": "выберите",
  "create.browse_2": " — он шифруется перед загрузкой",
  "create.remove_file": "Убрать файл",
  "create.pw_title": "Защитить паролем",
  "create.pw_sub": "Добавляет второй ключ, который мы не видим",
  "create.pw_placeholder": "Введите или сгенерируйте пароль",
  "create.show": "Показать",
  "create.hide": "Скрыть",
  "create.generate": "✦ Сгенерировать",
  "create.strength_1": "Слабый",
  "create.strength_2": "Средний",
  "create.strength_3": "Надёжный",
  "create.submit": "Создать секретную ссылку",
  "create.fragment_note_1": "Ключ дешифрования остаётся в ",
  "create.fragment_note_2": " ссылки — он не попадает на наши серверы.",
  "create.err_generic": "Что-то пошло не так",

  "create.encrypting": "Шифрование…",
  "create.encrypting_sub":
    "Шифруем на вашем устройстве алгоритмом AES-256. Большие файлы шифруются в фоне — страница остаётся отзывчивой.",
  "create.encrypted_pct": "{n}% зашифровано",
  "create.uploading": "Загрузка…",
  "create.uploading_sub": "Отправляем только шифротекст. Сервер не прочитает ни байта.",
  "create.uploading_pct": "{n}% · шифротекст",

  "create.ready": "Ваша секретная ссылка готова",
  "create.share_link": "Ссылка",
  "create.key_note": "Выделенный ключ существует только в ссылке.",
  "create.pw_separate": "Отправьте пароль отдельно",
  "create.copy": "Копировать",
  "create.copied": "Скопировано",
  "create.pw_separate_note":
    "Никогда не в одном сообщении со ссылкой — используйте другой канал (звонок, другое приложение).",
  "create.another": "Создать ещё",

  "view.decrypting": "Расшифровка…",
  "view.pw_required": "Требуется пароль",
  "view.pw_required_sub": "Этот секрет защищён. Введите пароль, который отправитель сообщил вам.",
  "view.pw_wrong": "Неверный пароль",
  "view.pw_wrong_sub": "Этот пароль не расшифровал секрет.",
  "view.password": "Пароль",
  "view.unlock": "Разблокировать",
  "view.unlocking": "Разблокировка…",
  "view.pw_hint": "Учтите: неверный пароль тоже засчитывается как просмотр.",
  "view.pw_spent": "Эта попытка потратила единственный просмотр. Ссылка теперь пуста.",
  "view.gate_title": "Этот секрет самоуничтожится после одного просмотра",
  "view.gate_sub":
    "Как только вы его откроете, он безвозвратно уничтожится, а ссылка перестанет работать. Готовы?",
  "view.reveal": "Показать секрет",
  "view.revealing": "Открываем…",
  "view.gate_note":
    "Ничего не расшифровывается, пока вы не нажмёте «Показать» — защита от предпросмотра ссылок.",
  "view.decrypted": "Расшифрованный секрет",
  "view.in_browser": "Расшифровано в вашем браузере",
  "view.copy_text": "Копировать текст",
  "view.copied": "✓ Скопировано",
  "view.destroyed": "Этот секрет уничтожен и больше не может быть открыт.",
  "view.file_ready": "Ваш файл готов",
  "view.download": "↓ Скачать файл",
  "view.decrypted_suffix": "расшифровано",
  "view.file_note": "Имя пришло изнутри зашифрованных данных. Ссылка теперь потрачена.",
  "view.unavailable": "Эта ссылка больше недоступна",
  "view.unavailable_sub":
    "Возможно, она истекла, уже была просмотрена или никогда не существовала. Ради вашей приватности мы не уточняем.",
  "view.create_own": "Создать свой секрет",
};

const dictionaries: Record<Lang, Record<string, string>> = { en, ru };

function resolveLang(): Lang {
  const stored = localStorage.getItem("lang");
  if (stored === "en" || stored === "ru") {
    return stored;
  }
  return navigator.language.toLowerCase().startsWith("ru") ? "ru" : "en";
}

let current: Lang = resolveLang();

export function getLang(): Lang {
  return current;
}

export function setLang(lang: Lang): void {
  localStorage.setItem("lang", lang);
  current = lang;
  window.location.reload();
}

export function t(key: string, vars?: Record<string, string | number>): string {
  const table = dictionaries[current];
  let value = table[key] ?? dictionaries.en[key] ?? key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      value = value.replace(`{${k}}`, String(v));
    }
  }
  return value;
}
