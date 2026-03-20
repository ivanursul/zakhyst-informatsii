# Лекція 8. PKCE та безпека публічних клієнтів

## Зміст

1. [Проблема публічних клієнтів](#1-проблема-публічних-клієнтів)
2. [Authorization Code Interception Attack](#2-authorization-code-interception-attack)
3. [PKCE — Proof Key for Code Exchange](#3-pkce--proof-key-for-code-exchange)
4. [code_verifier та code_challenge](#4-code_verifier-та-code_challenge)
5. [Повний flow з PKCE](#5-повний-flow-з-pkce)
6. [Mobile/SPA considerations](#6-mobilespa-considerations)
7. [OAuth 2.1 — PKCE обов'язковий для всіх клієнтів](#7-oauth-21--pkce-обовязковий-для-всіх-клієнтів)
8. [Практика — реалізація PKCE flow на Python](#8-практика--реалізація-pkce-flow-на-python)
9. [Підсумки](#9-підсумки)

---

## 1. Проблема публічних клієнтів

### Міст від попередньої лекції

У лекції 8 ми розглянули OAuth 2.0 Authorization Code Flow — найбезпечніший з грантів, де конфіденційний сервер обмінює authorization code на токен, автентифікуючись за допомогою `client_secret`. Але що робити, якщо клієнт **не може зберегти секрет**?

### Конфіденційні vs публічні клієнти

OAuth 2.0 (RFC 6749) розділяє клієнтів на два типи:

- **Конфіденційний клієнт** (confidential client) — серверний додаток, який може безпечно зберігати `client_secret`. Секрет ніколи не покидає сервер. Приклад: бекенд на Django, Spring Boot, Express.js
- **Публічний клієнт** (public client) — додаток, код якого доступний кінцевому користувачу. Будь-який секрет, вбудований у такий додаток, може бути видобутий. Приклад: SPA (React, Angular, Vue), мобільний додаток (iOS, Android), десктопний додаток

### Чому SPA не може зберегти секрет

Максим Витребенько додає SPA frontend для свого додатка SecureNotes. Весь JavaScript-код SPA завантажується у браузер користувача. Будь-хто може відкрити DevTools, перейти на вкладку Sources і побачити **весь вихідний код**, включаючи будь-які вбудовані секрети.

```
Конфіденційний клієнт (сервер):
┌──────────────────────────┐
│  Backend Server           │
│                           │
│  client_secret = "abc..." │  ← зберігається на сервері
│  (ніхто ззовні не бачить) │     (захищено ОС, firewall)
└──────────────────────────┘

Публічний клієнт (SPA):
┌──────────────────────────┐
│  Browser / DevTools       │
│                           │
│  const secret = "abc..."  │  ← видимий у Sources tab
│  // будь-хто може знайти  │     (мінімізація не допоможе)
└──────────────────────────┘
```

### Те ж саме для мобільних додатків

Мобільний додаток — це бінарний файл, який встановлюється на пристрій користувача. Навіть якщо секрет не видно в коді напряму, атакуючий може:

- Декомпілювати APK (Android) або IPA (iOS) за допомогою інструментів на кшталт `jadx`, `Hopper`, `Ghidra`
- Перехопити мережевий трафік через проксі (mitmproxy, Charles Proxy)
- Отримати доступ до файлової системи пристрою на рутованих/jailbroken пристроях

### Висновок

Публічний клієнт **не може автентифікуватися** при обміні authorization code на токен — він не може довести, що це саме він, а не зловмисник, який перехопив code. Це створює серйозну вразливість у стандартному Authorization Code Flow.

---

## 2. Authorization Code Interception Attack

### Суть атаки

Authorization Code Interception Attack (атака перехоплення коду авторизації) — це атака, при якій зловмисник перехоплює authorization code під час повернення користувача від Authorization Server до клієнта і використовує цей code для отримання access token.

### Як це працює

У стандартному Authorization Code Flow після автентифікації користувача Authorization Server перенаправляє браузер назад на `redirect_uri` клієнта з параметром `code`:

```
HTTP/1.1 302 Found
Location: https://app.example.com/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz
```

Зловмисник може перехопити цей code кількома способами.

### Вектори перехоплення на мобільних пристроях

На мобільних пристроях redirect зазвичай використовує **custom URI scheme** (наприклад, `myapp://callback`). Проблема в тому, що кілька додатків можуть зареєструвати **один і той самий URI scheme**:

```
Authorization Server
        │
        │ redirect: myapp://callback?code=abc123
        ▼
┌─────────────────────────────────┐
│        Операційна система        │
│                                  │
│  myapp:// зареєстровано:         │
│    ✓ SecureNotes (легітимний)    │
│    ✓ MalwareApp (зловмисник)     │
│                                  │
│  Хто отримає redirect?           │
│  → Невизначено! ОС може          │
│    передати будь-якому            │
└─────────────────────────────────┘
```

На Android будь-який додаток може зареєструвати intent filter для будь-якого custom URI scheme. Операційна система покаже діалог вибору або передасть redirect найбільш пріоритетному додатку — і зловмисний додаток може мати вищий пріоритет.

### Вектори перехоплення для SPA

Для SPA у браузері атака може використовувати інші вектори:

- **Відкриті redirectori** — якщо `redirect_uri` валідується недостатньо строго, зловмисник може перенаправити code на свій сервер
- **Browser extensions** — зловмисне розширення має доступ до URL-рядка і може витягти code
- **Shared logs** — code потрапляє в URL, а URL може бути записаний у логи сервера, проксі, або історію браузера

### Чому state параметр не рятує

Параметр `state` у OAuth 2.0 захищає від CSRF (Cross-Site Request Forgery) — він гарантує, що redirect ініціював саме цей користувач. Але `state` **не захищає від перехоплення code**, бо:

- `state` перевіряється на стороні клієнта
- Якщо зловмисник перехопив code, він відправляє його зі **свого** клієнта, де сам формує `state`
- `state` не прив'язує code до конкретного клієнта

### Наслідки

Зловмисник, який перехопив authorization code, може обміняти його на access token і отримати доступ до ресурсів жертви. Для публічного клієнта немає `client_secret`, який би зупинив атакуючого. Потрібен інший механізм, який прив'яже code до конкретної сесії клієнта.

---

## 3. PKCE — Proof Key for Code Exchange

### Визначення

**PKCE** (Proof Key for Code Exchange, вимовляється як "pixy") — це розширення OAuth 2.0, визначене в **RFC 7636** (2015). PKCE додає криптографічний механізм, який прив'язує запит авторизації до обміну code на токен. Навіть якщо зловмисник перехопить authorization code, він не зможе його використати без знання секрету, який ніколи не передавався по мережі.

### Ключова ідея

PKCE використовує техніку **commit-reveal** (зафіксувати-розкрити):

1. **Commit** — клієнт генерує випадковий секрет, обчислює від нього хеш і відправляє хеш разом із запитом авторизації
2. **Reveal** — при обміні code на токен клієнт відправляє оригінальний секрет. Authorization Server перевіряє, що хеш секрету збігається з тим, що був відправлений на першому кроці

```
Крок 1 — Commit (запит авторизації):

  Клієнт:
    secret = випадкове_значення
    hash   = SHA256(secret)
    → відправляє hash на Authorization Server

Крок 2 — Reveal (обмін code на токен):

  Клієнт:
    → відправляє secret на Authorization Server

  Authorization Server:
    SHA256(secret) == збережений hash?
    → Так: видати токен
    → Ні:  відмовити
```

### Чому це працює

Зловмисник може перехопити authorization code і навіть побачити hash (він передається у відкритому вигляді). Але зловмисник **не знає оригінальний secret**, бо він ніколи не передавався по мережі під час першого кроку. А SHA-256 — одностороння функція (ми розглянули це в лекції 2): знаючи хеш, неможливо відновити вхідне значення. Тому зловмисник не зможе обміняти перехоплений code на токен.

### Аналогія

Уявіть, що ви відправляєте лист у запечатаному конверті з відбитком печатки. Одержувач зберігає відбиток. Коли ви приходите забрати відповідь, ви показуєте оригінальну печатку — одержувач порівнює відбиток і впевнюється, що перед ним та сама людина. Зловмисник може побачити відбиток, але не зможе підробити печатку.

---

## 4. code_verifier та code_challenge

### code_verifier

**code_verifier** — це випадковий рядок, який генерує клієнт. Згідно з RFC 7636, він має відповідати таким вимогам:

- Довжина: від 43 до 128 символів
- Допустимі символи: `[A-Z]`, `[a-z]`, `[0-9]`, `-`, `.`, `_`, `~` (unreserved characters за RFC 3986)
- Має бути згенерований за допомогою CSPRNG (криптографічно безпечного генератора випадкових чисел)

```python
import secrets
import base64

# Генерація code_verifier (32 байти → 43 символи base64url)
code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode('ascii')
print(code_verifier)
# Приклад: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

### code_challenge

**code_challenge** — це трансформація code_verifier, яка відправляється на Authorization Server. RFC 7636 визначає два методи трансформації:

- **plain** — `code_challenge = code_verifier` (без трансформації). Використовується тільки якщо клієнт не може виконати SHA-256. **Не рекомендований**
- **S256** — `code_challenge = BASE64URL(SHA256(code_verifier))`. **Рекомендований метод**

### S256 transform крок за кроком

```
code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

Крок 1: SHA-256
  SHA256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
  → байти: [0xe9, 0x14, 0x6c, ...]  (32 байти)

Крок 2: Base64url-encode (без padding =)
  base64url([0xe9, 0x14, 0x6c, ...])
  → "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
```

### Реалізація на Python

```python
import hashlib
import base64
import secrets

def generate_pkce_pair():
    """Генерує пару code_verifier / code_challenge для PKCE (S256)."""
    # 1. Генеруємо code_verifier
    code_verifier = base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).rstrip(b'=').decode('ascii')

    # 2. Обчислюємо code_challenge = BASE64URL(SHA256(code_verifier))
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')

    return code_verifier, code_challenge

verifier, challenge = generate_pkce_pair()
print(f"code_verifier:  {verifier}")
print(f"code_challenge: {challenge}")
```

### Перевірка на стороні сервера

```python
def verify_pkce(code_verifier: str, stored_code_challenge: str) -> bool:
    """Перевіряє, чи code_verifier відповідає збереженому code_challenge."""
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    computed_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return computed_challenge == stored_code_challenge
```

### Чому base64url, а не base64

Стандартний Base64 використовує символи `+` і `/`, які мають спеціальне значення в URL. Base64url замінює їх на `-` і `_` відповідно, а також прибирає padding-символи `=`. Це дозволяє безпечно передавати значення як URL-параметри без додаткового кодування.

---

## 5. Повний flow з PKCE

### Діаграма

```
┌──────────┐                              ┌──────────────────┐
│  Client   │                              │ Authorization    │
│  (SPA /   │                              │ Server           │
│   Mobile) │                              │                  │
└────┬─────┘                              └────────┬─────────┘
     │                                              │
     │  1. Генерує code_verifier                    │
     │     Обчислює code_challenge                  │
     │                                              │
     │  2. GET /authorize?                          │
     │       response_type=code                     │
     │       &client_id=spa-app                     │
     │       &redirect_uri=https://app/callback     │
     │       &scope=read                            │
     │       &state=xyz                             │
     │       &code_challenge=E9Mel...               │
     │       &code_challenge_method=S256            │
     │  ──────────────────────────────────────────→ │
     │                                              │
     │                          3. Зберігає         │
     │                             code_challenge   │
     │                             разом із code    │
     │                                              │
     │                          4. Автентифікація   │
     │                             користувача +    │
     │                             згода (consent)  │
     │                                              │
     │  5. Redirect: /callback?code=abc123&state=xyz│
     │  ←────────────────────────────────────────── │
     │                                              │
     │  6. POST /token                              │
     │       grant_type=authorization_code           │
     │       &code=abc123                           │
     │       &redirect_uri=https://app/callback     │
     │       &client_id=spa-app                     │
     │       &code_verifier=dBjft...                │
     │  ──────────────────────────────────────────→ │
     │                                              │
     │                          7. Перевіряє:       │
     │                             SHA256(verifier) │
     │                             == challenge?    │
     │                                              │
     │  8. { access_token: "...", token_type: "..." }│
     │  ←────────────────────────────────────────── │
     │                                              │
```

### Крок за кроком

**Крок 1 — Генерація PKCE пари.** Клієнт генерує випадковий `code_verifier` та обчислює `code_challenge = BASE64URL(SHA256(code_verifier))`. `code_verifier` зберігається локально (в пам'яті браузера або на пристрої).

**Крок 2 — Запит авторизації.** Клієнт перенаправляє користувача на Authorization Server, додаючи до стандартних параметрів два нових: `code_challenge` та `code_challenge_method=S256`.

**Крок 3 — Збереження challenge.** Authorization Server зберігає `code_challenge` разом із виданим authorization code. Ці значення тепер прив'язані одне до одного.

**Крок 4 — Автентифікація та згода.** Користувач вводить логін/пароль і підтверджує доступ. Цей крок не змінюється порівняно зі стандартним flow.

**Крок 5 — Redirect з code.** Authorization Server перенаправляє браузер назад на `redirect_uri` з authorization code та state. Це місце, де зловмисник може перехопити code.

**Крок 6 — Обмін code на токен.** Клієнт відправляє POST-запит на token endpoint, додаючи `code_verifier` — оригінальне значення, з якого було обчислено challenge.

**Крок 7 — Перевірка PKCE.** Authorization Server обчислює `SHA256(code_verifier)` і порівнює результат із збереженим `code_challenge`. Якщо вони не збігаються — запит відхиляється.

**Крок 8 — Видача токена.** Якщо перевірка пройшла успішно, сервер видає access token (і, за потреби, refresh token).

### Чому зловмисник не може обійти PKCE

Навіть якщо зловмисник перехопив authorization code на кроці 5, він не зможе виконати крок 6, бо:

- `code_verifier` ніколи не передавався по мережі до кроку 6
- На кроці 2 передавався лише `code_challenge` — хеш verifier
- SHA-256 — одностороння функція: знаючи challenge, неможливо обчислити verifier
- Без правильного `code_verifier` token endpoint відхилить запит

---

## 6. Mobile/SPA considerations

### Custom URI schemes та їх проблеми

На мобільних платформах OAuth redirect традиційно використовує **custom URI schemes** — спеціальні протоколи, зареєстровані додатком:

```
myapp://callback?code=abc123&state=xyz
```

Проблема: custom URI schemes **не є унікальними**. На Android будь-який додаток може зареєструвати intent filter для будь-якої схеми. Це саме той вектор атаки, від якого захищає PKCE — але краще усунути проблему на рівні URI.

### Universal Links (iOS) та App Links (Android)

Сучасне рішення — **claimed HTTPS redirects**:

- **Universal Links** (iOS) — `https://app.example.com/callback` перехоплюється додатком, якщо він підтвердив володіння доменом через файл `apple-app-site-association`
- **App Links** (Android) — `https://app.example.com/callback` перехоплюється додатком, якщо він підтвердив володіння доменом через файл `assetlinks.json` у `.well-known/`

```
Custom URI scheme (небезпечно):
  myapp://callback  → будь-який додаток може перехопити

Universal Links / App Links (безпечно):
  https://app.example.com/callback
    → тільки додаток, що підтвердив
      володіння доменом
```

Ці механізми вимагають **криптографічного підтвердження** зв'язку між додатком і доменом — зловмисний додаток не зможе перехопити redirect.

### SPA: redirect_uri та захист від відкритих redirectорів

Для SPA у браузері redirect відбувається через стандартний HTTPS URL. Ключові правила безпеки:

- **Exact match** — redirect_uri має перевірятися за точним збігом, без wildcard
- **HTTPS обов'язковий** — HTTP redirect_uri дозволяє перехоплення code через мережеву атаку
- **Не зберігайте токени в localStorage** — використовуйте in-memory storage або secure cookies

```python
# Приклад перевірки redirect_uri на сервері
REGISTERED_REDIRECT_URIS = [
    "https://app.example.com/callback",
    "https://app.example.com/auth/complete",
]

def validate_redirect_uri(uri: str) -> bool:
    """Exact match — ніяких wildcard або підстрок."""
    return uri in REGISTERED_REDIRECT_URIS
```

### Зберігання токенів у SPA

| Метод | Безпека | Ризики |
|---|---|---|
| `localStorage` | Низька | Доступний для XSS-атак |
| `sessionStorage` | Середня | Доступний для XSS, зникає при закритті вкладки |
| In-memory (JavaScript змінна) | Висока | Зникає при оновленні сторінки |
| HttpOnly cookie (BFF pattern) | Висока | Потребує backend-for-frontend |

**Рекомендація:** для критичних додатків використовуйте **BFF (Backend-for-Frontend) pattern** — тонкий серверний шар, який зберігає токени в HttpOnly cookies, недоступних для JavaScript.

### Loopback redirect для десктопних додатків

Десктопні додатки (CLI tools, Electron apps) можуть використовувати **loopback interface** для отримання redirect:

```
redirect_uri = http://127.0.0.1:{port}/callback
```

Додаток запускає тимчасовий HTTP-сервер на випадковому порті і чекає redirect. Оскільки loopback трафік не виходить за межі пристрою, ризик мережевого перехоплення мінімальний. Але PKCE все одно необхідний — інший процес на тому ж пристрої може прослуховувати порт.

---

## 7. OAuth 2.1 — PKCE обов'язковий для всіх клієнтів

### Що таке OAuth 2.1

**OAuth 2.1** — це консолідація OAuth 2.0 (RFC 6749) із усіма best practices та security BCP (Best Current Practice), накопиченими за роки використання. Це не нова версія протоколу, а **кодифікація** того, що індустрія вже робить.

### Ключові зміни OAuth 2.1

| OAuth 2.0 | OAuth 2.1 |
|---|---|
| PKCE рекомендований для публічних клієнтів | **PKCE обов'язковий для всіх клієнтів** |
| Implicit Flow дозволений | **Implicit Flow видалений** |
| Resource Owner Password Flow дозволений | **ROPC Flow видалений** |
| Redirect URI — рекомендується exact match | **Redirect URI — обов'язковий exact match** |
| Refresh token rotation — рекомендується | **Refresh token rotation або sender-constraining — обов'язкові** |

### Чому PKCE для конфіденційних клієнтів теж

Здавалося б, конфіденційний клієнт і так автентифікується за допомогою `client_secret` — навіщо йому PKCE? Причини:

- **Defense in depth** (ешелонований захист) — навіть якщо `client_secret` скомпрометований, PKCE надає додатковий рівень захисту
- **Authorization code injection** — без PKCE зловмисник може підставити свій code у сесію жертви, навіть якщо client_secret не скомпрометований
- **Уніфікація** — один flow для всіх типів клієнтів спрощує реалізацію та аудит безпеки

### Implicit Flow видалений

Implicit Flow (`response_type=token`) повертав access token безпосередньо в URL fragment (`#access_token=...`). Проблеми:

- Токен видно в історії браузера та логах
- Немає refresh token — потрібна повторна авторизація
- Вразливий до token leakage через Referer header
- Не має механізму прив'язки токена до клієнта

OAuth 2.1 рекомендує замість Implicit Flow використовувати **Authorization Code Flow + PKCE** для всіх клієнтів, включаючи SPA.

---

## 8. Практика — реалізація PKCE flow на Python

### Сценарій

Максим Витребенько додає SPA frontend для SecureNotes і реалізує PKCE flow. Для демонстрації ми побудуємо мінімальний OAuth-клієнт, який виконує повний Authorization Code Flow із PKCE.

### Крок 1: Генерація PKCE параметрів

```python
import hashlib
import base64
import secrets
import urllib.parse
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler

# Конфігурація OAuth
AUTH_SERVER = "https://auth.example.com"
CLIENT_ID = "securenotes-spa"
REDIRECT_URI = "http://127.0.0.1:8080/callback"
SCOPE = "read write"

def generate_pkce_pair():
    """Генерує code_verifier та code_challenge (S256)."""
    # 32 байти ентропії → 43 символи base64url
    verifier_bytes = secrets.token_bytes(32)
    code_verifier = base64.urlsafe_b64encode(verifier_bytes).rstrip(b'=').decode('ascii')

    # S256: BASE64URL(SHA256(code_verifier))
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')

    return code_verifier, code_challenge
```

### Крок 2: Формування URL авторизації

```python
def build_authorization_url(code_challenge: str, state: str) -> str:
    """Формує URL для перенаправлення користувача на Authorization Server."""
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{AUTH_SERVER}/authorize?{urllib.parse.urlencode(params)}"
```

### Крок 3: Обробка callback та обмін code на токен

```python
import requests

def exchange_code_for_token(code: str, code_verifier: str) -> dict:
    """Обмінює authorization code на access token, додаючи code_verifier."""
    response = requests.post(
        f"{AUTH_SERVER}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": code_verifier,  # ← PKCE: відправляємо verifier
        },
    )
    response.raise_for_status()
    return response.json()
```

### Крок 4: Повний flow з локальним HTTP-сервером

```python
def run_pkce_flow():
    """Запускає повний PKCE flow з локальним callback сервером."""
    # 1. Генеруємо PKCE пару та state
    code_verifier, code_challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(16)

    print(f"code_verifier:  {code_verifier}")
    print(f"code_challenge: {code_challenge}")
    print(f"state:          {state}")

    # 2. Формуємо URL авторизації
    auth_url = build_authorization_url(code_challenge, state)
    print(f"\nВідкриваємо браузер: {auth_url}")
    webbrowser.open(auth_url)

    # 3. Запускаємо локальний сервер для отримання callback
    authorization_code = None

    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal authorization_code
            params = urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query
            )

            # Перевіряємо state
            received_state = params.get("state", [None])[0]
            if received_state != state:
                self.send_error(400, "Invalid state parameter")
                return

            authorization_code = params.get("code", [None])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Authorization successful! Close this tab.</h1>")

        def log_message(self, format, *args):
            pass  # тихий сервер

    server = HTTPServer(("127.0.0.1", 8080), CallbackHandler)
    server.handle_request()  # чекаємо один запит

    if not authorization_code:
        print("ERROR: No authorization code received")
        return

    print(f"\nОтримано code: {authorization_code}")

    # 4. Обмінюємо code на токен з code_verifier
    tokens = exchange_code_for_token(authorization_code, code_verifier)
    print(f"\naccess_token:  {tokens['access_token'][:20]}...")
    print(f"token_type:    {tokens['token_type']}")

if __name__ == "__main__":
    run_pkce_flow()
```

### Перевірка PKCE у Bash з curl

```bash
# 1. Генеруємо code_verifier (43 символи base64url)
CODE_VERIFIER=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
echo "code_verifier: $CODE_VERIFIER"

# 2. Обчислюємо code_challenge (S256)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | \
  openssl dgst -sha256 -binary | \
  openssl base64 | tr '+/' '-_' | tr -d '=')
echo "code_challenge: $CODE_CHALLENGE"

# 3. Формуємо URL авторизації (відкрити в браузері)
echo "https://auth.example.com/authorize?\
response_type=code&\
client_id=securenotes-spa&\
redirect_uri=http://127.0.0.1:8080/callback&\
scope=read%20write&\
state=$(openssl rand -hex 16)&\
code_challenge=$CODE_CHALLENGE&\
code_challenge_method=S256"

# 4. Після отримання code — обмін на токен
curl -X POST https://auth.example.com/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE_HERE" \
  -d "redirect_uri=http://127.0.0.1:8080/callback" \
  -d "client_id=securenotes-spa" \
  -d "code_verifier=$CODE_VERIFIER"
```

---

## 9. Підсумки

### Що ми розглянули

- Різницю між конфіденційними та публічними OAuth-клієнтами
- Authorization Code Interception Attack — як зловмисник перехоплює code
- PKCE (RFC 7636) — механізм захисту через commit-reveal із SHA-256
- Генерацію `code_verifier` та `code_challenge` (S256 transform)
- Повний Authorization Code Flow + PKCE крок за кроком
- Безпеку мобільних та SPA-клієнтів: Universal Links, App Links, BFF pattern
- OAuth 2.1 — PKCE обов'язковий для всіх клієнтів

### Ключові висновки

1. Публічні клієнти (SPA, mobile) **не можуть зберігати `client_secret`** — будь-який секрет у клієнтському коді доступний зловмиснику
2. PKCE захищає від перехоплення authorization code через **одноразовий криптографічний proof** — commit хеш, reveal оригінал
3. **S256 метод обов'язковий** — plain метод не забезпечує захисту від перехоплення challenge
4. OAuth 2.1 робить **PKCE обов'язковим для всіх клієнтів** — навіть конфіденційних (defense in depth)
5. Для мобільних додатків використовуйте **Universal Links / App Links** замість custom URI schemes

### Що далі?

У наступній лекції ми розглянемо **OpenID Connect (OIDC)** — Лекція 9: OIDC — автентифікація поверх OAuth.

OAuth 2.0 — це протокол **авторизації**: він надає доступ до ресурсів, але не відповідає на питання "хто цей користувач?". OIDC додає до OAuth рівень **автентифікації**:

- **ID Token** — JWT із інформацією про користувача
- **UserInfo endpoint** — стандартизований API для отримання профілю
- **Discovery** — автоматичне виявлення конфігурації Identity Provider
- **Claims** — стандартизовані атрибути ідентичності (sub, email, name)

Від "дати доступ" до "впізнати людину" — наступний крок у побудові безпечних систем.

---

## Література

1. RFC 7636 — Proof Key for Code Exchange by OAuth Public Clients — https://datatracker.ietf.org/doc/html/rfc7636
2. RFC 6749 — The OAuth 2.0 Authorization Framework — https://datatracker.ietf.org/doc/html/rfc6749
3. OAuth 2.1 Draft — https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1
4. OAuth 2.0 Security Best Current Practice — https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics
5. Aaron Parecki. *OAuth 2.0 Simplified.* — https://oauth.net/2/
6. Daniel Fett, Karsten Meyer zu Selhausen, Guido Schmitz. *An Extensive Formal Security Analysis of the OpenID Financial-grade API.* — 2019
