# Лекція 10. Атаки на OAuth та захист

## Зміст

1. [Чому атаки на OAuth важливі](#1-чому-атаки-на-oauth-важливі)
2. [CSRF атаки — відсутність state parameter](#2-csrf-атаки--відсутність-state-parameter)
3. [Open Redirect — маніпуляція redirect_uri](#3-open-redirect--маніпуляція-redirect_uri)
4. [Token Leakage через Referer](#4-token-leakage-через-referer)
5. [Mix-Up Attack](#5-mix-up-attack)
6. [Authorization Code Injection](#6-authorization-code-injection)
7. [Clickjacking](#7-clickjacking)
8. [Phishing — підроблений consent screen](#8-phishing--підроблений-consent-screen)
9. [Mitigations — комплексний захист](#9-mitigations--комплексний-захист)
10. [Практика — пен-тест SecureNotes](#10-практика--пен-тест-securenotes)
11. [Підсумки](#11-підсумки)

---

## 1. Чому атаки на OAuth важливі

### Міст від лекції 10

У попередній лекції ми побудували повноцінну OAuth-систему: Authorization Server, Resource Server, Client з підтримкою Authorization Code Flow + PKCE. Все працює, токени видаються, ресурси захищені. Здавалося б, завдання виконане.

Але у світі безпеки працює правило: **побудувати систему — це половина роботи, зламати її — друга половина**. Якщо ви не зламаєте свою систему самі, це зробить хтось інший.

### Чому OAuth — улюблена ціль атакуючих

OAuth 2.0 працює через перенаправлення (redirects) між різними доменами, передачу токенів через URL та browser, взаємодію кількох сторін. Кожен з цих етапів — потенційна точка атаки.

Типові наслідки успішної атаки на OAuth:

- **Захоплення акаунту** (account takeover) — атакуючий отримує access token жертви
- **Прив'язка акаунту** (account linking) — атакуючий прив'язує свій зовнішній акаунт до облікового запису жертви
- **Витік даних** — access token потрапляє до третіх сторін через логи, referrer або історію браузера
- **Підвищення привілеїв** — атакуючий отримує scope ширший, ніж дозволено

### Масштаб проблеми

```
2012 — OAuth 2.0 опубліковано (RFC 6749)
2016 — дослідники виявляють Mix-Up Attack
2019 — масові вразливості redirect_uri у великих провайдерах
2020 — RFC 9207 (Authorization Server Issuer Identification)
2023 — OAuth 2.1 консолідує best practices як обов'язкові вимоги
```

OAuth 2.0 специфікація навмисно **гнучка** — вона дозволяє різні реалізації. Ця гнучкість стала джерелом багатьох вразливостей. OAuth 2.1 усуває цю проблему, роблячи раніше опціональні механізми захисту обов'язковими.

Максим Витребенько вирішує провести пен-тест системи SecureNotes, яку побудував у попередніх лекціях. Його мета — знайти вразливості, перш ніж це зробить хтось інший.

---

## 2. CSRF атаки — відсутність state parameter

### Проблема

**CSRF (Cross-Site Request Forgery)** в контексті OAuth — це атака, при якій зловмисник змушує браузер жертви завершити OAuth flow з authorization code атакуючого. Результат: акаунт жертви прив'язується до зовнішнього акаунту атакуючого.

### Як працює атака

```
Атакуючий (Mallory)                    Жертва (Максим)
    │                                       │
    │  1. Mallory починає OAuth flow         │
    │     зі своїм акаунтом                  │
    │                                       │
    │  2. Mallory отримує authorization      │
    │     code, але НЕ завершує flow         │
    │                                       │
    │  3. Mallory створює URL з code:        │
    │     /callback?code=MALLORY_CODE        │
    │                                       │
    │  4. Mallory надсилає посилання         │
    │     Максиму (email, чат, сайт)   ────→│
    │                                       │
    │                                       │  5. Максим переходить
    │                                       │     за посиланням
    │                                       │
    │                                       │  6. Client обмінює code
    │                                       │     на access token
    │                                       │     Mallory
    │                                       │
    │                                       │  7. Акаунт Максима
    │                                       │     прив'язаний до
    │                                       │     Google Mallory!
```

### Конкретний сценарій

Максим тестує SecureNotes. Система підтримує «вхід через Google». Атакуючий Mallory:

1. Починає OAuth flow на SecureNotes зі своїм Google-акаунтом
2. Перехоплює callback URL: `https://securenotes.example/callback?code=abc123`
3. Надсилає це посилання Максиму
4. Максим клікає — його SecureNotes тепер прив'язаний до Google Mallory

Тепер Mallory може увійти в акаунт Максима через «вхід через Google», використовуючи свій Google-акаунт.

### Чому це працює

Client не перевіряє, чи цей authorization code був запитаний саме цим користувачем у цій сесії. Без `state` parameter немає зв'язку між початком flow та його завершенням.

### Вразливий код

```python
# ВРАЗЛИВИЙ — без state parameter
@app.get("/login")
def login():
    return redirect(
        f"{AUTH_SERVER}/authorize"
        f"?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
    )

@app.get("/callback")
def callback(code: str):
    # Обмінюємо code на token — без перевірки state!
    token = exchange_code(code)
    session["user"] = get_user_info(token)
    return redirect("/dashboard")
```

### Виправлений код

```python
import secrets

@app.get("/login")
def login():
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    return redirect(
        f"{AUTH_SERVER}/authorize"
        f"?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&state={state}"
    )

@app.get("/callback")
def callback(code: str, state: str):
    # Перевіряємо state!
    if state != session.get("oauth_state"):
        return "CSRF detected", 403

    del session["oauth_state"]
    token = exchange_code(code)
    session["user"] = get_user_info(token)
    return redirect("/dashboard")
```

---

## 3. Open Redirect — маніпуляція redirect_uri

### Проблема

**Open Redirect** — атака, при якій зловмисник маніпулює параметром `redirect_uri`, щоб Authorization Server перенаправив authorization code або token на сервер атакуючого.

### Як працює атака

```
Нормальний flow:
  redirect_uri=https://securenotes.example/callback
  → Authorization Server перенаправляє code на securenotes.example

Атака:
  redirect_uri=https://evil.example/steal
  → Authorization Server перенаправляє code на evil.example!
```

### Вектори маніпуляції redirect_uri

Якщо Authorization Server виконує лише часткову перевірку redirect_uri, атакуючий може обійти її різними способами:

```
Зареєстрований: https://securenotes.example/callback

Маніпуляції:
  https://securenotes.example/callback/../../../evil
  https://securenotes.example.evil.com/callback
  https://securenotes.example/callback?next=https://evil.com
  https://securenotes.example/callback#token_here
  https://securenotes.example/callback/..%2F..%2F..%2Fevil
  https://securenotes.example/callback%00@evil.com
```

### Демонстрація

Максим перевіряє, як SecureNotes валідує redirect_uri.

```python
# ВРАЗЛИВИЙ — перевірка лише початку URL
def validate_redirect_uri(uri, registered_uri):
    return uri.startswith(registered_uri)

# Ця перевірка пропустить:
validate_redirect_uri(
    "https://securenotes.example/callback/../evil",
    "https://securenotes.example/callback"
)  # True!
```

```python
# БЕЗПЕЧНИЙ — точне порівняння (exact match)
def validate_redirect_uri(uri, registered_uri):
    return uri == registered_uri

# Або з нормалізацією:
from urllib.parse import urlparse

def validate_redirect_uri_strict(uri, registered_uri):
    parsed = urlparse(uri)
    registered = urlparse(registered_uri)
    return (
        parsed.scheme == registered.scheme
        and parsed.netloc == registered.netloc
        and parsed.path == registered.path
        and not parsed.query  # забороняємо додаткові параметри
        and not parsed.fragment
    )
```

### Чому Implicit Flow особливо вразливий

У Implicit Flow token передається у fragment частині URL (`#access_token=...`). Якщо redirect_uri маніпульовано, token потрапляє безпосередньо на сервер атакуючого:

```
GET /authorize
  ?response_type=token
  &client_id=securenotes
  &redirect_uri=https://evil.example/steal

→ Redirect: https://evil.example/steal#access_token=eyJhbGci...

Атакуючий отримує access token напряму!
```

Це одна з причин, чому **OAuth 2.1 забороняє Implicit Flow**.

---

## 4. Token Leakage через Referer

### Проблема

Коли access token або authorization code передається через URL (як query parameter або fragment), він може витікати через HTTP заголовок `Referer`. Браузер автоматично додає `Referer` до кожного наступного HTTP-запиту, який містить URL поточної сторінки.

### Як працює витік

```
1. Authorization Server перенаправляє на:
   https://securenotes.example/callback?code=abc123

2. Сторінка callback завантажує зовнішній ресурс
   (зображення, скрипт, шрифт, analytics):

   <img src="https://analytics.example/pixel.gif">

3. Браузер надсилає запит до analytics.example
   з заголовком Referer:

   GET /pixel.gif HTTP/1.1
   Host: analytics.example
   Referer: https://securenotes.example/callback?code=abc123
                                                 ^^^^^^^^^^^^
                                                 Authorization code
                                                 у Referer!

4. analytics.example бачить authorization code
```

### Реальні вектори витоку

```
┌─────────────────────────────────────────────────────┐
│  Сторінка: /callback?code=SECRET                     │
│                                                      │
│  Зовнішні ресурси, кожен отримує Referer:           │
│  ├── Google Analytics (analytics.js)                 │
│  ├── CDN шрифти (fonts.googleapis.com)               │
│  ├── Рекламний пік сель (ads.example.com)             │
│  ├── Зовнішні зображення (img.example.com)           │
│  └── Соціальні кнопки (facebook.com/like.js)         │
│                                                      │
│  Кожен з цих сервісів бачить code у Referer!        │
└─────────────────────────────────────────────────────┘
```

### Захист

```python
# 1. Негайно обміняти code на token і перенаправити
@app.get("/callback")
def callback(code: str, state: str):
    if state != session.get("oauth_state"):
        return "CSRF detected", 403
    token = exchange_code(code)  # обмін відразу
    session["access_token"] = token
    return redirect("/dashboard")  # перенаправлення без code в URL

# 2. Додати Referrer-Policy заголовок
@app.after_request
def set_referrer_policy(response):
    response.headers["Referrer-Policy"] = "no-referrer"
    return response
```

```html
<!-- 3. HTML meta tag -->
<meta name="referrer" content="no-referrer">
```

Також допомагає **PKCE** — навіть якщо code витік через Referer, без `code_verifier` атакуючий не зможе обміняти його на token.

---

## 5. Mix-Up Attack

### Проблема

**Mix-Up Attack** виникає, коли Client підтримує кілька Authorization Server (наприклад, «вхід через Google» та «вхід через GitHub»). Атакуючий підміняє відповідь одного Authorization Server відповіддю іншого — і Client відправляє authorization code на неправильний сервер.

### Як працює атака

```
Легітимні сервери:                   Атакуючий сервер:
┌──────────────┐                     ┌──────────────┐
│    Google     │                     │   Evil AS    │
│   (честний)   │                     │  (атакуючий)  │
└──────────────┘                     └──────────────┘

1. Максим натискає "Вхід через Evil AS"
   (яке виглядає як легітимний провайдер)

2. Evil AS перенаправляє Максима на GOOGLE
   для автентифікації (підміна!)

3. Максим автентифікується в Google,
   Google видає authorization code

4. Client отримує code і думає, що це
   відповідь від Evil AS

5. Client відправляє code + client_secret
   на token endpoint Evil AS

6. Evil AS отримує Google code Максима!
```

### Детальна схема

```
Client              Evil AS              Google
  │                    │                    │
  │ 1. /authorize      │                    │
  │    (issuer=evil)   │                    │
  │───────────────────→│                    │
  │                    │                    │
  │ 2. redirect to     │                    │
  │    Google /auth    │                    │
  │←───────────────────│                    │
  │                    │                    │
  │ 3. /authorize      │                    │
  │───────────────────────────────────────→│
  │                    │                    │
  │ 4. code=GOOGLE_CODE│                    │
  │←───────────────────────────────────────│
  │                    │                    │
  │ 5. Client думає:   │                    │
  │    "це від Evil AS"│                    │
  │    Відправляє code │                    │
  │    на Evil AS      │                    │
  │───────────────────→│                    │
  │                    │                    │
  │         Evil AS тепер має Google code!  │
```

### Захист — RFC 9207

**Authorization Server Issuer Identification** (RFC 9207) вирішує цю проблему. Authorization Server додає параметр `iss` до callback:

```
/callback?code=abc123&iss=https://accounts.google.com
```

Client перевіряє, що `iss` відповідає тому Authorization Server, якому він відправляв запит:

```python
@app.get("/callback")
def callback(code: str, state: str, iss: str):
    # Визначаємо, якому AS ми відправляли запит
    expected_issuer = session.get("oauth_issuer")

    if iss != expected_issuer:
        return "Mix-Up Attack detected", 403

    # Обмінюємо code на token endpoint правильного AS
    token_endpoint = get_token_endpoint(iss)
    token = exchange_code(code, token_endpoint)
    # ...
```

---

## 6. Authorization Code Injection

### Проблема

**Authorization Code Injection** — атака, при якій зловмисник перехоплює authorization code одного користувача і використовує його у своєму OAuth flow, щоб отримати доступ до акаунту жертви.

### Різниця від CSRF

```
CSRF:
  Атакуючий підставляє СВІЙ code жертві
  → Акаунт жертви прив'язується до атакуючого

Code Injection:
  Атакуючий перехоплює code ЖЕРТВИ і використовує сам
  → Атакуючий отримує доступ до акаунту жертви
```

### Як працює атака

```
Жертва (Максим)           Атакуючий (Mallory)
     │                          │
     │  1. Максим автентифікується
     │     і отримує code
     │                          │
     │  2. Mallory перехоплює    │
     │     code (через Referer,  │
     │     open redirect,        │
     │     shared device тощо)   │
     │                     ────→│
     │                          │
     │                          │  3. Mallory починає свій
     │                          │     OAuth flow
     │                          │
     │                          │  4. Mallory підставляє
     │                          │     code Максима у свій
     │                          │     callback
     │                          │
     │                          │  5. Client обмінює code
     │                          │     на token Максима
     │                          │
     │                          │  6. Mallory має доступ
     │                          │     до акаунту Максима!
```

### Чому PKCE вирішує проблему

**PKCE (Proof Key for Code Exchange)** прив'язує authorization code до конкретного OAuth session. Навіть якщо code перехоплений, без `code_verifier` він марний.

```
Максим починає flow:
  code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  code_challenge = SHA256(code_verifier) = "E9Melhoa2OwvFrEMTJguCHaoeK1..."

  /authorize?...&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1...

Mallory перехоплює code, але НЕ знає code_verifier.

Mallory намагається обміняти code:
  POST /token
    code=STOLEN_CODE
    code_verifier=???  ← Mallory не знає!

Authorization Server:
  SHA256(???) != збережений code_challenge
  → 400 Bad Request
```

### Приклад перевірки

```python
import hashlib
import base64

def verify_pkce(code_verifier: str, stored_challenge: str) -> bool:
    """Authorization Server перевіряє PKCE."""
    computed = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode()
    return computed == stored_challenge

# Максим відправляє правильний code_verifier:
verify_pkce(
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    "E9Melhoa2OwvFrEMTJguCHaoeK1t36HtjIGhUBYmkKA"
)  # True

# Mallory не знає code_verifier:
verify_pkce(
    "mallory_guess_attempt",
    "E9Melhoa2OwvFrEMTJguCHaoeK1t36HtjIGhUBYmkKA"
)  # False — доступ заборонено
```

---

## 7. Clickjacking

### Проблема

**Clickjacking** — атака, при якій зловмисник вбудовує сторінку Authorization Server (consent screen) у прозорий iframe на своєму сайті. Жертва думає, що натискає кнопку на сайті атакуючого, а насправді натискає «Дозволити» на consent screen.

### Як працює атака

```
┌──────────────────────────────────────────────┐
│  evil.example (видимий шар)                   │
│                                               │
│  ┌─────────────────────────────────┐         │
│  │  "Натисніть тут, щоб виграти   │         │
│  │   iPhone 16!"                   │         │
│  │                                 │         │
│  │  ┌───────────────────────┐      │         │
│  │  │    [ОТРИМАТИ ПРИЗ]    │ ←── видима     │
│  │  └───────────────────────┘     кнопка     │
│  │                                 │         │
│  └─────────────────────────────────┘         │
│                                               │
│  ┌─────────────────────────────────┐         │
│  │  (прозорий iframe, opacity: 0)  │         │
│  │                                 │         │
│  │  Authorization Server:          │         │
│  │  "Дозволити securenotes         │         │
│  │   доступ до вашого акаунту?"    │         │
│  │                                 │         │
│  │  ┌───────────────────────┐      │         │
│  │  │    [ДОЗВОЛИТИ]        │ ←── справжня   │
│  │  └───────────────────────┘     кнопка     │
│  │                                 │         │
│  └─────────────────────────────────┘         │
│                                               │
│  Кнопки накладаються одна на одну!           │
└──────────────────────────────────────────────┘
```

### Код атаки

```html
<!-- evil.example -->
<style>
  .overlay {
    position: relative;
    width: 500px;
    height: 400px;
  }
  iframe {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    opacity: 0;        /* прозорий! */
    z-index: 2;        /* поверх видимого контенту */
  }
  .bait {
    position: absolute;
    top: 0;
    left: 0;
    z-index: 1;
  }
</style>

<div class="overlay">
  <div class="bait">
    <h2>Ви виграли iPhone 16!</h2>
    <button>Отримати приз</button>
  </div>
  <iframe src="https://auth.example/authorize?client_id=securenotes&redirect_uri=...&scope=read+write">
  </iframe>
</div>
```

### Захист

```python
# 1. X-Frame-Options — забороняє вбудовування у iframe
@app.after_request
def prevent_clickjacking(response):
    response.headers["X-Frame-Options"] = "DENY"
    # Або "SAMEORIGIN" — дозволяє iframe лише з того ж домену
    return response

# 2. Content-Security-Policy (сучасніший підхід)
@app.after_request
def csp_frame_ancestors(response):
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    return response
```

Authorization Server **обов'язково** повинен встановлювати ці заголовки на сторінці consent screen.

---

## 8. Phishing — підроблений consent screen

### Проблема

**Phishing** у контексті OAuth — це створення підробленого consent screen, який виглядає ідентично до справжнього. Жертва вводить свої credentials на сайті атакуючого, думаючи, що це справжній Authorization Server.

### Як працює атака

```
Легітимний flow:
  Client → redirect → https://accounts.google.com/authorize
                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                      Справжній Google

Phishing flow:
  Client → redirect → https://accounts.g00gle.com/authorize
                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                      Підроблений сайт атакуючого!

Або:
  Атакуючий надсилає email:
  "Ваш акаунт SecureNotes потребує повторної авторизації"
  → посилання на підроблений consent screen
```

### Відмінності від звичайного phishing

OAuth phishing особливо небезпечний, тому що:

1. **Користувачі звикли** бачити redirect на сторінку Google/GitHub під час OAuth flow
2. **URL може виглядати легітимно** — атакуючий реєструє схожий домен
3. **Після введення credentials** атакуючий може виконати справжній OAuth flow і перенаправити жертву назад — жертва нічого не підозрює

```
Жертва             Fake Auth Server        Real Auth Server
  │                      │                       │
  │  1. Credentials      │                       │
  │─────────────────────→│                       │
  │                      │  2. Login з            │
  │                      │     credentials жертви │
  │                      │──────────────────────→│
  │                      │                       │
  │                      │  3. Real code          │
  │                      │←──────────────────────│
  │                      │                       │
  │  4. Redirect з code  │                       │
  │←─────────────────────│                       │
  │                      │                       │
  │  Жертва нічого       │                       │
  │  не підозрює!        │                       │
```

### Захист

Повністю запобігти phishing складно, але є кілька механізмів:

```
1. Навчання користувачів:
   - Перевіряти URL у адресному рядку
   - Не переходити за посиланнями з email

2. Технічні заходи:
   - FIDO2/WebAuthn — phishing-resistant автентифікація
     (ключ прив'язаний до домену, підроблений домен не працює)
   - HTTPS + HSTS — браузер не дозволить HTTP
   - Certificate Transparency — виявлення підозрілих сертифікатів

3. OAuth-специфічні:
   - Registered redirect_uri — Client перевіряє, що redirect
     йде на правильний Authorization Server
   - Pushed Authorization Requests (PAR) — параметри авторизації
     передаються через back-channel, а не через URL
```

```python
# WebAuthn — phishing-resistant автентифікація
# Ключ прив'язаний до origin, підроблений домен не спрацює

# При реєстрації:
# origin = "https://accounts.google.com"
# credential прив'язаний до цього origin

# При phishing:
# origin = "https://accounts.g00gle.com" — ІНШИЙ!
# WebAuthn відмовить у автентифікації, бо origin не збігається
```

---

## 9. Mitigations — комплексний захист

### Огляд усіх атак та захисних механізмів

| Атака | Механізм захисту | Обов'язковий в OAuth 2.1? |
|---|---|---|
| CSRF | `state` parameter | Так (або PKCE) |
| Open Redirect | Exact redirect_uri matching | Так |
| Token Leakage (Referer) | Referrer-Policy, PKCE | Так (PKCE) |
| Mix-Up Attack | `iss` parameter (RFC 9207) | Рекомендовано |
| Code Injection | PKCE | Так |
| Clickjacking | X-Frame-Options, CSP | Рекомендовано |
| Phishing | WebAuthn, PAR | Рекомендовано |
| Implicit Flow | Заборонено в OAuth 2.1 | Так (заборонено) |

### state parameter

```python
# Генерація та перевірка state
import secrets

def generate_state() -> str:
    return secrets.token_urlsafe(32)

def verify_state(received: str, stored: str) -> bool:
    # Використовуємо hmac.compare_digest для timing-safe порівняння
    import hmac
    return hmac.compare_digest(received, stored)
```

### PKCE (Proof Key for Code Exchange)

```python
import secrets
import hashlib
import base64

def generate_pkce():
    """Генерація code_verifier та code_challenge."""
    code_verifier = secrets.token_urlsafe(64)

    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode()

    return code_verifier, code_challenge

verifier, challenge = generate_pkce()

# В /authorize:
# &code_challenge={challenge}&code_challenge_method=S256

# В /token:
# code_verifier={verifier}
```

### Exact redirect_uri matching

```python
# Authorization Server ПОВИНЕН:
def validate_redirect_uri(requested_uri: str, registered_uris: list) -> bool:
    """Точне порівняння redirect_uri."""
    return requested_uri in registered_uris

# Забороняється:
# - Wildcard matching (*.example.com)
# - Prefix matching (startswith)
# - Часткове порівняння
# - Ігнорування query/fragment
```

### Token Binding та Sender-Constrained Tokens

Традиційні access tokens — це **bearer tokens**: будь-хто, хто має token, може його використати. Sender-constrained tokens прив'язані до конкретного клієнта.

```
Bearer Token (традиційний):
┌──────────┐
│  Token   │ → Хто має — той використовує
└──────────┘

Sender-Constrained Token:
┌──────────┐   ┌──────────────┐
│  Token   │ + │ Client Cert  │ → Лише цей клієнт може використати
└──────────┘   └──────────────┘

Механізми:
- mTLS (RFC 8705) — token прив'язаний до TLS-сертифіката клієнта
- DPoP (RFC 9449) — token прив'язаний до ключа, proof-of-possession
```

```python
# DPoP (Demonstration of Proof-of-Possession)
import jwt
import time

def create_dpop_proof(method: str, url: str, private_key) -> str:
    """Клієнт створює DPoP proof для кожного запиту."""
    payload = {
        "jti": secrets.token_urlsafe(16),
        "htm": method,  # HTTP method
        "htu": url,     # URL ресурсу
        "iat": int(time.time()),
    }
    return jwt.encode(payload, private_key, algorithm="ES256",
                      headers={"typ": "dpop+jwt", "jwk": public_jwk})

# Використання:
# GET /resource
# Authorization: DPoP eyJhbGci...
# DPoP: eyJ0eXAiOiJkcG9wK2p3dCJ9...
```

### Checklist безпеки OAuth

```bash
#!/bin/bash
# oauth-security-checklist.sh

echo "=== OAuth Security Checklist ==="

echo "[1] state parameter"
echo "    - Генерується через CSPRNG"
echo "    - Перевіряється при callback"
echo "    - Одноразовий (видаляється після використання)"

echo "[2] PKCE"
echo "    - code_challenge_method=S256 (не plain)"
echo "    - code_verifier >= 43 символи"
echo "    - Використовується для ВСІХ клієнтів"

echo "[3] redirect_uri"
echo "    - Exact match (не prefix, не wildcard)"
echo "    - Зареєстрований заздалегідь"
echo "    - HTTPS only (крім localhost для розробки)"

echo "[4] Token security"
echo "    - Short-lived access tokens (5-15 хв)"
echo "    - Refresh tokens з rotation"
echo "    - Referrer-Policy: no-referrer"

echo "[5] Server headers"
echo "    - X-Frame-Options: DENY"
echo "    - Content-Security-Policy: frame-ancestors 'none'"
echo "    - Strict-Transport-Security: max-age=31536000"

echo "[6] Implicit Flow"
echo "    - ЗАБОРОНЕНО (використовуйте Authorization Code + PKCE)"
```

---

## 10. Практика — пен-тест SecureNotes

### Сценарій

Максим Витребенько проводить пен-тест SecureNotes — системи нотаток з OAuth-автентифікацією, побудованої в попередніх лекціях. Його мета — знайти та виправити вразливості.

### Вразливість 1: Відсутність state parameter

```python
# Знаходимо вразливість:
# securenotes/auth.py

@app.get("/login/google")
def login_google():
    return redirect(
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri=https://securenotes.example/callback"
        f"&response_type=code"
        f"&scope=openid+email+profile"
        # Немає state parameter!
    )

# Виправлення:
@app.get("/login/google")
def login_google():
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    return redirect(
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri=https://securenotes.example/callback"
        f"&response_type=code"
        f"&scope=openid+email+profile"
        f"&state={state}"
    )
```

### Вразливість 2: Неточна перевірка redirect_uri

```python
# Знаходимо вразливість на Authorization Server:
# securenotes/oauth_server.py

REGISTERED_REDIRECT_URIS = {
    "securenotes": "https://securenotes.example/callback"
}

def validate_redirect(client_id, redirect_uri):
    registered = REGISTERED_REDIRECT_URIS.get(client_id)
    return redirect_uri.startswith(registered)  # ВРАЗЛИВО!

# Виправлення:
def validate_redirect(client_id, redirect_uri):
    registered = REGISTERED_REDIRECT_URIS.get(client_id)
    return redirect_uri == registered  # Exact match
```

### Вразливість 3: Відсутність PKCE

```python
# Знаходимо: Client не відправляє code_challenge
# Виправлення:

import secrets, hashlib, base64

@app.get("/login/google")
def login_google():
    code_verifier = secrets.token_urlsafe(64)
    session["code_verifier"] = code_verifier

    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode()

    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    return redirect(
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={GOOGLE_CLIENT_ID}"
        f"&redirect_uri=https://securenotes.example/callback"
        f"&response_type=code"
        f"&scope=openid+email+profile"
        f"&state={state}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )

@app.get("/callback")
def callback(code: str, state: str):
    if state != session.pop("oauth_state", None):
        return "CSRF detected", 403

    code_verifier = session.pop("code_verifier", None)

    token_response = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://securenotes.example/callback",
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code_verifier": code_verifier,  # PKCE!
        }
    )
    # ...
```

### Вразливість 4: Clickjacking

```python
# Знаходимо: Authorization Server не встановлює frame headers
# securenotes/oauth_server.py

@app.get("/authorize")
def authorize():
    # ... рендерить consent screen
    return render_template("consent.html")
    # Немає X-Frame-Options!

# Виправлення:
@app.after_request
def security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    return response
```

### Вразливість 5: Token Leakage через логи

```python
# Знаходимо: access_token у query string
# securenotes/api.py

@app.get("/api/notes")
def get_notes():
    # Деякі клієнти передають token через query string:
    # GET /api/notes?access_token=eyJhbGci...
    token = request.args.get("access_token")  # ВРАЗЛИВО!
    # Token потрапляє в server logs, browser history, Referer

# Виправлення: приймати token ЛИШЕ через Authorization header
@app.get("/api/notes")
def get_notes():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return {"error": "Missing Bearer token"}, 401
    token = auth_header[7:]
    # Token не потрапляє в URL і логи
```

### Підсумок пен-тесту

```
┌─────────────────────────────────────────────────┐
│  SecureNotes Pen-Test Report                     │
│  Автор: Максим Витребенько                       │
├─────────────────────────────────────────────────┤
│  Знайдено вразливостей: 5                        │
│                                                  │
│  [CRITICAL] Відсутність state parameter          │
│  [HIGH]     Неточна перевірка redirect_uri       │
│  [HIGH]     Відсутність PKCE                     │
│  [MEDIUM]   Clickjacking consent screen          │
│  [MEDIUM]   Token leakage через query string     │
│                                                  │
│  Усі вразливості виправлено.                     │
│  Рекомендація: мігрувати на OAuth 2.1            │
└─────────────────────────────────────────────────┘
```

---

## 11. Підсумки

### Що ми розглянули

- **CSRF** — відсутність state parameter дозволяє прив'язати чужий акаунт
- **Open Redirect** — маніпуляція redirect_uri перенаправляє code/token на сервер атакуючого
- **Token Leakage через Referer** — token у URL витікає через HTTP Referer заголовок
- **Mix-Up Attack** — клієнт плутає Authorization Server і відправляє code не туди
- **Authorization Code Injection** — перехоплений code використовується атакуючим
- **Clickjacking** — прозорий iframe над consent screen
- **Phishing** — підроблений consent screen збирає credentials

### Ключові висновки

1. **PKCE вирішує більшість проблем** — code injection, token leakage, частково CSRF. PKCE обов'язковий в OAuth 2.1
2. **Exact redirect_uri matching** — ніяких wildcard, prefix, partial match
3. **State parameter** — обов'язковий для захисту від CSRF
4. **Security headers** — X-Frame-Options, CSP, Referrer-Policy на Authorization Server
5. **Bearer tokens вразливі** — sender-constrained tokens (mTLS, DPoP) є майбутнім
6. **OAuth 2.1** консолідує всі ці best practices як обов'язкові вимоги

### Що далі?

У наступній лекції ми розглянемо **OAuth у мікросервісах** — Лекція 11: OAuth у мікросервісній архітектурі.

Ми побудували та захистили OAuth-систему як монолітний додаток. Але у реальному світі більшість систем складаються з десятків мікросервісів. Як працює OAuth у такому середовищі?

- **Service-to-service authentication** — як мікросервіси автентифікують один одного
- **Token propagation** — як access token передається між сервісами
- **API Gateway** — єдина точка входу, яка перевіряє токени
- **Token Exchange** (RFC 8693) — обмін токенів для downstream сервісів
- **Zero Trust Architecture** — кожен сервіс перевіряє кожен запит

Ці концепції дозволяють масштабувати OAuth на розподілені системи з десятками та сотнями сервісів.

---

## Література

1. Aaron Parecki. *OAuth 2.0 Simplified.* — oauth.com: 2023
2. RFC 6749 — The OAuth 2.0 Authorization Framework
3. RFC 7636 — Proof Key for Code Exchange by OAuth Public Clients (PKCE)
4. RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification
5. RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)
6. RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
7. Daniel Fett, Ralf Kuesters, Guido Schmitz. *A Comprehensive Formal Security Analysis of OAuth 2.0.* — ACM CCS: 2016
8. OAuth 2.0 Security Best Current Practice — draft-ietf-oauth-security-topics
