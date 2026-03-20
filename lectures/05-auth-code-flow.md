# Лекція 5. Authorization Code Flow

## Зміст

1. [Чому Authorization Code Flow](#1-чому-authorization-code-flow)
2. [Крок за кроком — повний flow](#2-крок-за-кроком--повний-flow)
3. [Authorization Endpoint — параметри запиту](#3-authorization-endpoint--параметри-запиту)
4. [Token Endpoint — обмін коду на токен](#4-token-endpoint--обмін-коду-на-токен)
5. [Параметр state — CSRF protection](#5-параметр-state--csrf-protection)
6. [Валідація redirect_uri — exact matching](#6-валідація-redirect_uri--exact-matching)
7. [Confidential vs Public clients](#7-confidential-vs-public-clients)
8. [Практика — Python Flask](#8-практика--python-flask)
9. [Підсумки](#9-підсумки)

---

## 1. Чому Authorization Code Flow

### Місток з лекції 5

У попередній лекції ми розглянули **архітектуру OAuth 2.0**: ролі (Resource Owner, Client, Authorization Server, Resource Server), поняття grant types та загальну модель взаємодії між учасниками. Ми дізналися, що OAuth 2.0 визначає кілька способів (grant types), якими Client може отримати Access Token. Тепер настав час детально розібрати **найбезпечніший** з них.

### Чому саме Authorization Code Flow?

OAuth 2.0 (RFC 6749) визначає кілька grant types:

| Grant Type | Використання |
|---|---|
| **Authorization Code** | Серверні веб-додатки (найбезпечніший) |
| Implicit | SPA (deprecated у OAuth 2.1) |
| Resource Owner Password Credentials | Legacy-системи (deprecated) |
| Client Credentials | Machine-to-machine (без користувача) |

**Authorization Code Flow** — це рекомендований grant type для більшості сценаріїв, де є кінцевий користувач (Resource Owner). Чому?

1. **Access Token ніколи не потрапляє у браузер** — токен передається через back-channel (сервер-сервер), а не через URL або браузер користувача
2. **Client автентифікується** — Authorization Server перевіряє, що запит на обмін коду на токен справді надходить від легітимного Client
3. **Authorization Code — короткоживучий** — навіть якщо код перехоплять, він дійсний лише кілька хвилин і може бути використаний лише один раз
4. **Підтримує refresh tokens** — дозволяє отримати новий Access Token без повторної авторизації

### Порівняння з Implicit Flow

В **Implicit Flow** (який ми не будемо використовувати) Access Token повертається безпосередньо у фрагменті URL:

```
https://client.example.com/callback#access_token=abc123&token_type=bearer
```

Проблеми очевидні:
- Токен видно у browser history
- Токен може потрапити в логи сервера через Referer header
- Немає автентифікації Client — будь-хто може підставити свій redirect_uri
- Немає refresh tokens

**Authorization Code Flow** вирішує всі ці проблеми, додаючи проміжний крок — authorization code.

---

## 2. Крок за кроком — повний flow

### Сценарій

Максим Витребенько розробляє додаток **SecureNotes** — веб-сервіс для зберігання нотаток. Максим хоче дозволити користувачам логінитись через Google. Для цього SecureNotes реалізує Authorization Code Flow.

### Повна діаграма

```
┌──────────┐                                              ┌─────────────────┐
│ Resource  │                                              │  Authorization  │
│ Owner     │                                              │  Server         │
│ (User)    │                                              │  (Google)       │
└────┬──────┘                                              └───────┬─────────┘
     │                                                             │
     │  1. Натискає "Увійти через Google"                          │
     │                                                             │
     ▼                                                             │
┌──────────┐                                                       │
│  Client   │  2. Redirect на Authorization Endpoint               │
│ (Secure-  │  GET /authorize?                                     │
│  Notes)   │    response_type=code&                               │
│           │    client_id=securenotes&                             │
│           │    redirect_uri=https://securenotes.com/callback&     │
│           │    scope=openid+profile+email&                       │
│           │    state=xY7kLm9p                                    │
│           │─────────────────────────────────────────────────────→ │
└──────────┘                                                       │
                                                                   │
     ┌─────────────────────────────────────────────────────────────│
     │  3. Authorization Server показує Consent Screen:            │
     │     "SecureNotes хоче отримати доступ до вашого профілю"    │
     ▼                                                             │
┌──────────┐                                                       │
│ Resource  │  4. Користувач натискає "Дозволити"                   │
│ Owner     │─────────────────────────────────────────────────────→ │
└──────────┘                                                       │
                                                                   │
┌──────────┐  5. Redirect назад з Authorization Code               │
│  Client   │←─────────────────────────────────────────────────────│
│ (Secure-  │  302 Location: https://securenotes.com/callback?     │
│  Notes)   │    code=SplxlOBeZQQYbYS6WxSbIA&                     │
│           │    state=xY7kLm9p                                    │
│           │                                                      │
│           │  6. Back-channel: обмін коду на токен                 │
│           │  POST /token                                         │
│           │    grant_type=authorization_code&                     │
│           │    code=SplxlOBeZQQYbYS6WxSbIA&                     │
│           │    redirect_uri=https://securenotes.com/callback&     │
│           │    client_id=securenotes&                             │
│           │    client_secret=s3cr3t                               │
│           │─────────────────────────────────────────────────────→ │
│           │                                                      │
│           │  7. Authorization Server повертає токени              │
│           │←─────────────────────────────────────────────────────│
│           │  {                                                    │
│           │    "access_token": "eyJhbGciOi...",                   │
│           │    "token_type": "Bearer",                            │
│           │    "expires_in": 3600,                                │
│           │    "refresh_token": "tGzv3JOkF0..."                  │
│           │  }                                                    │
└──────────┘                                                       │
     │                                                             │
     │  8. Client використовує Access Token для запитів             │
     │  GET /userinfo                                              │
     │  Authorization: Bearer eyJhbGciOi...                        │
     │─────────────────────────────────────────────────────────────→
     │                                                Resource Server
     │  9. Resource Server повертає дані користувача                │
     │←─────────────────────────────────────────────────────────────
```

### Ключові спостереження

1. **Кроки 2-5** відбуваються через **front-channel** (браузер користувача) — тут передається лише authorization code, не Access Token
2. **Крок 6** відбувається через **back-channel** (сервер SecureNotes → сервер Google) — Access Token ніколи не проходить через браузер
3. **state** передається у кроці 2 і повертається у кроці 5 — Client перевіряє, що вони збігаються (захист від CSRF)
4. **client_secret** передається лише в кроці 6 через back-channel — він ніколи не потрапляє у браузер

---

## 3. Authorization Endpoint — параметри запиту

### Що це

Authorization Endpoint — це URL на Authorization Server, куди Client перенаправляє користувача для отримання авторизації. Це front-channel запит: він проходить через браузер користувача.

### Формат запиту

```http
GET /authorize?response_type=code
              &client_id=securenotes
              &redirect_uri=https%3A%2F%2Fsecurenotes.com%2Fcallback
              &scope=openid%20profile%20email
              &state=xY7kLm9p
HTTP/1.1
Host: accounts.google.com
```

### Параметри

| Параметр | Обов'язковий | Опис |
|---|---|---|
| `response_type` | так | Має бути `code` для Authorization Code Flow |
| `client_id` | так | Ідентифікатор Client, отриманий при реєстрації |
| `redirect_uri` | рекомендований | URL, на який Authorization Server поверне користувача з кодом |
| `scope` | рекомендований | Список дозволів, розділених пробілом |
| `state` | **рекомендований (де-факто обов'язковий)** | Випадкове значення для захисту від CSRF |

### response_type=code

Цей параметр повідомляє Authorization Server, що Client хоче отримати **authorization code**, а не токен безпосередньо. Це фундаментальна відмінність від Implicit Flow, де `response_type=token`.

### client_id

Client отримує `client_id` при реєстрації на Authorization Server. Наприклад, коли Максим Витребенько реєструє SecureNotes у Google Cloud Console, він отримує:
- `client_id` — публічний ідентифікатор (безпечно передавати через front-channel)
- `client_secret` — секретний ключ (тільки для back-channel)

### scope

Scope визначає, до яких ресурсів Client запитує доступ:

```
scope=openid profile email
```

| Scope | Що дає |
|---|---|
| `openid` | ID Token (ідентифікація користувача) |
| `profile` | Ім'я, аватар |
| `email` | Email-адреса |
| `photos.read` | Читання фото (Google Photos) |

Authorization Server може показати користувачу **consent screen** із переліком запитуваних scopes, і користувач вирішує, які дозволити.

### state

Параметр `state` — це випадкове значення, яке Client генерує перед початком flow і зберігає (наприклад, у сесії). Authorization Server повертає це значення разом з authorization code. Client перевіряє, що отримане `state` збігається із збереженим. Детальніше — у розділі 5.

---

## 4. Token Endpoint — обмін коду на токен

### Що це

Token Endpoint — це URL на Authorization Server, куди Client відправляє authorization code для обміну на Access Token. Це **back-channel** запит: він іде безпосередньо від сервера Client до сервера Authorization Server, без участі браузера.

### Формат запиту

```http
POST /token HTTP/1.1
Host: oauth2.googleapis.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fsecurenotes.com%2Fcallback
&client_id=securenotes
&client_secret=s3cr3t
```

### Параметри

| Параметр | Обов'язковий | Опис |
|---|---|---|
| `grant_type` | так | Має бути `authorization_code` |
| `code` | так | Authorization code, отриманий від Authorization Endpoint |
| `redirect_uri` | так (якщо був у запиті) | Має **точно збігатись** з redirect_uri із кроку авторизації |
| `client_id` | так | Ідентифікатор Client |
| `client_secret` | так (для confidential clients) | Секрет Client для автентифікації |

### Автентифікація Client

Client може автентифікуватись двома способами:

**Спосіб 1: через тіло запиту** (як вище)

```
client_id=securenotes&client_secret=s3cr3t
```

**Спосіб 2: через HTTP Basic Authentication**

```http
POST /token HTTP/1.1
Authorization: Basic c2VjdXJlbm90ZXM6czNjcjN0
```

Де `c2VjdXJlbm90ZXM6czNjcjN0` = Base64(`securenotes:s3cr3t`).

### Відповідь

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
  "scope": "openid profile email"
}
```

| Поле | Опис |
|---|---|
| `access_token` | Токен для доступу до ресурсів |
| `token_type` | Завжди `Bearer` |
| `expires_in` | Час життя токена в секундах |
| `refresh_token` | Токен для отримання нового access_token (опціональний) |
| `scope` | Scopes, які фактично були надані (можуть відрізнятись від запитуваних) |

### Що Authorization Server перевіряє

Перш ніж видати токен, Authorization Server виконує наступні перевірки:

```
1. Чи валідний authorization code?
   └── Код існує, не використаний, не прострочений

2. Чи збігається client_id?
   └── Код був виданий саме цьому Client

3. Чи валідний client_secret?
   └── Client автентифікований

4. Чи збігається redirect_uri?
   └── Exact match з тим, що був у /authorize запиті

5. Все ОК → видати access_token + refresh_token
   └── Інвалідувати authorization code (одноразове використання)
```

Якщо будь-яка перевірка не пройшла — Authorization Server повертає помилку:

```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code has expired or has been used"
}
```

---

## 5. Параметр state — CSRF protection

### Проблема: CSRF-атака на OAuth

**CSRF (Cross-Site Request Forgery)** — це атака, при якій зловмисник змушує браузер жертви виконати небажаний запит. У контексті OAuth це виглядає так:

#### Сценарій атаки без параметра state

1. Зловмисник починає OAuth flow зі **своїм** акаунтом: логіниться у Authorization Server і отримує authorization code
2. Зловмисник **не використовує** цей код сам, а формує URL:
   ```
   https://securenotes.com/callback?code=ATTACKER_CODE
   ```
3. Зловмисник відправляє цей URL жертві (наприклад, через email або вставляє у тег `<img>` на форумі)
4. Браузер жертви переходить за URL — SecureNotes обмінює `ATTACKER_CODE` на токен
5. Результат: акаунт жертви у SecureNotes **прив'язаний до акаунту зловмисника** у Google

```
Зловмисник                                    Жертва
    │                                             │
    │  1. Починає OAuth flow                      │
    │  зі своїм акаунтом                          │
    │  → отримує code=ATTACKER_CODE               │
    │                                             │
    │  2. Формує шкідливий URL:                   │
    │  securenotes.com/callback?code=ATTACKER_CODE│
    │                                             │
    │  3. Надсилає URL жертві ─────────────────→  │
    │     (email, <img>, посилання)                │
    │                                             │
    │                                    4. Браузер жертви
    │                                       переходить за URL
    │                                             │
    │                                    5. SecureNotes обмінює
    │                                       ATTACKER_CODE на токен
    │                                             │
    │                                    6. Акаунт жертви
    │                                       прив'язаний до
    │                                       акаунту ЗЛОВМИСНИКА
```

Це серйозна вразливість: зловмисник зможе увійти в акаунт жертви у SecureNotes через свій Google-акаунт.

### Розв'язок: параметр state

**state** — це непередбачуване випадкове значення, яке Client генерує на початку flow і зберігає у сесії користувача.

#### Як це працює

```python
import secrets

# Крок 1: Client генерує state і зберігає у сесії
state = secrets.token_urlsafe(32)
session['oauth_state'] = state

# Крок 2: state включається у redirect на Authorization Server
redirect_url = (
    f"https://accounts.google.com/o/oauth2/v2/auth"
    f"?response_type=code"
    f"&client_id={CLIENT_ID}"
    f"&redirect_uri={REDIRECT_URI}"
    f"&scope=openid+profile+email"
    f"&state={state}"
)

# Крок 3: у callback Client перевіряє state
def callback():
    if request.args.get('state') != session.get('oauth_state'):
        abort(403, "State mismatch — possible CSRF attack")
    # Якщо state збігається — продовжуємо обмін коду на токен
```

#### Чому атака тепер не працює

1. Зловмисник формує URL: `securenotes.com/callback?code=ATTACKER_CODE&state=abc`
2. Браузер жертви переходить за URL
3. SecureNotes перевіряє: `state=abc` збігається з `session['oauth_state']`?
4. **Ні** — у сесії жертви зберігається **інший** state (або жоден), бо жертва не починала OAuth flow
5. Запит відхилено

### Вимоги до state

- Генерувати за допомогою **CSPRNG** (`secrets.token_urlsafe()`, не `random()`)
- Мінімум **128 біт ентропії** (32 символи URL-safe Base64)
- Зберігати у сесії (прив'язаний до конкретного браузера)
- **Одноразовий** — використати і видалити після перевірки
- Перевіряти **перед** обміном коду на токен

---

## 6. Валідація redirect_uri — exact matching

### Навіщо валідувати redirect_uri

`redirect_uri` — це URL, на який Authorization Server перенаправляє користувача після авторизації, разом з authorization code. Якщо зловмисник зможе підставити свій `redirect_uri`, він перехопить authorization code.

### Атака: Open Redirect

#### Сценарій

1. Client зареєстрував `redirect_uri`: `https://securenotes.com/callback`
2. Зловмисник знаходить open redirect на `securenotes.com`:
   ```
   https://securenotes.com/redirect?url=https://evil.com
   ```
3. Зловмисник формує OAuth-запит з:
   ```
   redirect_uri=https://securenotes.com/redirect?url=https://evil.com
   ```
4. Якщо Authorization Server валідує лише **початок** URL — перевірка пройде
5. Authorization Server перенаправляє на `securenotes.com/redirect?url=...&code=VALID_CODE`
6. `securenotes.com` перенаправляє на `evil.com` — **з кодом у URL**
7. Зловмисник перехоплює authorization code

```
Зловмисник формує запит:
  redirect_uri = https://securenotes.com/redirect?url=https://evil.com

Authorization Server:
  ✗ Перевіряє лише "починається з https://securenotes.com" → ОК
  → Redirect: securenotes.com/redirect?url=evil.com&code=VALID_CODE

securenotes.com/redirect:
  → Redirect: evil.com?code=VALID_CODE  ← КОД ПЕРЕХОПЛЕНО!
```

### Правильна валідація: Exact Match

Authorization Server **повинен** валідувати `redirect_uri` за принципом **exact string matching**:

```
Зареєстрований:  https://securenotes.com/callback
Запит:           https://securenotes.com/callback        → OK
Запит:           https://securenotes.com/callback?foo=1   → REJECTED
Запит:           https://securenotes.com/callback/        → REJECTED
Запит:           https://securenotes.com/redirect?url=... → REJECTED
```

### Правила (RFC 6749 + RFC 6819)

1. **Exact match** — redirect_uri у `/authorize` запиті повинен **точно** збігатись із зареєстрованим
2. **Без wildcard** — не дозволяти `*.securenotes.com` або `securenotes.com/*`
3. **Тільки HTTPS** — HTTP дозволений лише для `localhost` (розробка)
4. **Без фрагментів** — redirect_uri не повинен містити `#fragment`
5. **Порівняння і в /token** — redirect_uri у запиті на Token Endpoint повинен збігатись із тим, що був у `/authorize`

### Приклад валідації на Python

```python
REGISTERED_REDIRECT_URIS = [
    "https://securenotes.com/callback",
    "http://localhost:5000/callback",  # тільки для розробки
]

def validate_redirect_uri(redirect_uri):
    """Exact string match — жодних wildcard або prefix matching."""
    if redirect_uri not in REGISTERED_REDIRECT_URIS:
        raise ValueError(f"Invalid redirect_uri: {redirect_uri}")
    return redirect_uri
```

---

## 7. Confidential vs Public clients

### Визначення

OAuth 2.0 розрізняє два типи Client залежно від їхньої здатності зберігати секрети:

| | Confidential Client | Public Client |
|---|---|---|
| **Визначення** | Може безпечно зберігати client_secret | Не може зберігати client_secret |
| **Приклади** | Серверний веб-додаток (Python, Node.js) | SPA (React, Angular), мобільний додаток |
| **Чому** | Код виконується на сервері, секрет у змінних середовища | Код виконується на пристрої користувача, його можна декомпілювати |
| **client_secret** | Так, використовує у /token запиті | Ні, не має секрету |
| **Захист** | client_secret + redirect_uri validation | PKCE (Лекція 8) |

### Чому SPA та мобільні додатки не можуть зберігати секрети

```
Confidential Client (сервер):
┌─────────────────────────────┐
│  Server (Python/Node.js)    │
│                             │
│  client_secret = os.env[..] │ ← Зберігається на сервері,
│                             │   недоступний ззовні
│  POST /token                │
│    client_secret=s3cr3t     │ ← Передається через back-channel
└─────────────────────────────┘

Public Client (SPA):
┌─────────────────────────────┐
│  Browser (JavaScript)       │
│                             │
│  const secret = "s3cr3t"    │ ← Видно у DevTools → Sources
│                             │   або View Page Source
│  // Будь-хто може           │
│  // прочитати секрет        │
└─────────────────────────────┘

Public Client (мобільний):
┌─────────────────────────────┐
│  APK / IPA                  │
│                             │
│  "client_secret": "s3cr3t"  │ ← Декомпіляція APK:
│                             │   apktool d app.apk
│                             │   strings app.apk | grep secret
└─────────────────────────────┘
```

### Як Public Clients використовують Authorization Code Flow

Public Clients все одно використовують Authorization Code Flow, але **без client_secret**:

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https://spa.example.com/callback
&client_id=spa-client
```

Зверніть увагу: **немає client_secret**. Це менш безпечно, бо будь-хто, хто перехопив authorization code, може обміняти його на токен. Розв'язок — **PKCE (Proof Key for Code Exchange)**, який ми детально розглянемо у Лекції 9.

### SecureNotes — який тип?

Максим Витребенько реалізує SecureNotes як **серверний веб-додаток** на Python Flask. Це означає:
- SecureNotes — це **Confidential Client**
- Код виконується на сервері, `client_secret` зберігається у змінних середовища
- У `/token` запиті SecureNotes надсилає `client_secret`

---

## 8. Практика — Python Flask

### Спрощений приклад: mock Authorization Server + Client

Максим Витребенько реалізує Authorization Code Flow для SecureNotes. Для навчальних цілей ми створимо **два Flask-додатки**: mock Authorization Server та Client (SecureNotes).

### Файл 1: Mock Authorization Server (`auth_server.py`)

```python
"""
Mock Authorization Server для демонстрації Authorization Code Flow.
НЕ для production — лише для навчальних цілей.
"""
from flask import Flask, request, redirect, jsonify, render_template_string
import secrets
import time
import urllib.parse

app = Flask(__name__)

# Зареєстровані clients (у реальності — у базі даних)
CLIENTS = {
    "securenotes": {
        "client_secret": "s3cr3t-k3y-f0r-s3cur3n0t3s",
        "redirect_uris": ["http://localhost:5000/callback"],
        "name": "SecureNotes",
    }
}

# Видані authorization codes (у реальності — у Redis або БД)
auth_codes = {}

CONSENT_PAGE = """
<html><body>
<h1>Authorization Server</h1>
<p><b>{{ client_name }}</b> хоче отримати доступ до:</p>
<ul>{% for s in scopes %}<li>{{ s }}</li>{% endfor %}</ul>
<form method="POST" action="/authorize/consent">
  <input type="hidden" name="client_id" value="{{ client_id }}">
  <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
  <input type="hidden" name="scope" value="{{ scope }}">
  <input type="hidden" name="state" value="{{ state }}">
  <button type="submit" name="action" value="allow">Дозволити</button>
  <button type="submit" name="action" value="deny">Відхилити</button>
</form>
</body></html>
"""

@app.route("/authorize")
def authorize():
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope", "")
    state = request.args.get("state", "")
    response_type = request.args.get("response_type")

    # Валідація
    if response_type != "code":
        return jsonify(error="unsupported_response_type"), 400

    client = CLIENTS.get(client_id)
    if not client:
        return jsonify(error="invalid_client"), 400

    # Exact match для redirect_uri
    if redirect_uri not in client["redirect_uris"]:
        return jsonify(error="invalid_redirect_uri"), 400

    # Показуємо consent screen
    return render_template_string(
        CONSENT_PAGE,
        client_name=client["name"],
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        scopes=scope.split(),
        state=state,
    )

@app.route("/authorize/consent", methods=["POST"])
def consent():
    if request.form.get("action") != "allow":
        redirect_uri = request.form["redirect_uri"]
        state = request.form.get("state", "")
        return redirect(f"{redirect_uri}?error=access_denied&state={state}")

    # Генеруємо authorization code
    code = secrets.token_urlsafe(32)
    auth_codes[code] = {
        "client_id": request.form["client_id"],
        "redirect_uri": request.form["redirect_uri"],
        "scope": request.form["scope"],
        "created_at": time.time(),
    }

    redirect_uri = request.form["redirect_uri"]
    state = request.form.get("state", "")
    params = urllib.parse.urlencode({"code": code, "state": state})
    return redirect(f"{redirect_uri}?{params}")

@app.route("/token", methods=["POST"])
def token():
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")

    # Перевірка grant_type
    if grant_type != "authorization_code":
        return jsonify(error="unsupported_grant_type"), 400

    # Автентифікація Client
    client = CLIENTS.get(client_id)
    if not client or client["client_secret"] != client_secret:
        return jsonify(error="invalid_client"), 401

    # Перевірка authorization code
    code_data = auth_codes.get(code)
    if not code_data:
        return jsonify(error="invalid_grant"), 400

    # Перевірка: код виданий цьому client
    if code_data["client_id"] != client_id:
        return jsonify(error="invalid_grant"), 400

    # Перевірка: redirect_uri збігається
    if code_data["redirect_uri"] != redirect_uri:
        return jsonify(error="invalid_grant"), 400

    # Перевірка: код не прострочений (10 хвилин)
    if time.time() - code_data["created_at"] > 600:
        del auth_codes[code]
        return jsonify(error="invalid_grant"), 400

    # Інвалідуємо код (одноразове використання)
    del auth_codes[code]

    # Генеруємо токени
    access_token = secrets.token_urlsafe(32)
    refresh_token = secrets.token_urlsafe(32)

    return jsonify(
        access_token=access_token,
        token_type="Bearer",
        expires_in=3600,
        refresh_token=refresh_token,
        scope=code_data["scope"],
    )

if __name__ == "__main__":
    app.run(port=8080, debug=True)
```

### Файл 2: Client — SecureNotes (`client.py`)

```python
"""
SecureNotes — Client, що реалізує Authorization Code Flow.
"""
from flask import Flask, redirect, request, session, jsonify
import secrets
import requests
import urllib.parse

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Конфігурація OAuth
AUTH_SERVER = "http://localhost:8080"
CLIENT_ID = "securenotes"
CLIENT_SECRET = "s3cr3t-k3y-f0r-s3cur3n0t3s"
REDIRECT_URI = "http://localhost:5000/callback"

@app.route("/")
def index():
    if "access_token" in session:
        return f"<h1>SecureNotes</h1><p>Ви увійшли! Token: {session['access_token'][:20]}...</p>"
    return '<h1>SecureNotes</h1><a href="/login">Увійти через OAuth</a>'

@app.route("/login")
def login():
    # Генеруємо state для CSRF protection
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state

    params = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile email",
        "state": state,
    })
    return redirect(f"{AUTH_SERVER}/authorize?{params}")

@app.route("/callback")
def callback():
    # Перевірка помилок від Authorization Server
    error = request.args.get("error")
    if error:
        return f"<h1>Помилка</h1><p>{error}</p>", 400

    # Перевірка state (CSRF protection)
    state = request.args.get("state")
    if state != session.pop("oauth_state", None):
        return "<h1>Помилка</h1><p>State mismatch — можлива CSRF-атака</p>", 403

    # Обмін authorization code на токен (back-channel)
    code = request.args.get("code")
    token_response = requests.post(
        f"{AUTH_SERVER}/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )

    if token_response.status_code != 200:
        return f"<h1>Помилка</h1><p>{token_response.json()}</p>", 400

    tokens = token_response.json()
    session["access_token"] = tokens["access_token"]
    return redirect("/")

if __name__ == "__main__":
    app.run(port=5000, debug=True)
```

### Запуск

```bash
# Термінал 1: Authorization Server
pip install flask
python auth_server.py
# → Running on http://localhost:8080

# Термінал 2: Client (SecureNotes)
pip install flask requests
python client.py
# → Running on http://localhost:5000

# Термінал 3: тестування
# Відкрийте http://localhost:5000 у браузері
# Натисніть "Увійти через OAuth"
# Дозвольте доступ на consent screen
# SecureNotes отримає access_token
```

### Що відбувається під капотом

```
Браузер                     SecureNotes (:5000)       Auth Server (:8080)
   │                              │                          │
   │  GET /login                  │                          │
   │─────────────────────────────→│                          │
   │                              │ Генерує state,           │
   │  302 → /authorize?           │ зберігає в session       │
   │    response_type=code&       │                          │
   │    client_id=securenotes&    │                          │
   │    state=xY7kLm9p            │                          │
   │←─────────────────────────────│                          │
   │                                                         │
   │  GET /authorize?...                                     │
   │────────────────────────────────────────────────────────→│
   │                                                         │
   │  Consent screen                                         │
   │←────────────────────────────────────────────────────────│
   │                                                         │
   │  POST /authorize/consent (action=allow)                 │
   │────────────────────────────────────────────────────────→│
   │                                                         │
   │  302 → /callback?code=abc&state=xY7kLm9p               │
   │←────────────────────────────────────────────────────────│
   │                                                         │
   │  GET /callback?code=abc&state=xY7kLm9p                  │
   │─────────────────────────────→│                          │
   │                              │  Перевіряє state         │
   │                              │                          │
   │                              │  POST /token             │
   │                              │  code=abc                │
   │                              │  client_secret=s3cr3t    │
   │                              │─────────────────────────→│
   │                              │                          │
   │                              │  {"access_token":"..."}  │
   │                              │←─────────────────────────│
   │                              │                          │
   │  302 → /                     │  Зберігає token у session│
   │←─────────────────────────────│                          │
```

---

## 9. Підсумки

### Що ми розглянули

- **Authorization Code Flow** — найбезпечніший grant type OAuth 2.0, де Access Token передається через back-channel
- **Authorization Endpoint** — front-channel запит з параметрами `response_type`, `client_id`, `redirect_uri`, `scope`, `state`
- **Token Endpoint** — back-channel обмін authorization code на access_token з автентифікацією Client
- **Параметр state** — захист від CSRF-атак, генерується через CSPRNG, перевіряється при callback
- **Валідація redirect_uri** — exact string matching для захисту від open redirect атак
- **Confidential vs Public clients** — серверні додатки мають client_secret, SPA та мобільні — ні

### Ключові висновки

1. Authorization Code Flow додає **проміжний крок** (authorization code), щоб Access Token ніколи не проходив через браузер
2. **state** — де-факто обов'язковий параметр, без нього OAuth вразливий до CSRF
3. **redirect_uri** повинен валідуватись через **exact match** — будь-яке послаблення створює вразливість
4. **Confidential Clients** автентифікуються через `client_secret`, **Public Clients** потребують PKCE
5. Authorization code — **одноразовий** і **короткоживучий** (зазвичай 10 хвилин)

### Що далі?

У наступній лекції ми розглянемо **JWT (JSON Web Token)** — Лекція 6: JWT: токени зсередини.

Ми щойно отримали `access_token` від Authorization Server. Але що саме він собою являє? Як він структурований? Як Resource Server перевіряє його без звернення до Authorization Server?

- **JWT (JSON Web Token)** — стандарт для передачі claims між сторонами у формі підписаного JSON-об'єкта
- **Структура: Header.Payload.Signature** — три частини, кожна закодована у Base64URL
- **Claims** — стандартні (`iss`, `sub`, `exp`, `aud`) та кастомні
- **Підпис** — HMAC (симетричний) vs RSA/ECDSA (асиметричний)
- **Валідація** — як Resource Server перевіряє токен без звернення до Authorization Server

JWT — це фундамент, на якому побудовані Access Token та ID Token у сучасних OAuth/OIDC системах.

---

## Література

1. Dick Hardt. *RFC 6749 — The OAuth 2.0 Authorization Framework.* — IETF: 2012
2. Torsten Lodderstedt, Mark McGloin, Phil Hunt. *RFC 6819 — OAuth 2.0 Threat Model and Security Considerations.* — IETF: 2013
3. Aaron Parecki. *OAuth 2.0 Simplified.* — Lulu.com: 2018
4. Justin Richer, Antonio Sanso. *OAuth 2 in Action.* — Manning: 2017
