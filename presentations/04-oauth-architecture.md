---
marp: true
theme: default
paginate: false
style: |
  section {
    font-family: 'Courier New', monospace;
    font-size: 28px;
    padding: 60px 80px;
    justify-content: flex-start;
  }
  h1 {
    color: #000;
    font-size: 42px;
    border-bottom: none;
    margin-bottom: 40px;
  }
  h2 {
    color: #000;
    font-size: 34px;
  }
  table {
    font-size: 24px;
    width: 100%;
  }
  th {
    background: none;
    border-bottom: 2px solid #000;
  }
  td, th {
    padding: 10px 16px;
  }
  code {
    font-size: 22px;
  }
  ul, ol {
    font-size: 28px;
    line-height: 1.6;
  }
  blockquote {
    border-left: 4px solid #999;
    color: #555;
  }
  section.title {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    text-align: center;
  }
  section.title h1 {
    font-size: 44px;
    margin-bottom: 20px;
  }
  section.title p {
    font-size: 24px;
    margin: 4px 0;
  }
  .columns {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 40px;
  }
---

<!-- _class: title -->

# Захист інформації: OAuth від фундаменту до впровадження

Лекція 4. OAuth 2.0 — архітектура протоколу

Львівський національний університет імені Івана Франка
Спеціальність 113 — Прикладна математика

2025

---

# План лекції

1. Чому OAuth існує — password anti-pattern
2. Чотири ролі OAuth 2.0
3. Реєстрація клієнта (Client Registration)
4. Scopes — гранулярний контроль доступу
5. Огляд типів грантів (Grant Types)
6. Redirect URIs — чому це важливо
7. Модель загроз делегування (STRIDE)

---

# Міст від попередніх лекцій

Лекції 1-4: **криптопримітиви**

- Хешування (SHA-256, bcrypt, Argon2) — цілісність
- Симетричне шифрування (AES-GCM) — конфіденційність
- Асиметрична криптографія (RSA, ECDSA) — підписи, обмін ключами

Лекція 4: **як зібрати це у протокол?**

Максим Витребенько проєктує архітектуру OAuth для **SecureNotes** — сервісу зашифрованих нотаток

---

# Що ми будуємо: SecureNotes

**SecureNotes** — сервіс зашифрованих нотаток Максима Витребенка

```
┌───────────────────────────────────────────────────┐
│                  SecureNotes                       │
│                                                   │
│  📝 Нотатки    🔐 Шифрування    👤 Профіль       │
│                                                   │
└────────┬──────────────┬───────────────┬───────────┘
         │              │               │
    Google Keep     PrintApp        Dropbox
    (імпорт)        (друк)         (експорт)
```

**Проблема:** як дати стороннім додаткам доступ до нотаток користувача, **не передаючи їм пароль**?

---

# Interactive Demo

**[Open Interactive OAuth Demo](04-oauth-interactive.html)**

Step-by-step animated walkthrough of the entire OAuth 2.0 protocol

---

# Password anti-pattern

Максим хоче дати **PrintApp** доступ до нотаток для друку

**Наївний підхід:** передати логін і пароль сторонньому додатку

```
┌──────────┐  username   ┌──────────┐
│  Максим  │─────────────│ PrintApp │
│          │  password   │  (друк)  │
└──────────┘             └────┬─────┘
                              │
                   Повний доступ до акаунту
                              │
                              ▼
                    ┌──────────────────┐
                    │  SecureNotes API │
                    │                  │
                    │  📝 нотатки      │
                    │  👤 профіль      │
                    │  🗑  видалення   │
                    └──────────────────┘
```

---

# Чому password anti-pattern — це погано

1. **Надмірний доступ** — PrintApp отримує повний доступ, хоча потрібне лише читання
2. **Неможливість відкликання** — щоб забрати доступ, треба змінити пароль для всіх
3. **Поширення секрету** — пароль у кожному сторонньому додатку
4. **Відсутність аудиту** — не відрізнити запити Максима від PrintApp
5. **Порушення Least Privilege** — додаток отримує більше прав, ніж потребує

> OAuth 2.0 (RFC 6749) вирішує саме цю проблему

---

# Чотири ролі OAuth 2.0

```
┌────────────────┐ 1. логін + consent  ┌──────────────────────┐
│ Resource Owner │────────────────────→│ Authorization Server │
│ (Максим)       │                     │ (SecureNotes Auth)   │
└───────┬────────┘                     └──┬──────────────┬────┘
        │                                 │              │
  2. запит доступу                3. auth code    5. валідація
        │                                 │         токена
        ▼                                 ▼              │
┌────────────────┐ 4. access token  ┌─────▼──────────────┴───┐
│ Client         │←─────────────────│                        │
│ (PrintApp)     │                  │ Resource Server        │
│                │─────────────────→│ (SecureNotes API)      │
└────────────────┘ 6. Bearer token  └────────────────────────┘
                      → дані
```

---

# Resource Owner (Власник ресурсів)

Сутність, яка може надати доступ до захищеного ресурсу. Зазвичай — кінцевий користувач

**У нашому сценарії:** Максим Витребенько (його нотатки)

- **Приймає рішення** — натискає "Дозволити" на consent screen
- **Не передає credentials** стороннім додаткам
- Може **відкликати** доступ у будь-який момент

---

# Client (Клієнт)

Додаток, який запитує доступ від імені Resource Owner

**Два типи за здатністю зберігати секрети:**

| Тип | Опис | Приклад |
|---|---|---|
| **Confidential** | Може зберігати `client_secret` | Backend-додаток |
| **Public** | Не може зберігати секрети | SPA, мобільний додаток |

**У нашому сценарії:** PrintApp — сервіс друку нотаток

> Різниця критична для вибору grant type та рівня безпеки

---

# Authorization Server

Автентифікує Resource Owner, отримує consent, видає токени

**Основні endpoint-и:**

| Endpoint | Призначення |
|---|---|
| `/authorize` | Автентифікація та consent |
| `/token` | Обмін code на access token |
| `/revoke` | Відкликання токенів |
| `/introspect` | Перевірка валідності токена |

**У нашому сценарії:** SecureNotes Authorization Server

---

# Resource Server

Зберігає захищені ресурси, приймає запити з access token

```bash
curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9..." \
     https://securenotes.example/api/notes
```

**Відповідає за:**
- Валідацію access token (підпис, термін дії, scope)
- Перевірку scope для запитуваної операції
- Повернення ресурсу або відмову

**У нашому сценарії:** SecureNotes API

> Authorization Server і Resource Server можуть бути одним або різними серверами

---

# Client Registration

Перш ніж Client зможе запитувати доступ, він **реєструється** в Authorization Server

```
Реєстрація PrintApp:
  Назва:          PrintApp
  Тип:            confidential
  Redirect URIs:  https://printapp.example/callback
  Scopes:         notes:read

Результат:
  client_id:      pa_7f3a2b1c9d4e
  client_secret:  sk_X9mK4pL7qR2sT5uW8vY1zA3bC...
```

---

# client_id vs client_secret

<div class="columns">
<div>

**client_id** (публічний)

- Унікальний ідентифікатор клієнта
- Може бути в URL, логах
- Показується на consent screen
- Є у всіх типів клієнтів

</div>
<div>

**client_secret** (секретний)

- Аналог пароля клієнта
- Тільки для **confidential** клієнтів
- Передається при обміні code на token
- Зберігати у secret manager
- Public клієнти замість нього використовують **PKCE**

</div>
</div>

---

# redirect_uri

URL, на який Authorization Server перенаправляє після авторизації

```
Крок 1: Client → Authorization Server
  /oauth/authorize
    ?response_type=code
    &client_id=pa_7f3a2b1c9d4e
    &redirect_uri=https://printapp.example/callback
    &scope=notes:read

Крок 2: Authorization Server → Client
  https://printapp.example/callback
    ?code=SplxlOBeZQQYbYS6WxSbIA
```

Зареєстрований redirect_uri **повинен точно збігатися** з redirect_uri у запиті

---

# Scopes — гранулярний контроль

**Scope** — механізм обмеження доступу (Principle of Least Privilege)

```
SecureNotes Scopes:
  notes:read      — читання нотаток
  notes:write     — створення та редагування
  notes:delete    — видалення
  profile:read    — читання профілю
  profile:write   — редагування профілю
  sharing:manage  — керування спільним доступом

PrintApp запитує: notes:read (мінімально для друку)
```

---

# Scopes в OAuth-потоці

1. **Запит** — Client вказує бажані scopes
2. **Consent** — Authorization Server показує їх користувачу
3. **Токен** — видані scopes записуються в access token
4. **Перевірка** — Resource Server перевіряє scope при кожному запиті

```python
def get_notes(request):
    token = validate_access_token(
        request.headers["Authorization"]
    )
    if "notes:read" not in token["scope"]:
        return {"error": "insufficient_scope"}, 403
    return get_user_notes(token["sub"])
```

---

# Grant Types — огляд

**Grant type** — метод, за яким Client отримує access token

| Grant Type | Для кого | Статус |
|---|---|---|
| **Authorization Code** | Серверні, SPA (+ PKCE) | Рекомендований |
| **Client Credentials** | Machine-to-machine | Активний |
| **Implicit** | SPA (legacy) | **Deprecated** |
| **ROPC** | First-party (legacy) | **Deprecated** |

---

# Authorization Code Grant

**Найбезпечніший** грант-тип

```
Resource Owner       Client            Auth Server
      |                 |                    |
      | 1. "Увійти"     |                    |
      |────────────────>|                    |
      |                 | 2. /authorize      |
      |                 |───────────────────>|
      |                 |                    |
      |<────────────────────── 3. Логін ─────|
      |                 |                    |
      |──────────────────── 4. Consent ─────>|
      |                 |                    |
      |                 |<──── 5. code ──────|
      |                 |                    |
      |                 |── 6. POST /token ─>|
      |                 |                    |
      |                 |<── 7. Token ───────|
      |                 |                    |
```

Code обмінюється **back-channel** (сервер-сервер)

---

# Client Credentials Grant

Для **machine-to-machine** комунікації (без Resource Owner)

```python
import requests

response = requests.post(
    "https://securenotes.example/oauth/token",
    data={
        "grant_type": "client_credentials",
        "client_id": "analytics_service",
        "client_secret": "sk_analytics_secret_key",
        "scope": "stats:read",
    }
)
access_token = response.json()["access_token"]
```

**Використання:** мікросервіси, cron jobs, backend-інтеграції

---

# Чому Implicit та ROPC deprecated

<div class="columns">
<div>

**Implicit (deprecated)**

- Token у URL fragment `#access_token=...`
- Потрапляє в browser history, логи
- Немає автентифікації клієнта
- Немає refresh token
- **Замінений на Auth Code + PKCE**

</div>
<div>

**ROPC (deprecated)**

- Client збирає username + password
- Повертає password anti-pattern
- Допустимий лише для first-party
- Навіть тоді краще Auth Code + PKCE

</div>
</div>

---

# Redirect URI — атака підміни

```
1. Зловмисник формує URL з підміненим redirect_uri:
   /oauth/authorize?redirect_uri=https://evil.example/steal

2. Жертва бачить легітимний consent screen SecureNotes

3. Жертва натискає "Дозволити"

4. Authorization Server перенаправляє на evil.example:
   https://evil.example/steal?code=SplxlOBeZQQYbYS6WxSbIA

5. Зловмисник обмінює code на access token
```

> Без валідації redirect_uri зловмисник перехоплює authorization code

---

# Redirect URI — exact matching

**Захист:** Authorization Server вимагає точного збігу

```
Зареєстрований:  https://printapp.example/callback

https://printapp.example/callback          OK
https://printapp.example/callback?foo=bar  FAIL
https://printapp.example/callback/         FAIL
https://evil.example/callback              FAIL
http://printapp.example/callback           FAIL
```

**Правила:**
- Exact match (жодних wildcards)
- Тільки HTTPS (виняток: `localhost` для розробки)
- Без URL fragments (`#`)

---

# STRIDE для OAuth — DFD

```
Resource Owner                   Authorization Server
  (Browser)                        /authorize, /token
      │                                   │
   (F1,F2) consent                     (F5) token
      │                               validation
      ▼                                   │
   Client          ──── (F4) ────→   Resource Server
  (PrintApp)       Bearer token      (SecureNotes API)
                   ←── (F6) ────
                   protected data
```

Кожен потік (F1-F6) — потенційний вектор атаки

---

# STRIDE: загрози OAuth

| STRIDE | Загроза | Контрзахід |
|---|---|---|
| **S** Spoofing | Фішинговий Client, підміна redirect_uri | Exact match URI, client_secret |
| **T** Tampering | Модифікація code або token | HTTPS, цифрові підписи (JWS) |
| **R** Repudiation | Заперечення consent | Логування, audit trail |
| **I** Info Disclosure | Токени в логах, URL, referrer | Back-channel, маскування |
| **D** DoS | Flood на /authorize, /token | Rate limiting per IP/client |
| **E** Elevation | Розширення scope, повторний code | Валідація scopes, одноразовий code |

---

# Пріоритети загроз

| Загроза | Ймовірність | Вплив | Пріоритет |
|---|---|---|---|
| Підміна redirect_uri | Висока | Критичний | **P0** |
| Модифікація access token | Середня | Критичний | **P0** |
| Токени у логах | Висока | Високий | **P1** |
| Повторне використання auth code | Середня | Високий | **P1** |
| Flood на /token | Середня | Середній | **P2** |
| Заперечення consent | Низька | Низький | **P3** |

---

# Підсумки

- **Password anti-pattern** — передача пароля третій стороні є фундаментальною помилкою
- **4 ролі OAuth** — Resource Owner, Client, Authorization Server, Resource Server
- **Client Registration** — client_id, client_secret, redirect_uri
- **Scopes** — Principle of Least Privilege у дії
- **Grant Types** — Authorization Code (рекомендований) та Client Credentials (M2M)
- **Redirect URI exact matching** — критичний механізм безпеки
- **STRIDE** — систематичний аналіз загроз OAuth-архітектури

---

# Що далі?

**Лекція 5: Authorization Code Flow у деталях**

- **Authorization Code Flow** — кожен крок з HTTP-запитами та відповідями
- **PKCE** (Proof Key for Code Exchange) — безпечний Auth Code для SPA та мобільних додатків
- **State parameter** — захист від CSRF атак
- **Access Token та Refresh Token** — структура, термін дії, ротація

Максим Витребенько інтегрує PrintApp із SecureNotes за допомогою Authorization Code + PKCE

---

<!-- _class: title -->

# Дякую за увагу!

Питання?
