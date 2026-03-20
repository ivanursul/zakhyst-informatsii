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

Лекція 5. Authorization Code Flow

Львівський національний університет імені Івана Франка
Спеціальність 113 — Прикладна математика

2025

---

# План лекції

1. Чому Authorization Code Flow
2. Крок за кроком — повний flow
3. Authorization Endpoint — параметри запиту
4. Token Endpoint — обмін коду на токен
5. Параметр state — CSRF protection
6. Валідація redirect_uri
7. Confidential vs Public clients

---

# Чому Authorization Code Flow?

У лекції 5 ми розглянули **архітектуру OAuth 2.0** та grant types

Тепер розбираємо **найбезпечніший** grant type:

| Grant Type | Використання |
|---|---|
| **Authorization Code** | Серверні веб-додатки (рекомендований) |
| Implicit | SPA (deprecated у OAuth 2.1) |
| ROPC | Legacy (deprecated) |
| Client Credentials | Machine-to-machine |

---

# Чому саме Authorization Code?

**4 ключові переваги:**

1. **Access Token не у браузері** — передається через back-channel (сервер-сервер)
2. **Client автентифікується** — Authorization Server перевіряє client_secret
3. **Code короткоживучий** — дійсний кілька хвилин, одноразовий
4. **Refresh tokens** — оновлення без повторної авторизації

> Implicit Flow передає токен прямо в URL — видно в browser history, логах, Referer header

---

# Сценарій

Максим Витребенько реалізує **Authorization Code Flow** для **SecureNotes** — веб-сервісу для нотаток

Користувачі SecureNotes логіняться через Google

**Учасники:**
- **Resource Owner** — користувач
- **Client** — SecureNotes (Python Flask)
- **Authorization Server** — Google
- **Resource Server** — Google APIs

---

# Повний flow: огляд

```
Browser             SecureNotes           Auth Server
  │ 1. "Увійти"          │                      │
  │─────────────────────→│                      │
  │ 2. 302 /authorize    │                      │
  │←─────────────────────│                      │
  │ 3. GET /authorize?response_type=code&...    │
  │────────────────────────────────────────────→│
  │ 4. Consent screen    │                      │
  │←────────────────────────────────────────────│
  │ 5. "Дозволити"       │                      │
  │────────────────────────────────────────────→│
  │ 6. 302 /callback?code=...&state=...         │
  │←────────────────────────────────────────────│
  │ 7. GET /callback     │                      │
  │─────────────────────→│ 8. POST /token       │
  │                      │─────────────────────→│
  │                      │ 9. access_token      │
  │                      │←─────────────────────│
  │ 10. Logged in        │                      │
  │←─────────────────────│                      │
```

---

# Front-channel vs Back-channel

<div class="columns">
<div>

**Front-channel** (через браузер)

- Кроки 2-5: redirect
- Передається лише **authorization code**
- Видно користувачу
- Потенційно перехоплюється

</div>
<div>

**Back-channel** (сервер-сервер)

- Крок 6: POST /token
- Передається **client_secret**
- Повертається **access_token**
- Недоступний для браузера

</div>
</div>

> Access Token **ніколи** не проходить через браузер

---

# Authorization Endpoint

```http
GET /authorize?response_type=code
              &client_id=securenotes
              &redirect_uri=https://securenotes.com/callback
              &scope=openid profile email
              &state=xY7kLm9p
Host: accounts.google.com
```

Front-channel запит: проходить через браузер користувача

---

# Параметри /authorize

| Параметр | Обов'язковий | Опис |
|---|---|---|
| `response_type` | так | `code` для Authorization Code Flow |
| `client_id` | так | Ідентифікатор Client (публічний) |
| `redirect_uri` | рекомендований | URL для повернення з кодом |
| `scope` | рекомендований | Список дозволів через пробіл |
| `state` | **де-факто обов'язковий** | CSRF protection (CSPRNG) |

---

# Scope — контроль доступу

Scope визначає, **що саме** Client може робити:

| Scope | Що дає |
|---|---|
| `openid` | ID Token (ідентифікація) |
| `profile` | Ім'я, аватар |
| `email` | Email-адреса |
| `photos.read` | Читання фото |

Authorization Server показує **consent screen** з переліком scopes

Користувач вирішує, які дозволити

---

# Token Endpoint

```http
POST /token HTTP/1.1
Host: oauth2.googleapis.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https://securenotes.com/callback
&client_id=securenotes
&client_secret=s3cr3t
```

**Back-channel** запит: сервер SecureNotes → сервер Google

---

# Параметри /token

| Параметр | Обов'язковий | Опис |
|---|---|---|
| `grant_type` | так | `authorization_code` |
| `code` | так | Код з Authorization Endpoint |
| `redirect_uri` | так* | Exact match з /authorize |
| `client_id` | так | Ідентифікатор Client |
| `client_secret` | так** | Секрет (confidential clients) |

\* якщо був у /authorize запиті
\** для confidential clients

---

# Відповідь Token Endpoint

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
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
| `expires_in` | Час життя (секунди) |
| `refresh_token` | Для оновлення access_token |

---

# Що перевіряє Authorization Server

```
1. Чи валідний authorization code?
   └── Існує, не використаний, не прострочений
2. Чи збігається client_id?
   └── Код виданий саме цьому Client
3. Чи валідний client_secret?
   └── Client автентифікований
4. Чи збігається redirect_uri?
   └── Exact match з /authorize запиту
5. Все ОК → access_token + refresh_token
   └── Код інвалідується (одноразовий!)
```

---

# Параметр state — навіщо?

**Проблема:** CSRF-атака на OAuth

1. Зловмисник починає OAuth зі **своїм** акаунтом, отримує code
2. Формує URL: `securenotes.com/callback?code=ATTACKER_CODE`
3. Надсилає жертві (email, `<img>`, посилання)
4. Браузер жертви переходить за URL
5. SecureNotes обмінює ATTACKER_CODE на токен

**Результат:** акаунт жертви прив'язаний до акаунту зловмисника

---

# CSRF-атака без state

```
Зловмисник                          Жертва
    │                                   │
    │  1. OAuth flow → code=ATTACKER    │
    │                                   │
    │  2. Надсилає посилання:           │
    │  securenotes.com/callback?code=…  │
    │  ────────────────────────────→    │
    │                                   │
    │                 3. Браузер переходить за URL
    │                 4. SecureNotes обмінює код
    │                 5. Акаунт жертви = ЗЛОВМИСНИКА
```

---

# State — розв'язок

```python
import secrets

# 1. Генеруємо state, зберігаємо у сесії
state = secrets.token_urlsafe(32)
session['oauth_state'] = state

# 2. Включаємо state у redirect
redirect_url = f"/authorize?...&state={state}"

# 3. У callback перевіряємо state
def callback():
    if request.args['state'] != session.pop('oauth_state'):
        abort(403, "State mismatch!")
    # Продовжуємо обмін коду на токен
```

Атака не працює: у сесії жертви **інший** state (або жоден)

---

# Вимоги до state

- **CSPRNG** — `secrets.token_urlsafe()`, не `random()`
- **128+ біт ентропії** — мінімум 32 символи URL-safe Base64
- **Прив'язаний до сесії** — конкретний браузер
- **Одноразовий** — використати і видалити
- **Перевіряти перед** обміном коду на токен

---

# Валідація redirect_uri

**Загроза:** Open Redirect

1. Зловмисник знаходить open redirect: `securenotes.com/redirect?url=evil.com`
2. Підставляє як redirect_uri в OAuth-запит
3. Authorization Server перевіряє лише початок URL
4. Code потрапляє до зловмисника через redirect

```
redirect_uri = securenotes.com/redirect?url=evil.com

Auth Server (prefix match): "починається з securenotes.com" → OK
→ Redirect на evil.com?code=VALID_CODE  ← ПЕРЕХОПЛЕНО!
```

---

# Exact Match — правильна валідація

```
Зареєстрований: https://securenotes.com/callback

https://securenotes.com/callback          → OK
https://securenotes.com/callback?foo=1    → REJECTED
https://securenotes.com/callback/         → REJECTED
https://securenotes.com/redirect?url=...  → REJECTED
```

**Правила:**
- **Exact string match** — жодних wildcard або prefix
- **Тільки HTTPS** (HTTP лише для localhost)
- **Без фрагментів** (`#fragment`)
- **Збіг і в /token** — redirect_uri перевіряється двічі

---

# Confidential vs Public Clients

<div class="columns">
<div>

**Confidential Client**

- Серверний додаток (Python, Node.js)
- **Може** зберігати client_secret
- Секрет у змінних середовища
- Автентифікується у /token

</div>
<div>

**Public Client**

- SPA (React), мобільний додаток
- **Не може** зберігати client_secret
- Код доступний користувачу
- Потребує **PKCE** (Лекція 8)

</div>
</div>

---

# Чому Public Client не може зберігати секрет

```
Confidential (сервер):
┌──────────────────────────┐
│  client_secret = os.env  │ ← На сервері,
│                          │   недоступний ззовні
└──────────────────────────┘

Public (SPA):
┌──────────────────────────┐
│  const secret = "s3cr3t" │ ← DevTools → Sources
│                          │   View Page Source
└──────────────────────────┘

Public (мобільний):
┌──────────────────────────┐
│  "secret": "s3cr3t"      │ ← apktool d app.apk
│                          │   strings app | grep secret
└──────────────────────────┘
```

---

# Підсумки

- **Authorization Code Flow** — найбезпечніший grant type: токен через back-channel
- **Authorization Endpoint** — front-channel: `response_type=code`, `client_id`, `scope`, `state`
- **Token Endpoint** — back-channel: `code` + `client_secret` → `access_token`
- **state** — захист від CSRF (CSPRNG, одноразовий, перевірити перед обміном)
- **redirect_uri** — exact string match, ніяких wildcard
- **Confidential Clients** мають `client_secret`, **Public** — потребують PKCE

---

# Що далі?

**Лекція 6: JWT — токени зсередини**

Ми отримали `access_token`. Але що він собою являє?

- **JWT (JSON Web Token)** — підписаний JSON-об'єкт
- **Header.Payload.Signature** — три частини в Base64URL
- **Claims** — `iss`, `sub`, `exp`, `aud` та кастомні
- **Підпис** — HMAC (симетричний) vs RSA/ECDSA (асиметричний)
- **Валідація** — перевірка токена без звернення до Authorization Server

---

<!-- _class: title -->

# Дякую за увагу!

Питання?
