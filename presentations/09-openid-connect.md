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

Лекція 9. OpenID Connect

Львівський національний університет імені Івана Франка
Спеціальність 113 — Прикладна математика

2025

---

# План лекції

1. Authentication vs Authorization
2. OIDC як identity layer поверх OAuth
3. ID Token — структура та відмінність від access token
4. Standard Claims та Standard Scopes
5. UserInfo Endpoint
6. Discovery Document
7. Nonce — захист від replay attacks
8. Session Management
9. Практика — login via Google OIDC

---

# Нагадування: OAuth 2.0

У лекції 9 ми розглянули PKCE — захист Authorization Code Flow для публічних клієнтів

OAuth 2.0 видає **access token** — він дозволяє клієнту діяти від імені користувача

Але access token відповідає на питання:

> **Що ти можеш робити?** (авторизація)

А хто відповідає на питання:

> **Хто ти?** (автентифікація)

---

# Authentication vs Authorization

<div class="columns">
<div>

**Authorization (OAuth 2.0)**

- Що ти можеш робити?
- Доступ до ресурсів
- Access Token
- Читати пошту, файли
- Не знає, хто користувач

</div>
<div>

**Authentication (OIDC)**

- Хто ти?
- Ідентичність користувача
- ID Token
- Ім'я, email, фото
- Підтверджує особу

</div>
</div>

---

# Задача Максима

Максим додає «Увійти через Google» до SecureNotes за допомогою OpenID Connect

Після OAuth 2.0 + PKCE він отримує access token. Але на сторінці потрібно показати **ім'я, email, аватарку**

```
OAuth 2.0:
Користувач → Auth Server → access_token → "Можеш читати ресурси"
                                           Але ХТО ти? — невідомо

OIDC:
Користувач → Auth Server → access_token + id_token
                                  │           │
                                  │           └── "Ти — Максим"
                                  └── "Можеш читати ресурси"
```

---

# Що таке OpenID Connect

**OpenID Connect (OIDC)** — identity layer поверх OAuth 2.0

- **Не замінює** OAuth — **доповнює** його
- OAuth = фреймворк авторизації
- OIDC = стандартизований механізм автентифікації

```
┌────────────────────────────────────────┐
│         OpenID Connect                  │
│  ┌──────────────────────────────────┐  │
│  │  Identity Layer (автентифікація) │  │
│  │  ID Token, UserInfo, Claims      │  │
│  └──────────────────────────────────┘  │
│  ┌──────────────────────────────────┐  │
│  │  OAuth 2.0 (авторизація)         │  │
│  │  Auth Code Flow, Access Token    │  │
│  └──────────────────────────────────┘  │
└────────────────────────────────────────┘
```

---

# Чому окремий стандарт

До OIDC кожен провайдер реалізовував автентифікацію по-своєму

OIDC стандартизував:

- **Формат ідентичності** — ID Token у форматі JWT
- **Атрибути** — стандартні claims (sub, name, email, picture)
- **Scopes** — openid, profile, email, address, phone
- **Endpoint для профілю** — UserInfo Endpoint
- **Автоконфігурацію** — Discovery Document

---

# Терміни OIDC

| OAuth 2.0 | OpenID Connect |
|---|---|
| Authorization Server | **OpenID Provider (OP)** |
| Client | **Relying Party (RP)** |
| Resource Owner | **End-User** |

- Google, Microsoft, Apple — **OpenID Providers**
- SecureNotes Максима — **Relying Party** (покладається на OP для перевірки ідентичності)

---

# ID Token

**ID Token** — JWT з інформацією про автентифікацію користувача

Видається разом з access token, коли scope містить `openid`

```json
{
  "iss": "https://accounts.google.com",
  "sub": "110169484474386276334",
  "aud": "123456789.apps.googleusercontent.com",
  "exp": 1720000000,
  "iat": 1720000000,
  "nonce": "abc123",
  "name": "Максим Витребенько",
  "email": "maksym@example.com",
  "email_verified": true,
  "picture": "https://lh3.googleusercontent.com/a/photo.jpg"
}
```

---

# Обов'язкові claims у ID Token

| Claim | Опис |
|---|---|
| `iss` | URL провайдера (issuer) |
| `sub` | Унікальний ідентифікатор користувача |
| `aud` | Client ID додатку |
| `exp` | Час закінчення дії (Unix timestamp) |
| `iat` | Час видачі (Unix timestamp) |

Клієнт **обов'язково** перевіряє: підпис, `iss`, `aud`, `exp`, `nonce`

---

# Access Token vs ID Token

| | Access Token | ID Token |
|---|---|---|
| Призначення | Доступ до API | Ідентифікація |
| Аудиторія | Resource Server | Client (RP) |
| Хто читає | API сервер | Додаток |
| Формат | Opaque або JWT | **Завжди JWT** |
| Передається API | Так (Bearer) | **Ні** |
| Ідентичність | Не обов'язково | **Так** |

> ID Token **ніколи** не передається як Bearer token до API

---

# Standard Claims

| Claim | Опис |
|---|---|
| `sub` | Унікальний ідентифікатор (головний!) |
| `name` | Повне ім'я |
| `given_name` | Ім'я |
| `family_name` | Прізвище |
| `email` | Email-адреса |
| `email_verified` | Чи підтверджений email |
| `picture` | URL аватара |
| `locale` | Мова та регіон (`uk-UA`) |
| `phone_number` | Телефон (E.164) |
| `address` | Поштова адреса (об'єкт) |

---

# Чому sub, а не email

Email — **поганий** ідентифікатор:

- Користувач може **змінити** email
- Різні провайдери можуть повернути **однаковий** email
- Email може бути **перевикористаний** після видалення акаунту

Правильний підхід — пара `(iss, sub)`:

```python
# НЕПРАВИЛЬНО:
user = db.find_user(email=claims["email"])

# ПРАВИЛЬНО:
user = db.find_user(
    provider=claims["iss"],
    provider_id=claims["sub"]
)
```

---

# Standard Scopes

| Scope | Claims | Обов'язковий? |
|---|---|---|
| `openid` | `sub` | **Так** |
| `profile` | `name`, `given_name`, `family_name`, `picture`, `locale`, ... | Ні |
| `email` | `email`, `email_verified` | Ні |
| `address` | `address` | Ні |
| `phone` | `phone_number`, `phone_number_verified` | Ні |

Без `openid` — це звичайний OAuth, а не OIDC

---

# Scopes у запиті

```
GET /authorize?
  response_type=code
  &client_id=123456789
  &redirect_uri=https://securenotes.example.com/callback
  &scope=openid profile email
  &state=xyz123
  &nonce=abc456
  &code_challenge=E9Melhoa2Ow...
  &code_challenge_method=S256
```

Максим запитує лише потрібне: `openid profile email`

Принцип мінімальних привілеїв — не запитуй `address` та `phone`, якщо не потрібні

---

# UserInfo Endpoint

ID Token може містити обмежений набір claims. UserInfo Endpoint повертає **повний профіль**

```
GET /userinfo HTTP/1.1
Host: accounts.google.com
Authorization: Bearer ya29.a0AfH6SM...
```

```json
{
  "sub": "110169484474386276334",
  "name": "Максим Витребенько",
  "given_name": "Максим",
  "family_name": "Витребенько",
  "picture": "https://lh3.googleusercontent.com/a/photo.jpg",
  "email": "maksym@example.com",
  "email_verified": true,
  "locale": "uk"
}
```

---

# ID Token vs UserInfo

| Сценарій | Використовувати |
|---|---|
| Встановити ідентичність при логіні | **ID Token** |
| Показати актуальний профіль | **UserInfo** |
| Зберегти provider_id у базі | `sub` з **ID Token** |
| Оновити аватарку/ім'я | **UserInfo** |

- ID Token — одноразовий, видається при автентифікації
- UserInfo — актуальні дані, запитуються з access token

---

# Discovery Document

Кожен OIDC-провайдер публікує конфігурацію за стандартною адресою:

```
https://{issuer}/.well-known/openid-configuration
```

```bash
curl https://accounts.google.com/.well-known/openid-configuration
```

```json
{
  "issuer": "https://accounts.google.com",
  "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_endpoint": "https://oauth2.googleapis.com/token",
  "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
  "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
  "scopes_supported": ["openid", "profile", "email"]
}
```

---

# Discovery: автоматична конфігурація

Клієнтська бібліотека налаштовується автоматично, знаючи лише issuer:

```python
from authlib.integrations.requests_client import OAuth2Session

session = OAuth2Session(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=(
        "https://accounts.google.com/"
        ".well-known/openid-configuration"
    )
)
```

> Перше, що потрібно зробити при інтеграції — відкрити Discovery Document

---

# Nonce — захист від replay attacks

**Replay attack** — атакуючий перехоплює ID Token і повторно його використовує

```
1. Клієнт генерує nonce = "x7y8z9"
   зберігає у сесії

2. Authorization Request:
   GET /authorize?...&nonce=x7y8z9

3. ID Token містить:
   { "sub": "1101694...", "nonce": "x7y8z9" }

4. Клієнт перевіряє:
   token.nonce == session.nonce?
   ЗБІГАЄТЬСЯ → OK
   НЕ ЗБІГАЄТЬСЯ → replay attack!
```

---

# Nonce vs State

| Параметр | Захищає від | Перевіряється |
|---|---|---|
| `state` | CSRF | При redirect |
| `nonce` | Replay | У ID Token |

Максим використовує **обидва**:

```python
state = secrets.token_urlsafe(32)   # проти CSRF
nonce = secrets.token_urlsafe(32)   # проти replay

auth_url = (
    f"{authorization_endpoint}"
    f"?response_type=code"
    f"&scope=openid profile email"
    f"&state={state}"
    f"&nonce={nonce}"
)
```

---

# Session Management

Після верифікації ID Token, RP створює **власну сесію**

```
┌──────────┐   ID Token    ┌──────────────┐  Session Cookie  ┌─────────┐
│  Google  │ ────────────→ │  SecureNotes │ ───────────────→ │ Browser │
│  (OP)    │               │  (RP)        │ ←─────────────── │         │
└──────────┘               └──────────────┘                  └─────────┘
                                  │
                            Зберігає сесію:
                            - user_id (sub)
                            - name, email
                            - session_expiry
```

- Не прив'язуйте сесію до ID Token
- ID Token не оновлюється
- Secure, httpOnly cookies для session ID

---

# Logout

**RP-Initiated Logout** — користувач натискає «Вийти» в SecureNotes:

```
GET /logout?
  id_token_hint=eyJhbGci...
  &post_logout_redirect_uri=https://securenotes.example.com
```

**Back-Channel Logout** — провайдер повідомляє всі RP:

```
┌──────────┐  POST /backchannel-logout  ┌──────────────┐
│  Google  │ ─────────────────────────→ │  SecureNotes │
│  (OP)    │                            └──────────────┘
│          │  POST /backchannel-logout  ┌──────────────┐
│          │ ─────────────────────────→ │  OtherApp    │
└──────────┘                            └──────────────┘
```

---

# Практика: повний OIDC flow

```python
@app.route("/login")
def login():
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()

    session["oauth_state"] = state
    session["oidc_nonce"] = nonce
    session["code_verifier"] = code_verifier

    auth_url = (
        f"{config['authorization_endpoint']}"
        f"?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope=openid profile email"
        f"&state={state}&nonce={nonce}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )
    return redirect(auth_url)
```

---

# Практика: callback

```python
@app.route("/callback")
def callback():
    # 1. Перевірка state (CSRF)
    if request.args["state"] != session.pop("oauth_state"):
        return "CSRF attack", 403

    # 2. Обмін code на токени
    tokens = requests.post(config["token_endpoint"], data={
        "grant_type": "authorization_code",
        "code": request.args["code"],
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code_verifier": session.pop("code_verifier"),
    }).json()

    # 3. Верифікація ID Token (підпис, iss, aud, exp)
    id_claims = jwt.decode(tokens["id_token"], ...)

    # 4. Перевірка nonce (replay)
    if id_claims["nonce"] != session.pop("oidc_nonce"):
        return "Replay attack", 403

    # 5. UserInfo → створення сесії
    userinfo = requests.get(config["userinfo_endpoint"],
        headers={"Authorization": f"Bearer {tokens['access_token']}"}).json()
    session["user"] = userinfo
```

---

# Повний flow: крок за кроком

```
 1. Натиснути "Увійти через Google"
         │
 2. Redirect на Google з scope=openid, state, nonce, PKCE
         │
 3. Користувач вводить логін/пароль
         │
 4. Google redirect на /callback з code + state
         │
 5. Перевірка state (CSRF)
         │
 6. Обмін code + code_verifier → access_token + id_token
         │
 7. Верифікація id_token: підпис, iss, aud, exp, nonce
         │
 8. Запит UserInfo з access_token
         │
 9. Створення локальної сесії
         │
10. Відображення профілю
```

---

# Підсумки

- **OAuth 2.0** = авторизація (що можна робити)
- **OIDC** = автентифікація (хто ти) поверх OAuth
- **ID Token** — JWT для клієнта, **не для API**
- **sub** — головний ідентифікатор, не email
- **Standard Scopes** — `openid` обов'язковий
- **UserInfo** — актуальний профіль через access token
- **Discovery Document** — автоконфігурація провайдера
- **Nonce** — захист від replay, **state** — від CSRF
- Завжди перевіряйте: підпис, `iss`, `aud`, `exp`, `nonce`

---

# Що далі?

**Лекція 10: Атаки на OAuth та захист**

- **Redirect URI manipulation** — підміна redirect_uri
- **Token leakage** — витік через Referer, history, logs
- **CSRF та token injection** — обхід state та nonce
- **Authorization Code Injection** — підміна коду
- **Mix-Up Attack** — атака при декількох провайдерах

Максим має логін через Google — але наскільки це безпечно?

---

<!-- _class: title -->

# Дякую за увагу!

Питання?
