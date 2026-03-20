# Лекція 9. OpenID Connect

## Зміст

1. [Authentication vs Authorization — міст з лекції 9](#1-authentication-vs-authorization--міст-з-лекції-9)
2. [OIDC як identity layer поверх OAuth](#2-oidc-як-identity-layer-поверх-oauth)
3. [ID Token — що це і чим відрізняється від access token](#3-id-token--що-це-і-чим-відрізняється-від-access-token)
4. [Standard Claims](#4-standard-claims)
5. [Standard Scopes](#5-standard-scopes)
6. [UserInfo Endpoint](#6-userinfo-endpoint)
7. [Discovery Document](#7-discovery-document)
8. [Nonce — захист від replay attacks](#8-nonce--захист-від-replay-attacks)
9. [Session Management](#9-session-management)
10. [Практика — login via Google OIDC](#10-практика--login-via-google-oidc)
11. [Підсумки](#11-підсумки)

---

## 1. Authentication vs Authorization — міст з лекції 9

### Де ми зупинились

У лекції 9 ми розглянули **PKCE** (Proof Key for Code Exchange) — механізм захисту Authorization Code Flow для публічних клієнтів. Завдяки PKCE навіть SPA або мобільний додаток може безпечно отримати access token. Але давайте зупинимось і поставимо просте питання: **access token дає доступ до ресурсів — але хто саме його отримав?**

### Проблема

OAuth 2.0 — це протокол **авторизації** (authorization), а не **автентифікації** (authentication). Ця різниця фундаментальна:

- **Авторизація** (Authorization) — відповідає на питання «Що ти можеш робити?». OAuth 2.0 видає access token, який дозволяє клієнту діяти від імені користувача — читати пошту, отримувати список файлів. Але сам access token не містить інформації про те, **хто** цей користувач
- **Автентифікація** (Authentication) — відповідає на питання «Хто ти?». Встановлення ідентичності користувача — його ім'я, email, унікальний ідентифікатор

### Сценарій Максима

Максим Витребенько побудував SecureNotes — додаток для зберігання нотаток. У лекції 9 він додав OAuth 2.0 з PKCE, щоб користувачі могли авторизуватись через Google. Тепер Максим отримує access token і може звертатись до Google API від імені користувача. Але перед ним стоїть нова задача: на сторінці SecureNotes має відображатись **ім'я користувача, аватарка і email**. Як їх отримати?

```
OAuth 2.0:
Користувач → Authorization Server → access_token → Resource Server
                                          │
                                          └── "Можеш читати ресурси"
                                               Але ХТО ти? — невідомо

OIDC:
Користувач → Authorization Server → access_token + id_token → Resource Server
                                          │            │
                                          │            └── "Ти — Максим Витребенько,
                                          │                 maksym@example.com"
                                          └── "Можеш читати ресурси"
```

Перший рефлекс — використати access token, щоб зробити запит до якогось API Google і дізнатися ім'я користувача. Деякі сервіси так і роблять — але це **неправильний підхід**. Access token не гарантує, що він був виданий саме тому користувачу, який зараз перед нами. Потрібен стандартний, безпечний спосіб отримати інформацію про ідентичність.

---

## 2. OIDC як identity layer поверх OAuth

### Що таке OpenID Connect

**OpenID Connect (OIDC)** — це identity layer (рівень ідентичності), побудований **поверх** OAuth 2.0. OIDC не замінює OAuth — він його доповнює. OAuth залишається фреймворком авторизації, а OIDC додає стандартизований механізм автентифікації.

Аналогія: OAuth 2.0 — це пропуск до будівлі (authorization). OIDC — це паспорт, який підтверджує вашу особу (authentication). Ви можете мати пропуск, але без паспорта охоронець не знає, хто ви.

### Чому окремий стандарт

До OIDC кожен провайдер реалізовував автентифікацію по-своєму. Facebook мав свій спосіб повернути профіль, Google — інший, Twitter — третій. Розробники мусили писати окремий код для кожного провайдера. OIDC стандартизував:

- **Формат ідентичності** — ID token у форматі JWT
- **Набір атрибутів** — стандартні claims (sub, name, email, picture)
- **Набір scopes** — openid, profile, email, address, phone
- **Endpoint для профілю** — UserInfo Endpoint
- **Автоконфігурацію** — Discovery Document (.well-known/openid-configuration)

### Архітектура

```
┌──────────────────────────────────────────────────────────┐
│                    OpenID Connect                         │
│  ┌──────────────────────────────────────────────────┐    │
│  │     Identity Layer (автентифікація)               │    │
│  │     ID Token, UserInfo, Standard Claims           │    │
│  └──────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────┐    │
│  │     OAuth 2.0 (авторизація)                       │    │
│  │     Authorization Code Flow, Access Token, PKCE   │    │
│  └──────────────────────────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────┐    │
│  │     HTTP / TLS (транспорт)                        │    │
│  └──────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

OIDC перевикористовує всю інфраструктуру OAuth 2.0 — endpoints, flows, токени — і додає поверх стандартизований ID Token та механізми роботи з ідентичністю.

### Терміни OIDC

У контексті OIDC ролі OAuth отримують нові назви:

| OAuth 2.0 | OpenID Connect |
|---|---|
| Authorization Server | OpenID Provider (OP) |
| Client | Relying Party (RP) |
| Resource Owner | End-User |

Google, Microsoft, Apple — це **OpenID Providers**. Додаток Максима SecureNotes — це **Relying Party**, тому що він «покладається» (relies) на OpenID Provider для перевірки ідентичності.

---

## 3. ID Token — що це і чим відрізняється від access token

### Визначення

**ID Token** — це JWT (JSON Web Token), який містить інформацію про автентифікацію користувача. ID Token видається Authorization Server (OpenID Provider) разом з access token, коли клієнт запитує scope `openid`.

### Структура

ID Token — це звичайний JWT, який складається з трьох частин: Header, Payload, Signature.

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.
eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC
JzdWIiOiIxMTAxNjk0ODQ0NzQzODYyNzYzMzQiLCJhdWQiOiI
xMjM0NTY3ODkuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20i
LCJleHAiOjE3MjAwMDAwMDAsImlhdCI6MTcyMDAwMDAwMCwib
m9uY2UiOiJhYmMxMjMifQ.
<підпис>
```

Decoded Payload:

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

### Обов'язкові claims у ID Token

| Claim | Опис |
|---|---|
| `iss` (Issuer) | URL провайдера, який видав токен. Наприклад, `https://accounts.google.com` |
| `sub` (Subject) | Унікальний ідентифікатор користувача у провайдера. Стабільний — не змінюється, навіть якщо користувач змінить email |
| `aud` (Audience) | Client ID додатку, для якого токен виданий. Клієнт **обов'язково** перевіряє, що `aud` відповідає його client_id |
| `exp` (Expiration) | Час закінчення дії токена (Unix timestamp) |
| `iat` (Issued At) | Час видачі токена (Unix timestamp) |

### Відмінність від access token

Ця різниця — ключ до розуміння OIDC:

| | Access Token | ID Token |
|---|---|---|
| **Призначення** | Доступ до ресурсів (API) | Ідентифікація користувача |
| **Аудиторія** | Resource Server (API) | Client (Relying Party) |
| **Хто читає** | API сервер | Додаток клієнта |
| **Формат** | Може бути opaque або JWT | **Завжди** JWT |
| **Передається API** | Так, у заголовку `Authorization` | **Ні** — тільки для клієнта |
| **Містить ідентичність** | Не обов'язково | **Так** — sub, name, email |
| **Час життя** | Коротший, оновлюється через refresh | Зазвичай короткий, не оновлюється |

**Критично важливо:** ID Token **ніколи** не передається як Bearer token до API. Він призначений виключно для клієнтського додатку, щоб встановити, хто саме увійшов.

### Верифікація ID Token

Клієнт (Relying Party) **обов'язково** верифікує ID Token перед використанням:

1. Перевірити **підпис** — використовуючи публічний ключ провайдера (з JWKS endpoint)
2. Перевірити `iss` — має збігатись з URL очікуваного провайдера
3. Перевірити `aud` — має містити client_id додатку
4. Перевірити `exp` — токен не має бути простроченим
5. Перевірити `nonce` — має збігатись зі значенням, надісланим у запиті (захист від replay)

```python
import jwt
import requests

# Отримання публічних ключів Google
jwks_url = "https://www.googleapis.com/oauth2/v3/certs"
jwks = requests.get(jwks_url).json()

# Верифікація ID Token
decoded = jwt.decode(
    id_token,
    key=jwks,                # публічні ключі
    algorithms=["RS256"],
    audience=CLIENT_ID,      # перевірка aud
    issuer="https://accounts.google.com"  # перевірка iss
)
```

---

## 4. Standard Claims

### Що таке claims

**Claims** — це пари «ключ-значення» у payload JWT, які описують атрибути (attributes) користувача. OIDC стандартизує набір claims, щоб кожен провайдер повертав інформацію в однаковому форматі.

### Основні стандартні claims

| Claim | Тип | Опис |
|---|---|---|
| `sub` | string | Унікальний ідентифікатор користувача. **Головний ідентифікатор** — не email, не username |
| `name` | string | Повне ім'я користувача |
| `given_name` | string | Ім'я (first name) |
| `family_name` | string | Прізвище (last name) |
| `email` | string | Email-адреса |
| `email_verified` | boolean | Чи підтверджений email |
| `picture` | string | URL фото/аватара |
| `locale` | string | Мова та регіон, наприклад `uk-UA` |
| `updated_at` | number | Час останнього оновлення профілю (Unix timestamp) |
| `phone_number` | string | Номер телефону у форматі E.164, наприклад `+380501234567` |
| `phone_number_verified` | boolean | Чи підтверджений номер телефону |
| `address` | object | Об'єкт з полями: `street_address`, `locality`, `region`, `postal_code`, `country` |

### Чому sub, а не email

Максим може подумати: «Я використаю email як унікальний ідентифікатор користувача в SecureNotes». Це помилка:

- Користувач може **змінити email** у Google — але `sub` залишиться тим самим
- Різні провайдери можуть повернути **однаковий email** для різних людей
- Email може бути **перевикористаний** після видалення акаунту

Правильний підхід — використовувати пару `(iss, sub)` як первинний ключ:

```python
# НЕПРАВИЛЬНО — email може змінитись:
user = db.find_user(email=claims["email"])

# ПРАВИЛЬНО — sub стабільний, iss визначає провайдера:
user = db.find_user(
    provider=claims["iss"],
    provider_id=claims["sub"]
)
```

---

## 5. Standard Scopes

### Зв'язок scopes та claims

У OAuth 2.0 scopes визначають **обсяг доступу**. У OIDC scopes визначають, **які claims** будуть повернуті в ID Token та через UserInfo Endpoint. Клієнт вказує потрібні scopes у authorization request, а провайдер повертає відповідні claims.

### Стандартні scopes OIDC

| Scope | Claims | Опис |
|---|---|---|
| `openid` | `sub` | **Обов'язковий**. Без нього це не OIDC-запит, а звичайний OAuth |
| `profile` | `name`, `family_name`, `given_name`, `middle_name`, `nickname`, `preferred_username`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` | Базова інформація про профіль |
| `email` | `email`, `email_verified` | Email-адреса та статус верифікації |
| `address` | `address` | Поштова адреса (об'єкт) |
| `phone` | `phone_number`, `phone_number_verified` | Телефон та статус верифікації |

### Як це виглядає у запиті

```
GET /authorize?
  response_type=code
  &client_id=123456789
  &redirect_uri=https://securenotes.example.com/callback
  &scope=openid profile email       ← OIDC scopes
  &state=xyz123
  &nonce=abc456
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

Зверніть увагу: scope **обов'язково** містить `openid` — це маркер, який каже Authorization Server: «Це OIDC-запит, поверни ID Token».

### Мінімалізм scopes

Максим запитує лише ті scopes, які дійсно потрібні. SecureNotes потребує ім'я та email — тому scope = `openid profile email`. Немає потреби запитувати `address` чи `phone`, якщо додаток їх не використовує. Це принцип **мінімальних привілеїв** (principle of least privilege), який ми обговорювали в попередніх лекціях.

---

## 6. UserInfo Endpoint

### Навіщо потрібен, якщо є ID Token

ID Token може містити обмежений набір claims — не всі провайдери включають усі запитані claims у токен. Причини:

- **Розмір токена** — JWT передається у кожному redirect, і URL має обмеження довжини
- **Актуальність** — ID Token видається один раз при автентифікації. Якщо користувач змінив ім'я або фото — ID Token міститиме старі дані
- **Політика провайдера** — деякі провайдери свідомо повертають мінімум claims у ID Token

### Як працює UserInfo Endpoint

UserInfo Endpoint — це захищений REST API endpoint на стороні OpenID Provider. Клієнт звертається до нього з **access token** і отримує повний набір claims.

```
GET /userinfo HTTP/1.1
Host: accounts.google.com
Authorization: Bearer ya29.a0AfH6SM...
```

Відповідь:

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

### Приклад на Python

```python
import requests

userinfo_url = "https://openidconnect.googleapis.com/v1/userinfo"
headers = {"Authorization": f"Bearer {access_token}"}
response = requests.get(userinfo_url, headers=headers)
userinfo = response.json()

print(f"Ім'я: {userinfo['name']}")
print(f"Email: {userinfo['email']}")
print(f"Фото: {userinfo['picture']}")
```

### ID Token vs UserInfo — коли що використовувати

| Сценарій | Використовувати |
|---|---|
| Встановити ідентичність при логіні | ID Token |
| Показати актуальний профіль | UserInfo Endpoint |
| Зберегти provider_id у базі | `sub` з ID Token |
| Оновити аватарку/ім'я у додатку | UserInfo Endpoint |

---

## 7. Discovery Document

### Проблема конфігурації

Щоб інтегрувати OIDC з конкретним провайдером, Максиму потрібно знати:

- URL для authorization endpoint
- URL для token endpoint
- URL для UserInfo endpoint
- URL для JWKS (публічні ключі для верифікації токенів)
- Підтримувані scopes, response types, алгоритми підпису

Вручну шукати ці URL у документації кожного провайдера — незручно і ненадійно. OIDC вирішує це через **Discovery Document**.

### .well-known/openid-configuration

Кожен OIDC-провайдер публікує JSON-документ за стандартною адресою:

```
https://{issuer}/.well-known/openid-configuration
```

Наприклад, для Google:

```bash
curl https://accounts.google.com/.well-known/openid-configuration | python3 -m json.tool
```

Відповідь (скорочено):

```json
{
  "issuer": "https://accounts.google.com",
  "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_endpoint": "https://oauth2.googleapis.com/token",
  "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
  "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code", "token", "id_token", "code token", "code id_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "claims_supported": [
    "sub", "name", "given_name", "family_name",
    "picture", "email", "email_verified", "locale"
  ]
}
```

### Автоматична конфігурація

Завдяки Discovery Document клієнтська бібліотека може автоматично налаштуватись, знаючи лише `issuer`:

```python
from authlib.integrations.requests_client import OAuth2Session

# Бібліотека сама завантажить discovery document
# і налаштує всі endpoints
session = OAuth2Session(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=(
        "https://accounts.google.com/"
        ".well-known/openid-configuration"
    )
)
```

### Практичне правило

Перед інтеграцією з будь-яким OIDC-провайдером перше, що потрібно зробити — відкрити його Discovery Document. Якщо провайдер підтримує OIDC, цей документ існує і містить усе необхідне.

```
┌──────────────┐     GET /.well-known/        ┌──────────────────┐
│  Relying     │  ───openid-configuration───→ │  OpenID Provider │
│  Party (RP)  │                               │                  │
│              │  ←── JSON: endpoints,         │  (Google,        │
│              │      scopes, algorithms       │   Microsoft,     │
│  SecureNotes │                               │   Apple)         │
└──────────────┘                               └──────────────────┘
       │
       │  Тепер RP знає:
       │  - authorization_endpoint
       │  - token_endpoint
       │  - userinfo_endpoint
       │  - jwks_uri
       │  - підтримувані scopes та алгоритми
       ▼
```

---

## 8. Nonce — захист від replay attacks

### Проблема

**Replay attack** (атака повторного відтворення) — атакуючий перехоплює легітимну відповідь від Authorization Server і повторно використовує її, щоб увійти як інший користувач.

Сценарій:

1. Максим автентифікується через Google і отримує authorization code
2. Атакуючий перехоплює redirect з ID Token (наприклад, через відкритий redirect або XSS)
3. Атакуючий надсилає перехоплений ID Token до SecureNotes
4. SecureNotes приймає токен — він валідний, підписаний Google
5. Атакуючий увійшов як Максим

### Рішення — nonce

**Nonce** (number used once) — це випадкове значення, яке клієнт генерує для кожного authorization request і включає як параметр. Authorization Server вписує це значення у claim `nonce` в ID Token. Клієнт при верифікації перевіряє, що `nonce` у токені збігається зі збереженим значенням.

```
1. Клієнт генерує nonce = "x7y8z9"
   і зберігає його в сесії

2. Authorization Request:
   GET /authorize?
     ...
     &nonce=x7y8z9           ← nonce в запиті

3. ID Token містить:
   {
     "sub": "1101694...",
     "nonce": "x7y8z9",     ← той самий nonce
     ...
   }

4. Клієнт перевіряє:
   token.nonce == session.nonce?  ← ЗБІГАЄТЬСЯ → OK
```

### Чому це працює

Якщо атакуючий спробує повторити (replay) ID Token:

1. Токен містить `nonce = "x7y8z9"`
2. У сесії жертви очікується інший nonce (або nonce вже використаний і видалений)
3. Перевірка nonce провалюється — replay attack заблокований

### Реалізація

```python
import secrets

# 1. Генерація nonce перед redirect
nonce = secrets.token_urlsafe(32)
session["oidc_nonce"] = nonce  # зберігаємо у сесії

# 2. Включення nonce у authorization URL
auth_url = (
    f"{authorization_endpoint}"
    f"?response_type=code"
    f"&client_id={CLIENT_ID}"
    f"&redirect_uri={REDIRECT_URI}"
    f"&scope=openid profile email"
    f"&state={state}"
    f"&nonce={nonce}"
    f"&code_challenge={code_challenge}"
    f"&code_challenge_method=S256"
)

# 3. Верифікація nonce після отримання ID Token
decoded = jwt.decode(id_token, ...)
if decoded["nonce"] != session.pop("oidc_nonce"):
    raise ValueError("Nonce mismatch — possible replay attack")
```

### Nonce vs State

Обидва параметри захищають від різних атак:

| Параметр | Захищає від | Зберігається |
|---|---|---|
| `state` | CSRF — підміна authorization request | Клієнт перевіряє при redirect |
| `nonce` | Replay — повторне використання ID Token | Зашивається в ID Token, перевіряється після декодування |

Максим використовує **обидва** — `state` для захисту від CSRF і `nonce` для захисту від replay.

---

## 9. Session Management

### Проблема

Після успішного логіну через OIDC Максиму потрібно керувати сесією користувача в SecureNotes. Виникають питання:

- Як довго тримати користувача залогіненим?
- Що робити, коли ID Token закінчується?
- Як реалізувати logout?

### Сесія у Relying Party

Після отримання та верифікації ID Token, Relying Party створює **власну сесію**. ID Token використовується лише для встановлення ідентичності — далі додаток керує сесією самостійно.

```
┌───────────┐    ID Token     ┌──────────────┐    Session Cookie    ┌──────────┐
│  OpenID   │ ──────────────→ │   Relying    │ ───────────────────→ │  Browser │
│  Provider │                 │   Party      │                      │          │
│  (Google) │                 │  (SecureNotes)│ ←─────────────────── │          │
└───────────┘                 └──────────────┘    Requests with      └──────────┘
                                    │             session cookie
                                    │
                              Зберігає сесію:
                              - user_id (sub)
                              - name, email
                              - session_expiry
```

### Logout

OIDC визначає кілька механізмів logout:

**RP-Initiated Logout** — користувач натискає «Вийти» в SecureNotes:

1. SecureNotes видаляє локальну сесію
2. Перенаправляє браузер на `end_session_endpoint` провайдера
3. Провайдер завершує свою сесію

```
GET /logout?
  id_token_hint=eyJhbGci...          ← ID Token як підказка
  &post_logout_redirect_uri=https://securenotes.example.com
  &state=logout_state_123
```

**Back-Channel Logout** — провайдер повідомляє всі Relying Parties про logout:

1. Користувач виходить з Google
2. Google надсилає POST-запит з Logout Token на back-channel кожному RP
3. Кожен RP видаляє відповідну сесію

```
┌──────────────┐  POST /backchannel-logout   ┌──────────────┐
│   OpenID     │ ──────────────────────────→  │  RP 1        │
│   Provider   │                              │  SecureNotes │
│              │  POST /backchannel-logout   ┌──────────────┐
│   (Google)   │ ──────────────────────────→ │  RP 2        │
│              │                             │  OtherApp    │
└──────────────┘                             └──────────────┘
```

### Практичні поради

- **Не прив'язуйте сесію до ID Token** — створюйте власну сесію з власним часом життя
- **ID Token не оновлюється** — коли він закінчується, це не означає кінець сесії
- **Використовуйте secure, httpOnly cookies** для зберігання session ID
- **Реалізуйте timeout** — навіть якщо користувач не натискає «Вийти»

---

## 10. Практика — login via Google OIDC

### Задача

Максим додає «Увійти через Google» до SecureNotes за допомогою OpenID Connect. Повний flow: від натискання кнопки до відображення профілю.

### Крок 1. Підготовка

Зареєструвати додаток у Google Cloud Console:

1. Створити проєкт у https://console.cloud.google.com
2. APIs & Services → Credentials → Create OAuth 2.0 Client ID
3. Додати Authorized redirect URI: `http://localhost:5000/callback`
4. Зберегти `CLIENT_ID` та `CLIENT_SECRET`

### Крок 2. Discovery

```python
import requests

GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

# Завантажуємо конфігурацію
config = requests.get(GOOGLE_DISCOVERY_URL).json()

authorization_endpoint = config["authorization_endpoint"]
token_endpoint = config["token_endpoint"]
userinfo_endpoint = config["userinfo_endpoint"]
jwks_uri = config["jwks_uri"]

print(f"Auth:     {authorization_endpoint}")
print(f"Token:    {token_endpoint}")
print(f"UserInfo: {userinfo_endpoint}")
print(f"JWKS:     {jwks_uri}")
```

### Крок 3. Повний додаток на Flask

```python
import secrets
import hashlib
import base64
import requests
import jwt
from flask import Flask, redirect, request, session, url_for

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

CLIENT_ID = "YOUR_CLIENT_ID"
CLIENT_SECRET = "YOUR_CLIENT_SECRET"
REDIRECT_URI = "http://localhost:5000/callback"

# Discovery
config = requests.get(
    "https://accounts.google.com/.well-known/openid-configuration"
).json()

@app.route("/")
def index():
    if "user" in session:
        user = session["user"]
        return (
            f"<h1>SecureNotes</h1>"
            f"<img src='{user['picture']}' width='80'>"
            f"<p>Вітаю, {user['name']}!</p>"
            f"<p>Email: {user['email']}</p>"
            f"<a href='/logout'>Вийти</a>"
        )
    return "<h1>SecureNotes</h1><a href='/login'>Увійти через Google</a>"

@app.route("/login")
def login():
    # Генеруємо state, nonce, PKCE
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
        f"&state={state}"
        f"&nonce={nonce}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
    )
    return redirect(auth_url)

@app.route("/callback")
def callback():
    # 1. Перевіряємо state
    if request.args.get("state") != session.pop("oauth_state", None):
        return "State mismatch — можлива CSRF атака", 403

    # 2. Обмінюємо code на токени
    code = request.args.get("code")
    token_response = requests.post(
        config["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code_verifier": session.pop("code_verifier"),
        },
    ).json()

    access_token = token_response["access_token"]
    id_token_raw = token_response["id_token"]

    # 3. Верифікуємо ID Token
    jwks = requests.get(config["jwks_uri"]).json()
    id_claims = jwt.decode(
        id_token_raw,
        key=jwt.PyJWKSet.from_dict(jwks),
        algorithms=["RS256"],
        audience=CLIENT_ID,
        issuer="https://accounts.google.com",
    )

    # 4. Перевіряємо nonce
    if id_claims.get("nonce") != session.pop("oidc_nonce", None):
        return "Nonce mismatch — можлива replay атака", 403

    # 5. Отримуємо UserInfo
    userinfo = requests.get(
        config["userinfo_endpoint"],
        headers={"Authorization": f"Bearer {access_token}"},
    ).json()

    # 6. Створюємо сесію
    session["user"] = {
        "sub": id_claims["sub"],
        "name": userinfo.get("name", ""),
        "email": userinfo.get("email", ""),
        "picture": userinfo.get("picture", ""),
    }

    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True, port=5000)
```

### Крок 4. Тестування

```bash
# Встановити залежності
pip install flask requests PyJWT cryptography

# Запустити
python app.py

# Відкрити у браузері
# http://localhost:5000
```

### Що відбувається крок за кроком

```
1. Користувач натискає "Увійти через Google"
         │
2. Redirect на Google Authorization Endpoint
   з scope=openid profile email, state, nonce, PKCE
         │
3. Користувач вводить логін/пароль у Google
         │
4. Google redirect на /callback з code та state
         │
5. SecureNotes перевіряє state
         │
6. SecureNotes обмінює code + code_verifier на:
   - access_token
   - id_token
         │
7. SecureNotes верифікує id_token:
   - підпис (JWKS)
   - iss, aud, exp
   - nonce
         │
8. SecureNotes запитує UserInfo з access_token
         │
9. Створення локальної сесії
         │
10. Відображення профілю: ім'я, email, фото
```

---

## 11. Підсумки

### Що ми розглянули

- **Authentication vs Authorization** — OAuth 2.0 вирішує авторизацію, OIDC додає автентифікацію
- **OIDC** — identity layer поверх OAuth 2.0, стандарт для отримання інформації про користувача
- **ID Token** — JWT з ідентичністю користувача; відрізняється від access token за призначенням і аудиторією
- **Standard Claims** — стандартизовані атрибути (sub, name, email, picture); sub — головний ідентифікатор
- **Standard Scopes** — openid (обов'язковий), profile, email, address, phone
- **UserInfo Endpoint** — актуальна інформація про профіль через access token
- **Discovery Document** — автоматична конфігурація через .well-known/openid-configuration
- **Nonce** — захист від replay attacks
- **Session Management** — створення власної сесії, RP-Initiated та Back-Channel Logout

### Ключові висновки

1. OAuth 2.0 = **авторизація** (що можна робити). OIDC = **автентифікація** (хто ти)
2. ID Token — це JWT **для клієнта**, не для API. Ніколи не передавайте ID Token як Bearer token
3. Використовуйте пару `(iss, sub)` як первинний ключ користувача, а не email
4. Завжди перевіряйте **підпис, iss, aud, exp, nonce** у ID Token
5. Discovery Document — перше, що потрібно перевірити при інтеграції з OIDC-провайдером

### Що далі?

У наступній лекції ми розглянемо **атаки на OAuth та захист** — Лекція 10: Атаки на OAuth та захист.

Тепер Максим має повноцінний логін через Google у SecureNotes. Але наскільки це безпечно? OAuth і OIDC мають значну поверхню атаки, і зловмисники активно її експлуатують:

- **Redirect URI manipulation** — що відбувається, якщо атакуючий змінить redirect_uri?
- **Token leakage** — як токени потрапляють до зловмисників через Referer, browser history, logs?
- **CSRF та token injection** — як state та nonce можуть бути обійдені?
- **Authorization Code Injection** — підміна authorization code
- **Mix-Up Attack** — коли клієнт підтримує декілька провайдерів

---

## Література

1. OpenID Connect Core 1.0 — https://openid.net/specs/openid-connect-core-1_0.html
2. OpenID Connect Discovery 1.0 — https://openid.net/specs/openid-connect-discovery-1_0.html
3. OpenID Connect Session Management 1.0 — https://openid.net/specs/openid-connect-session-1_0.html
4. RFC 7519 — JSON Web Token (JWT)
5. Nikos Sakimura et al. *OpenID Connect Core 1.0.* — OpenID Foundation, 2014
6. Daniel Fett, Ralf Kuesters, Guido Schmitz. *A Comprehensive Formal Security Analysis of OAuth 2.0.* — ACM CCS, 2016
