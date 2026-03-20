# Лекція 6. JWT — токени зсередини

## Зміст

1. [Що таке JWT](#1-що-таке-jwt)
2. [Структура JWT](#2-структура-jwt)
3. [Claims — вміст payload](#3-claims--вміст-payload)
4. [JWS vs JWE — підпис vs шифрування](#4-jws-vs-jwe--підпис-vs-шифрування)
5. [Алгоритми підпису](#5-алгоритми-підпису)
6. [JWKS — JSON Web Key Set](#6-jwks--json-web-key-set)
7. [JWT Validation Checklist](#7-jwt-validation-checklist)
8. [Типові помилки з JWT](#8-типові-помилки-з-jwt)
9. [Практика — PyJWT](#9-практика--pyjwt)
10. [Підсумки](#10-підсумки)

---

## 1. Що таке JWT

### Мотивація

У попередній лекції ми розглянули OAuth 2.0 Authorization Code Flow. Після успішного обміну authorization code на access token клієнт отримує рядок, який виглядає приблизно так:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwi
bmFtZSI6Ik1ha3N5bSBWeXRyZWJlbmtvIiwiaWF0IjoxNjE2MjM5MDIyfQ.SflKxwR
JSSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Що всередині цього рядка? Чому сервер може довіряти цьому токену без звернення до бази даних? Яким чином Resource Server переконується, що токен справжній і не підроблений?

Відповідь — **JWT** (JSON Web Token, вимовляється "jot"). JWT — це відкритий стандарт (RFC 7519), що визначає компактний, самодостатній (self-contained) спосіб безпечної передачі інформації між сторонами у вигляді JSON-об'єкта. Ця інформація може бути верифікована та довірена, оскільки вона має **цифровий підпис**.

### Контекст SecureNotes

Максим Витребенько будує додаток SecureNotes — сервіс для зберігання зашифрованих нотаток. У лекції 6 він налаштував OAuth 2.0 Authorization Code Flow для автентифікації користувачів. Тепер Максим реалізує JWT-based access tokens для SecureNotes, щоб API-сервер міг верифікувати запити без звернення до Authorization Server при кожному виклику.

### Чому саме JWT?

JWT вирішує ключову проблему stateless-верифікації:

```
Session-based (stateful):
Client ──→ API Server ──→ Session Store (Redis/DB)
                          "Чи існує сесія abc123?"
                          Потрібне мережеве звернення!

JWT-based (stateless):
Client ──→ API Server ──→ Перевірка підпису (локально)
                          "Чи підпис валідний?"
                          Без мережевих звернень!
```

Сервер не зберігає стан — він лише перевіряє криптографічний підпис токена. Це дає горизонтальне масштабування: будь-який екземпляр API може верифікувати токен, маючи лише публічний ключ.

---

## 2. Структура JWT

### Три частини

JWT складається з трьох частин, розділених крапкою:

```
HEADER.PAYLOAD.SIGNATURE
```

Кожна частина закодована у **Base64URL** (варіант Base64, безпечний для URL — замість `+` використовується `-`, замість `/` — `_`, без padding `=`).

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
.
eyJzdWIiOiJ1c2VyLTEyMyIsIm5hbWUiOiLQnNCw0LrRgdC40Lwg0JLQuNGC0YDQtdCx0LXQvdGM0LrQviIsInJvbGUiOiJlZGl0b3IiLCJpYXQiOjE3MTYyMzkwMjIsImV4cCI6MTcxNjI0MjYyMn0
.
SflKxwRJSSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Header (Заголовок)

Header містить метадані про токен — алгоритм підпису та тип токена:

```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

- `alg` — алгоритм підпису (RS256, HS256, ES256 тощо)
- `typ` — тип токена (завжди `JWT`)
- `kid` — (опціонально) ідентифікатор ключа для вибору з JWKS

### Payload (Корисне навантаження)

Payload містить **claims** — твердження про сутність (зазвичай користувача) та додаткові метадані:

```json
{
  "sub": "user-123",
  "name": "Максим Витребенько",
  "role": "editor",
  "iat": 1716239022,
  "exp": 1716242622
}
```

Payload **не зашифрований** — лише закодований у Base64URL. Будь-хто може декодувати payload і прочитати його вміст. JWT гарантує **цілісність** (дані не підроблені), але не **конфіденційність** (дані видимі).

### Signature (Підпис)

Підпис обчислюється за формулою:

```
SIGNATURE = алгоритм(
  base64url(header) + "." + base64url(payload),
  ключ
)
```

Для HMAC (симетричний):
```
HMAC-SHA256(header + "." + payload, secret)
```

Для RSA (асиметричний):
```
RSA-SHA256(header + "." + payload, private_key)
```

### Візуалізація структури

```
┌──────────────────────────────────────────────────────┐
│                    JWT Token                          │
├───────────────┬───────────────┬──────────────────────┤
│    HEADER     │    PAYLOAD    │      SIGNATURE        │
│  (base64url)  │  (base64url)  │      (base64url)      │
├───────────────┼───────────────┼──────────────────────┤
│ {             │ {             │                        │
│   "alg":"RS256│   "sub":"123" │  RSA-SHA256(           │
│   "typ":"JWT" │   "name":"Max"│    header + "." +      │
│ }             │   "exp":17162 │    payload,            │
│               │ }             │    private_key         │
│               │               │  )                     │
├───────────────┴───────────────┼──────────────────────┤
│    Може прочитати будь-хто    │ Може створити лише    │
│    (Base64URL decode)         │ власник ключа          │
└───────────────────────────────┴──────────────────────┘
```

### Декодування на практиці

```bash
# Декодування header
echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"RS256","typ":"JWT"}

# Декодування payload
echo "eyJzdWIiOiJ1c2VyLTEyMyJ9" | base64 -d
# {"sub":"user-123"}
```

```python
import base64
import json

token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.signature"
header_b64, payload_b64, signature_b64 = token.split(".")

# Додаємо padding для Base64
payload_b64 += "=" * (4 - len(payload_b64) % 4)
payload = json.loads(base64.urlsafe_b64decode(payload_b64))
print(payload)  # {'sub': 'user-123'}
```

---

## 3. Claims — вміст payload

### Що таке claims

**Claims** (твердження) — це пари ключ-значення в payload, що містять інформацію про токен та його суб'єкта. RFC 7519 визначає три категорії claims.

### Registered Claims (Зареєстровані)

Стандартизовані claims з визначеною семантикою (RFC 7519, Section 4.1). Жоден з них не є обов'язковим, але всі рекомендовані:

| Claim | Назва | Опис | Приклад |
|-------|-------|------|---------|
| `iss` | Issuer | Хто видав токен | `"https://auth.securenotes.com"` |
| `sub` | Subject | Для кого видано (ID користувача) | `"user-123"` |
| `aud` | Audience | Для якого сервісу призначено | `"https://api.securenotes.com"` |
| `exp` | Expiration Time | Коли токен стає недійсним (Unix timestamp) | `1716242622` |
| `nbf` | Not Before | До якого часу токен недійсний | `1716239022` |
| `iat` | Issued At | Коли видано | `1716239022` |
| `jti` | JWT ID | Унікальний ідентифікатор токена | `"a1b2c3d4"` |

### Public Claims (Публічні)

Claims, зареєстровані в IANA JSON Web Token Claims Registry або визначені як URI для уникнення колізій імен. Приклади:

```json
{
  "email": "maksym.vytrebenko@example.com",
  "email_verified": true,
  "name": "Максим Витребенько"
}
```

OpenID Connect визначає стандартний набір public claims для інформації про користувача: `name`, `email`, `picture`, `locale` тощо.

### Private Claims (Приватні)

Claims, визначені за домовленістю між сторонами. Не зареєстровані в IANA, не є URI — використовуються для внутрішніх потреб конкретної системи:

```json
{
  "role": "editor",
  "workspace_id": "ws-456",
  "features": ["export", "share"]
}
```

### Приклад повного payload для SecureNotes

```json
{
  "iss": "https://auth.securenotes.com",
  "sub": "user-123",
  "aud": "https://api.securenotes.com",
  "exp": 1716242622,
  "iat": 1716239022,
  "nbf": 1716239022,
  "jti": "tok-7f3a9b2c",
  "name": "Максим Витребенько",
  "email": "maksym.vytrebenko@example.com",
  "role": "editor",
  "scopes": ["notes:read", "notes:write"]
}
```

### Важливе застереження

Payload **НЕ зашифрований**. Не зберігайте в JWT:

- Паролі або хеші паролів
- Номери кредитних карток
- Персональні ідентифікаційні номери (ІПН, SSN)
- Секретні ключі

Все, що потрапляє в payload, може прочитати будь-хто, хто має доступ до токена.

---

## 4. JWS vs JWE — підпис vs шифрування

### Два способи захисту JWT

JWT — це загальний формат. Конкретна реалізація може використовувати один із двох механізмів:

- **JWS** (JSON Web Signature, RFC 7515) — забезпечує **цілісність** та **автентичність**. Payload видимий, але захищений від підробки
- **JWE** (JSON Web Encryption, RFC 7516) — забезпечує **конфіденційність**. Payload зашифрований, його не може прочитати ніхто, окрім отримувача

### JWS — те, що зазвичай називають "JWT"

Коли говорять "JWT", у 99% випадків мають на увазі саме JWS. Структура: `header.payload.signature`.

```
JWS (JSON Web Signature):
┌──────────┐    ┌──────────┐    ┌──────────┐
│  HEADER  │ .  │ PAYLOAD  │ .  │SIGNATURE │
│ (видимий)│    │ (видимий)│    │(підпис)  │
└──────────┘    └──────────┘    └──────────┘
     │                │               │
     └────────────────┼───────────────┘
                      │
              Будь-хто може прочитати,
              але ніхто не може підробити
```

### JWE — коли потрібна конфіденційність

JWE має п'ять частин: `header.encrypted_key.iv.ciphertext.tag`.

```
JWE (JSON Web Encryption):
┌──────────┐ . ┌─────────────┐ . ┌────┐ . ┌────────────┐ . ┌─────┐
│  HEADER  │   │ENCRYPTED_KEY│   │ IV │   │ CIPHERTEXT │   │ TAG │
└──────────┘   └─────────────┘   └────┘   └────────────┘   └─────┘
                                               │
                                    Payload зашифрований —
                                    прочитати може лише
                                    власник ключа
```

### Коли що використовувати

| | JWS | JWE |
|---|---|---|
| Payload видимий | так | ні |
| Захист від підробки | так | так |
| Конфіденційність payload | ні | так |
| Типове використання | Access tokens, ID tokens | Токени з sensitive data |
| Складність | простіший | складніший |

Для більшості сценаріїв (OAuth access tokens, API-автентифікація) достатньо **JWS**. JWE потрібен лише тоді, коли payload містить конфіденційну інформацію, яку не повинні бачити проміжні сторони.

Максим обирає JWS для SecureNotes — payload містить лише user ID, роль та scopes, жодних секретних даних.

---

## 5. Алгоритми підпису

### Огляд

Алгоритм підпису визначається в полі `alg` заголовка JWT. Вибір алгоритму впливає на безпеку, продуктивність та архітектуру системи.

### HS256 — HMAC з SHA-256 (симетричний)

**HMAC** (Hash-based Message Authentication Code) — код автентифікації повідомлення на основі хеш-функції. Один і той самий секретний ключ використовується для створення та перевірки підпису.

```
Створення:   HMAC-SHA256(header + "." + payload, secret) = signature
Перевірка:   HMAC-SHA256(header + "." + payload, secret) == signature?
```

```
┌──────────────┐                 ┌──────────────┐
│  Auth Server │   secret_key    │  API Server  │
│  (створює)   │ ════════════════│  (перевіряє) │
│              │  Один і той     │              │
│  sign(key)   │  самий ключ!    │  verify(key) │
└──────────────┘                 └──────────────┘
```

**Переваги:** простий, швидкий, компактний підпис.
**Недоліки:** секретний ключ потрібно передати всім сервісам, що верифікують токен. Кожен сервіс, що знає ключ, може також **створювати** токени. Не підходить для розподілених систем, де верифікатори не довірені.

### RS256 — RSA з SHA-256 (асиметричний)

Використовує пару ключів: **приватний ключ** для створення підпису, **публічний ключ** для верифікації. Лише Authorization Server має приватний ключ. Публічний ключ може бути доступний будь-кому.

```
Створення:   RSA-SHA256(header + "." + payload, private_key) = signature
Перевірка:   RSA-SHA256-verify(header + "." + payload, signature, public_key)
```

```
┌──────────────┐                 ┌──────────────┐
│  Auth Server │                 │  API Server  │
│  (створює)   │                 │  (перевіряє) │
│              │   public_key    │              │
│  sign(       │ ───────────────→│  verify(     │
│   private_key│                 │   public_key)│
│  )           │                 │              │
└──────────────┘                 └──────────────┘
     │                                │
     │ Має ПРИВАТНИЙ ключ             │ Має лише ПУБЛІЧНИЙ ключ
     │ (може створювати токени)       │ (може лише перевіряти)
```

**Переваги:** верифікатор не може створити токен — ідеально для мікросервісів.
**Недоліки:** повільніший за HS256, більший розмір підпису (256 байт для RSA-2048).

### ES256 — ECDSA з P-256 (асиметричний)

Еліптичні криві (Elliptic Curve Digital Signature Algorithm). Асиметричний, як RS256, але з коротшими ключами та підписами при аналогічному рівні безпеки.

| Параметр | RS256 | ES256 |
|----------|-------|-------|
| Розмір ключа | 2048+ біт | 256 біт |
| Розмір підпису | 256 байт | 64 байти |
| Швидкість підпису | повільна | швидка |
| Швидкість верифікації | швидка | повільніша |
| Рівень безпеки | 112 біт (RSA-2048) | 128 біт |

ES256 рекомендований для нових систем, де розмір токена має значення (мобільні додатки, IoT).

### "alg": "none" — НЕБЕЗПЕЧНО!

Специфікація JWT дозволяє `"alg": "none"` — токен без підпису. Це означає, що **будь-хто може створити довільний токен**, і сервер, що приймає `none`, сліпо йому довіряє.

```json
{
  "alg": "none",
  "typ": "JWT"
}
```

```
Атакуючий створює токен:

Header:  {"alg": "none", "typ": "JWT"}
Payload: {"sub": "admin", "role": "superadmin"}
Signature: (порожній)

Результат: eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
                                                     ^ порожній підпис!
```

**НІКОЛИ** не приймайте `alg: none` у production. Бібліотеки JWT повинні бути налаштовані на явний список дозволених алгоритмів.

### Порівняльна таблиця

| Алгоритм | Тип | Ключ для підпису | Ключ для верифікації | Рекомендація |
|----------|-----|------------------|----------------------|--------------|
| HS256 | Симетричний | shared secret | shared secret | Монолітні системи |
| RS256 | Асиметричний | private key | public key | Мікросервіси |
| ES256 | Асиметричний | private key | public key | Мобільні, IoT |
| none | Немає | — | — | **ЗАБОРОНЕНО!** |

---

## 6. JWKS — JSON Web Key Set

### Проблема розповсюдження ключів

Максим має Authorization Server, який підписує токени приватним ключем (RS256). У нього є 5 мікросервісів, які потрібно верифікувати ці токени. Як передати публічний ключ усім сервісам? А що робити при ротації ключів?

### Рішення: JWKS endpoint

**JWKS** (JSON Web Key Set) — це JSON-документ, що містить набір публічних ключів. Authorization Server публікує його за відомим URL, і будь-який сервіс може отримати ключі для верифікації.

Стандартний URL (за конвенцією OpenID Connect):

```
https://auth.securenotes.com/.well-known/jwks.json
```

### Формат JWKS

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-2024-01",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7agoebGcQSuu...",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "kid": "key-2024-02",
      "use": "sig",
      "alg": "RS256",
      "n": "x9AjQb2fGnBbB8u...",
      "e": "AQAB"
    }
  ]
}
```

Основні поля:

| Поле | Опис |
|------|------|
| `kty` | Key Type — тип ключа (`RSA`, `EC`) |
| `kid` | Key ID — ідентифікатор ключа |
| `use` | Призначення (`sig` — підпис, `enc` — шифрування) |
| `alg` | Алгоритм (`RS256`, `ES256`) |
| `n`, `e` | Компоненти RSA-ключа (modulus, exponent) |

### Процес верифікації з JWKS

```
1. API Server отримує JWT
2. Читає kid з header JWT
3. Завантажує JWKS з Authorization Server (з кешуванням!)
4. Знаходить ключ з відповідним kid
5. Верифікує підпис JWT цим ключем

┌──────────┐    JWT (kid: "key-2024-01")    ┌──────────────┐
│  Client  │ ──────────────────────────────→ │  API Server  │
└──────────┘                                 │              │
                                             │ 1. Читає kid │
                                             │ 2. Шукає в   │
                                             │    кеші JWKS │
                                             │              │
                 GET /.well-known/jwks.json   │ 3. (якщо     │
┌──────────────┐ ←───────────────────────── │    не в кеші)│
│  Auth Server │ ──────────────────────────→ │              │
│              │   { "keys": [...] }         │ 4. Верифікує │
└──────────────┘                             └──────────────┘
```

### Ротація ключів

JWKS дозволяє безшовну ротацію ключів:

1. Authorization Server генерує новий ключ (`key-2024-02`)
2. Публікує обидва ключі в JWKS (старий і новий)
3. Починає підписувати нові токени новим ключем
4. Старі токени (підписані `key-2024-01`) продовжують верифікуватися
5. Після закінчення терміну дії всіх старих токенів — видаляє старий ключ з JWKS

Завдяки полю `kid` у заголовку JWT, API Server завжди знає, яким ключем перевіряти підпис.

---

## 7. JWT Validation Checklist

### Порядок перевірки

Коли API Server отримує JWT, він повинен виконати серію перевірок у чіткому порядку. Пропуск будь-якого кроку — потенційна вразливість.

```
JWT отримано
    │
    ▼
1. Структура: три частини, розділені крапкою?
    │ ні → відхилити
    ▼
2. Header: alg у списку дозволених?
    │ ні → відхилити (захист від alg:none)
    ▼
3. Signature: підпис валідний?
    │ ні → відхилити (токен підроблений)
    ▼
4. exp: токен не прострочений? (поточний час < exp)
    │ ні → відхилити (токен expired)
    ▼
5. nbf: токен вже активний? (поточний час >= nbf)
    │ ні → відхилити (токен ще не діє)
    ▼
6. iss: видавець очікуваний?
    │ ні → відхилити (невідомий issuer)
    ▼
7. aud: токен призначений для цього сервісу?
    │ ні → відхилити (не наш токен)
    ▼
8. Додаткові перевірки (scopes, roles, etc.)
    │
    ▼
Токен прийнято ✓
```

### Деталі кожного кроку

**Крок 1 — Структура.** Перевірити, що токен має рівно три частини (`header.payload.signature`), кожна з яких є валідним Base64URL.

**Крок 2 — Алгоритм.** Перевірити `alg` у header проти **whitelist** дозволених алгоритмів. Якщо ваш сервер очікує тільки RS256 — відхиляйте все інше, включаючи `none`, `HS256` тощо.

**Крок 3 — Підпис.** Верифікувати підпис відповідним ключем. Для RS256 — публічним ключем з JWKS. Для HS256 — спільним секретом.

**Крок 4 — Expiration (exp).** Порівняти `exp` з поточним часом сервера. Рекомендується додавати невеликий **clock skew tolerance** (зазвичай 30-60 секунд), щоб компенсувати розсинхронізацію годинників між серверами.

**Крок 5 — Not Before (nbf).** Якщо є claim `nbf`, токен не повинен прийматися до цього моменту.

**Крок 6 — Issuer (iss).** Переконатися, що токен видано очікуваним Authorization Server. Захист від підробки токенів іншим issuer.

**Крок 7 — Audience (aud).** Переконатися, що токен призначений для цього сервісу. Це запобігає використанню токена, виданого для іншого API, у вашому сервісі.

**Крок 8 — Бізнес-перевірки.** Перевірити scopes, roles, permissions тощо відповідно до логіки конкретного ендпоінта.

### Clock skew

Годинники серверів не ідеально синхронізовані. Якщо Authorization Server видав токен з `exp = 1716242622`, а годинник API Server випереджає на 2 секунди — токен буде відхилений передчасно.

```python
import time

CLOCK_SKEW_SECONDS = 30

def is_expired(exp_claim):
    return time.time() > exp_claim + CLOCK_SKEW_SECONDS
```

---

## 8. Типові помилки з JWT

### 8.1. Атака "alg: none"

Атакуючий підміняє заголовок токена, встановлюючи `"alg": "none"`, та видаляє підпис. Якщо сервер не перевіряє алгоритм — він приймає непідписаний токен.

```
Оригінальний токен (RS256, з підписом):
eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.abc123...

Підроблений токен (none, без підпису):
eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcmFkbWluIn0.

Сервер без перевірки alg: "Підпис? Алгоритм none — підпис не потрібен. ОК!"
```

**Захист:** завжди перевіряти `alg` проти whitelist, **ніколи** не приймати `none`.

### 8.2. Symmetric key confusion (плутанина ключів)

Сервер очікує RS256 (асиметричний), але атакуючий надсилає токен з `"alg": "HS256"`. Деякі бібліотеки при цьому використовують **публічний ключ RSA** як HMAC-секрет для верифікації. Оскільки публічний ключ відомий (з JWKS), атакуючий підписує токен цим ключем з алгоритмом HS256.

```
Атакуючий:
1. Завантажує public_key з JWKS
2. Змінює header: {"alg": "HS256"}
3. Підписує: HMAC-SHA256(header.payload, public_key)
4. Відправляє токен

Вразливий сервер:
1. Читає alg: "HS256"
2. Бере "ключ" для верифікації — а це public_key!
3. HMAC-SHA256(header.payload, public_key) == signature? ТАК!
4. Токен прийнято!
```

**Захист:** при верифікації **завжди** явно вказувати очікуваний алгоритм, не довіряти `alg` з заголовка.

### 8.3. Не перевіряти exp

Якщо сервер не перевіряє `exp`, вкрадений токен залишається дійсним **назавжди**. Навіть якщо користувач змінив пароль або відкликав доступ.

```python
# НЕПРАВИЛЬНО — exp не перевіряється:
payload = jwt.decode(token, key, algorithms=["RS256"],
                     options={"verify_exp": False})  # НЕБЕЗПЕЧНО!

# ПРАВИЛЬНО — exp перевіряється автоматично:
payload = jwt.decode(token, key, algorithms=["RS256"])
```

### 8.4. Sensitive data у payload

Payload лише закодований (Base64URL), не зашифрований. Все, що в ньому — видиме.

```python
# НЕПРАВИЛЬНО:
payload = {
    "sub": "user-123",
    "credit_card": "4111-1111-1111-1111",  # видно всім!
    "ssn": "123-45-6789"                    # видно всім!
}

# ПРАВИЛЬНО:
payload = {
    "sub": "user-123",
    "role": "editor",
    "scopes": ["notes:read", "notes:write"]
}
```

### 8.5. Занадто довгий час життя (exp)

Токен з `exp` через 30 днів — це 30 днів, протягом яких вкрадений токен залишається дійсним.

| Тип токена | Рекомендований exp |
|------------|-------------------|
| Access Token | 5-15 хвилин |
| ID Token | 5-60 хвилин |
| Refresh Token | дні-тижні (з ротацією) |

### Чеклист помилок

| Помилка | Наслідок | Захист |
|---------|----------|--------|
| `alg: none` | Будь-хто створює токени | Whitelist алгоритмів |
| Key confusion | Публічний ключ = HMAC секрет | Явно вказувати алгоритм |
| Без перевірки `exp` | Вічний токен | Завжди перевіряти `exp` |
| Sensitive data | Витік через Base64 decode | Лише несекретні дані |
| Довгий `exp` | Довге вікно атаки | Short-lived + refresh |

---

## 9. Практика — PyJWT

### Встановлення

```bash
pip install PyJWT cryptography
```

### HS256 — симетричний підпис

```python
import jwt
import time

SECRET_KEY = "supersecret-key-at-least-32-bytes-long!"

# --- Створення токена ---
payload = {
    "iss": "https://auth.securenotes.com",
    "sub": "user-123",
    "aud": "https://api.securenotes.com",
    "exp": int(time.time()) + 3600,   # 1 година
    "iat": int(time.time()),
    "name": "Максим Витребенько",
    "role": "editor",
    "scopes": ["notes:read", "notes:write"]
}

token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
print(f"Token: {token}")

# --- Верифікація токена ---
try:
    decoded = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"],           # whitelist алгоритмів!
        audience="https://api.securenotes.com",
        issuer="https://auth.securenotes.com"
    )
    print(f"Subject: {decoded['sub']}")
    print(f"Role: {decoded['role']}")
    print(f"Scopes: {decoded['scopes']}")
except jwt.ExpiredSignatureError:
    print("Токен прострочений!")
except jwt.InvalidAudienceError:
    print("Невірний audience!")
except jwt.InvalidIssuerError:
    print("Невірний issuer!")
except jwt.InvalidSignatureError:
    print("Підпис невалідний — токен підроблений!")
```

### RS256 — асиметричний підпис

```python
import jwt
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# --- Генерація ключів (один раз, на Auth Server) ---
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Серіалізація для збереження/передачі
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# --- Auth Server: створення токена (приватний ключ) ---
payload = {
    "iss": "https://auth.securenotes.com",
    "sub": "user-123",
    "aud": "https://api.securenotes.com",
    "exp": int(time.time()) + 900,  # 15 хвилин
    "iat": int(time.time()),
    "role": "editor"
}

token = jwt.encode(payload, private_key, algorithm="RS256",
                   headers={"kid": "key-2024-01"})
print(f"Token: {token}")

# --- API Server: верифікація (лише публічний ключ!) ---
try:
    decoded = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience="https://api.securenotes.com",
        issuer="https://auth.securenotes.com"
    )
    print(f"Верифікація успішна!")
    print(f"Subject: {decoded['sub']}")
    print(f"Role: {decoded['role']}")
except jwt.InvalidSignatureError:
    print("Підпис невалідний!")
except jwt.ExpiredSignatureError:
    print("Токен прострочений!")
```

### Демонстрація атаки: підробка payload

```python
import jwt
import base64
import json

# Легітимний токен
SECRET = "my-secret-key-32-bytes-long!!!!!"
token = jwt.encode({"sub": "user-123", "role": "viewer"}, SECRET, algorithm="HS256")
print(f"Оригінальний токен: {token}")

# Атакуючий декодує payload (це просто Base64)
parts = token.split(".")
payload_bytes = base64.urlsafe_b64decode(parts[1] + "==")
payload = json.loads(payload_bytes)
print(f"Payload (видимий!): {payload}")

# Атакуючий змінює role
payload["role"] = "admin"
new_payload = base64.urlsafe_b64encode(
    json.dumps(payload).encode()
).rstrip(b"=").decode()

# Збираємо підроблений токен (з оригінальним підписом)
forged_token = f"{parts[0]}.{new_payload}.{parts[2]}"

# Верифікація відхиляє підроблений токен!
try:
    jwt.decode(forged_token, SECRET, algorithms=["HS256"])
    print("ПРОБЛЕМА: підроблений токен прийнято!")
except jwt.InvalidSignatureError:
    print("Підпис невалідний — підробку виявлено!")
```

### Інспектування токена з командного рядка

```bash
# Декодувати header (перша частина до першої крапки)
echo "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d 2>/dev/null
# {"alg":"RS256","typ":"JWT"}

# Або з Python:
python3 -c "
import jwt
token = 'YOUR_TOKEN_HERE'
# decode без верифікації — лише для інспектування!
print(jwt.decode(token, options={'verify_signature': False},
                 algorithms=['RS256', 'HS256']))
"
```

---

## 10. Підсумки

### Що ми розглянули

- **JWT** — self-contained токен із структурою header.payload.signature
- **Claims** — registered (iss, sub, aud, exp), public, private
- **JWS vs JWE** — підпис (цілісність) vs шифрування (конфіденційність)
- **Алгоритми** — HS256 (симетричний), RS256/ES256 (асиметричні), none (заборонено!)
- **JWKS** — публікація ключів для верифікації, ротація ключів
- **Validation** — обов'язковий порядок перевірок
- **Типові помилки** — alg:none, key confusion, відсутність перевірки exp

### Ключові висновки

1. JWT payload **НЕ зашифрований** — не зберігайте в ньому секретні дані
2. Безпека JWT тримається на **перевірці підпису** та **валідації claims**
3. Для мікросервісів використовуйте **асиметричні алгоритми** (RS256, ES256) та **JWKS**
4. **Завжди** перевіряйте `alg` проти whitelist, `exp`, `iss`, `aud`
5. Access tokens мають бути **короткоживучими** (5-15 хвилин)

### Що далі?

У наступній лекції ми розглянемо **Лекція 7: Access Token vs Refresh Token — lifecycle**.

Якщо access token живе лише 15 хвилин, чи повинен користувач логінитися кожні 15 хвилин? Ні — для цього існують **Refresh Tokens**. Ми розглянемо:

- **Access Token** vs **Refresh Token** — різні ролі, різний час життя
- **Token Rotation** — автоматична ротація refresh tokens для захисту від викрадення
- **Token Revocation** — як відкликати токен у stateless-архітектурі
- **Sliding sessions** vs **absolute expiration** — стратегії продовження сесій

Максим Витребенько реалізує повний lifecycle токенів для SecureNotes — від видачі до ротації та відкликання.

---

## Література

1. RFC 7519 — JSON Web Token (JWT)
2. RFC 7515 — JSON Web Signature (JWS)
3. RFC 7516 — JSON Web Encryption (JWE)
4. RFC 7517 — JSON Web Key (JWK)
5. RFC 7518 — JSON Web Algorithms (JWA)
6. Auth0. *JWT Handbook.* — https://auth0.com/resources/ebooks/jwt-handbook
7. Tim McLean. *Critical vulnerabilities in JSON Web Token libraries.* — 2015
8. Sjoerd Langkemper. *Attacking JWT authentication.* — https://www.sjoerdlangkemper.nl/2016/09/28/attacking-jwt-authentication/
