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

Лекція 6. JWT — токени зсередини

Львівський національний університет імені Івана Франка
Спеціальність 113 — Прикладна математика

2025

---

# План лекції

1. Що таке JWT
2. Структура JWT — header.payload.signature
3. Claims — registered, public, private
4. JWS vs JWE — підпис vs шифрування
5. Алгоритми підпису — HS256, RS256, ES256, none
6. JWKS — публікація ключів для верифікації
7. JWT Validation Checklist
8. Типові помилки з JWT
9. Практика — PyJWT

---

# Де ми зупинились

OAuth 2.0 Authorization Code Flow видає **access token**

```
Authorization Server ──→ { "access_token": "eyJhbGciOi..." }
```

Що всередині цього рядка? Як сервер йому довіряє **без звернення до БД**?

Відповідь — **JWT** (JSON Web Token, RFC 7519)

---

# Контекст: SecureNotes

Максим Витребенько реалізує JWT-based access tokens для SecureNotes

```
Session-based (stateful):
Client ──→ API Server ──→ Session Store (Redis/DB)
                          "Чи існує сесія abc123?"

JWT-based (stateless):
Client ──→ API Server ──→ Перевірка підпису (локально)
                          "Чи підпис валідний?"
                          Без мережевих звернень!
```

Будь-який екземпляр API верифікує токен, маючи лише публічний ключ

---

# Структура JWT

Три частини, розділені крапкою, кожна у **Base64URL**:

```
HEADER.PAYLOAD.SIGNATURE
```

```
eyJhbGciOiJSUzI1NiJ9
.
eyJzdWIiOiJ1c2VyLTEyMyIsInJvbGUiOiJlZGl0b3IifQ
.
SflKxwRJSSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

---

# Header (Заголовок)

Метадані про токен:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-2024-01"
}
```

- `alg` — алгоритм підпису (RS256, HS256, ES256)
- `typ` — тип токена (JWT)
- `kid` — ідентифікатор ключа (для JWKS)

---

# Payload (Корисне навантаження)

Claims — твердження про суб'єкта токена:

```json
{
  "iss": "https://auth.securenotes.com",
  "sub": "user-123",
  "aud": "https://api.securenotes.com",
  "exp": 1716242622,
  "iat": 1716239022,
  "name": "Максим Витребенько",
  "role": "editor",
  "scopes": ["notes:read", "notes:write"]
}
```

> Payload **НЕ зашифрований** — лише закодований у Base64URL. Будь-хто може його прочитати!

---

# Signature (Підпис)

```
SIGNATURE = алгоритм(
  base64url(header) + "." + base64url(payload),
  ключ
)
```

```
┌───────────────────────────────┬──────────────────────┐
│  Може прочитати будь-хто      │ Може створити лише   │
│  (Header + Payload)           │ власник ключа        │
│  Base64URL decode             │ (Signature)          │
└───────────────────────────────┴──────────────────────┘
```

JWT гарантує **цілісність** (не підроблений), але не **конфіденційність** (видимий)

---

# Registered Claims

Стандартизовані claims (RFC 7519), всі рекомендовані:

| Claim | Назва | Опис |
|-------|-------|------|
| `iss` | Issuer | Хто видав токен |
| `sub` | Subject | Для кого видано (ID) |
| `aud` | Audience | Для якого сервісу |
| `exp` | Expiration | Коли стає недійсним |
| `nbf` | Not Before | До якого часу недійсний |
| `iat` | Issued At | Коли видано |
| `jti` | JWT ID | Унікальний ідентифікатор |

---

# Public та Private Claims

<div class="columns">
<div>

**Public Claims**

Зареєстровані в IANA або визначені як URI

```json
{
  "email": "maksym@example.com",
  "email_verified": true,
  "name": "Максим Витребенько"
}
```

OpenID Connect стандарт

</div>
<div>

**Private Claims**

За домовленістю між сторонами

```json
{
  "role": "editor",
  "workspace_id": "ws-456",
  "features": ["export"]
}
```

Внутрішні потреби системи

</div>
</div>

---

# JWS vs JWE

<div class="columns">
<div>

**JWS** (JSON Web Signature)

- Payload **видимий**
- Захист від **підробки**
- `header.payload.signature`
- 99% випадків "JWT"

</div>
<div>

**JWE** (JSON Web Encryption)

- Payload **зашифрований**
- Захист від **читання**
- 5 частин: `header.key.iv.ciphertext.tag`
- Коли payload конфіденційний

</div>
</div>

Для SecureNotes Максим обирає **JWS** — payload містить лише user ID, роль та scopes

---

# HS256 — симетричний підпис

**HMAC-SHA256** — один секретний ключ для створення та перевірки

```
┌──────────────┐   secret_key    ┌──────────────┐
│  Auth Server │ ════════════════ │  API Server  │
│  sign(key)   │  Один і той     │  verify(key) │
└──────────────┘  самий ключ!    └──────────────┘
```

**Плюс:** простий, швидкий

**Мінус:** кожен, хто знає ключ, може **створювати** токени

Підходить для монолітних систем

---

# RS256 — асиметричний підпис

**RSA-SHA256** — приватний ключ для підпису, публічний для верифікації

```
┌──────────────┐                 ┌──────────────┐
│  Auth Server │                 │  API Server  │
│              │   public_key    │              │
│  sign(       │ ──────────────→ │  verify(     │
│   private_key│                 │   public_key)│
│  )           │                 │              │
└──────────────┘                 └──────────────┘
  Може створювати                  Може лише
  токени                           перевіряти
```

Ідеально для **мікросервісів** — верифікатор не може підробити токен

---

# ES256 — ECDSA

Еліптичні криві — асиметричний, як RS256, але компактніший

| Параметр | RS256 | ES256 |
|----------|-------|-------|
| Розмір ключа | 2048+ біт | 256 біт |
| Розмір підпису | 256 байт | 64 байти |
| Швидкість підпису | повільна | швидка |
| Швидкість верифікації | швидка | повільніша |
| Рівень безпеки | 112 біт | 128 біт |

Рекомендований для мобільних додатків та IoT

---

# "alg": "none" — НЕБЕЗПЕЧНО!

Специфікація JWT дозволяє `"alg": "none"` — токен без підпису

```
Атакуючий:
Header:    {"alg": "none", "typ": "JWT"}
Payload:   {"sub": "admin", "role": "superadmin"}
Signature: (порожній)

Результат: eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
                                                     ^
                                          порожній підпис!
```

**НІКОЛИ** не приймайте `alg: none` у production

Завжди налаштовуйте whitelist дозволених алгоритмів

---

# Порівняння алгоритмів

| Алгоритм | Тип | Підпис | Верифікація | Рекомендація |
|----------|-----|--------|-------------|--------------|
| HS256 | Симетричний | shared secret | shared secret | Моноліти |
| RS256 | Асиметричний | private key | public key | Мікросервіси |
| ES256 | Асиметричний | private key | public key | Мобільні, IoT |
| none | Немає | — | — | **ЗАБОРОНЕНО** |

---

# JWKS — JSON Web Key Set

**Проблема:** як передати публічний ключ 5 мікросервісам? А при ротації ключів?

**Рішення:** Authorization Server публікує ключі за відомим URL:

```
GET https://auth.securenotes.com/.well-known/jwks.json
```

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
    }
  ]
}
```

---

# Верифікація з JWKS

```
┌──────────┐  JWT (kid: "key-2024-01")  ┌──────────────┐
│  Client  │ ─────────────────────────→ │  API Server  │
└──────────┘                            │              │
                                        │ 1. Читає kid │
              GET /.well-known/jwks.json│              │
┌──────────────┐ ←──────────────────── │ 2. Запитує   │
│  Auth Server │ ─────────────────────→ │    JWKS      │
│              │  { "keys": [...] }     │              │
└──────────────┘                        │ 3. Верифікує │
                                        └──────────────┘
```

API Server **кешує** JWKS — не запитує при кожному токені

Поле `kid` у JWT header визначає, яким ключем перевіряти

---

# Ротація ключів через JWKS

1. Auth Server генерує новий ключ (`key-2024-02`)
2. Публікує **обидва** ключі в JWKS (старий + новий)
3. Нові токени підписує новим ключем
4. Старі токени продовжують верифікуватися старим ключем
5. Після закінчення всіх старих токенів — видаляє старий ключ

Безшовна ротація без downtime

---

# JWT Validation Checklist

```
JWT отримано
    │
    ▼
1. Структура: три частини?         ──→ ні → відхилити
    ▼
2. Header: alg у whitelist?        ──→ ні → відхилити
    ▼
3. Signature валідний?             ──→ ні → відхилити
    ▼
4. exp: не прострочений?           ──→ ні → відхилити
    ▼
5. nbf: вже активний?             ──→ ні → відхилити
    ▼
6. iss: очікуваний issuer?        ──→ ні → відхилити
    ▼
7. aud: для цього сервісу?        ──→ ні → відхилити
    ▼
8. Scopes, roles?                 ──→ ні → відхилити
    ▼
Токен прийнято
```

---

# Clock Skew

Годинники серверів не ідеально синхронізовані

Рекомендується tolerance **30-60 секунд**:

```python
import time

CLOCK_SKEW_SECONDS = 30

def is_expired(exp_claim):
    return time.time() > exp_claim + CLOCK_SKEW_SECONDS
```

Без clock skew tolerance — токен може бути відхилений передчасно

---

# Атака "alg: none"

```
Оригінал:   {"alg": "RS256"} . {"sub": "user-123"} . <підпис>
Підробка:   {"alg": "none"}  . {"sub": "admin"}     .

Вразливий сервер:
  "Алгоритм none — підпис не потрібен. ОК!"
```

**Захист:** завжди перевіряти `alg` проти whitelist

```python
# ПРАВИЛЬНО — явний whitelist:
decoded = jwt.decode(token, key, algorithms=["RS256"])

# НЕПРАВИЛЬНО — довіряти alg з токена:
decoded = jwt.decode(token, key, algorithms=jwt.get_unverified_header(token)["alg"])
```

---

# Symmetric Key Confusion

Сервер очікує **RS256**, атакуючий надсилає **HS256**

```
Атакуючий:
1. Завантажує public_key з JWKS
2. Змінює header: {"alg": "HS256"}
3. HMAC-SHA256(header.payload, public_key) = signature
4. Відправляє токен

Вразливий сервер:
  alg = "HS256" → бере public_key як HMAC-секрет
  HMAC(data, public_key) == signature? ТАК!
```

**Захист:** завжди явно вказувати очікуваний алгоритм при верифікації

---

# Ще типові помилки

| Помилка | Наслідок | Захист |
|---------|----------|--------|
| Не перевіряти `exp` | Вічний токен | Завжди перевіряти `exp` |
| Sensitive data у payload | Витік через Base64 decode | Лише несекретні дані |
| `exp` = 30 днів | Довге вікно атаки | Short-lived + refresh |

**Рекомендований час життя:**

| Тип токена | Рекомендований exp |
|------------|-------------------|
| Access Token | 5-15 хвилин |
| ID Token | 5-60 хвилин |
| Refresh Token | дні-тижні (з ротацією) |

---

# Практика: HS256 з PyJWT

```python
import jwt, time

SECRET_KEY = "supersecret-key-at-least-32-bytes-long!"

# Створення
token = jwt.encode({
    "iss": "https://auth.securenotes.com",
    "sub": "user-123",
    "aud": "https://api.securenotes.com",
    "exp": int(time.time()) + 900,
    "role": "editor"
}, SECRET_KEY, algorithm="HS256")

# Верифікація
decoded = jwt.decode(token, SECRET_KEY,
    algorithms=["HS256"],
    audience="https://api.securenotes.com",
    issuer="https://auth.securenotes.com")
print(decoded["role"])  # "editor"
```

---

# Практика: RS256 з PyJWT

```python
import jwt, time
from cryptography.hazmat.primitives.asymmetric import rsa

# Генерація ключів (Auth Server, один раз)
private_key = rsa.generate_private_key(
    public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Auth Server: створення (приватний ключ)
token = jwt.encode(
    {"sub": "user-123", "exp": int(time.time()) + 900,
     "aud": "https://api.securenotes.com"},
    private_key, algorithm="RS256",
    headers={"kid": "key-2024-01"})

# API Server: верифікація (публічний ключ)
decoded = jwt.decode(token, public_key,
    algorithms=["RS256"],
    audience="https://api.securenotes.com")
```

---

# Демонстрація: підробка payload

```python
import jwt, base64, json

SECRET = "my-secret-key-32-bytes-long!!!!!"
token = jwt.encode({"sub": "user-123", "role": "viewer"},
                   SECRET, algorithm="HS256")

# Атакуючий декодує payload (це просто Base64!)
parts = token.split(".")
payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
payload["role"] = "admin"  # Змінює роль!

new_payload = base64.urlsafe_b64encode(
    json.dumps(payload).encode()).rstrip(b"=").decode()
forged = f"{parts[0]}.{new_payload}.{parts[2]}"

try:
    jwt.decode(forged, SECRET, algorithms=["HS256"])
except jwt.InvalidSignatureError:
    print("Підпис невалідний — підробку виявлено!")
```

---

# Підсумки

- **JWT** = self-contained токен: header.payload.signature
- Payload **НЕ зашифрований** — не зберігайте секретні дані
- **HS256** — симетричний (моноліти), **RS256/ES256** — асиметричні (мікросервіси)
- **JWKS** — публікація ключів, безшовна ротація
- **Validation**: alg whitelist, signature, exp, iss, aud
- **alg: none** та **key confusion** — найнебезпечніші атаки

---

# Що далі?

**Лекція 7: Access Token vs Refresh Token — lifecycle**

- **Access Token** vs **Refresh Token** — різні ролі, різний час життя
- **Token Rotation** — ротація refresh tokens
- **Token Revocation** — відкликання у stateless-архітектурі
- **Sliding sessions** vs **absolute expiration**

Максим Витребенько реалізує повний lifecycle токенів для SecureNotes

---

<!-- _class: title -->

# Дякую за увагу!

Питання?
