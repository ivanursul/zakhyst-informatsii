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

# Захист інформації: OAuth від фундаменту до продакшену

Лекція 1. Вступ. Проблема довіри в інтернеті

Львівський національний університет імені Івана Франка
Спеціальність 113 — Прикладна математика

2025

---

# План лекції

1. Вступ до захисту інформації
2. Проблема довіри в інтернеті
3. Identity, Authentication, Authorization
4. Історія: Basic Auth → Сесії → Токени → OAuth
5. Threat Modeling: модель STRIDE

---

# CIA Triad

Три стовпи інформаційної безпеки:

| Принцип | Опис |
|---------|------|
| **Confidentiality** | Доступ лише для уповноважених осіб |
| **Integrity** | Дані не змінені несанкціоновано |
| **Availability** | Інформація доступна, коли потрібно |

Кожна атака порушує щонайменше один з цих принципів

---

# Про цей курс

**OAuth 2.0** — центральна вісь курсу

Через OAuth розкриваємо:

- Криптографічні примітиви (хешування, шифрування, підписи)
- Протоколи автентифікації та авторизації
- Безпеку веб-додатків та мікросервісів
- Моделювання загроз

**Принцип:** спочатку проблема → потім інструмент

---

# Проблема довіри в інтернеті

Коли ви заходите на сайт банку:

1. Чи справжній цей **сайт**? *(автентичність сервера)*
2. Чи справжній цей **користувач**? *(автентифікація клієнта)*
3. Чи **дозволено** виконати цю дію? *(авторизація)*
4. Чи не **перехоплено** дані? *(конфіденційність каналу)*
5. Чи не **підмінено** дані? *(цілісність)*

---

# Проблема делегування доступу

**Сценарій:** Максим Витребенько хоче, щоб сервіс друку отримав доступ до його фото в Google Photos

**Наївний підхід — Максим дає свій пароль:**

- Сервіс отримує **повний доступ** до акаунту Максима
- Неможливо **відкликати** без зміни пароля
- Якщо сервіс зламають — зламають і Google Максима
- Немає **контролю** над діями сервісу

OAuth 2.0 вирішує саме цю проблему

---

# Модель загроз у мережі

Ми припускаємо існування **активного атакуючого**, який може:

- **Перехоплювати** трафік *(eavesdropping)*
- **Модифікувати** повідомлення *(tampering)*
- **Повторювати** перехоплені запити *(replay attack)*
- **Видавати себе** за іншу сторону *(impersonation)*

Кожен механізм безпеки — відповідь на ці загрози

---

# Identity — Ідентичність

**"Хто це?"**

Набір атрибутів, що описують сутність у системі:

- Username: `maksym.vytrebenko`
- Email: `maksym.vytrebenko@example.com`
- ID: `user-12345`
- X.509 сертифікат

Один користувач може мати **кілька identity** в різних системах

---

# Authentication — Автентифікація

**"Доведіть, що це ви"**

| Фактор | Опис | Приклад |
|--------|------|---------|
| **Something you know** | Знаєте лише ви | Пароль, PIN |
| **Something you have** | Маєте лише ви | Телефон, YubiKey |
| **Something you are** | Частина вас | Відбиток пальця, Face ID |

**MFA** = 2+ факторів одночасно

---

# Authorization — Авторизація

**"Що вам дозволено?"**

<div class="columns">
<div>

**Моделі авторизації:**

- **ACL** — список дозволів для кожного ресурсу
- **RBAC** — дозволи прив'язані до ролей
- **ABAC** — рішення на основі атрибутів
- **OAuth Scopes** — `read`, `write`, `admin`

</div>
<div>

**Послідовність:**

Автентифікація **завжди** передує авторизації: спочатку система впевнюється, хто ви, а потім вирішує, що вам дозволено

</div>
</div>

---

# Identity → Authentication → Authorization

```
  Запит користувача
         │
         ▼
  ┌──────────────────┐
  │  IDENTIFICATION   │  "Хто ви?"      → username: maksym
  └────────┬─────────┘
           ▼
  ┌──────────────────┐
  │  AUTHENTICATION   │  "Доведіть"     → password + 2FA
  └────────┬─────────┘
           ▼
  ┌──────────────────┐
  │  AUTHORIZATION    │  "Що дозволено?" → role: editor
  └──────────────────┘
```

---

# Еволюція автентифікації

```
Basic Auth ──→ Сесії ──→ Токени ──→ OAuth 2.0

Credentials    Credentials   Stateless    Делеговане
кожен запит    один раз      Scalable     авторизація
Base64         Stateful      JWT          Scopes
               Session ID    Self-contained
```

---

# HTTP Basic Auth

```http
GET /api/data HTTP/1.1
Authorization: Basic aXZhbjpwYXNzd29yZA==
```

**Проблеми:**

- Credentials з **кожним запитом** (Base64 ≠ шифрування!)
- Без HTTPS — plain text
- Немає **logout**
- Немає **делегування**
- Немає **гранулярності**

---

# Session-based Authentication

```
Client                    Server              Session Store
  │── POST /login ──────→│                    │
  │   (credentials)      │── create session ─→│ abc123: {user: ivan}
  │←── Set-Cookie: ──────│                    │
  │    session_id=abc123  │                    │
  │                       │                    │
  │── GET /resource ─────→│── lookup ─────────→│
  │   Cookie: abc123      │←── user data ─────│
  │←── 200 OK ───────────│                    │
```

**+** Credentials один раз, logout, стан
**−** Stateful, CSRF, cross-domain

---

# Token-based Authentication

```
Client                    Server
  │── POST /login ──────→│
  │   (credentials)      │ Генерує підписаний JWT
  │←── { token: "eyJ.." }│
  │                       │
  │── GET /resource ─────→│
  │   Authorization:      │ Верифікує підпис
  │   Bearer eyJ...       │ (без БД!)
  │←── 200 OK ───────────│
```

**+** Stateless, cross-domain, self-contained
**−** Revocation, розмір, зберігання на клієнті

---

# OAuth 2.0 — Делегована авторизація

```
User ──→ Client (сервіс друку)
              │
              │ redirect
              ▼
         Authorization Server (Google)
              │
              │ "Дозволити читати фото?"
              ▼
         User: "Так" (consent)
              │
              │ authorization code
              ▼
         Client ──→ Token Exchange ──→ Access Token
              │
              │ Bearer token (scope: photos.read)
              ▼
         Resource Server (Google Photos)
```

---

# Ролі OAuth 2.0

| Роль | Опис | Приклад |
|------|------|---------|
| **Resource Owner** | Власник ресурсів | Ви (ваші фото) |
| **Client** | Запитує доступ | Сервіс друку |
| **Authorization Server** | Видає токени | Google OAuth |
| **Resource Server** | Зберігає ресурси | Google Photos API |

---

# Що дає OAuth 2.0

- Користувач **не передає пароль** сторонньому сервісу
- Доступ обмежений **scopes** (тільки читання фото)
- Доступ можна **відкликати** в будь-який момент
- **Стандартизований** протокол (RFC 6749)

---

# Порівняння механізмів

| | Basic Auth | Сесії | Токени | OAuth 2.0 |
|--|-----------|-------|--------|-----------|
| Credentials кожен запит | Так | Ні | Ні | Ні |
| Stateless | Так | Ні | Так | Так |
| Logout | Ні | Так | Складно | Так |
| Cross-domain | Ні | Ні | Так | Так |
| Делегування | Ні | Ні | Ні | **Так** |
| Scopes | Ні | Ні | Ні | **Так** |

---

# Threat Modeling

**Систематичний підхід до визначення загроз**

<div class="columns">
<div>

**Ключові питання:**

1. **Що ми будуємо?** → Опис системи
2. **Що може піти не так?** → Ідентифікація загроз
3. **Що ми з цим зробимо?** → Mitigation
4. **Чи достатньо?** → Validation

</div>
<div>

**Стратегії реагування:**

- **Mitigate** — усунути загрозу
- **Accept** — прийняти ризик
- **Transfer** — передати відповідальність
- **Avoid** — уникнути сценарію

</div>
</div>

---

# Модель STRIDE

| Загроза | Порушує | Приклад |
|---------|---------|---------|
| **S**poofing | Authentication | Фішинговий сайт |
| **T**ampering | Integrity | Модифікація JWT payload |
| **R**epudiation | Non-repudiation | Заперечення транзакції |
| **I**nfo Disclosure | Confidentiality | Перехоплення токенів |
| **D**enial of Service | Availability | DDoS на Auth Server |
| **E**levation of Privilege | Authorization | Зміна scope на admin |

---

# STRIDE + OAuth 2.0

| STRIDE | Загроза в OAuth | Захист |
|--------|----------------|--------|
| **S** | Фішинговий Client, підробка redirect_uri | Валідація redirect_uri, client_secret |
| **T** | Модифікація authorization code, JWT | Цифрові підписи, HTTPS |
| **R** | Клієнт заперечує запит scope | Логування, audit trail |
| **I** | Токени в URL → логи, referrer | Back-channel, не в URL |
| **D** | Flood на token endpoint | Rate limiting |
| **E** | Розширення scope в токені | Валідація scopes, підпис |

---

# STRIDE: елементи DFD

| DFD Element | Applicable STRIDE |
|-------------|-------------------|
| External Entity | S, R |
| Process | S, T, R, I, D, E |
| Data Store | T, R, I, D |
| Data Flow | T, I, D |

---

# Підсумки

- **CIA Triad** — фундамент захисту інформації
- **Identity → Authentication → Authorization** — три окремі процеси
- **Basic Auth → Sessions → Tokens → OAuth** — кожен наступний крок вирішує проблеми попереднього
- OAuth 2.0 вирішує проблему **делегованого доступу**
- **STRIDE** — систематичний підхід до threat modeling

---

# Що далі?

**Лекція 2: Хешування та цілісність даних**

- SHA-256, bcrypt, Argon2
- Ентропія та CSPRNG
- HMAC
- Rainbow tables та salting
- Використання в OAuth-екосистемі

---

<!-- _class: title -->

# Дякую за увагу!

Питання?
