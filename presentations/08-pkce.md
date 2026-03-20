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

Лекція 8. PKCE та безпека публічних клієнтів

Львівський національний університет імені Івана Франка
Спеціальність 113 — Прикладна математика

2025

---

# План лекції

1. Проблема публічних клієнтів
2. Authorization Code Interception Attack
3. PKCE — Proof Key for Code Exchange (RFC 7636)
4. code_verifier та code_challenge (S256)
5. Повний flow з PKCE
6. Mobile/SPA considerations
7. OAuth 2.1 — PKCE обов'язковий для всіх
8. Практика — PKCE flow на Python

---

# Міст від лекції 8

У лекції 8 ми розглянули **Authorization Code Flow**:

- Клієнт отримує authorization code
- Обмінює code на токен, автентифікуючись через `client_secret`
- Безпечно, бо секрет зберігається **на сервері**

**Але що, якщо клієнт не може зберегти секрет?**

---

# Два типи клієнтів (RFC 6749)

<div class="columns">
<div>

**Конфіденційний клієнт**

- Серверний додаток
- `client_secret` на сервері
- Django, Spring Boot, Express
- Секрет ніколи не покидає сервер

</div>
<div>

**Публічний клієнт**

- Код доступний користувачу
- Будь-який секрет видобувається
- SPA (React, Vue, Angular)
- Мобільний додаток (iOS, Android)

</div>
</div>

---

# SPA не може зберегти секрет

Максим Витребенько додає SPA frontend для SecureNotes

```
Конфіденційний клієнт (сервер):
┌───────────────────────────┐
│  client_secret = "abc..."  │  ← захищено на сервері
└───────────────────────────┘

Публічний клієнт (SPA):
┌───────────────────────────┐
│  const secret = "abc..."   │  ← видимий у DevTools
│  // Sources tab → весь код │     мінімізація не допоможе
└───────────────────────────┘
```

Мобільний додаток: декомпіляція (jadx, Ghidra), mitmproxy, jailbreak

---

# Висновок: публічний клієнт беззахисний

Публічний клієнт **не може автентифікуватися** при обміні code на токен

Він не може довести, що це саме він, а не зловмисник, який перехопив code

> Потрібен інший механізм, який прив'яже code до конкретної сесії клієнта

---

# Authorization Code Interception Attack

Зловмисник перехоплює authorization code під час redirect і обмінює його на access token

```
Authorization Server
        │
        │  redirect: myapp://callback?code=abc123
        ▼
┌─────────────────────────────────┐
│         Операційна система       │
│                                  │
│  myapp:// зареєстровано:         │
│    ✓  SecureNotes (легітимний)   │
│    ✓  MalwareApp (зловмисник)    │
│                                  │
│  Хто отримає redirect?           │
│  → ОС може передати будь-якому!  │
└─────────────────────────────────┘
```

---

# Вектори перехоплення

**Мобільні додатки:**
- Custom URI scheme (`myapp://`) — будь-який додаток може зареєструвати
- На Android: intent filter без обмежень
- ОС може передати redirect зловмисному додатку

**SPA у браузері:**
- Відкриті redirectори — недостатня валідація `redirect_uri`
- Зловмисні browser extensions — доступ до URL-рядка
- Shared logs — code в URL потрапляє в логи, проксі, історію

---

# Чому state не рятує

Параметр `state` захищає від **CSRF**, але **не від перехоплення code**:

- `state` перевіряється на стороні клієнта
- Зловмисник відправляє code зі **свого** клієнта, де сам формує `state`
- `state` не прив'язує code до конкретного клієнта

**Потрібен механізм, який прив'яже code до того, хто його запросив**

---

# PKCE — Proof Key for Code Exchange

**PKCE** (вимовляється "pixy") — розширення OAuth 2.0, визначене в **RFC 7636** (2015)

Техніка **commit-reveal**:

1. **Commit** — клієнт генерує секрет, обчислює хеш, відправляє хеш
2. **Reveal** — при обміні code на токен клієнт розкриває секрет

Сервер перевіряє: `SHA256(секрет) == збережений хеш?`

> Навіть перехопивши code, зловмисник не знає секрет

---

# Аналогія з печаткою

```
Крок 1 — Commit:
  Максим ставить відбиток печатки на конверт
  → Одержувач зберігає відбиток

Крок 2 — Reveal:
  Максим приходить з оригіналом печатки
  → Одержувач порівнює: відбиток збігається?
  → Так: видати відповідь
  → Ні:  відмовити

Зловмисник бачить відбиток, але не має печатки
SHA-256 = одностороння функція (лекція 2)
```

---

# code_verifier

**code_verifier** — випадковий рядок, згенерований клієнтом

- Довжина: 43-128 символів
- Символи: `[A-Za-z0-9]`, `-`, `.`, `_`, `~`
- Генерується через **CSPRNG**

```python
import secrets
import base64

code_verifier = base64.urlsafe_b64encode(
    secrets.token_bytes(32)
).rstrip(b'=').decode('ascii')

# Приклад: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

---

# code_challenge (S256)

**code_challenge** = `BASE64URL(SHA256(code_verifier))`

```
code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

Крок 1: SHA-256
  SHA256(code_verifier) → [0xe9, 0x14, 0x6c, ...]

Крок 2: Base64url (без padding)
  base64url(bytes) → "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
```

```python
import hashlib

digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
```

---

# Два методи трансформації

| Метод | Формула | Рекомендація |
|---|---|---|
| `plain` | `challenge = verifier` | Не рекомендований |
| `S256` | `challenge = BASE64URL(SHA256(verifier))` | **Обов'язковий** |

**plain** — без трансформації, не захищає від перехоплення challenge

**S256** — SHA-256 + base64url, зловмисник не може відновити verifier з challenge

---

# Повний flow з PKCE (1/2)

```
Client (SPA)                        Authorization Server
    │                                       │
    │ 1. code_verifier = random()           │
    │    code_challenge = SHA256(verifier)   │
    │                                       │
    │ 2. GET /authorize?                    │
    │      code_challenge=E9Mel...          │
    │      &code_challenge_method=S256      │
    │      &client_id=spa-app               │
    │      &response_type=code              │
    │  ───────────────────────────────────→  │
    │                                       │
    │              3. Зберігає challenge     │
    │              4. Логін + consent        │
    │                                       │
    │ 5. /callback?code=abc123&state=xyz    │
    │  ←───────────────────────────────────  │
```

---

# Повний flow з PKCE (2/2)

```
Client (SPA)                        Authorization Server
    │                                       │
    │ 6. POST /token                        │
    │      code=abc123                      │
    │      code_verifier=dBjft...           │
    │      client_id=spa-app                │
    │  ───────────────────────────────────→  │
    │                                       │
    │              7. SHA256(verifier)       │
    │                 == challenge?          │
    │                 ✓ Так → токен          │
    │                 ✗ Ні  → 400 error     │
    │                                       │
    │ 8. { access_token, token_type }       │
    │  ←───────────────────────────────────  │
```

---

# Чому зловмисник не може обійти PKCE

1. `code_verifier` **ніколи не передавався по мережі** до кроку 6
2. На кроці 2 передавався лише `code_challenge` — **хеш** verifier
3. SHA-256 — **одностороння функція**: знаючи challenge, неможливо обчислити verifier
4. Без правильного `code_verifier` token endpoint **відхилить запит**

> Перехоплення code без verifier — як знайти замок без ключа

---

# Custom URI schemes: проблема

```
myapp://callback?code=abc123
```

- На Android: будь-який додаток може зареєструвати `myapp://`
- На iOS: можливі конфлікти URI schemes між додатками
- ОС вирішує, кому передати redirect — може помилитися

**Рішення:** Universal Links (iOS), App Links (Android)

---

# Universal Links та App Links

```
Custom URI scheme (небезпечно):
  myapp://callback  → будь-який додаток

Claimed HTTPS redirect (безпечно):
  https://app.example.com/callback
    → тільки додаток, що підтвердив
      володіння доменом
```

- **iOS:** файл `apple-app-site-association` на домені
- **Android:** файл `assetlinks.json` у `.well-known/`
- Криптографічне підтвердження зв'язку додаток-домен

---

# Зберігання токенів у SPA

| Метод | Безпека | Ризики |
|---|---|---|
| `localStorage` | Низька | XSS-атаки |
| `sessionStorage` | Середня | XSS, зникає при закритті |
| In-memory | Висока | Зникає при refresh |
| HttpOnly cookie (BFF) | Висока | Потребує backend |

**Рекомендація:** BFF (Backend-for-Frontend) pattern — тонкий серверний шар, токени в HttpOnly cookies, недоступних для JavaScript

---

# OAuth 2.1: ключові зміни

| OAuth 2.0 | OAuth 2.1 |
|---|---|
| PKCE рекомендований | **PKCE обов'язковий для всіх** |
| Implicit Flow дозволений | **Implicit Flow видалений** |
| ROPC Flow дозволений | **ROPC Flow видалений** |
| redirect_uri — рекомендується exact match | **Exact match обов'язковий** |
| Refresh token rotation — рекомендується | **Rotation обов'язкова** |

OAuth 2.1 — кодифікація best practices, накопичених за роки

---

# Чому PKCE навіть для конфіденційних клієнтів

- **Defense in depth** — додатковий рівень захисту, навіть якщо `client_secret` скомпрометований
- **Authorization code injection** — без PKCE зловмисник може підставити свій code у сесію жертви
- **Уніфікація** — один flow для всіх клієнтів спрощує реалізацію та аудит

> Implicit Flow (`response_type=token`) — **видалений** в OAuth 2.1. Замість нього: Authorization Code + PKCE

---

# Практика: генерація PKCE пари

```python
import hashlib, base64, secrets

def generate_pkce_pair():
    """Генерує code_verifier та code_challenge (S256)."""
    verifier_bytes = secrets.token_bytes(32)
    code_verifier = base64.urlsafe_b64encode(
        verifier_bytes
    ).rstrip(b'=').decode('ascii')

    digest = hashlib.sha256(
        code_verifier.encode('ascii')
    ).digest()
    code_challenge = base64.urlsafe_b64encode(
        digest
    ).rstrip(b'=').decode('ascii')

    return code_verifier, code_challenge
```

---

# Практика: обмін code на токен

```python
import requests

def exchange_code_for_token(code, code_verifier):
    response = requests.post(
        "https://auth.example.com/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": code_verifier,
        },
    )
    return response.json()
```

`code_verifier` замість `client_secret` — proof для публічного клієнта

---

# Практика: PKCE в Bash

```bash
# 1. Генеруємо code_verifier
CODE_VERIFIER=$(openssl rand -base64 32 | \
  tr '+/' '-_' | tr -d '=')

# 2. Обчислюємо code_challenge (S256)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | \
  openssl dgst -sha256 -binary | \
  openssl base64 | tr '+/' '-_' | tr -d '=')

# 3. Обмін code на токен
curl -X POST https://auth.example.com/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "client_id=securenotes-spa" \
  -d "code_verifier=$CODE_VERIFIER"
```

---

# Підсумки

- Публічні клієнти (SPA, mobile) **не можуть зберігати `client_secret`**
- PKCE (RFC 7636) — **commit-reveal** через SHA-256 + base64url
- `code_challenge` = `BASE64URL(SHA256(code_verifier))` — метод S256
- Зловмисник, перехопивши code, не знає verifier — SHA-256 одностороння
- Мобільні додатки: **Universal Links / App Links** замість custom URI schemes
- OAuth 2.1: **PKCE обов'язковий для всіх клієнтів**

---

# Що далі?

**Лекція 9: OIDC — автентифікація поверх OAuth**

OAuth 2.0 = **авторизація** (дати доступ до ресурсів)
OIDC = **автентифікація** (впізнати людину)

- **ID Token** — JWT з інформацією про користувача
- **UserInfo endpoint** — стандартизований API для профілю
- **Discovery** — автоматичне виявлення конфігурації IdP
- **Claims** — стандартизовані атрибути (sub, email, name)

---

<!-- _class: title -->

# Дякую за увагу!

Питання?
