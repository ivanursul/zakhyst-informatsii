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

Лекція 10. Атаки на OAuth та захист

Львівський національний університет імені Івана Франка
Спеціальність 113 — Прикладна математика

2025

---

# План лекції

1. Чому атаки на OAuth важливі
2. CSRF атаки (відсутність state)
3. Open Redirect (маніпуляція redirect_uri)
4. Token Leakage через Referer
5. Mix-Up Attack
6. Authorization Code Injection
7. Clickjacking та Phishing
8. Комплексний захист (Mitigations)
9. Практика: пен-тест SecureNotes

---

# Від побудови до зламу

У лекції 10 ми **побудували** повноцінну OAuth-систему

Тепер ми її **зламаємо**

> Якщо ви не зламаєте свою систему самі, це зробить хтось інший

**Максим Витребенько** проводить пен-тест SecureNotes і знаходить вразливості

---

# Чому OAuth — улюблена ціль

OAuth працює через:

- **Redirects** між різними доменами
- **Передачу токенів** через URL та browser
- **Взаємодію кількох сторін** (Client, AS, RS, User)

Кожен з цих етапів — потенційна точка атаки

| Наслідок | Опис |
|---|---|
| Account takeover | Атакуючий отримує access token жертви |
| Account linking | Прив'язка чужого акаунту |
| Token leakage | Token витікає через логи, Referer |
| Privilege escalation | Ширший scope, ніж дозволено |

---

# CSRF атака: проблема

**CSRF (Cross-Site Request Forgery)** — атакуючий змушує браузер жертви завершити OAuth flow з **authorization code атакуючого**

Результат: акаунт жертви прив'язується до зовнішнього акаунту атакуючого

---

# CSRF атака: схема

```
Mallory                                 Максим
  │                                       │
  │ 1. Починає OAuth flow зі своїм        │
  │    акаунтом, отримує code             │
  │                                       │
  │ 2. НЕ завершує flow, створює URL:     │
  │    /callback?code=MALLORY_CODE        │
  │                                       │
  │ 3. Надсилає посилання Максиму   ────→ │
  │                                       │
  │                    4. Максим клікає    │
  │                    5. Client обмінює   │
  │                       code Mallory    │
  │                    6. Акаунт Максима   │
  │                       прив'язаний до   │
  │                       Google Mallory!  │
```

---

# CSRF атака: захист — state parameter

```python
# ВРАЗЛИВИЙ — без state
@app.get("/login")
def login():
    return redirect(f"{AUTH_SERVER}/authorize"
        f"?response_type=code&client_id={CLIENT_ID}")

# БЕЗПЕЧНИЙ — з state
@app.get("/login")
def login():
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    return redirect(f"{AUTH_SERVER}/authorize"
        f"?response_type=code&client_id={CLIENT_ID}"
        f"&state={state}")

@app.get("/callback")
def callback(code: str, state: str):
    if state != session.get("oauth_state"):
        return "CSRF detected", 403
```

---

# Open Redirect: проблема

Атакуючий маніпулює `redirect_uri` — Authorization Server перенаправляє code/token на сервер атакуючого

```
Нормально:
  redirect_uri=https://securenotes.example/callback
  → code йде на securenotes.example

Атака:
  redirect_uri=https://evil.example/steal
  → code йде на evil.example!
```

---

# Open Redirect: вектори маніпуляції

```
Зареєстрований: https://securenotes.example/callback

Маніпуляції:
  .../callback/../../../evil
  .../callback%00@evil.com
  https://securenotes.example.evil.com/callback
  .../callback?next=https://evil.com
```

```python
# ВРАЗЛИВО — перевірка початку URL
def validate(uri, registered):
    return uri.startswith(registered)  # Обходиться!

# БЕЗПЕЧНО — точне порівняння
def validate(uri, registered):
    return uri == registered  # Exact match
```

---

# Implicit Flow — особливо вразливий

```
GET /authorize
  ?response_type=token
  &redirect_uri=https://evil.example/steal

→ https://evil.example/steal#access_token=eyJhbGci...

Атакуючий отримує access token напряму!
```

Саме тому **OAuth 2.1 забороняє Implicit Flow**

---

# Token Leakage через Referer

```
1. Redirect: /callback?code=abc123

2. Сторінка завантажує зовнішній ресурс:
   <img src="https://analytics.example/pixel.gif">

3. Браузер додає Referer:
   GET /pixel.gif
   Referer: .../callback?code=abc123
                         ^^^^^^^^^^^^
                         Code у Referer!

4. analytics.example бачить code
```

Кожен зовнішній ресурс (analytics, CDN, ads, fonts) отримує Referer з authorization code

---

# Token Leakage: захист

```python
# 1. Негайно обміняти code і перенаправити
@app.get("/callback")
def callback(code: str, state: str):
    token = exchange_code(code)
    session["access_token"] = token
    return redirect("/dashboard")  # URL без code

# 2. Referrer-Policy заголовок
@app.after_request
def headers(response):
    response.headers["Referrer-Policy"] = "no-referrer"
    return response
```

**PKCE** також допомагає: навіть якщо code витік, без `code_verifier` він марний

---

# Mix-Up Attack

Client підтримує кілька Authorization Server. Атакуючий підміняє відповідь одного AS відповіддю іншого

```
Client          Evil AS           Google
  │ 1. /authorize  │                │
  │ (issuer=evil)  │                │
  │───────────────→│                │
  │ 2. redirect    │                │
  │    to Google   │                │
  │←───────────────│                │
  │ 3. /authorize  │                │
  │────────────────────────────────→│
  │ 4. code=GOOGLE_CODE             │
  │←────────────────────────────────│
  │ 5. Client думає: "це від Evil"  │
  │    Відправляє code на Evil AS   │
  │───────────────→│                │
  │    Evil має Google code!        │
```

---

# Mix-Up Attack: захист — RFC 9207

Authorization Server додає `iss` до callback:

```
/callback?code=abc123&iss=https://accounts.google.com
```

```python
@app.get("/callback")
def callback(code: str, state: str, iss: str):
    expected_issuer = session.get("oauth_issuer")

    if iss != expected_issuer:
        return "Mix-Up Attack detected", 403

    token_endpoint = get_token_endpoint(iss)
    token = exchange_code(code, token_endpoint)
```

---

# Authorization Code Injection

Атакуючий перехоплює code жертви і використовує у своєму flow

```
CSRF:            Атакуючий підставляє СВІЙ code жертві
Code Injection:  Атакуючий використовує code ЖЕРТВИ
```

```
Максим отримує code → Mallory перехоплює →
→ Mallory підставляє у свій callback →
→ Client обмінює code → Mallory має доступ до Максима!
```

---

# Code Injection: захист — PKCE

```
Максим починає flow:
  code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1..."
  code_challenge = SHA256(code_verifier)
  /authorize?...&code_challenge=E9Melhoa2Owv...

Mallory перехоплює code, але НЕ знає code_verifier

POST /token
  code=STOLEN_CODE
  code_verifier=???  ← Mallory не знає!

Authorization Server:
  SHA256(???) != stored code_challenge
  → 400 Bad Request
```

---

# Clickjacking

Атакуючий вбудовує consent screen в прозорий iframe

```
┌──────────────────────────────────────┐
│  evil.example                         │
│                                       │
│  "Натисніть тут для призу!"          │
│  [ОТРИМАТИ ПРИЗ]  ←── видима кнопка  │
│                                       │
│  (прозорий iframe під кнопкою)       │
│  "Дозволити доступ?"                 │
│  [ДОЗВОЛИТИ]      ←── справжня кнопка│
│                                       │
│  Кнопки накладаються!                │
└──────────────────────────────────────┘
```

Жертва думає, що натискає "Приз", а натискає "Дозволити"

---

# Clickjacking: захист

```python
@app.after_request
def security_headers(response):
    # Забороняє вбудовування в iframe
    response.headers["X-Frame-Options"] = "DENY"

    # Сучасніший підхід
    response.headers["Content-Security-Policy"] = (
        "frame-ancestors 'none'"
    )
    return response
```

Authorization Server **обов'язково** встановлює ці заголовки на consent screen

---

# Phishing — підроблений consent screen

```
Легітимний:  https://accounts.google.com/authorize
Підроблений: https://accounts.g00gle.com/authorize
```

Особливо небезпечний в контексті OAuth:

- Користувачі **звикли** бачити redirect на Google/GitHub
- Після крадіжки credentials атакуючий **виконує справжній flow** — жертва нічого не підозрює

**Захист:**

- **FIDO2/WebAuthn** — ключ прив'язаний до домену (phishing-resistant)
- **Pushed Authorization Requests (PAR)** — параметри через back-channel
- Навчання користувачів перевіряти URL

---

# Огляд атак та захисту

| Атака | Захист | OAuth 2.1? |
|---|---|---|
| CSRF | `state` parameter | Так |
| Open Redirect | Exact redirect_uri match | Так |
| Token Leakage | Referrer-Policy, PKCE | Так |
| Mix-Up Attack | `iss` (RFC 9207) | Рекомендовано |
| Code Injection | PKCE | Так |
| Clickjacking | X-Frame-Options, CSP | Рекомендовано |
| Phishing | WebAuthn, PAR | Рекомендовано |
| Implicit Flow | Заборонено | Так |

---

# PKCE вирішує більшість проблем

```python
import secrets, hashlib, base64

def generate_pkce():
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(
            code_verifier.encode()
        ).digest()
    ).rstrip(b'=').decode()
    return code_verifier, code_challenge

# /authorize: &code_challenge={challenge}
#             &code_challenge_method=S256
# /token:     code_verifier={verifier}
```

PKCE захищає від: Code Injection, Token Leakage, частково CSRF

---

# Sender-Constrained Tokens

<div class="columns">
<div>

**Bearer Token (традиційний):**

Хто має token — той використовує

Якщо token вкрадено — атакуючий має повний доступ

</div>
<div>

**Sender-Constrained:**

Token прив'язаний до конкретного клієнта

- **mTLS** (RFC 8705) — прив'язка до TLS-сертифіката
- **DPoP** (RFC 9449) — proof-of-possession з ключем

</div>
</div>

---

# Практика: пен-тест SecureNotes

Максим Витребенько проводить пен-тест і знаходить:

```
┌─────────────────────────────────────────────┐
│  SecureNotes Pen-Test Report                 │
├─────────────────────────────────────────────┤
│  [CRITICAL] Відсутність state parameter      │
│  [HIGH]     Неточна перевірка redirect_uri   │
│  [HIGH]     Відсутність PKCE                 │
│  [MEDIUM]   Clickjacking consent screen      │
│  [MEDIUM]   Token leakage (query string)     │
├─────────────────────────────────────────────┤
│  Усі вразливості виправлено                  │
│  Рекомендація: мігрувати на OAuth 2.1        │
└─────────────────────────────────────────────┘
```

---

# Виправлення: повний безпечний flow

```python
@app.get("/login")
def login():
    state = secrets.token_urlsafe(32)
    verifier, challenge = generate_pkce()
    session["oauth_state"] = state
    session["code_verifier"] = verifier
    return redirect(
        f"{AUTH}/authorize?response_type=code"
        f"&client_id={CID}&redirect_uri={URI}"
        f"&state={state}"
        f"&code_challenge={challenge}"
        f"&code_challenge_method=S256")

@app.get("/callback")
def callback(code: str, state: str):
    if state != session.pop("oauth_state", None):
        return "CSRF detected", 403
    verifier = session.pop("code_verifier")
    token = exchange_code(code, verifier)
```

---

# Підсумки

- **CSRF** — state parameter прив'язує flow до сесії
- **Open Redirect** — лише exact match для redirect_uri
- **Token Leakage** — Referrer-Policy + PKCE
- **Mix-Up** — iss parameter (RFC 9207)
- **Code Injection** — PKCE прив'язує code до сесії
- **Clickjacking** — X-Frame-Options / CSP
- **Phishing** — WebAuthn, навчання користувачів

**OAuth 2.1** робить PKCE та exact redirect_uri обов'язковими

---

# Що далі?

**Лекція 11: OAuth у мікросервісній архітектурі**

- **Service-to-service authentication** — як мікросервіси автентифікують один одного
- **Token propagation** — передача access token між сервісами
- **API Gateway** — єдина точка входу для перевірки токенів
- **Token Exchange** (RFC 8693) — обмін токенів для downstream сервісів
- **Zero Trust Architecture** — кожен сервіс перевіряє кожен запит

---

<!-- _class: title -->

# Дякую за увагу!

Питання?
