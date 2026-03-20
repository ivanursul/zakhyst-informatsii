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

Лекція 13. Проєктування безпечної системи. Підсумок

Львівський національний університет імені Івана Франка
Спеціальність 113 — Прикладна математика

2025

---

# План лекції

1. Від окремих механізмів до системи
2. Defense in Depth — багаторівневий захист
3. Zero Trust Architecture
4. Security by Design Principles
5. OWASP Top 10
6. Security Review Checklist
7. Повна архітектура SecureNotes
8. Підсумок курсу

---

# Від окремих механізмів до системи

12 лекцій — 12 інструментів захисту. Але **окремі цеглини ще не є будинком**

```
Л.2:  Хешування (Argon2)              ──┐
Л.3:  Шифрування та підписи — огляд   ──┤
Л.4:  OAuth 2.0 — архітектура         ──┤
Л.5:  Authorization Code Flow         ──┤
Л.6:  JWT                             ──┤
Л.7:  Access / Refresh Tokens         ──┼──→ Безпечна система
Л.8:  PKCE                            ──┤
Л.9:  OpenID Connect                  ──┤
Л.10: Атаки на OAuth та захист        ──┤
Л.11: OAuth у мікросервісах           ──┤
Л.12: Безпека веб-додатків            ──┘
```

Максим проводить фінальний security audit SecureNotes

---

# Defense in Depth: аналогія

Середньовічний замок має **множину рівнів** захисту:

```
┌─────────────────────────────────┐
│          Донжон                 │  ← Шифрування at rest
│       (останній рубіж)          │     (AES-256)
└─────────┬───────────────────────┘
┌─────────┴───────────────────────┐
│       Внутрішня стіна           │  ← Авторизація
│       (другий рубіж)            │     (OAuth scopes)
└─────────┬───────────────────────┘
┌─────────┴───────────────────────┐
│       Зовнішня стіна            │  ← Автентифікація
│       (перший рубіж)            │     (OIDC, MFA)
└─────────┬───────────────────────┘
┌─────────┴───────────────────────┐
│           Рів                   │  ← TLS, WAF, firewall
└─────────────────────────────────┘
```

Злом одного рівня **не** означає злом усієї системи

---

# Defense in Depth: рівні SecureNotes

| Рівень | Механізм | Лекція |
|---|---|---|
| Мережа | TLS 1.3, firewall, WAF | 3 |
| Периметр | Rate limiting, CORS, CSP | 12 |
| Автентифікація | OIDC + MFA, PKCE | 8, 9 |
| Авторизація | OAuth 2.0 scopes, RBAC | 4 |
| Транспорт | JWT з підписом (RS256) | 6 |
| Дані в русі | TLS 1.3 (AES-GCM) | 3 |
| Дані в спокої | AES-256-GCM шифрування | 3 |
| Паролі | Argon2id хешування | 2 |
| Аудит | Логування, моніторинг | 13 |

---

# Defense in Depth: при зломі одного рівня

```python
# Сценарій: TLS скомпрометований
# Атакуючий перехопив трафік. Що далі?

# JWT підписаний RS256 — не підробити
token = "eyJhbGciOiJSUzI1NiJ9..."

# Дані зашифровані AES-256-GCM
encrypted_note = encrypt_aes_gcm(
    key=user_key, plaintext=note
)

# Паролі хешовані Argon2id — не відновити
password_hash = argon2id(
    password, salt, t=3, m=65536, p=4
)
```

Кожен рівень працює **незалежно**

---

# Zero Trust: традиційна модель vs Zero Trust

```
Традиційна модель:              Zero Trust:

┌──────────────────┐            ┌──────────────────┐
│  Довірена зона   │            │  Кожен запит     │
│  ┌────┐ ┌────┐   │            │  ┌────┐ ┌────┐   │
│  │ A  │→│ B  │   │            │  │ A  │?│ B  │   │
│  └────┘ └────┘   │            │  └──┬─┘ └─┬──┘   │
│  "Ти всередині   │            │     │verify│     │
│   — значить свій"│            │     └──┬───┘     │
└──────────────────┘            │  "Доведи, хто ти"│
      Firewall                  └──────────────────┘
```

**Never trust, always verify** — навіть внутрішні сервіси

---

# Принципи Zero Trust

1. **Never trust, always verify** — кожен запит автентифікується
2. **Least privilege access** — мінімальні необхідні права
3. **Assume breach** — проєктуйте, ніби зловмисник вже всередині
4. **Verify explicitly** — рішення на основі identity, пристрою, локації
5. **Micro-segmentation** — ізоляція сервісів, кожен має свій периметр

---

# Zero Trust у SecureNotes

```python
@app.before_request
def verify_request():
    token = request.headers.get(
        "Authorization", ""
    ).replace("Bearer ", "")

    # 1. Перевірити підпис токена
    payload = jwt.decode(
        token, public_key, algorithms=["RS256"]
    )

    # 2. Чи не відкликаний токен?
    if is_token_revoked(payload["jti"]):
        abort(401, "Token revoked")

    # 3. Перевірити scope для операції
    required = get_required_scope(
        request.method, request.path
    )
    if required not in payload["scope"].split():
        abort(403, "Insufficient scope")
```

---

# Security by Design: Least Privilege

Кожен компонент має лише **мінімально необхідні** права

```python
# НЕПРАВИЛЬНО — надмірні привілеї
oauth_scopes = [
    "notes:read", "notes:write",
    "notes:delete", "users:write",
    "admin:all"
]

# ПРАВИЛЬНО — лише необхідне
# Для перегляду нотаток:
oauth_scopes = ["notes:read"]

# Для редагування власних:
oauth_scopes = ["notes:read", "notes:write"]
```

---

# Security by Design: Fail Secure

При збої система переходить у **безпечний стан**, не у відкритий

```python
# НЕПРАВИЛЬНО — fail open
def check_access(user, resource):
    try:
        return auth_service.check(user, resource)
    except ServiceUnavailableError:
        return True  # Сервіс впав — дозволимо!

# ПРАВИЛЬНО — fail secure
def check_access(user, resource):
    try:
        return auth_service.check(user, resource)
    except ServiceUnavailableError:
        log.error("Auth service unavailable")
        return False  # Сервіс впав — заборонимо!
```

---

# Security by Design: Separation of Duties

Критичні операції вимагають участі **кількох осіб**

```
Розгортання в production:

Розробник ──→ Code Review ──→ CI/CD тести ──→ Security ──→ Deploy
  написав       другий         автоматичні      review      ops
  код           розробник                                   team
```

Жодна людина не може самостійно розгорнути код у production

---

# Security by Design: Open Design

Безпека **не залежить** від секретності архітектури

```
НЕПРАВИЛЬНО (security through obscurity):
  "Захищено, бо ніхто не знає
   URL /api/v2/secret-admin"

ПРАВИЛЬНО (open design):
  "Захищено OIDC + OAuth scopes +
   TLS 1.3 + JWT RS256 — навіть
   знаючи всі endpoint-и, без
   валідного токена доступ неможливий"
```

**Принцип Керкгоффса:** система безпечна, навіть якщо все, крім ключа, є публічним

---

# Зведена таблиця принципів

| Принцип | Суть | Приклад |
|---|---|---|
| Least Privilege | Мінімальні права | `notes:read` замість `*` |
| Fail Secure | Безпечна відмова | Deny при збої auth |
| Defense in Depth | Множинні рівні | TLS + JWT + AES |
| Separation of Duties | Розмежування | Code review + CI |
| Open Design | Публічна архітектура | Kerckhoffs's principle |

---

# OWASP Top 10 (2021)

| # | Категорія | Захист у SecureNotes |
|---|---|---|
| A01 | Broken Access Control | OAuth scopes, RBAC |
| A02 | Cryptographic Failures | AES-256-GCM, TLS 1.3 |
| A03 | Injection | Параметризовані запити |
| A04 | Insecure Design | Threat modeling |
| A05 | Security Misconfiguration | CSP, HSTS headers |
| A06 | Vulnerable Components | Dependabot, SCA |
| A07 | Authentication Failures | OIDC, MFA, PKCE |
| A08 | Integrity Failures | JWT підписи, SRI |
| A09 | Logging Failures | Structured logging |
| A10 | SSRF | Allowlist URLs |

---

# A01: Broken Access Control (IDOR)

```python
# ВРАЗЛИВО — будь-хто бачить будь-яку нотатку
@app.route("/api/notes/<note_id>")
def get_note(note_id):
    note = db.get_note(note_id)
    return jsonify(note)

# ЗАХИЩЕНО — перевірка ownership
@app.route("/api/notes/<note_id>")
@require_auth
def get_note(note_id):
    note = db.get_note(note_id)
    if note.owner_id != current_user.id:
        abort(403, "Access denied")
    return jsonify(note)
```

> A01 — **найпоширеніша** вразливість за OWASP 2021

---

# A03: Injection

```python
# ВРАЗЛИВО — SQL injection
query = f"SELECT * FROM notes WHERE id = '{note_id}'"
db.execute(query)
# note_id = "1' OR '1'='1" → витік всіх нотаток!

# ЗАХИЩЕНО — параметризований запит
query = "SELECT * FROM notes WHERE id = %s"
db.execute(query, (note_id,))
```

Також: XSS захист через CSP та sanitization, Command injection через allowlists

---

# A07: Authentication Failures

```python
# ВРАЗЛИВО — без rate limiting
@app.route("/login", methods=["POST"])
def login():
    user = db.get_user(request.json["username"])
    if bcrypt.checkpw(
        request.json["password"], user.password_hash
    ):
        return create_session(user)
    return {"error": "Invalid"}, 401

# ЗАХИЩЕНО — rate limiting + lockout
@app.route("/login", methods=["POST"])
@rate_limit(max_attempts=5, window=300)
def login():
    user = db.get_user(request.json["username"])
    if user.is_locked():
        return {"error": "Account locked"}, 423
    # ...
```

---

# Security Review Checklist

```
АВТЕНТИФІКАЦІЯ
[x] Argon2id для паролів
[x] MFA (TOTP або WebAuthn)
[x] OAuth 2.0 + PKCE
[x] Rate limiting на логіні

АВТОРИЗАЦІЯ
[x] Мінімальні OAuth scopes
[x] Перевірка ownership (IDOR)
[x] RBAC, deny за замовчуванням

КРИПТОГРАФІЯ
[x] TLS 1.3 для всіх з'єднань
[x] AES-256-GCM at rest
[x] JWT RS256, exp = 15 хвилин
[x] CSPRNG для всіх секретів
```

---

# Security Review Checklist (продовження)

```
ВЕБ-БЕЗПЕКА
[x] Content-Security-Policy
[x] CORS з explicit allowlist
[x] HttpOnly + Secure + SameSite
[x] CSRF захист
[x] XSS санітизація
[x] Subresource Integrity

ІНФРАСТРУКТУРА
[x] Мережева сегментація
[x] mTLS між сервісами
[x] Secrets у Vault
[x] Dependabot/Snyk

МОНІТОРИНГ
[x] JSON логи без PII
[x] Алерти на аномалії
[x] Incident response plan
```

---

# Автоматизація аудиту

```bash
#!/bin/bash
echo "=== Security Audit: SecureNotes ==="

# Перевірка TLS 1.3
openssl s_client -connect securenotes.com:443 \
  -tls1_3 2>/dev/null | grep "TLSv1.3"

# Перевірка security headers
curl -sI https://securenotes.com \
  | grep -i "content-security-policy"
curl -sI https://securenotes.com \
  | grep -i "strict-transport-security"

# Перевірка вразливих залежностей
pip-audit --strict
npm audit --audit-level=high

echo "=== Аудит завершено ==="
```

---

# Повна архітектура SecureNotes

```
          Браузер (PKCE, SRI, CSP)
                    │
        ════════════╪═══ TLS 1.3 (Л.3) ═══
                    │
          WAF / Load Balancer (Л.12)
            ┌───────┴────────┐
    ┌───────▼──────┐  ┌──────▼───────────┐
    │ API Gateway  │  │ Auth Server      │
    │ JWT (Л.6)    │  │ OIDC (Л.9)       │
    │ Scopes (Л.4) │  │ OAuth 2.0 (Л.4)  │
    │ mTLS (Л.3)   │  │ PKCE (Л.8)       │
    └──┬────────┬──┘  │ Argon2id (Л.2)   │
       │        │     └──────────────────┘
  ┌────▼──┐ ┌───▼────┐
  │Notes  │ │Users   │
  │AES-GCM│ │RBAC    │
  │(Л.3)  │ │(Л.3,4) │
  └───┬───┘ └───┬────┘
      │         │
  ┌───▼─────────▼─────────────┐
  │  PostgreSQL │ Redis │Vault│
  │  (Л.3)      │(Л.6)  │(Л.11)
  │  Logging & Monitoring(Л.13)
  └───────────────────────────┘
```

---

# Потік автентифікації (повний)

```
User    Browser      Auth Server    API GW     Notes
 │  1.Login  │            │           │          │
 ├──────────→│            │           │          │
 │           │ 2.PKCE     │           │          │
 │           ├───────────→│           │          │
 │ 4.MFA     │            │ 3.OIDC+   │          │
 │←──────────────────────┤  Argon2id │          │
 │ 5.TOTP    │            │           │          │
 ├───────────────────────→│           │          │
 │           │ 6.auth code│           │          │
 │           │←───────────┤           │          │
 │           │ 7.code+    │           │          │
 │           │ verifier   │           │          │
 │           ├───────────→│           │          │
 │           │ 8.JWT+     │           │          │
 │           │ refresh    │           │          │
 │           │←───────────┤           │          │
 │           │ 9.GET /notes           │          │
 │           ├───────────────────────→│          │
 │           │            │ 10.verify │          │
 │           │            │  JWT+scope├────────→│
 │           │            │           │11.decrypt│
 │           │ 12.notes   │           │←────────┤
 │           │←──────────────────────────────────┤
```

---

# Як кожна лекція вписується

```python
# Л.2: Хешування
argon2id.hash(password)

# Л.3: Шифрування та підписи — огляд
aes_gcm_encrypt(key, nonce, plaintext)
rsa_encrypt(public_key, aes_key)
rsa_sign(private_key, document_hash)
# TLS 1.3 на всіх з'єднаннях

# Л.4: OAuth scopes = "notes:read"
# Л.5: Authorization Code Flow
# Л.6: jwt.encode(payload, key, "RS256")
# Л.7: Access Token + Refresh Token
# Л.8: code_challenge = base64url(sha256(v))
# Л.9: id_token["sub"] = user identity
# Л.10: Threat modeling, token attacks
# Л.11: mTLS + Vault
# Л.12: CSP + CORS + SRI + cookies
# Л.13: Defense in Depth + Zero Trust
```

---

# Підсумок курсу (лекції 1-7)

| Лекція | Тема | Ключовий висновок |
|---|---|---|
| 1 | Вступ, CIA Triad | C + I + A = безпека |
| 2 | Хешування | Argon2id для паролів |
| 3 | Шифрування та підписи | AES-256-GCM, RSA, TLS 1.3 |
| 4 | OAuth 2.0 — архітектура | Делегована авторизація |
| 5 | Authorization Code Flow | Redirect-based flow |
| 6 | JWT | Stateless токени, RS256 |
| 7 | Access / Refresh Tokens | Lifecycle токенів |

---

# Підсумок курсу (лекції 8-13)

| Лекція | Тема | Ключовий висновок |
|---|---|---|
| 8 | PKCE | Захист auth code flow |
| 9 | OpenID Connect | id_token = хто ти |
| 10 | Атаки на OAuth | Threat modeling, захист |
| 11 | OAuth у мікросервісах | mTLS, Vault, service mesh |
| 12 | Безпека веб-додатків | CSP, CORS, SRI, cookies |
| 13 | Проєктування | Defense in Depth, Zero Trust |

---

# П'ять головних принципів

1. **Не винаходьте криптографію** — використовуйте стандарти (AES-GCM, Argon2id, RS256)

2. **Defense in Depth** — жоден механізм не є абсолютним; комбінуйте рівні

3. **Zero Trust** — «ніколи не довіряй, завжди перевіряй»

4. **Least Privilege** — мінімальні необхідні права

5. **Fail Secure** — при збої система закривається, не відкривається

> «Безпека — це подорож, а не пункт призначення.» — Bruce Schneier

---

<!-- _class: title -->

# Дякую за увагу!

Питання?
