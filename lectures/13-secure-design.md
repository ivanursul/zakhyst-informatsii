# Лекція 13. Проєктування безпечної системи. Підсумок

## Зміст

1. [Від окремих механізмів до системи](#1-від-окремих-механізмів-до-системи)
2. [Defense in Depth — багаторівневий захист](#2-defense-in-depth--багаторівневий-захист)
3. [Zero Trust Architecture](#3-zero-trust-architecture)
4. [Security by Design Principles](#4-security-by-design-principles)
5. [OWASP Top 10 — найпоширеніші вразливості](#5-owasp-top-10--найпоширеніші-вразливості)
6. [Security Review Checklist](#6-security-review-checklist)
7. [Повна архітектура SecureNotes](#7-повна-архітектура-securenotes)
8. [Підсумок курсу](#8-підсумок-курсу)

---

## 1. Від окремих механізмів до системи

### Мотивація

За дванадцять попередніх лекцій ми зібрали повний арсенал інструментів захисту інформації: хешування, шифрування, цифрові підписи, OAuth 2.0, JWT, PKCE, OIDC, безпеку мікросервісів і веб-додатків. Кожен із цих інструментів розв'язує конкретну задачу. Але окремі цеглини ще не є будинком.

Максим Витребенько побудував SecureNotes — додаток для захищених нотаток. У кожній лекції він додавав новий захисний механізм. Тепер настав час подивитися на систему цілісно: **чи утворюють усі ці механізми узгоджену архітектуру безпеки?**

Максим проводить фінальний security audit SecureNotes і документує архітектуру.

### Від фрагментів до цілого

```
Лекція 2:  Хешування (Argon2)              ──┐
Лекція 3:  Шифрування та підписи — огляд   ──┤
Лекція 4:  OAuth 2.0 — архітектура         ──┤
Лекція 5:  Authorization Code Flow         ──┤
Лекція 6:  JWT                             ──┤
Лекція 7:  Access / Refresh Tokens         ──┼──→  Безпечна система
Лекція 8:  PKCE                            ──┤     SecureNotes
Лекція 9:  OpenID Connect                  ──┤
Лекція 10: Атаки на OAuth та захист        ──┤
Лекція 11: OAuth у мікросервісах           ──┤
Лекція 12: Безпека веб-додатків            ──┘
```

Кожен компонент є необхідним, але **недостатнім** сам по собі. Система безпечна лише тоді, коли всі рівні працюють узгоджено. У цій лекції ми розглянемо принципи, які перетворюють набір механізмів на цілісну архітектуру.

---

## 2. Defense in Depth — багаторівневий захист

### Аналогія: середньовічний замок

Уявіть середньовічний замок. Його захист не обмежується одною стіною:

```
                    ┌─────────────────────────────┐
                    │          Донжон             │  ← Шифрування даних
                    │       (останній рубіж)       │     at rest (AES-256)
                    └─────────┬───────────────────┘
                    ┌─────────┴───────────────────┐
                    │       Внутрішня стіна        │  ← Авторизація (OAuth
                    │       (другий рубіж)         │     scopes, RBAC)
                    └─────────┬───────────────────┘
                    ┌─────────┴───────────────────┐
                    │       Зовнішня стіна         │  ← Автентифікація
                    │       (перший рубіж)         │     (OIDC, MFA)
                    └─────────┬───────────────────┘
                    ┌─────────┴───────────────────┐
                    │           Рів               │  ← TLS, WAF, firewall
                    │       (перешкода)            │
                    └─────────────────────────────┘
```

Якщо ворог перепливе рів (обійде firewall), він зіткнеться зі стіною (автентифікацією). Якщо подолає стіну — є внутрішня стіна (авторизація). Навіть якщо проникне всередину — донжон захищає найцінніше (шифрування даних).

### Визначення

**Defense in Depth** (глибинний захист) — стратегія безпеки, яка використовує **множину незалежних рівнів захисту**. Компрометація одного рівня не призводить до компрометації всієї системи.

### Рівні захисту в SecureNotes

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

### Приклад: що відбувається при зломі одного рівня

```python
# Сценарій: атакуючий перехопив мережевий трафік
# Рівень 1 (TLS) скомпрометований

# Але JWT все ще підписаний RS256 — не підробити
token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtYWtzeW0ifQ.signature"

# Навіть маючи JWT, дані зашифровані AES-256-GCM
encrypted_note = encrypt_aes_gcm(key=user_key, plaintext=note)

# Навіть маючи дані, паролі хешовані Argon2id — не відновити
password_hash = argon2id(password, salt, t=3, m=65536, p=4)
```

Кожен рівень працює **незалежно**. Злом одного не знищує інші.

---

## 3. Zero Trust Architecture

### Традиційна модель vs Zero Trust

Традиційна модель безпеки — це «замок з ровом»: все всередині мережі вважається довіреним. Коли атакуючий потрапляє за периметр — він має доступ до всього.

**Zero Trust** (нульова довіра) перевертає цю парадигму: **ніхто не є довіреним за замовчуванням** — ні зовнішній користувач, ні внутрішній сервіс, ні адміністратор.

```
Традиційна модель:                 Zero Trust:

┌──────────────────┐               ┌──────────────────┐
│  Довірена зона   │               │  Кожен запит     │
│  ┌────┐ ┌────┐   │               │  ┌────┐ ┌────┐   │
│  │ A  │→│ B  │   │               │  │ A  │?│ B  │   │
│  └────┘ └────┘   │               │  └──┬─┘ └─┬──┘   │
│  "Ти всередині   │               │     │verify│     │
│   — значить свій"│               │     └──┬───┘     │
└──────────────────┘               │  "Доведи, хто ти"│
      Firewall                     └──────────────────┘
                                     Кожен запит
                                     перевіряється
```

### Принципи Zero Trust

1. **Never trust, always verify** — кожен запит автентифікується та авторизується, незалежно від джерела
2. **Least privilege access** — мінімальні необхідні права, не більше
3. **Assume breach** — проєктуйте систему так, ніби зловмисник вже всередині
4. **Verify explicitly** — рішення про доступ базуються на всіх доступних даних (identity, пристрій, локація, час)
5. **Micro-segmentation** — ізоляція сервісів, кожен має свій периметр

### Zero Trust у SecureNotes

```python
# Кожен мікросервіс перевіряє JWT при КОЖНОМУ запиті
@app.before_request
def verify_request():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")

    # 1. Перевірити підпис токена
    payload = jwt.decode(token, public_key, algorithms=["RS256"])

    # 2. Перевірити, чи не відкликаний токен
    if is_token_revoked(payload["jti"]):
        abort(401, "Token revoked")

    # 3. Перевірити scope для конкретної операції
    required_scope = get_required_scope(request.method, request.path)
    if required_scope not in payload["scope"].split():
        abort(403, "Insufficient scope")

    # 4. Перевірити час життя
    if payload["exp"] < time.time():
        abort(401, "Token expired")
```

### Service-to-service автентифікація

У Zero Trust архітектурі навіть внутрішні сервіси не довіряють один одному. Кожен виклик між мікросервісами вимагає автентифікації:

```
┌─────────────┐  mTLS + JWT   ┌─────────────┐
│  Notes API  │──────────────→│  Users API  │
│             │  Bearer token │             │
└─────────────┘  з service    └─────────────┘
                 account
```

```bash
# Сервіс отримує власний JWT через Client Credentials Grant
curl -X POST https://auth.securenotes.com/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=notes-service" \
  -d "client_secret=$SERVICE_SECRET" \
  -d "scope=users:read"
```

---

## 4. Security by Design Principles

### Принцип 1: Least Privilege (мінімальні привілеї)

Кожен компонент, користувач і процес повинен мати лише ті права, які необхідні для виконання його функції — і не більше.

```python
# НЕПРАВИЛЬНО — надмірні привілеї
oauth_scopes = ["notes:read", "notes:write", "notes:delete",
                "users:read", "users:write", "admin:all"]

# ПРАВИЛЬНО — лише необхідне
# Для перегляду нотаток:
oauth_scopes = ["notes:read"]

# Для редагування власних нотаток:
oauth_scopes = ["notes:read", "notes:write"]
```

### Принцип 2: Fail Secure (безпечна відмова)

Коли система зазнає збою, вона повинна переходити у **безпечний стан**, а не у відкритий.

```python
# НЕПРАВИЛЬНО — fail open
def check_access(user, resource):
    try:
        return authorization_service.check(user, resource)
    except ServiceUnavailableError:
        return True  # "Сервіс недоступний — дозволимо"

# ПРАВИЛЬНО — fail secure
def check_access(user, resource):
    try:
        return authorization_service.check(user, resource)
    except ServiceUnavailableError:
        log.error("Authorization service unavailable")
        return False  # "Сервіс недоступний — заборонимо"
```

### Принцип 3: Defense in Depth (глибинний захист)

Множинні незалежні рівні захисту. Детально розглянуто у розділі 2.

### Принцип 4: Separation of Duties (розмежування обов'язків)

Критичні операції вимагають участі кількох незалежних осіб або компонентів.

```
Приклад: розгортання в production

Розробник ──→ Code Review ──→ Автоматичні ──→ Security ──→ Deploy
  написав       другий         тести           review      ops team
  код           розробник      CI/CD           перевірив   розгорнув
                перевірив
```

Жодна людина не може самостійно розгорнути код у production — це захищає від внутрішніх загроз та помилок.

### Принцип 5: Open Design (відкрите проєктування)

Безпека системи не повинна залежати від секретності її архітектури. Система має бути безпечною навіть якщо зловмисник знає, як вона працює. Секретами мають бути лише ключі.

```
НЕПРАВИЛЬНО (security through obscurity):
  "Наш API захищений, бо ніхто не знає URL /api/v2/secret-admin"

ПРАВИЛЬНО (open design):
  "Наш API захищений автентифікацією (OIDC), авторизацією (OAuth scopes),
   шифруванням (TLS 1.3), підписами (JWT RS256) — навіть якщо ви знаєте
   всі endpoint-и, без валідного токена доступ неможливий"
```

Це прямо пов'язано з **принципом Керкгоффса** (Kerckhoffs's principle): криптографічна система має бути безпечною, навіть якщо все, крім ключа, є публічним.

### Зведена таблиця принципів

| Принцип | Суть | Приклад у SecureNotes |
|---|---|---|
| Least Privilege | Мінімальні права | OAuth scopes: `notes:read` замість `*` |
| Fail Secure | Безпечна відмова | Deny за замовчуванням при збої авторизації |
| Defense in Depth | Множинні рівні | TLS + JWT + AES + Argon2 |
| Separation of Duties | Розмежування | Code review + CI + security review |
| Open Design | Не залежить від таємності | Kerckhoffs's principle, публічні алгоритми |

---

## 5. OWASP Top 10 — найпоширеніші вразливості

### Що таке OWASP

**OWASP** (Open Worldwide Application Security Project) — це відкрита спільнота, яка займається підвищенням безпеки програмного забезпечення. Їхній найвідоміший проєкт — **OWASP Top 10** — список десяти найпоширеніших і найкритичніших вразливостей веб-додатків.

### OWASP Top 10 (2021)

| # | Категорія | Опис | Захист у SecureNotes |
|---|---|---|---|
| A01 | Broken Access Control | Неправильний контроль доступу | OAuth scopes, RBAC, перевірка ownership |
| A02 | Cryptographic Failures | Помилки криптографії | AES-256-GCM, TLS 1.3, Argon2id |
| A03 | Injection | SQL/XSS/Command injection | Параметризовані запити, CSP, sanitization |
| A04 | Insecure Design | Небезпечне проєктування | Threat modeling, Security by Design |
| A05 | Security Misconfiguration | Неправильна конфігурація | Hardened defaults, CSP headers |
| A06 | Vulnerable Components | Вразливі залежності | Dependabot, SCA, оновлення |
| A07 | Authentication Failures | Помилки автентифікації | OIDC, MFA, PKCE, rate limiting |
| A08 | Software and Data Integrity | Порушення цілісності | JWT підписи, SRI, code signing |
| A09 | Logging and Monitoring | Недостатнє логування | Structured logging, alerting |
| A10 | SSRF | Server-Side Request Forgery | Allowlist URLs, мережева ізоляція |

### A01: Broken Access Control — найпоширеніша вразливість

```python
# ВРАЗЛИВО — IDOR (Insecure Direct Object Reference)
@app.route("/api/notes/<note_id>")
def get_note(note_id):
    note = db.get_note(note_id)  # Будь-хто бачить будь-яку нотатку!
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

### A03: Injection — класична вразливість

```python
# ВРАЗЛИВО — SQL injection
query = f"SELECT * FROM notes WHERE id = '{note_id}'"
db.execute(query)  # note_id = "1' OR '1'='1" → витік всіх нотаток

# ЗАХИЩЕНО — параметризований запит
query = "SELECT * FROM notes WHERE id = %s"
db.execute(query, (note_id,))
```

### A07: Authentication Failures

```python
# ВРАЗЛИВО — без rate limiting
@app.route("/login", methods=["POST"])
def login():
    user = db.get_user(request.json["username"])
    if bcrypt.checkpw(request.json["password"], user.password_hash):
        return create_session(user)
    return {"error": "Invalid credentials"}, 401

# ЗАХИЩЕНО — rate limiting + account lockout
@app.route("/login", methods=["POST"])
@rate_limit(max_attempts=5, window=300)  # 5 спроб за 5 хвилин
def login():
    user = db.get_user(request.json["username"])
    if user.is_locked():
        return {"error": "Account locked"}, 423
    if bcrypt.checkpw(request.json["password"], user.password_hash):
        user.reset_failed_attempts()
        return create_session(user)
    user.increment_failed_attempts()
    return {"error": "Invalid credentials"}, 401
```

---

## 6. Security Review Checklist

### Навіщо потрібен checklist

Максим проводить фінальний security audit SecureNotes. Щоб нічого не пропустити, він використовує структурований checklist. Такий підхід гарантує, що кожен аспект безпеки перевірено систематично.

### Checklist для аудиту безпеки

```
╔══════════════════════════════════════════════════════════════════╗
║                SECURITY REVIEW CHECKLIST                        ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  АВТЕНТИФІКАЦІЯ                                                  ║
║  [x] Паролі хешуються Argon2id (не MD5, не SHA-256)            ║
║  [x] Реалізовано MFA (TOTP або WebAuthn)                        ║
║  [x] OAuth 2.0 + PKCE для публічних клієнтів                   ║
║  [x] OIDC для федеративної автентифікації                       ║
║  [x] Rate limiting на endpoint-ах логіну                        ║
║  [x] Account lockout після N невдалих спроб                     ║
║                                                                  ║
║  АВТОРИЗАЦІЯ                                                     ║
║  [x] Мінімальні OAuth scopes для кожного клієнта                ║
║  [x] Перевірка ownership для кожного ресурсу (IDOR захист)      ║
║  [x] RBAC з чіткими ролями (user, editor, admin)               ║
║  [x] Deny за замовчуванням (fail secure)                        ║
║                                                                  ║
║  КРИПТОГРАФІЯ                                                    ║
║  [x] TLS 1.3 для всіх з'єднань                                 ║
║  [x] AES-256-GCM для шифрування нотаток at rest                ║
║  [x] RSA-2048+ або Ed25519 для цифрових підписів               ║
║  [x] JWT підписані RS256, короткий час життя (15 хвилин)       ║
║  [x] Refresh tokens з ротацією                                  ║
║  [x] CSPRNG для генерації всіх секретів                         ║
║                                                                  ║
║  ВЕБ-БЕЗПЕКА                                                    ║
║  [x] Content-Security-Policy header                             ║
║  [x] CORS з explicit allowlist                                  ║
║  [x] HttpOnly + Secure + SameSite cookies                       ║
║  [x] CSRF захист (SameSite + anti-CSRF token)                  ║
║  [x] XSS санітизація всіх user inputs                          ║
║  [x] Subresource Integrity (SRI) для зовнішніх скриптів        ║
║                                                                  ║
║  ІНФРАСТРУКТУРА                                                  ║
║  [x] Мережева сегментація (мікросервіси ізольовані)             ║
║  [x] mTLS між сервісами                                         ║
║  [x] Secrets у vault (не в коді, не в env)                      ║
║  [x] Автоматичне сканування залежностей (Dependabot/Snyk)       ║
║                                                                  ║
║  МОНІТОРИНГ ТА РЕАГУВАННЯ                                       ║
║  [x] Структуроване логування (JSON) без PII у логах            ║
║  [x] Алерти на аномальну активність                             ║
║  [x] Incident response plan задокументований                    ║
║  [x] Регулярне тестування на проникнення                        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

### Автоматизація перевірок

```bash
#!/bin/bash
# security-audit.sh — автоматичний аудит SecureNotes

echo "=== Security Audit: SecureNotes ==="

# 1. Перевірка TLS конфігурації
echo "[*] Перевірка TLS..."
openssl s_client -connect securenotes.com:443 \
  -tls1_3 2>/dev/null | grep "Protocol" | grep "TLSv1.3" && \
  echo "[OK] TLS 1.3 активний" || echo "[FAIL] TLS 1.3 не знайдено"

# 2. Перевірка security headers
echo "[*] Перевірка HTTP headers..."
curl -sI https://securenotes.com | grep -i "content-security-policy" && \
  echo "[OK] CSP header присутній" || echo "[FAIL] CSP header відсутній"

curl -sI https://securenotes.com | grep -i "strict-transport-security" && \
  echo "[OK] HSTS header присутній" || echo "[FAIL] HSTS header відсутній"

# 3. Перевірка відкритих портів
echo "[*] Сканування портів..."
nmap -sT securenotes.com -p 80,443,8080,3306,5432 --open

# 4. Перевірка залежностей
echo "[*] Перевірка вразливих залежностей..."
pip-audit --strict
npm audit --audit-level=high

echo "=== Аудит завершено ==="
```

---

## 7. Повна архітектура SecureNotes

### Загальна діаграма

Ось повна архітектура SecureNotes, яка об'єднує всі механізми захисту з 13 лекцій:

```
                            SECURENOTES — ПОВНА АРХІТЕКТУРА
                         ┌─────────────────────────────────────┐
                         │            ІНТЕРНЕТ                 │
                         └────────────────┬────────────────────┘
                                          │
                    ┌─────────────────────┐│┌─────────────────────┐
                    │ Браузер / Mobile App │││  Зловмисник        │
                    │ ┌─────────────────┐ │││  (threat model)     │
                    │ │ PKCE (Л.8)      │ │││                     │
                    │ │ code_verifier   │ ││└─────────────────────┘
                    │ │ code_challenge  │ ││
                    │ └─────────────────┘ ││
                    │ SRI (Л.12)          ││
                    │ CSP (Л.12)          ││
                    └─────────┬───────────┘│
                              │            │
                    ══════════╪════════════╪═══ TLS 1.3 (Л.3) ═══
                              │            │
                    ┌─────────▼────────────▼──────────────────────┐
                    │              WAF / Load Balancer             │
                    │  Rate limiting (Л.12)   CORS (Л.12)         │
                    └──────┬──────────────────────┬───────────────┘
                           │                      │
             ┌─────────────▼──────────┐  ┌────────▼──────────────┐
             │    API Gateway         │  │  Authorization Server │
             │                        │  │  (Identity Provider)  │
             │  JWT validation (Л.6)  │  │                       │
             │  Scope check (Л.4)     │  │  OIDC (Л.9)          │
             │  mTLS (Л.3)            │  │  OAuth 2.0 (Л.4)     │
             │                        │  │  PKCE verify (Л.8)   │
             └──┬──────────┬──────────┘  │  MFA (Л.9)           │
                │          │             │                       │
                │          │             │  Argon2id (Л.2)       │
                │          │             │  CSPRNG (Л.2)         │
                │          │             └───────────────────────┘
                │          │
    ┌───────────▼───┐  ┌───▼───────────────┐
    │  Notes Service│  │  Users Service    │
    │               │  │                   │
    │  AES-256-GCM  │  │  RBAC (Л.4)      │
    │  encrypt/     │  │  Ownership check  │
    │  decrypt      │  │                   │
    │  (Л.3)        │  │  Digital          │
    │               │  │  signatures (Л.3) │
    │  RSA encrypt  │  │                   │
    │  note keys    │  └─────────┬─────────┘
    │  (Л.3)        │            │
    └───────┬───────┘            │
            │                    │
    ┌───────▼────────────────────▼─────────────────────┐
    │                   Data Layer                      │
    │                                                   │
    │  ┌──────────────┐  ┌──────────┐  ┌─────────────┐ │
    │  │ PostgreSQL   │  │  Redis   │  │ Vault       │ │
    │  │ (encrypted   │  │ (token   │  │ (secrets    │ │
    │  │  at rest)    │  │  revoc.) │  │  mgmt)      │ │
    │  │ (Л.3)        │  │ (Л.6)    │  │ (Л.11)      │ │
    │  └──────────────┘  └──────────┘  └─────────────┘ │
    │                                                   │
    │  ┌──────────────────────────────────────────────┐ │
    │  │  Logging & Monitoring (Л.13)                 │ │
    │  │  Structured JSON logs, no PII, alerting      │ │
    │  └──────────────────────────────────────────────┘ │
    └───────────────────────────────────────────────────┘
```

### Потік автентифікації (повний)

```
Користувач          Браузер/SPA        Auth Server        API Gateway       Notes Service
    │                   │                  │                   │                  │
    │  1. Логін         │                  │                   │                  │
    ├──────────────────→│                  │                   │                  │
    │                   │  2. PKCE:        │                   │                  │
    │                   │  code_verifier   │                   │                  │
    │                   │  code_challenge  │                   │                  │
    │                   ├─────────────────→│                   │                  │
    │                   │                  │  3. OIDC login    │                  │
    │  4. MFA challenge │                  │  + Argon2id       │                  │
    │←─────────────────────────────────────┤  verify           │                  │
    │  5. TOTP code     │                  │                   │                  │
    ├──────────────────────────────────────→│                   │                  │
    │                   │  6. auth code    │                   │                  │
    │                   │←─────────────────┤                   │                  │
    │                   │  7. code +       │                   │                  │
    │                   │  code_verifier   │                   │                  │
    │                   ├─────────────────→│                   │                  │
    │                   │  8. JWT (RS256)  │                   │                  │
    │                   │  + refresh token │                   │                  │
    │                   │←─────────────────┤                   │                  │
    │                   │                  │                   │                  │
    │                   │  9. GET /notes   │                   │                  │
    │                   │  Authorization:  │                   │                  │
    │                   │  Bearer <JWT>    │                   │                  │
    │                   ├──────────────────────────────────────→│                  │
    │                   │                  │                   │  10. Verify JWT  │
    │                   │                  │                   │  Check scope     │
    │                   │                  │                   │  Check revocation│
    │                   │                  │                   ├─────────────────→│
    │                   │                  │                   │                  │
    │                   │                  │                   │  11. Decrypt     │
    │                   │                  │                   │  AES-256-GCM     │
    │                   │                  │                   │  Check ownership │
    │                   │  12. Notes data  │                   │←─────────────────┤
    │                   │←─────────────────────────────────────────────────────────┤
    │  13. Відображення │                  │                   │                  │
    │←─────────────────┤                  │                   │                  │
```

### Як кожна лекція вписується в архітектуру

```python
# Лекція 2: Хешування
password_hash = argon2id.hash(password)  # Зберігання паролів

# Лекція 3: Шифрування та підписи — огляд
encrypted_note = aes_gcm_encrypt(key, nonce, plaintext)  # AES-256-GCM
encrypted_key = rsa_encrypt(public_key, aes_key)  # RSA для обміну ключами
signature = rsa_sign(private_key, document_hash)  # Цифрові підписи
# TLS 1.3 на всіх з'єднаннях, X.509 сертифікати

# Лекція 4: OAuth 2.0 — архітектура протоколу
scope = "notes:read notes:write"  # Делегована авторизація

# Лекція 5: Authorization Code Flow
# Redirect-based flow для серверних додатків

# Лекція 6: JWT
token = jwt.encode(payload, private_key, algorithm="RS256")  # Токени доступу

# Лекція 7: Access Token, Refresh Token, Token Lifecycle
# Короткий access token, ротація refresh token

# Лекція 8: PKCE
code_challenge = base64url(sha256(code_verifier))  # Захист auth code flow

# Лекція 9: OpenID Connect
id_token = decode_id_token(token)  # Федеративна автентифікація
userinfo = id_token["sub"]  # Identity користувача

# Лекція 10: Атаки на OAuth та захист
# Threat modeling, token theft, redirect attacks

# Лекція 11: OAuth у мікросервісній архітектурі
# mTLS між сервісами, service mesh, secrets у Vault

# Лекція 12: Безпека веб-додатків навколо OAuth
# CSP, CORS, SRI, HttpOnly cookies, CSRF захист

# Лекція 13: Проєктування безпечної системи. Підсумок
# Defense in Depth, Zero Trust, Security by Design
```

---

## 8. Підсумок курсу

### Що ми вивчили — ключові висновки з кожної лекції

| Лекція | Тема | Ключовий висновок |
|---|---|---|
| 1 | Вступ, довіра, CIA Triad | Безпека = конфіденційність + цілісність + доступність |
| 2 | Хешування | SHA-256 для цілісності, Argon2id для паролів, лише CSPRNG |
| 3 | Шифрування та підписи — огляд | AES-256-GCM, RSA/ECDH, цифрові підписи, TLS 1.3 |
| 4 | OAuth 2.0 — архітектура | Делегована авторизація без передачі credentials |
| 5 | Authorization Code Flow | Redirect-based flow з auth code для серверних додатків |
| 6 | JWT | Stateless токени з підписом; короткий час життя |
| 7 | Access / Refresh Tokens | Lifecycle токенів, ротація, відкликання |
| 8 | PKCE | Захист auth code від перехоплення у публічних клієнтах |
| 9 | OpenID Connect | Автентифікація поверх OAuth; id_token = хто ти |
| 10 | Атаки на OAuth та захист | Threat modeling, token theft, redirect attacks |
| 11 | OAuth у мікросервісах | Service mesh, mTLS, централізоване управління секретами |
| 12 | Безпека веб-додатків | CSP, CORS, SRI, cookies — захист на стороні браузера |
| 13 | Проєктування безпечної системи | Defense in Depth, Zero Trust, Security by Design |

### П'ять головних принципів курсу

1. **Не винаходьте криптографію** — використовуйте перевірені бібліотеки та стандарти (AES-GCM, Argon2id, RS256)
2. **Defense in Depth** — жоден механізм не є абсолютним; комбінуйте рівні захисту
3. **Zero Trust** — «ніколи не довіряй, завжди перевіряй»; кожен запит автентифікується
4. **Least Privilege** — мінімальні необхідні права; OAuth scopes, RBAC, ownership checks
5. **Fail Secure** — при збої система закривається, а не відкривається

### Карта знань

```
                    ┌──────────────────────┐
                    │   CIA Triad (Л.1)    │
                    │  C     I     A       │
                    └──┬─────┬─────┬───────┘
                       │     │     │
              ┌────────▼┐  ┌▼────────┐  ┌▼────────┐
              │Confiden- │  │Integrity│  │Availab- │
              │tiality   │  │         │  │ility    │
              └──┬───────┘  └──┬──────┘  └──┬──────┘
                 │             │             │
         ┌───────▼──────┐ ┌───▼─────┐  ┌────▼─────┐
         │ Шифрування   │ │ Хеші    │  │ Rate     │
         │ AES (Л.3)    │ │ SHA-256 │  │ limiting │
         │ RSA (Л.3)    │ │ (Л.2)   │  │ (Л.12)   │
         │ TLS (Л.3)    │ │ Підписи │  │          │
         └───────┬──────┘ │ (Л.3)   │  └──────────┘
                 │        └───┬─────┘
                 │            │
         ┌───────▼────────────▼──────────────────────┐
         │           Протоколи (Л.4-11)              │
         │  OAuth 2.0 → JWT → PKCE → OIDC → mTLS    │
         └───────────────────┬───────────────────────┘
                             │
         ┌───────────────────▼───────────────────────┐
         │        Архітектура (Л.12-13)              │
         │  Web Security → Secure Design             │
         └───────────────────────────────────────────┘
```

### Фінальні слова

Безпека — це не стан, а **процес**. Немає «безпечної» системи — є системи, які **активно підтримують** свою безпеку. Нові вразливості з'являються щодня, алгоритми старіють, атакуючі вдосконалюються.

Максим завершив security audit SecureNotes і переконався: система захищена на всіх рівнях. Але він знає, що завтра потрібно буде перевіряти знову — бо безпека ніколи не буває «готовою».

> «Безпека — це подорож, а не пункт призначення.» — Bruce Schneier

---

## Література

1. OWASP Top 10 (2021) — https://owasp.org/Top10/
2. NIST SP 800-207 — Zero Trust Architecture — https://csrc.nist.gov/publications/detail/sp/800-207/final
3. Saltzer, J.H., Schroeder, M.D. *The Protection of Information in Computer Systems.* — Proceedings of the IEEE, 1975
4. Ross Anderson. *Security Engineering.* — 3rd Edition, Wiley: 2020
5. Bruce Schneier. *Secrets and Lies: Digital Security in a Networked World.* — Wiley: 2015
6. Adam Shostack. *Threat Modeling: Designing for Security.* — Wiley: 2014
