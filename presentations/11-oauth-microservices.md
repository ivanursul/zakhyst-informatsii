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

Лекція 11. OAuth у мікросервісній архітектурі

Львівський національний університет імені Івана Франка
Спеціальність 113 — Прикладна математика

2025

---

# План лекції

1. Від моноліту до мікросервісів
2. Token Propagation
3. API Gateway Pattern
4. Service-to-Service Auth (Client Credentials)
5. Token Exchange (RFC 8693)
6. Audience Restriction
7. Централізована vs розподілена валідація
8. Sidecar Pattern (Envoy / Istio)
9. Практика: SecureNotes як мікросервіси

---

# Від моноліту до мікросервісів

Максим Витребенько побудував SecureNotes як моноліт. Бізнес зростає:

- Три команди розробників працюють над одним кодом
- Кожен деплой = перезбирання всього додатку
- Помилка в нотифікаціях кладе автентифікацію

**Рішення:** розділити SecureNotes на мікросервіси

---

# Моноліт vs мікросервіси

```
МОНОЛІТ:                           МІКРОСЕРВІСИ:
┌──────────────────────┐           ┌──────────────┐
│  Auth Module         │           │ Auth Service │
│  Notes Module        │    ──→    ├──────────────┤
│  Search Module       │           │ Notes Service│
│  Notifications       │           ├──────────────┤
│  Analytics           │           │ Search Svc   │
└──────────────────────┘           ├──────────────┤
                                   │ Notif. Svc   │
Одна точка відмови                 └──────────────┘
                                   Незалежний деплой
```

---

# Нові проблеми безпеки

У моноліті: токен перевіряється на вході, об'єкт `user` передається через виклики функцій у пам'яті

У мікросервісах: кожен виклик функції = HTTP-запит через мережу

- **Token propagation** — як передавати токен між сервісами?
- **Service identity** — як сервіс впевниться, що запит від Gateway, а не від зловмисника?
- **Blast radius** — скомпрометований сервіс = доступ до всіх інших?
- **Валідація** — кожен сервіс валідує окремо чи є центральна точка?

---

# Token Propagation

Найпростіший підхід: прокидати оригінальний access token через весь ланцюжок

```
Клієнт ──Bearer token──→ Gateway ──Bearer token──→ Notes Svc
                                   ──Bearer token──→ Search Svc
```

Кожен сервіс отримує той самий JWT і може перевірити identity користувача

---

# Token Propagation: приклад

```python
@app.route("/notes/<int:note_id>")
@propagate_token
def get_note(note_id):
    # Виклик Search Service з тим самим токеном
    resp = requests.get(
        f"http://search-service:8082/internal/tags/{note_id}",
        headers={
            "Authorization": f"Bearer {request.bearer_token}"
        }
    )
    tags = resp.json()
    return jsonify({
        "note_id": note_id,
        "tags": tags,
        "owner": request.user_claims["sub"]
    })
```

---

# Token Propagation: trade-offs

<div class="columns">
<div>

**Переваги**

- Простота реалізації
- Кожен сервіс знає користувача
- Аудит: логування `sub` claim

</div>
<div>

**Недоліки**

- Надмірні привілеї
- Кожен сервіс валідує JWT
- Токен може закінчитися у ланцюжку
- Confusion deputy attack

</div>
</div>

---

# API Gateway Pattern

Єдина точка входу. Зовнішні клієнти спілкуються лише з Gateway

```
                       ┌── Мережевий периметр ──────────┐
                       │                                 │
Клієнт ── HTTPS ──→ API Gateway ── HTTP ──→ Notes Svc   │
                       │     │                           │
                       │     ├── HTTP ──→ Search Svc     │
                       │     │                           │
                       │     └── HTTP ──→ Notif. Svc     │
                       │                                 │
                       └─────────────────────────────────┘
```

---

# API Gateway: функції безпеки

1. **TLS termination** — зовнішнє HTTPS, внутрішнє HTTP у довіреній мережі
2. **Валідація токенів** — підпис, expiration, audience, scope
3. **Rate limiting** — обмеження запитів від клієнта
4. **Маршрутизація** — `/notes/*` в Notes Service, `/users/*` в Auth Service
5. **Трансформація контексту** — JWT в внутрішні заголовки

```
Клієнт → Gateway:     Authorization: Bearer eyJhbGci...
Gateway → Notes Svc:   X-User-Id: user-12345
                        X-User-Scopes: read:notes,write:notes
```

---

# Мережева ізоляція

Gateway ефективний лише якщо внутрішні сервіси **недоступні ззовні**

- **Network policies** (Kubernetes) — трафік лише від Gateway
- **Private subnets** (AWS VPC) — без публічної IP
- **Firewall rules** — cloud security groups

> Без ізоляції зловмисник обійде Gateway і надішле підроблені `X-User-Id` заголовки

---

# Client Credentials Flow (RFC 6749 Section 4.4)

Не всі виклики в контексті користувача:

- Analytics Service збирає статистику **щоночі**
- Notification Service — фонове завдання
- Міграція даних — системна операція

**Client Credentials Flow:** сервіс діє від свого імені

```
Service ──→ POST /oauth/token
             grant_type=client_credentials
             client_id=analytics-service
             client_secret=<secret>
             scope=read:notes:stats
        ←── { "access_token": "eyJ..." }
```

---

# Client Credentials: приклад

```python
class ServiceClient:
    def __init__(self, client_id, client_secret, token_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self._token = None
        self._expires_at = 0

    def get_headers(self, scope="read:notes:stats"):
        if not self._token or time.time() >= self._expires_at:
            resp = requests.post(self.token_url, data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": scope,
            })
            data = resp.json()
            self._token = data["access_token"]
            self._expires_at = time.time() + data["expires_in"] - 60
        return {"Authorization": f"Bearer {self._token}"}
```

---

# Authorization Code vs Client Credentials

| | Authorization Code | Client Credentials |
|---|---|---|
| **Хто діє** | Від імені користувача | Від імені сервісу |
| **Користувач** | Потрібен (логін) | Не потрібен |
| **Refresh token** | Так | Зазвичай ні |
| **`sub` claim** | ID користувача | client_id сервісу |
| **Типовий scope** | `read:notes` | `service:read:stats` |

---

# Token Exchange (RFC 8693)

**Проблема:** прокидання повного токена порушує принцип найменших привілеїв

**Token Exchange:** обмін одного токена на інший з вужчими правами

```
Notes Svc ──→ POST /oauth/token
               grant_type=...token-exchange
               subject_token=<user_jwt>
               audience=search-service
               scope=read:tags
          ←── { "access_token": "<narrowed_jwt>" }
```

Новий токен: `aud=search-service`, `scope=read:tags`, `exp=5min`

---

# Token Exchange: delegation

Новий токен містить `act` (actor) claim — хто виконує дію:

```json
{
  "sub": "user-12345",
  "aud": "search-service",
  "scope": "read:tags",
  "act": {
    "sub": "notes-service"
  }
}
```

`notes-service` діє від імені `user-12345` з обмеженим scope

Authorization Server бачить повний ланцюжок делегування

---

# Audience Restriction (aud claim)

Токен із `aud` валідний **лише** для зазначених сервісів

```json
{
  "sub": "user-12345",
  "aud": ["notes-service"],
  "scope": "read:notes write:notes"
}
```

Search Service отримає цей токен та **відхилить** його: `invalid_audience`

```python
claims = jwt.decode(
    token, public_key,
    algorithms=["RS256"],
    audience="search-service"  # notes-service != search-service
)
# jwt.InvalidAudienceError!
```

---

# Без aud vs з aud

```
БЕЗ audience restriction:
Зловмисник ──токен──→ Notes Service   ДОСТУП!
(через      ──токен──→ Auth Service    ДОСТУП!
Search Svc) ──токен──→ Analytics Svc   ДОСТУП!

З audience restriction:
Зловмисник ──aud=search──→ Notes Service   ВІДХИЛЕНО!
(через      ──aud=search──→ Auth Service    ВІДХИЛЕНО!
Search Svc) ──aud=search──→ Search Svc      (вже скомпр.)
```

Audience + Token Exchange = **ізоляція blast radius**

---

# Централізована валідація (introspection)

Кожен сервіс запитує Authorization Server через `/introspect` (RFC 7662)

```
Notes Svc ──→ POST /oauth/introspect
               token=eyJhbGciOiJS...
          ←── { "active": true, "sub": "user-12345", ... }
```

- Миттєвий revocation
- Підтримує opaque tokens
- +мережевий запит на кожен виклик
- Залежність від Auth Server

---

# Розподілена валідація (JWT local)

Кожен сервіс перевіряє JWT підпис локально за допомогою публічного ключа з JWKS

```
Notes Svc ──→ GET /.well-known/jwks.json   (кеш на годину)
          ←── { "keys": [...] }

Далі локально:
1. Перевірити підпис JWT
2. Перевірити exp
3. Перевірити aud
4. Перевірити iss
```

- Мілісекунди, без мережі
- Працює навіть якщо Auth Server down
- Revocation лише після закінчення exp

---

# Централізована vs розподілена: порівняння

| Критерій | Introspection | JWT local |
|---|---|---|
| **Затримка** | +мережевий запит | Мілісекунди |
| **Відмовостійкість** | Залежить від Auth Server | Автономно |
| **Revocation** | Миттєвий | Після exp |
| **Навантаження** | Високе | Мінімальне |
| **Opaque tokens** | Так | Ні |

**Гібрид:** JWT (5-15 хв) + introspection для критичних операцій

---

# Sidecar Pattern

**Проблема:** дублювання коду безпеки в кожному сервісі

**Sidecar** — окремий контейнер поруч із сервісом (у тому ж Pod)

```
┌──── Kubernetes Pod ───────────────────────┐
│                                            │
│  ┌──────────┐         ┌────────────────┐  │
│  │  Envoy   │ ◄──────→│ Notes Service  │  │
│  │  Sidecar │  :8080  │ (бізнес-логіка)│  │
│  │          │         │                │  │
│  │ - TLS    │         │ Не знає про:   │  │
│  │ - JWT    │         │ - токени       │  │
│  │ - mTLS   │         │ - TLS          │  │
│  │ - Metrics│         │ - Rate limiting│  │
│  └──────────┘         └────────────────┘  │
│       ↑                                    │
└───────│────────────────────────────────────┘
   Мережа
```

---

# Istio Service Mesh

```yaml
# mTLS між усіма сервісами
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: securenotes
spec:
  mtls:
    mode: STRICT
---
# JWT валідація на вході
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: jwt-auth
spec:
  jwtRules:
    - issuer: "https://auth.securenotes.example"
      jwksUri: "https://auth.securenotes.example/.well-known/jwks.json"
      audiences: ["notes-service"]
```

---

# mTLS: взаємна автентифікація

```
Notes Service Pod               Search Service Pod
┌────────────────┐              ┌────────────────┐
│ Envoy ◄── mTLS ──────────────→ Envoy          │
│ (cert: notes)  │              │ (cert: search) │
│                │              │                │
│ Notes Service  │              │ Search Service │
│ (plain HTTP)   │              │ (plain HTTP)   │
└────────────────┘              └────────────────┘
```

- Бізнес-сервіси: plain HTTP з локальним Envoy
- Envoy: шифрований mTLS канал між Pod'ами
- Сертифікати автоматично від Istio CA

---

# Практика: архітектура SecureNotes

Максим розділяє SecureNotes на мікросервіси: Auth Service, Notes Service, API Gateway

```
Клієнт ── HTTPS ──→ ┌──────────────┐
                     │ API Gateway  │
                     └──┬────┬──────┘
                        │    │
               ┌────────┘    └────────┐
               ▼                      ▼
        ┌────────────┐        ┌────────────┐
        │Auth Service│        │Notes Service│
        │            │        │             │
        │/oauth/token│        │/notes/      │
        │/introspect │        │/internal/   │
        │/.well-known│        │             │
        └────────────┘        └────────────┘
```

---

# Практика: token flow

```bash
# 1. Отримати токен (Client Credentials)
TOKEN=$(curl -s -X POST http://localhost:8081/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=notes-service" \
  -d "client_secret=notes-s3cr3t-hash" \
  -d "scope=read:notes write:notes" \
  | python3 -c "import sys,json; \
    print(json.load(sys.stdin)['access_token'])")

# 2. Запит до Notes Service
curl -s http://localhost:8080/notes \
  -H "Authorization: Bearer $TOKEN"

# 3. Token Exchange для downstream
curl -s -X POST http://localhost:8081/oauth/token \
  -d "grant_type=urn:ietf:params:oauth:\
grant-type:token-exchange" \
  -d "subject_token=$TOKEN" \
  -d "audience=search-service" \
  -d "scope=read:tags"
```

---

# Підсумки

- **Token Propagation** — прокидання JWT через ланцюжок сервісів
- **API Gateway** — єдина точка входу + мережева ізоляція
- **Client Credentials** — service-to-service без контексту користувача
- **Token Exchange** — звуження привілеїв для downstream
- **Audience Restriction** — `aud` claim обмежує blast radius
- **Introspection vs JWT** — гібридний підхід на практиці
- **Sidecar / Service Mesh** — безпека без зміни бізнес-коду

---

# Що далі?

**Лекція 12: Web Security Hardening**

Максим захистив міжсервісну комунікацію. Але атака може бути спрямована на веб-інтерфейс:

- **OWASP Top 10** — найпоширеніші вразливості
- **Content Security Policy (CSP)** — захист від XSS
- **CSRF protection** — OAuth + SameSite cookies
- **Security headers** — HSTS, X-Frame-Options

---

<!-- _class: title -->

# Дякую за увагу!

Питання?
