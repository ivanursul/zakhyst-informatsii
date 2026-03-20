# Лекція 11. OAuth у мікросервісній архітектурі

## Зміст

1. [Від моноліту до мікросервісів](#1-від-моноліту-до-мікросервісів)
2. [Token Propagation — передача токенів між сервісами](#2-token-propagation--передача-токенів-між-сервісами)
3. [API Gateway Pattern — єдина точка входу](#3-api-gateway-pattern--єдина-точка-входу)
4. [Service-to-Service Auth — Client Credentials Flow](#4-service-to-service-auth--client-credentials-flow)
5. [Token Exchange — RFC 8693](#5-token-exchange--rfc-8693)
6. [Audience Restriction — обмеження токенів](#6-audience-restriction--обмеження-токенів)
7. [Централізована vs розподілена валідація](#7-централізована-vs-розподілена-валідація)
8. [Sidecar Pattern — Envoy та Istio](#8-sidecar-pattern--envoy-та-istio)
9. [Практика — розділяємо SecureNotes на мікросервіси](#9-практика--розділяємо-securenotes-на-мікросервіси)
10. [Підсумки](#10-підсумки)

---

## 1. Від моноліту до мікросервісів

### Мотивація

У попередніх лекціях Максим Витребенько побудував SecureNotes — додаток, де користувачі автентифікуються через OAuth 2.0 з PKCE, отримують JWT-токени та працюють із захищеними нотатками. Поки SecureNotes був невеликим додатком, моноліт працював чудово: один сервер, одна база даних, один процес.

Але бізнес зростає. Додаються нові функції: пошук по нотатках, спільний доступ, нотифікації, аналітика використання. Команда збільшується до трьох груп розробників. Кожен деплой вимагає перезбирання всього додатку. Помилка в модулі нотифікацій кладе весь сервіс, включно з автентифікацією.

### Навіщо мікросервіси

Максим вирішує розділити SecureNotes на окремі сервіси:

```
МОНОЛІТ SecureNotes:                    МІКРОСЕРВІСИ SecureNotes:
┌──────────────────────┐                ┌──────────────┐
│  Auth Module         │                │ Auth Service │
│  Notes Module        │       ──→      ├──────────────┤
│  Search Module       │                │ Notes Service│
│  Notifications       │                ├──────────────┤
│  Analytics           │                │ Search Svc   │
└──────────────────────┘                ├──────────────┤
  Одна кодова база,                     │ Notif. Svc   │
  один деплой,                          ├──────────────┤
  одна точка відмови                    │ Analytics Svc│
                                        └──────────────┘
                                         Окремі деплої,
                                         незалежне масштабування
```

Переваги зрозумілі: незалежний деплой, масштабування окремих компонентів, ізоляція відмов. Але з'являється нове фундаментальне питання: **як сервіси автентифікують один одного і як передається контекст користувача?**

У моноліті все було просто — токен перевірявся на вході, і далі об'єкт `user` передавався через внутрішні виклики функцій у пам'яті. У мікросервісній архітектурі кожен сервіс — це окремий процес, часто на окремій машині. Внутрішній виклик функції перетворюється на HTTP-запит через мережу.

### Нові проблеми безпеки

Розбиття на мікросервіси створює кілька критичних питань:

- **Token propagation** — як передавати токен користувача між сервісами?
- **Service identity** — як Notes Service впевниться, що запит прийшов саме від API Gateway, а не від зловмисника?
- **Blast radius** — якщо скомпрометований один сервіс, чи отримає атакуючий доступ до всіх інших?
- **Валідація** — чи кожен сервіс повинен валідувати токени самостійно, чи є центральна точка?

Кожну з цих проблем ми розглянемо в наступних розділах.

---

## 2. Token Propagation — передача токенів між сервісами

### Проблема

Користувач надсилає запит на отримання нотатки. Запит проходить через кілька сервісів: API Gateway, Notes Service, а Notes Service може викликати Search Service для пошуку тегів. Як кожен сервіс у ланцюжку дізнається, хто є користувач?

### Простий підхід: передача токена в заголовку

Найпростіший спосіб — **прокидати** (propagate) оригінальний access token користувача через весь ланцюжок викликів:

```
Користувач                API Gateway         Notes Service       Search Service
    │                         │                     │                    │
    │  GET /notes/42          │                     │                    │
    │  Authorization:         │                     │                    │
    │  Bearer <user_token>    │                     │                    │
    │────────────────────────→│                     │                    │
    │                         │  GET /internal/notes│                    │
    │                         │  Authorization:     │                    │
    │                         │  Bearer <user_token>│                    │
    │                         │────────────────────→│                    │
    │                         │                     │  GET /internal/tags│
    │                         │                     │  Authorization:    │
    │                         │                     │  Bearer <user_token>
    │                         │                     │───────────────────→│
```

Кожен сервіс отримує той самий токен і може перевірити identity користувача.

### Приклад на Python (Flask)

```python
import requests
from flask import Flask, request, jsonify
from functools import wraps
import jwt

app = Flask(__name__)

JWKS_URI = "https://auth.securenotes.example/.well-known/jwks.json"

def propagate_token(func):
    """Middleware: витягує і валідує токен, передає далі."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "missing_token"}), 401

        token = auth_header.split(" ", 1)[1]
        try:
            claims = jwt.decode(token, options={"verify_signature": True},
                                algorithms=["RS256"],
                                audience="notes-service")
        except jwt.InvalidTokenError as e:
            return jsonify({"error": str(e)}), 401

        request.user_claims = claims
        request.bearer_token = token
        return func(*args, **kwargs)
    return wrapper

@app.route("/notes/<int:note_id>")
@propagate_token
def get_note(note_id):
    # Виклик Search Service з тим самим токеном
    resp = requests.get(
        f"http://search-service:8082/internal/tags/{note_id}",
        headers={"Authorization": f"Bearer {request.bearer_token}"}
    )
    tags = resp.json()
    return jsonify({"note_id": note_id, "tags": tags,
                     "owner": request.user_claims["sub"]})
```

### Переваги та недоліки простого прокидання

**Переваги:**

- Простота реалізації — не потрібна додаткова інфраструктура
- Кожен сервіс знає, хто є кінцевий користувач
- Аудит: кожен сервіс може логувати `sub` claim

**Недоліки:**

- **Надмірні привілеї** — Notes Service отримує повний токен користувача, хоча йому потрібен лише `sub` та `read:notes` scope
- **Зв'язаність** — кожен сервіс повинен вміти валідувати JWT
- **Проблема lifetime** — якщо ланцюжок викликів довгий, токен може закінчитися посередині
- **Confusion deputy** — сервіс може випадково використати токен користувача для дій, яких користувач не запитував

Ці недоліки мотивують більш просунуті патерни, які ми розглянемо далі.

---

## 3. API Gateway Pattern — єдина точка входу

### Ідея

Замість того, щоб кожен мікросервіс був доступний ззовні та самостійно валідував токени, ми ставимо єдину точку входу — **API Gateway**. Зовнішні клієнти спілкуються лише з Gateway, а Gateway маршрутизує запити до внутрішніх сервісів.

```
                              ┌─── Мережевий периметр ───────────────────┐
                              │                                           │
Клієнт ──── HTTPS ────→ API Gateway ──── HTTP ────→ Notes Service        │
                              │         │                                 │
                              │         ├──── HTTP ────→ Search Service   │
                              │         │                                 │
                              │         └──── HTTP ────→ Notif. Service   │
                              │                                           │
                              └───────────────────────────────────────────┘
```

### Що робить Gateway

API Gateway виконує кілька ключових функцій, пов'язаних із безпекою:

1. **TLS termination** — зовнішнє з'єднання завжди HTTPS; внутрішні виклики можуть бути HTTP у довіреній мережі
2. **Валідація токенів** — Gateway перевіряє JWT-підпис, expiration, audience, scope
3. **Rate limiting** — обмеження кількості запитів від одного клієнта
4. **Маршрутизація** — `/notes/*` йде в Notes Service, `/users/*` — в Auth Service
5. **Трансформація контексту** — Gateway може витягти claims з JWT і передати їх у внутрішніх заголовках

### Трансформація контексту

Після валідації токена Gateway може зняти JWT і передати downstream-сервісам лише потрібну інформацію у внутрішніх заголовках:

```
Клієнт → API Gateway:
  Authorization: Bearer eyJhbGciOiJSUzI1NiIs...

API Gateway → Notes Service:
  X-User-Id: user-12345
  X-User-Email: maksym.vytrebenko@example.com
  X-User-Scopes: read:notes,write:notes
  X-Request-Id: req-abc-123
```

Внутрішні сервіси більше не працюють із JWT безпосередньо — вони довіряють заголовкам від Gateway. Це спрощує внутрішні сервіси, але вимагає гарантії, що ніхто, крім Gateway, не може надсилати запити до внутрішніх сервісів.

### Приклад: конфігурація NGINX як API Gateway

```bash
# nginx.conf (спрощений приклад)
upstream notes_service {
    server notes-svc:8080;
}

server {
    listen 443 ssl;
    server_name api.securenotes.example;

    ssl_certificate     /etc/ssl/certs/api.crt;
    ssl_certificate_key /etc/ssl/private/api.key;

    # Валідація JWT через модуль njs або auth_request
    location /notes/ {
        auth_request /auth/validate;
        auth_request_set $user_id $upstream_http_x_user_id;
        auth_request_set $user_scopes $upstream_http_x_user_scopes;

        proxy_set_header X-User-Id $user_id;
        proxy_set_header X-User-Scopes $user_scopes;
        proxy_pass http://notes_service;
    }

    location = /auth/validate {
        internal;
        proxy_pass http://auth-svc:8081/validate;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Authorization $http_authorization;
    }
}
```

### Мережева ізоляція

API Gateway ефективний лише якщо внутрішні сервіси **недоступні ззовні**. Це забезпечується:

- **Network policies** (Kubernetes) — правила, які дозволяють трафік до внутрішніх сервісів лише від Gateway
- **Private subnets** (AWS VPC) — внутрішні сервіси у приватній підмережі без публічної IP-адреси
- **Firewall rules** — на рівні мережевого обладнання або cloud security groups

Без мережевої ізоляції зловмисник може обійти Gateway і надіслати запит безпосередньо до Notes Service з підробленими заголовками `X-User-Id`.

---

## 4. Service-to-Service Auth — Client Credentials Flow

### Проблема

Не всі взаємодії між сервісами відбуваються в контексті користувача. Наприклад:

- Analytics Service збирає статистику по нотатках щоночі — без участі жодного користувача
- Notification Service перевіряє нові нотатки для розсилки — це фонове завдання
- Сервіс міграції даних переносить нотатки між базами — це системна операція

У цих випадках немає користувацького токена для прокидання. Сервіс діє **від свого імені**, а не від імені користувача.

### Client Credentials Flow (RFC 6749, Section 4.4)

OAuth 2.0 передбачає для таких сценаріїв **Client Credentials Flow** — потік, де клієнтом є сам сервіс:

```
Analytics Service                    Authorization Server
       │                                     │
       │  POST /oauth/token                  │
       │  grant_type=client_credentials      │
       │  client_id=analytics-service        │
       │  client_secret=<secret>             │
       │  scope=read:notes:stats             │
       │────────────────────────────────────→│
       │                                     │
       │  {                                  │
       │    "access_token": "eyJ...",        │
       │    "token_type": "bearer",          │
       │    "expires_in": 3600               │
       │  }                                  │
       │←────────────────────────────────────│
       │                                     │
       │  GET /internal/notes/stats          │
       │  Authorization: Bearer eyJ...       │
       │────────────────────────────────────→│
       │           Notes Service             │
```

### Приклад на Python

```python
import requests
import time

class ServiceClient:
    """Клієнт для service-to-service автентифікації."""

    def __init__(self, client_id, client_secret, token_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self._token = None
        self._expires_at = 0

    def _get_token(self, scope):
        """Отримати токен через Client Credentials Flow."""
        resp = requests.post(self.token_url, data={
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": scope,
        })
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        # Оновлюємо за 60 сек до закінчення
        self._expires_at = time.time() + data["expires_in"] - 60
        return self._token

    def get_headers(self, scope="read:notes:stats"):
        """Повертає заголовки з актуальним токеном."""
        if not self._token or time.time() >= self._expires_at:
            self._get_token(scope)
        return {"Authorization": f"Bearer {self._token}"}


# Використання
analytics = ServiceClient(
    client_id="analytics-service",
    client_secret="s3cr3t-for-analytics",
    token_url="https://auth.securenotes.example/oauth/token"
)

stats = requests.get(
    "http://notes-service:8080/internal/notes/stats",
    headers=analytics.get_headers()
)
```

### Ключові відмінності від Authorization Code Flow

| | Authorization Code Flow | Client Credentials Flow |
|---|---|---|
| **Хто діє** | Від імені користувача | Від імені сервісу |
| **Взаємодія з користувачем** | Потрібна (логін, consent) | Не потрібна |
| **Refresh token** | Так | Зазвичай ні |
| **Типовий scope** | `read:notes write:notes` | `service:read:stats` |
| **`sub` claim у токені** | ID користувача | ID сервісу (client_id) |

### Зберігання client_secret

Client secret сервісу — це еквівалент пароля. Його ніколи не зберігають у коді:

- **Kubernetes Secrets** — зашифровані секрети кластера
- **HashiCorp Vault** — централізоване сховище секретів із ротацією
- **AWS Secrets Manager / GCP Secret Manager** — хмарні сховища
- **Environment variables** — мінімальний варіант, краще за hardcoding, але гірше за спеціалізовані рішення

---

## 5. Token Exchange — RFC 8693

### Проблема

Простий propagation прокидає оригінальний токен користувача без змін. Але що, якщо Notes Service потрібен токен із вужчими правами для виклику Search Service? Або якщо Notes Service повинен діяти від імені користувача, але з обмеженим scope?

### Що таке Token Exchange

**Token Exchange** (RFC 8693) — стандартний механізм обміну одного токена на інший з іншими характеристиками. Сервіс надсилає свій поточний токен до Authorization Server і отримує новий токен із потрібними scope, audience або lifetime.

```
Notes Service                    Authorization Server
       │                                     │
       │  POST /oauth/token                  │
       │  grant_type=                        │
       │    urn:ietf:params:oauth:           │
       │    grant-type:token-exchange        │
       │  subject_token=<user_jwt>           │
       │  subject_token_type=               │
       │    urn:ietf:params:oauth:           │
       │    token-type:access_token          │
       │  audience=search-service            │
       │  scope=read:tags                    │
       │────────────────────────────────────→│
       │                                     │
       │  {                                  │
       │    "access_token": "eyJ...(new)",   │
       │    "token_type": "bearer",          │
       │    "issued_token_type":             │
       │      "urn:ietf:params:oauth:       │
       │       token-type:access_token",     │
       │    "expires_in": 300                │
       │  }                                  │
       │←────────────────────────────────────│
```

### Параметри запиту

| Параметр | Опис |
|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | Токен, який обмінюється (токен користувача) |
| `subject_token_type` | Тип subject_token (access_token, id_token, jwt) |
| `audience` | Для якого сервісу призначений новий токен |
| `scope` | Бажаний scope нового токена (підмножина оригінального) |
| `resource` | URI ресурсу, для якого потрібен токен |

### Приклад на Python

```python
def exchange_token(original_token, target_audience, target_scope):
    """Обмін токена для downstream-сервісу."""
    resp = requests.post(
        "https://auth.securenotes.example/oauth/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": original_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": target_audience,
            "scope": target_scope,
        },
        auth=("notes-service", "notes-service-secret"),
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


# Notes Service обмінює токен користувача на вужчий
# для виклику Search Service
narrowed = exchange_token(
    original_token=request.bearer_token,
    target_audience="search-service",
    target_scope="read:tags"
)

resp = requests.get(
    "http://search-service:8082/internal/tags/42",
    headers={"Authorization": f"Bearer {narrowed}"}
)
```

### Навіщо це потрібно

Token Exchange реалізує **принцип найменших привілеїв** (principle of least privilege):

- Notes Service отримує від користувача токен із scope `read:notes write:notes`
- Для виклику Search Service йому потрібен лише `read:tags`
- Token Exchange звужує scope та встановлює правильний audience
- Якщо Search Service скомпрометований, атакуючий отримує лише `read:tags`, а не повний доступ до нотаток

### Delegation vs Impersonation

RFC 8693 розрізняє два режими:

- **Delegation** — новий токен містить інформацію про обидвох: і користувача (`sub`), і сервіс, який виконує дію (`act` claim). Authorization Server бачить повний ланцюжок делегування
- **Impersonation** — новий токен виглядає так, ніби його видав безпосередньо користувач. `act` claim відсутній. Небезпечніший варіант, використовується обережно

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

Claim `act` (actor) показує, що запит виконує `notes-service` від імені `user-12345`.

---

## 6. Audience Restriction — обмеження токенів

### Проблема

Якщо один і той самий токен валідний для всіх сервісів, скомпрометований сервіс може використати цей токен для доступу до будь-якого іншого сервісу. Це порушує принцип ізоляції — одна з головних причин переходу на мікросервіси.

### Claim `aud` (audience)

JWT-стандарт (RFC 7519) передбачає claim `aud` — список реципієнтів, для яких призначений токен. Сервіс повинен відхиляти токени, у яких його ідентифікатор відсутній у `aud`:

```json
{
  "sub": "user-12345",
  "aud": ["notes-service"],
  "scope": "read:notes write:notes",
  "iss": "https://auth.securenotes.example",
  "exp": 1709136000
}
```

Цей токен валідний **лише** для Notes Service. Якщо хтось спробує використати його для Search Service, той перевірить `aud`, не знайде `search-service` і відхилить запит з помилкою `invalid_audience`.

### Приклад валідації audience

```python
import jwt

def validate_token_with_audience(token, expected_audience):
    """Валідація токена з перевіркою audience."""
    try:
        claims = jwt.decode(
            token,
            key=get_public_key(),
            algorithms=["RS256"],
            audience=expected_audience,  # <-- перевірка aud
            issuer="https://auth.securenotes.example"
        )
        return claims
    except jwt.InvalidAudienceError:
        raise AuthError("Token not intended for this service")
    except jwt.ExpiredSignatureError:
        raise AuthError("Token expired")
    except jwt.InvalidTokenError as e:
        raise AuthError(f"Invalid token: {e}")
```

### Audience + Token Exchange = ізоляція

Комбінація audience restriction та token exchange дає потужну ізоляцію:

```
1. Користувач отримує токен:     aud=["api-gateway"]
2. Gateway обмінює на:           aud=["notes-service"], scope=read:notes
3. Notes Service обмінює на:     aud=["search-service"], scope=read:tags
```

На кожному кроці токен звужується. Якщо скомпрометований Search Service — атакуючий має токен лише з `aud=search-service` та `scope=read:tags`. Він не зможе використати його для Notes Service чи API Gateway.

### Без audience restriction

Без `aud` один скомпрометований сервіс може використати отриманий токен для доступу до будь-якого іншого сервісу:

```
НЕБЕЗПЕЧНО:
┌──────────────┐    токен (без aud)    ┌──────────────┐
│ Зловмисник   │──────────────────────→│ Notes Service│  ДОСТУП!
│ (через       │──────────────────────→│ Auth Service │  ДОСТУП!
│  Search Svc) │──────────────────────→│ Analytics Svc│  ДОСТУП!
└──────────────┘                       └──────────────┘

БЕЗПЕЧНО (з aud):
┌──────────────┐  токен aud=search-svc ┌──────────────┐
│ Зловмисник   │──────────────────────→│ Notes Service│  ВІДХИЛЕНО!
│ (через       │──────────────────────→│ Auth Service │  ВІДХИЛЕНО!
│  Search Svc) │──────────────────────→│ Search Svc   │  (вже скомпр.)
└──────────────┘                       └──────────────┘
```

---

## 7. Централізована vs розподілена валідація

### Два підходи

У мікросервісній архітектурі є два фундаментально різних підходи до валідації токенів:

**Централізована валідація (introspection)** — кожен сервіс надсилає токен до Authorization Server для перевірки через endpoint `/introspect` (RFC 7662).

**Розподілена валідація (local)** — кожен сервіс самостійно перевіряє JWT-підпис за допомогою публічного ключа, отриманого з JWKS endpoint.

### Централізована валідація

```
Notes Service                    Authorization Server
       │                                     │
       │  POST /oauth/introspect             │
       │  token=eyJhbGciOiJS...              │
       │────────────────────────────────────→│
       │                                     │  Перевіряє підпис,
       │                                     │  expiration, revocation
       │  {                                  │
       │    "active": true,                  │
       │    "sub": "user-12345",             │
       │    "scope": "read:notes",           │
       │    "client_id": "web-app"           │
       │  }                                  │
       │←────────────────────────────────────│
```

### Розподілена валідація

```
Notes Service                    JWKS Endpoint
       │                              │
       │  GET /.well-known/jwks.json   │   (кешується на годину)
       │─────────────────────────────→│
       │  { "keys": [...] }           │
       │←─────────────────────────────│
       │                              │
       │  Локально:                   │
       │  1. Перевірити підпис JWT    │
       │  2. Перевірити exp           │
       │  3. Перевірити aud           │
       │  4. Перевірити iss           │
```

### Порівняння

| Критерій | Централізована (introspect) | Розподілена (JWT local) |
|---|---|---|
| **Затримка** | +мережевий запит на кожен виклик | Локально, мілісекунди |
| **Відмовостійкість** | Залежить від Auth Server | Працює навіть якщо Auth Server down |
| **Revocation** | Миттєвий відклик | Діє до закінчення exp (або до ротації JWKS) |
| **Навантаження на Auth Server** | Високе (кожен запит) | Мінімальне (лише JWKS) |
| **Opaque tokens** | Підтримує | Ні (потрібен JWT) |
| **Складність сервісів** | Мінімальна | Потрібна JWT-бібліотека |

### Гібридний підхід

На практиці найчастіше використовують **гібридний** підхід:

- JWT з коротким lifetime (5-15 хвилин) для розподіленої валідації
- Introspection для операцій із підвищеною безпекою (видалення, зміна прав)
- Кешування результатів introspection на кілька секунд для зменшення навантаження

```python
import time
from functools import lru_cache

# Гібридна валідація
def validate_token(token, operation_sensitivity="normal"):
    if operation_sensitivity == "high":
        # Критичні операції — завжди introspect
        return introspect_token(token)
    else:
        # Звичайні операції — локальна валідація JWT
        return validate_jwt_locally(token)

@lru_cache(maxsize=1000)
def introspect_token(token):
    """Introspection з кешуванням на 5 секунд."""
    resp = requests.post(
        "https://auth.securenotes.example/oauth/introspect",
        data={"token": token},
        auth=("notes-service", "notes-service-secret")
    )
    return resp.json()
```

---

## 8. Sidecar Pattern — Envoy та Istio

### Проблема

У попередніх розділах кожен сервіс містив логіку валідації токенів, TLS, rate limiting. Це означає:

- Дублювання коду безпеки в кожному сервісі
- Потреба оновлювати бібліотеки JWT у кожному сервісі окремо
- Різні мови програмування — різні реалізації валідації
- Розробники бізнес-логіки повинні розуміти OAuth

### Sidecar — автентифікація за межами сервісу

**Sidecar** (бічний вагон) — це окремий контейнер, який працює поруч із основним сервісом (у тому ж Pod у Kubernetes) і бере на себе cross-cutting concerns: автентифікацію, TLS, метрики, трейсинг.

```
┌──── Kubernetes Pod ────────────────────────────┐
│                                                 │
│  ┌─────────────┐         ┌──────────────────┐  │
│  │   Envoy     │ ◄──────→│  Notes Service   │  │
│  │   Sidecar   │ :8080   │  (бізнес-логіка) │  │
│  │             │         │                  │  │
│  │ - TLS       │         │  Не знає про:    │  │
│  │ - JWT valid.│         │  - токени        │  │
│  │ - Rate limit│         │  - TLS           │  │
│  │ - mTLS      │         │  - Rate limiting │  │
│  │ - Metrics   │         │                  │  │
│  └─────────────┘         └──────────────────┘  │
│        ↑                                        │
│        │ Весь зовнішній трафік                  │
│        │ проходить через sidecar               │
└────────│────────────────────────────────────────┘
         │
    Мережа
```

### Istio Service Mesh

**Istio** — це service mesh платформа, яка автоматично додає Envoy sidecar до кожного Pod і централізовано керує політиками безпеки.

Ключові компоненти Istio для автентифікації:

- **PeerAuthentication** — mTLS між сервісами (service-to-service identity)
- **RequestAuthentication** — валідація JWT на вході
- **AuthorizationPolicy** — правила доступу (RBAC)

### Приклад: конфігурація Istio

```yaml
# PeerAuthentication — вимагати mTLS між усіма сервісами
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: securenotes
spec:
  mtls:
    mode: STRICT

---
# RequestAuthentication — валідація JWT
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: jwt-auth
  namespace: securenotes
spec:
  selector:
    matchLabels:
      app: notes-service
  jwtRules:
    - issuer: "https://auth.securenotes.example"
      jwksUri: "https://auth.securenotes.example/.well-known/jwks.json"
      audiences:
        - "notes-service"

---
# AuthorizationPolicy — тільки автентифіковані запити
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: notes-policy
  namespace: securenotes
spec:
  selector:
    matchLabels:
      app: notes-service
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/securenotes/sa/api-gateway"]
      to:
        - operation:
            methods: ["GET", "POST", "PUT", "DELETE"]
      when:
        - key: request.auth.claims[iss]
          values: ["https://auth.securenotes.example"]
```

### mTLS — взаємна автентифікація сервісів

У sidecar-архітектурі Istio забезпечує **mutual TLS** (mTLS) між усіма сервісами автоматично. Кожен sidecar отримує сертифікат від Istio CA, і при кожному з'єднанні обидві сторони перевіряють сертифікати одна одної:

```
Notes Service Pod                    Search Service Pod
┌──────────────────┐                ┌──────────────────┐
│ Envoy ◄── mTLS ──────────────────→ Envoy            │
│ (cert: notes-svc)│                │ (cert: search-svc)│
│                  │                │                  │
│ Notes Service    │                │ Search Service   │
│ (plain HTTP)     │                │ (plain HTTP)     │
└──────────────────┘                └──────────────────┘
```

Бізнес-сервіси спілкуються по plain HTTP з локальним Envoy, а Envoy забезпечує шифрований канал.

### Переваги sidecar-підходу

- **Розділення відповідальностей** — розробники бізнес-логіки не пишуть код безпеки
- **Єдина реалізація** — оновлення політик безпеки без зміни коду сервісів
- **Мовна незалежність** — Python, Go, Java сервіси отримують однакову безпеку
- **Observability** — sidecar автоматично збирає метрики та трейси
- **Zero-trust** — mTLS між усіма сервісами без довіри до мережевого периметру

---

## 9. Практика — розділяємо SecureNotes на мікросервіси

### Архітектура

Максим розділяє SecureNotes на мікросервіси: Auth Service, Notes Service, API Gateway. Кожен сервіс має чітку зону відповідальності:

```
                        ┌──────────────────────────────────────────┐
                        │            Kubernetes Cluster             │
                        │                                          │
Клієнт ── HTTPS ──→ ┌──┴────────────┐                             │
                     │  API Gateway  │                             │
                     │  (port 443)   │                             │
                     └──┬─────┬──────┘                             │
                        │     │                                    │
               ┌────────┘     └────────┐                           │
               ▼                       ▼                           │
        ┌──────────────┐       ┌──────────────┐                    │
        │ Auth Service │       │ Notes Service│                    │
        │ (port 8081)  │       │ (port 8080)  │                    │
        │              │       │              │                    │
        │ - /oauth/    │       │ - /notes/    │                    │
        │   authorize  │       │ - /internal/ │                    │
        │ - /oauth/    │       │   notes/     │                    │
        │   token      │       └──────────────┘                    │
        │ - /oauth/    │                                           │
        │   introspect │                                           │
        │ - /.well-    │                                           │
        │   known/jwks │                                           │
        └──────────────┘                                           │
                        └──────────────────────────────────────────┘
```

### Auth Service — видача та валідація токенів

```python
# auth_service.py
from flask import Flask, request, jsonify
import jwt
import time
import secrets
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# RSA ключова пара для підпису JWT
PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537, key_size=2048
)
PUBLIC_KEY = PRIVATE_KEY.public_key()

# Зареєстровані сервіси (client credentials)
SERVICE_CLIENTS = {
    "notes-service": {
        "secret": "notes-s3cr3t-hash",
        "allowed_scopes": ["read:notes", "write:notes"]
    },
    "api-gateway": {
        "secret": "gateway-s3cr3t-hash",
        "allowed_scopes": ["token:exchange", "token:introspect"]
    }
}

ISSUED_TOKENS = {}  # Для introspection та revocation


@app.route("/oauth/token", methods=["POST"])
def token_endpoint():
    grant_type = request.form.get("grant_type")

    if grant_type == "client_credentials":
        return handle_client_credentials()
    elif grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
        return handle_token_exchange()
    else:
        return jsonify({"error": "unsupported_grant_type"}), 400


def handle_client_credentials():
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    scope = request.form.get("scope", "")

    client = SERVICE_CLIENTS.get(client_id)
    if not client or client["secret"] != client_secret:
        return jsonify({"error": "invalid_client"}), 401

    requested_scopes = scope.split()
    for s in requested_scopes:
        if s not in client["allowed_scopes"]:
            return jsonify({"error": "invalid_scope"}), 400

    token_id = secrets.token_hex(16)
    now = int(time.time())

    payload = {
        "jti": token_id,
        "sub": client_id,
        "iss": "https://auth.securenotes.example",
        "aud": client_id,
        "scope": scope,
        "iat": now,
        "exp": now + 3600,
    }

    access_token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
    ISSUED_TOKENS[token_id] = payload

    return jsonify({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 3600,
    })


def handle_token_exchange():
    """RFC 8693 Token Exchange."""
    subject_token = request.form.get("subject_token")
    audience = request.form.get("audience")
    scope = request.form.get("scope", "")

    # Валідуємо subject_token
    try:
        original = jwt.decode(subject_token, PUBLIC_KEY,
                              algorithms=["RS256"],
                              options={"verify_aud": False})
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid_grant"}), 400

    token_id = secrets.token_hex(16)
    now = int(time.time())

    new_payload = {
        "jti": token_id,
        "sub": original["sub"],
        "iss": "https://auth.securenotes.example",
        "aud": audience,
        "scope": scope,
        "iat": now,
        "exp": now + 300,  # Коротший lifetime
        "act": {"sub": request.authorization.username}
    }

    new_token = jwt.encode(new_payload, PRIVATE_KEY, algorithm="RS256")
    ISSUED_TOKENS[token_id] = new_payload

    return jsonify({
        "access_token": new_token,
        "token_type": "bearer",
        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "expires_in": 300,
    })


@app.route("/oauth/introspect", methods=["POST"])
def introspect():
    token = request.form.get("token")
    try:
        claims = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"],
                            options={"verify_aud": False})
        return jsonify({"active": True, **claims})
    except jwt.InvalidTokenError:
        return jsonify({"active": False})


@app.route("/.well-known/jwks.json")
def jwks():
    from jwt import algorithms
    pub_numbers = PUBLIC_KEY.public_numbers()
    jwk = algorithms.RSAAlgorithm.to_jwk(PUBLIC_KEY, as_dict=True)
    jwk["kid"] = "securenotes-key-1"
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return jsonify({"keys": [jwk]})


if __name__ == "__main__":
    app.run(port=8081)
```

### Notes Service — бізнес-логіка нотаток

```python
# notes_service.py
from flask import Flask, request, jsonify
import jwt
import requests

app = Flask(__name__)

AUTH_JWKS_URI = "http://auth-service:8081/.well-known/jwks.json"
AUTH_ISSUER = "https://auth.securenotes.example"

# Імітація бази даних
NOTES_DB = {
    1: {"title": "OAuth нотатки", "body": "PKCE є обов'язковим...",
        "owner": "maksym.vytrebenko"},
    2: {"title": "JWT структура", "body": "Header.Payload.Signature",
        "owner": "maksym.vytrebenko"},
}

_public_key_cache = None


def get_public_key():
    global _public_key_cache
    if not _public_key_cache:
        resp = requests.get(AUTH_JWKS_URI)
        jwks = resp.json()
        key_data = jwks["keys"][0]
        _public_key_cache = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
    return _public_key_cache


def require_auth(f):
    """Middleware для валідації JWT із перевіркою audience."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing_token"}), 401
        token = auth.split(" ", 1)[1]
        try:
            claims = jwt.decode(
                token, get_public_key(),
                algorithms=["RS256"],
                audience="notes-service",
                issuer=AUTH_ISSUER
            )
        except jwt.InvalidTokenError as e:
            return jsonify({"error": str(e)}), 401
        request.claims = claims
        request.bearer_token = token
        return f(*args, **kwargs)
    return decorated


@app.route("/notes", methods=["GET"])
@require_auth
def list_notes():
    user = request.claims["sub"]
    user_notes = {k: v for k, v in NOTES_DB.items()
                  if v["owner"] == user}
    return jsonify(user_notes)


@app.route("/notes/<int:note_id>", methods=["GET"])
@require_auth
def get_note(note_id):
    note = NOTES_DB.get(note_id)
    if not note:
        return jsonify({"error": "not_found"}), 404
    if note["owner"] != request.claims["sub"]:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(note)


@app.route("/notes", methods=["POST"])
@require_auth
def create_note():
    if "write:notes" not in request.claims.get("scope", "").split():
        return jsonify({"error": "insufficient_scope"}), 403
    data = request.get_json()
    note_id = max(NOTES_DB.keys()) + 1
    NOTES_DB[note_id] = {
        "title": data["title"],
        "body": data["body"],
        "owner": request.claims["sub"]
    }
    return jsonify({"id": note_id}), 201


if __name__ == "__main__":
    app.run(port=8080)
```

### API Gateway — маршрутизація та валідація

```python
# api_gateway.py
from flask import Flask, request, Response
import requests
import jwt

app = Flask(__name__)

AUTH_SERVICE = "http://auth-service:8081"
NOTES_SERVICE = "http://notes-service:8080"

ROUTES = {
    "/api/notes": NOTES_SERVICE + "/notes",
    "/api/auth": AUTH_SERVICE + "/oauth",
}

_public_key_cache = None


def get_public_key():
    global _public_key_cache
    if not _public_key_cache:
        resp = requests.get(f"{AUTH_SERVICE}/.well-known/jwks.json")
        jwks = resp.json()
        _public_key_cache = jwt.algorithms.RSAAlgorithm.from_jwk(
            jwks["keys"][0]
        )
    return _public_key_cache


@app.before_request
def validate_and_route():
    # Пропускаємо auth endpoints без валідації
    if request.path.startswith("/api/auth"):
        return None

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return Response(
            '{"error":"missing_token"}',
            status=401,
            content_type="application/json"
        )

    token = auth.split(" ", 1)[1]
    try:
        claims = jwt.decode(
            token, get_public_key(),
            algorithms=["RS256"],
            audience="api-gateway",
            issuer="https://auth.securenotes.example"
        )
    except jwt.InvalidTokenError as e:
        return Response(
            f'{{"error":"{e}"}}',
            status=401,
            content_type="application/json"
        )

    # Token exchange: звужуємо токен для notes-service
    exchange_resp = requests.post(
        f"{AUTH_SERVICE}/oauth/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": "notes-service",
            "scope": claims.get("scope", ""),
        },
        auth=("api-gateway", "gateway-s3cr3t-hash")
    )

    if exchange_resp.status_code == 200:
        request.downstream_token = exchange_resp.json()["access_token"]
    else:
        request.downstream_token = token  # fallback


@app.route("/api/notes", methods=["GET", "POST"])
@app.route("/api/notes/<path:subpath>", methods=["GET", "PUT", "DELETE"])
def proxy_notes(subpath=""):
    url = f"{NOTES_SERVICE}/notes"
    if subpath:
        url += f"/{subpath}"

    downstream_token = getattr(request, "downstream_token", "")

    resp = requests.request(
        method=request.method,
        url=url,
        headers={
            "Authorization": f"Bearer {downstream_token}",
            "Content-Type": request.content_type or "application/json",
        },
        data=request.get_data(),
    )

    return Response(
        resp.content,
        status=resp.status_code,
        content_type=resp.headers.get("Content-Type")
    )


if __name__ == "__main__":
    app.run(port=443)
```

### Docker Compose для локального запуску

```yaml
# docker-compose.yml
version: "3.8"
services:
  auth-service:
    build: ./auth-service
    ports:
      - "8081:8081"
    environment:
      - FLASK_ENV=development

  notes-service:
    build: ./notes-service
    ports:
      - "8080:8080"
    environment:
      - AUTH_JWKS_URI=http://auth-service:8081/.well-known/jwks.json

  api-gateway:
    build: ./api-gateway
    ports:
      - "443:443"
    depends_on:
      - auth-service
      - notes-service
    environment:
      - AUTH_SERVICE=http://auth-service:8081
      - NOTES_SERVICE=http://notes-service:8080
```

### Тестування

```bash
# 1. Отримати сервісний токен для тестування
TOKEN=$(curl -s -X POST http://localhost:8081/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=notes-service" \
  -d "client_secret=notes-s3cr3t-hash" \
  -d "scope=read:notes write:notes" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Token: ${TOKEN:0:20}..."

# 2. Отримати список нотаток
curl -s http://localhost:8080/notes \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# 3. Створити нотатку
curl -s -X POST http://localhost:8080/notes \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Мікросервіси","body":"OAuth у мікросервісах"}' | python3 -m json.tool

# 4. Introspection
curl -s -X POST http://localhost:8081/oauth/introspect \
  -d "token=$TOKEN" | python3 -m json.tool

# 5. Token exchange
curl -s -X POST http://localhost:8081/oauth/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=search-service" \
  -d "scope=read:tags" \
  -u "api-gateway:gateway-s3cr3t-hash" | python3 -m json.tool
```

---

## 10. Підсумки

### Що ми розглянули

- **Token Propagation** — прокидання токена через ланцюжок мікросервісів
- **API Gateway** — єдина точка входу з валідацією токенів та мережевою ізоляцією
- **Client Credentials Flow** — автентифікація сервіс-до-сервісу без участі користувача
- **Token Exchange (RFC 8693)** — обмін токенів для звуження привілеїв та зміни audience
- **Audience Restriction** — `aud` claim обмежує використання токена конкретним сервісом
- **Централізована vs розподілена валідація** — introspection vs локальна перевірка JWT
- **Sidecar Pattern** — Envoy/Istio для винесення безпеки з бізнес-коду

### Ключові висновки

1. Перехід від моноліту до мікросервісів створює нові проблеми безпеки — identity propagation, service-to-service auth, blast radius
2. **API Gateway** — обов'язковий елемент, але ефективний лише з мережевою ізоляцією
3. **Client Credentials Flow** — для фонових задач без контексту користувача
4. **Token Exchange + Audience Restriction** = принцип найменших привілеїв на рівні токенів
5. **Sidecar/Service Mesh** — промисловий підхід до безпеки мікросервісів, який відділяє безпеку від бізнес-логіки

### Що далі?

У наступній лекції ми розглянемо **безпеку веб-додатків** — Лекція 12: Web Security Hardening.

Максим захистив комунікацію між мікросервісами SecureNotes. Але що, якщо атака спрямована не на міжсервісну комунікацію, а на сам веб-інтерфейс? XSS, CSRF, clickjacking, Content Security Policy — це загрози рівня браузера, які OAuth сам по собі не вирішує.

- **OWASP Top 10** — найпоширеніші вразливості веб-додатків
- **Content Security Policy (CSP)** — захист від XSS на рівні заголовків
- **CSRF protection** — як OAuth та SameSite cookies працюють разом
- **Security headers** — HSTS, X-Frame-Options, X-Content-Type-Options

---

## Література

1. RFC 6749 — The OAuth 2.0 Authorization Framework (Section 4.4 — Client Credentials Grant)
2. RFC 8693 — OAuth 2.0 Token Exchange
3. RFC 7662 — OAuth 2.0 Token Introspection
4. RFC 7519 — JSON Web Token (JWT) — `aud` claim
5. Chris Richardson. *Microservices Patterns.* — Manning: 2018
6. Prabath Siriwardena. *Advanced API Security.* — Apress: 2019
7. Istio Documentation — Security — https://istio.io/latest/docs/concepts/security/
8. NIST SP 800-204 — Security Strategies for Microservices-based Application Systems
