# Лекція 7. Access Token, Refresh Token, Token Lifecycle

## Зміст

1. [Проблема — JWT не можна відкликати](#1-проблема--jwt-не-можна-відкликати)
2. [Short-lived Access Tokens — чому короткий термін дії](#2-short-lived-access-tokens--чому-короткий-термін-дії)
3. [Refresh Tokens — довгоживучий ключ до оновлення](#3-refresh-tokens--довгоживучий-ключ-до-оновлення)
4. [Token Storage Strategies — де зберігати на клієнті](#4-token-storage-strategies--де-зберігати-на-клієнті)
5. [Token Revocation — RFC 7009](#5-token-revocation--rfc-7009)
6. [Token Introspection — RFC 7662](#6-token-introspection--rfc-7662)
7. [Refresh Token Rotation — кожен раз новий refresh token](#7-refresh-token-rotation--кожен-раз-новий-refresh-token)
8. [Sliding Sessions — автоматичне продовження](#8-sliding-sessions--автоматичне-продовження)
9. [Logout — як правильно завершити сесію](#9-logout--як-правильно-завершити-сесію)
10. [Підсумки](#10-підсумки)

---

## 1. Проблема — JWT не можна відкликати

### Місток від лекції 7

У лекції 7 ми розглянули **JWT** (JSON Web Token) — самодостатній (self-contained) токен, який містить усю інформацію про користувача та підписаний сервером. Resource Server може перевірити JWT локально, без звернення до Authorization Server. Це дає масштабованість та швидкість.

Але є фундаментальна проблема: **JWT — stateless**. Сервер не зберігає інформацію про видані токени. А якщо токен вкрадено?

### Сценарій: вкрадений токен

Максим Витребенько розробляє додаток **SecureNotes**. Він реалізував авторизацію через OAuth 2.0 з JWT access token. Все працювало чудово, доки одного дня не стався інцидент:

1. Користувач Олена залогінилась у SecureNotes і отримала JWT access token з терміном дії 24 години
2. Олена підключилась до публічного Wi-Fi у кав'ярні
3. Зловмисник перехопив її access token (man-in-the-middle атака або XSS-ін'єкція)
4. Олена помітила підозрілу активність і змінила пароль

**Питання:** чи зупинить зміна пароля зловмисника?

**Відповідь:** ні. JWT — self-contained. Resource Server перевіряє лише підпис і термін дії. Він не знає, що пароль змінився. Зловмисник продовжує використовувати вкрадений токен наступні 24 години.

### Чому це критично

```
┌──────────┐     вкрадений JWT      ┌──────────────────┐
│ Зловмис- │ ─────────────────────→ │  Resource Server  │
│   ник    │                        │                   │
└──────────┘                        │ Перевірка:        │
                                    │ ✓ Підпис валідний │
                                    │ ✓ exp не минув    │
                                    │ ✓ Доступ надано!  │
                                    └──────────────────┘
                                           │
                                    Сервер НЕ знає,
                                    що токен вкрадено
```

JWT не має механізму відкликання (revocation) за замовчуванням. Сервер не тримає список виданих токенів — у цьому й суть stateless-підходу. Але це означає, що **єдиний спосіб зупинити вкрадений JWT — чекати, поки він сам не протухне**.

З токеном на 24 години — це 24 години повного доступу для зловмисника. Нам потрібна інша стратегія.

---

## 2. Short-lived Access Tokens — чому короткий термін дії

### Ідея: мінімізувати вікно вразливості

Якщо ми не можемо відкликати JWT, ми можемо **мінімізувати час, протягом якого вкрадений токен є дійсним**. Замість 24 годин — видавати access token на 5-15 хвилин.

```
Довгоживучий токен (24 год):
|████████████████████████████████████████████████| вікно атаки

Короткоживучий токен (15 хв):
|██|                                              вікно атаки
```

Якщо зловмисник перехопить токен з терміном дії 15 хвилин, він має лише 15 хвилин доступу замість цілої доби. Це не ідеальний захист, але значно зменшує ризик.

### Рекомендовані значення

| Тип додатку | Термін дії access token |
|---|---|
| Банківський додаток | 5 хвилин |
| SaaS-платформа | 10-15 хвилин |
| Внутрішній сервіс (B2B) | 15-30 хвилин |
| IoT-пристрій | залежить від контексту |

### Нова проблема

Але тепер виникає інше питання: якщо access token живе лише 15 хвилин, що робити далі? Просити користувача вводити логін і пароль кожні 15 хвилин?

Очевидно, це неприйнятно з точки зору UX. Нам потрібен механізм **тихого оновлення** (silent refresh) токена без участі користувача.

---

## 3. Refresh Tokens — довгоживучий ключ до оновлення

### Визначення

**Refresh Token** — це довгоживучий токен (години, дні, тижні), який використовується **виключно** для отримання нового access token. Refresh token ніколи не надсилається до Resource Server — він відправляється тільки до Authorization Server.

### Як це працює

```
┌──────────┐                    ┌───────────────────┐
│  Client  │ ── access_token ─→ │  Resource Server   │
│          │ ←── 200 OK ──────  │                    │
│          │                    └───────────────────┘
│          │
│          │   ... через 15 хв access_token протухає ...
│          │
│          │ ── access_token ─→ │  Resource Server   │
│          │ ←── 401 Expired ── │                    │
│          │                    └───────────────────┘
│          │
│          │ ── refresh_token → ┌───────────────────┐
│          │ ←── new access  ── │ Authorization      │
│          │     token          │ Server             │
└──────────┘                    └───────────────────┘
```

### Refresh Token Grant (RFC 6749, Section 6)

```http
POST /oauth/token HTTP/1.1
Host: auth.securenotes.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4...
&client_id=securenotes-web
&client_secret=s3cr3t
```

Відповідь:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "bmV3IHJlZnJlc2ggdG9rZW4..."
}
```

### Приклад на Python

```python
import requests

def refresh_access_token(auth_server_url, refresh_token, client_id, client_secret):
    """Отримати новий access token за допомогою refresh token."""
    response = requests.post(
        f"{auth_server_url}/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    )
    if response.status_code == 200:
        tokens = response.json()
        return tokens["access_token"], tokens.get("refresh_token")
    else:
        # Refresh token протух або відкликаний — потрібен повторний логін
        raise Exception("Refresh failed — redirect to login")
```

### Чому це безпечніше

| Властивість | Access Token | Refresh Token |
|---|---|---|
| Термін дії | 5-15 хвилин | дні або тижні |
| Куди надсилається | Resource Server (кожен запит) | Authorization Server (рідко) |
| Формат | зазвичай JWT (self-contained) | зазвичай opaque string |
| Зберігається на сервері | ні (stateless) | так (stateful) |
| Можна відкликати | складно (blacklist) | так (видалити з БД) |

Ключова різниця: refresh token надсилається **набагато рідше** (лише коли access token протух) і тільки до **одного** сервера (Authorization Server). Це зменшує поверхню атаки. А оскільки refresh token зазвичай opaque (непрозорий рядок) і зберігається в базі Authorization Server, його **можна відкликати** — просто видалити з бази.

---

## 4. Token Storage Strategies — де зберігати на клієнті

### Проблема

Максим реалізував access token + refresh token у SecureNotes. Тепер питання: де на клієнті (у браузері) зберігати ці токени? Кожен варіант має свої ризики.

### Порівняння варіантів

| Місце зберігання | XSS-стійкість | CSRF-стійкість | Переваги | Недоліки |
|---|---|---|---|---|
| `localStorage` | ні | так | простота, не надсилається автоматично | JavaScript має повний доступ |
| `sessionStorage` | ні | так | очищується при закритті вкладки | не зберігається між вкладками |
| `httpOnly cookie` | так | ні | недоступна для JS | потребує CSRF-захисту |
| In-memory (змінна JS) | частково | так | зникає при перезавантаженні | не переживає refresh сторінки |

### localStorage

```javascript
// Зберегти
localStorage.setItem('access_token', token);

// Прочитати
const token = localStorage.getItem('access_token');
```

**Ризик:** будь-який JavaScript-код на сторінці (включаючи XSS-ін'єкцію) має повний доступ до `localStorage`. Одна XSS-вразливість — і зловмисник отримує всі токени.

### httpOnly cookie

```http
Set-Cookie: refresh_token=abc123;
  HttpOnly;
  Secure;
  SameSite=Strict;
  Path=/oauth/token;
  Max-Age=604800
```

**HttpOnly** — cookie недоступна для JavaScript (`document.cookie` її не бачить). **Secure** — надсилається тільки через HTTPS. **SameSite=Strict** — не надсилається з cross-origin запитів. **Path=/oauth/token** — надсилається тільки до endpoint оновлення токена.

**Ризик:** cookie автоматично додається браузером до запитів, що відкриває вектор для CSRF-атак. Але `SameSite=Strict` та CSRF-токени це нейтралізують.

### Рекомендована стратегія

```
┌──────────────────────────────────────────────┐
│              Браузер (клієнт)                 │
│                                              │
│  Access Token  →  in-memory (JS змінна)      │
│  Refresh Token →  httpOnly Secure cookie     │
│                                              │
│  ✓ Access token: не переживає XSS             │
│    (зникає при оновленні сторінки)           │
│  ✓ Refresh token: недоступний для JS          │
│    (httpOnly захищає від XSS)                │
└──────────────────────────────────────────────┘
```

Access token зберігається в пам'яті JavaScript (змінна або closure). Якщо сторінка перезавантажується — токен втрачається, але клієнт використовує refresh token cookie для отримання нового. Refresh token зберігається як httpOnly cookie — JavaScript не має до нього доступу.

---

## 5. Token Revocation — RFC 7009

### Навіщо потрібен revocation

Refresh token довгоживучий — він може існувати тижнями. Але що, якщо:

- Користувач натиснув "Вийти" (logout)?
- Адміністратор заблокував обліковий запис?
- Виявлено компрометацію (compromise) токена?

Потрібен механізм, щоб **явно анулювати** (revoke) токен до закінчення його терміну дії.

### RFC 7009 — Token Revocation

RFC 7009 визначає стандартний endpoint для відкликання токенів:

```http
POST /oauth/revoke HTTP/1.1
Host: auth.securenotes.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czNjcjN0OmNsaWVudF9zZWNyZXQ=

token=dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4...
&token_type_hint=refresh_token
```

**Важливі деталі:**

- Endpoint **завжди повертає 200 OK**, навіть якщо токен не існує або вже відкликаний. Це зроблено навмисно — щоб атакуючий не міг визначити, які токени є валідними (timing attack prevention)
- `token_type_hint` — підказка серверу, який тип токена відкликається (`access_token` або `refresh_token`). Не обов'язковий, але прискорює пошук
- При відкликанні refresh token сервер **повинен** також інвалідувати всі пов'язані access tokens

### Реалізація на Python (серверна частина)

```python
from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)

# Множина відкликаних токенів (у production — Redis або БД)
revoked_tokens = set()

@app.route("/oauth/revoke", methods=["POST"])
def revoke_token():
    token = request.form.get("token")
    if token:
        # Зберігаємо хеш токена, не сам токен
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        revoked_tokens.add(token_hash)
    # Завжди 200 OK (RFC 7009)
    return jsonify({}), 200

def is_token_revoked(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token_hash in revoked_tokens
```

### Blacklist для access tokens

Для stateless JWT access tokens єдиний спосіб відкликання — **blacklist** (чорний список). Сервер зберігає список відкликаних JWT (або їх `jti` — JWT ID) і перевіряє кожен вхідний токен.

```
┌──────────┐   JWT    ┌──────────────────┐
│  Client  │ ───────→ │ Resource Server   │
└──────────┘          │                   │
                      │ 1. Перевірити     │
                      │    підпис         │
                      │ 2. Перевірити exp │    ┌─────────────┐
                      │ 3. Перевірити jti │───→│  Blacklist   │
                      │    у blacklist    │    │  (Redis)     │
                      └──────────────────┘    └─────────────┘
```

**Компроміс:** blacklist додає stateful-компонент до stateless JWT. Але якщо access token живе лише 15 хвилин, blacklist потрібно тримати максимум 15 хвилин — це допустимий trade-off.

---

## 6. Token Introspection — RFC 7662

### Навіщо потрібна інтроспекція

Не всі токени — JWT. Opaque tokens (непрозорі рядки) не містять інформації всередині. Resource Server не може самостійно перевірити такий токен — йому потрібно **запитати Authorization Server** про стан токена.

### RFC 7662 — Token Introspection

```http
POST /oauth/introspect HTTP/1.1
Host: auth.securenotes.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czNjcjN0OmNsaWVudF9zZWNyZXQ=

token=mF_9.B5f-4.1JqM
&token_type_hint=access_token
```

Відповідь для **активного** токена:

```json
{
  "active": true,
  "client_id": "securenotes-web",
  "username": "maksym.vytrebenko",
  "scope": "read write",
  "sub": "user-12345",
  "aud": "https://api.securenotes.com",
  "iss": "https://auth.securenotes.com",
  "exp": 1700000000,
  "iat": 1699999100,
  "token_type": "Bearer"
}
```

Відповідь для **неактивного** токена (протух, відкликаний, невалідний):

```json
{
  "active": false
}
```

### Коли використовувати introspection vs JWT

| Підхід | JWT (self-contained) | Opaque + Introspection |
|---|---|---|
| Перевірка | локально (підпис + exp) | запит до Authorization Server |
| Швидкість | дуже швидко | мережевий запит |
| Відкликання | blacklist (складно) | перевіряється кожен раз |
| Розмір токена | великий (payload) | маленький (випадковий рядок) |
| Масштабованість | висока | залежить від Auth Server |

На практиці часто використовують **гібридний підхід**: JWT access tokens для швидкої перевірки з коротким терміном дії, а для критичних операцій (переказ коштів, зміна пароля) — додаткова introspection-перевірка.

---

## 7. Refresh Token Rotation — кожен раз новий refresh token

### Проблема: вкрадений refresh token

Access token живе 15 хвилин — навіть якщо його вкрадуть, збитки обмежені. Але refresh token живе тижнями. Якщо зловмисник вкраде refresh token, він зможе генерувати нові access tokens протягом всього терміну дії refresh token.

### Ідея: ротація

**Refresh Token Rotation** — кожного разу, коли клієнт використовує refresh token для отримання нового access token, Authorization Server видає **і новий refresh token**. Старий refresh token стає недійсним.

```
Запит 1:
  refresh_token_v1 → Authorization Server
  ← access_token_2, refresh_token_v2  (v1 тепер недійсний)

Запит 2:
  refresh_token_v2 → Authorization Server
  ← access_token_3, refresh_token_v3  (v2 тепер недійсний)
```

### Виявлення компрометації (Reuse Detection)

Ключова перевага ротації — **виявлення крадіжки**. Якщо зловмисник вкрав `refresh_token_v2` і використав його, Authorization Server видасть `refresh_token_v3` зловмиснику. Коли легітимний клієнт спробує використати `refresh_token_v2`, сервер побачить, що цей токен вже був використаний.

```
Нормальний потік:
  Client: refresh_token_v2 → Server → refresh_token_v3 ✓

Після крадіжки:
  Зловмисник: refresh_token_v2 → Server → refresh_token_v3a ✓
  Client:     refresh_token_v2 → Server → ВІДХИЛЕНО! (вже використаний)
                                          │
                                  Сервер виявив reuse →
                                  інвалідувати ВСЮ сімʼю
                                  refresh tokens
```

Коли сервер виявляє повторне використання refresh token — це сигнал компрометації. Правильна реакція: **інвалідувати всю сім'ю токенів** (всі refresh tokens для цієї сесії) і змусити користувача пройти повторну автентифікацію.

### Реалізація на Python

```python
import secrets
import hashlib
from datetime import datetime, timedelta

# Сховище: token_hash → {user_id, family_id, used, expires_at}
refresh_tokens_db = {}

def issue_refresh_token(user_id, family_id=None):
    """Видати новий refresh token у межах сім'ї."""
    token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if family_id is None:
        family_id = secrets.token_urlsafe(16)  # нова сім'я
    refresh_tokens_db[token_hash] = {
        "user_id": user_id,
        "family_id": family_id,
        "used": False,
        "expires_at": datetime.utcnow() + timedelta(days=30),
    }
    return token, family_id

def rotate_refresh_token(old_token):
    """Ротація: видати новий, інвалідувати старий."""
    old_hash = hashlib.sha256(old_token.encode()).hexdigest()
    record = refresh_tokens_db.get(old_hash)
    if not record:
        return None  # токен не існує
    if record["used"]:
        # REUSE DETECTED — інвалідувати всю сім'ю
        invalidate_family(record["family_id"])
        return None
    if record["expires_at"] < datetime.utcnow():
        return None  # протух
    # Позначити старий як використаний
    record["used"] = True
    # Видати новий у тій самій сім'ї
    new_token, _ = issue_refresh_token(record["user_id"], record["family_id"])
    return new_token

def invalidate_family(family_id):
    """Інвалідувати всі refresh tokens у сім'ї."""
    for token_hash, record in refresh_tokens_db.items():
        if record["family_id"] == family_id:
            record["used"] = True
```

---

## 8. Sliding Sessions — автоматичне продовження

### Проблема

Максим хоче, щоб користувачі SecureNotes не втрачали сесію під час активної роботи. Якщо refresh token живе 30 днів від моменту видачі — користувач, який працює кожен день, все одно буде змушений перелогінитись через 30 днів. Це особливо дратує для додатків, якими користуються постійно.

### Абсолютний vs ковзний термін дії

**Абсолютний термін дії** (absolute expiration):

```
Видача         Протухає (30 днів)
  │                    │
  ▼────────────────────▼
  ████████████████████████  — незалежно від активності
```

**Ковзний термін дії** (sliding expiration):

```
Видача      Активність    Нова межа
  │              │             │
  ▼──────────────▼─────────────▼
  ███████████████████████████████  — продовжується при кожному
                                    використанні refresh token
```

При ковзному підході кожне успішне оновлення (refresh) скидає таймер. Користувач, який працює щодня, ніколи не втратить сесію. Але якщо він не повертається 30 днів — сесія завершується.

### Безпечна реалізація

На практиці комбінують обидва підходи:

```python
class SessionPolicy:
    SLIDING_WINDOW = timedelta(days=30)      # ковзне вікно
    ABSOLUTE_LIFETIME = timedelta(days=90)   # абсолютна межа

    def is_session_valid(self, session):
        now = datetime.utcnow()
        # Ковзний термін: чи був refresh протягом останніх 30 днів?
        if now - session["last_refresh"] > self.SLIDING_WINDOW:
            return False
        # Абсолютний термін: чи не минуло 90 днів від створення?
        if now - session["created_at"] > self.ABSOLUTE_LIFETIME:
            return False
        return True
```

**Абсолютна межа** (absolute lifetime) — обов'язкова. Навіть при ковзному підході сесія має мати максимальний час життя. Це гарантує, що навіть при активному використанні сесія колись завершиться, і credentials будуть перевірені повторно.

---

## 9. Logout — як правильно завершити сесію

### Що означає "вийти"

Logout здається простою дією, але в системі з access token + refresh token потрібно коректно обробити декілька рівнів:

```
┌──────────────────────────────────────────────┐
│              Logout Checklist                 │
│                                              │
│  1. Видалити access token з пам'яті клієнта  │
│  2. Видалити refresh token cookie            │
│  3. Відкликати refresh token на сервері      │
│  4. Інвалідувати серверну сесію (якщо є)     │
│  5. (Опціонально) Blacklist access token     │
└──────────────────────────────────────────────┘
```

### Клієнтська частина (JavaScript)

```javascript
async function logout() {
    // 1. Відкликати refresh token на сервері
    await fetch('/oauth/revoke', {
        method: 'POST',
        credentials: 'include',  // надсилає cookie
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'token_type_hint=refresh_token',
    });

    // 2. Очистити access token з пам'яті
    accessToken = null;

    // 3. Cookie refresh_token буде видалено сервером
    //    (Set-Cookie з Max-Age=0)

    // 4. Перенаправити на сторінку логіну
    window.location.href = '/login';
}
```

### Серверна частина (Python / Flask)

```python
@app.route("/oauth/revoke", methods=["POST"])
def revoke_and_logout():
    # Отримати refresh token з cookie
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        record = refresh_tokens_db.get(token_hash)
        if record:
            # Інвалідувати всю сім'ю токенів
            invalidate_family(record["family_id"])

    response = make_response(jsonify({}), 200)
    # Видалити cookie refresh token
    response.set_cookie(
        "refresh_token", "", max_age=0,
        httponly=True, secure=True, samesite="Strict",
    )
    return response
```

### Типові помилки при logout

1. **Видалити тільки cookie, не відкликати токен.** Зловмисник, який вже скопіював refresh token, продовжує його використовувати
2. **Не інвалідувати серверну сесію.** Якщо сервер зберігає сесію, її потрібно знищити
3. **Забути про інші пристрої.** Кнопка "Вийти з усіх пристроїв" повинна інвалідувати всі refresh tokens користувача, а не тільки поточний
4. **Ігнорувати access token.** Навіть після logout access token залишається валідним до закінчення терміну дії. Для критичних систем — додавати до blacklist

### Logout з усіх пристроїв

```python
def logout_all_devices(user_id):
    """Інвалідувати ВСІ refresh tokens користувача."""
    for token_hash, record in refresh_tokens_db.items():
        if record["user_id"] == user_id:
            record["used"] = True
```

---

## 10. Підсумки

### Що ми розглянули

- Фундаментальна проблема JWT — неможливість відкликання stateless токена
- Short-lived access tokens — зменшення вікна вразливості до 5-15 хвилин
- Refresh tokens — довгоживучий механізм тихого оновлення access token
- Token storage — httpOnly cookie для refresh token, in-memory для access token
- Token Revocation (RFC 7009) — стандартний endpoint для відкликання токенів
- Token Introspection (RFC 7662) — перевірка стану opaque token
- Refresh Token Rotation — ротація з виявленням компрометації (reuse detection)
- Sliding Sessions — ковзний термін дії з абсолютною межею
- Logout — правильне завершення сесії на всіх рівнях

### Ключові висновки

1. **Access token має бути короткоживучим** (5-15 хв) — це основний механізм обмеження збитків при крадіжці
2. **Refresh token — stateful** — зберігається на сервері і може бути відкликаний у будь-який момент
3. **Refresh Token Rotation** — кожен refresh видає новий токен; повторне використання старого = сигнал компрометації
4. **Зберігання:** access token — in-memory, refresh token — httpOnly Secure cookie
5. **Logout — це не тільки очищення cookie** — потрібно відкликати refresh token і, за потреби, blacklist-нути access token

### Що далі?

У наступній лекції ми розглянемо **PKCE** (Proof Key for Code Exchange) — Лекція 8: PKCE та публічні клієнти.

Refresh token + access token вирішують проблему lifecycle. Але є ще одна: **публічні клієнти** (мобільні додатки, SPA) не можуть зберігати `client_secret` у безпеці — його можна витягти з коду. Authorization Code flow без захисту вразливий до перехоплення коду. PKCE вирішує цю проблему без потреби у секреті.

---

## Література

1. RFC 6749 — The OAuth 2.0 Authorization Framework (Section 6: Refreshing an Access Token)
2. RFC 7009 — OAuth 2.0 Token Revocation
3. RFC 7662 — OAuth 2.0 Token Introspection
4. Auth0 — Refresh Token Rotation — https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation
5. OWASP — Session Management Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
6. Aaron Parecki. *OAuth 2.0 Simplified.* — Lulu.com: 2020
