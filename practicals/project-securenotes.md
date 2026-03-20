# Практичний проєкт: SecureNotes

Захищений API для нотаток — покроковий проєкт на 13 лекцій

---

## Вступ

**SecureNotes** — REST API для захищеного зберігання нотаток. Кожна лекція додає новий рівень захисту: від хешування паролів до OAuth 2.0, OpenID Connect, мікросервісів та аудиту безпеки. Максим Витребенько — наш типовий користувач, який хоче безпечно зберігати нотатки і надавати обмежений доступ стороннім додаткам.

**Технології:** Python 3.10+, Flask, SQLite, `cryptography`, `PyJWT`, `argon2-cffi`, `hashlib`, `flask-limiter`

**Структура проєкту (фінальна):**

```
securenotes/
    app.py              # Flask-додаток
    database.py         # SQLite
    models.py           # User, Note
    auth.py             # Реєстрація, логін, JWT
    crypto.py           # AES-GCM, RSA-підписи
    oauth.py            # OAuth 2.0 endpoints
    oidc.py             # OpenID Connect
    middleware.py       # JWT validation
    security.py         # CSP, CORS, rate limiting
    keys/               # RSA keys, TLS cert
    services/           # Мікросервіси (Milestone 11)
    tests/              # Тести
    requirements.txt
```

Кожен **Milestone** = одна лекція. Код у кроках — каркас (scaffolding); місця з `# TODO` реалізуйте самостійно.

---

## Налаштування середовища

```bash
mkdir -p securenotes/keys securenotes/tests && cd securenotes
python3 -m venv venv && source venv/bin/activate
pip install flask cryptography PyJWT argon2-cffi flask-limiter requests
pip freeze > requirements.txt
```

**database.py** — ініціалізація SQLite з таблицями `users` та `notes`:

```python
import sqlite3, os
DB_PATH = os.path.join(os.path.dirname(__file__), "securenotes.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            title TEXT NOT NULL, content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
    """)
    db.commit(); db.close()
```

**models.py** — базові CRUD для `User` та `Note`:

```python
from database import get_db

class User:
    @staticmethod
    def create(username, password_hash):
        db = get_db()
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                   (username, password_hash))
        db.commit(); db.close()

    @staticmethod
    def find_by_username(username):
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?",
                          (username,)).fetchone()
        db.close()
        return user

class Note:
    @staticmethod
    def create(user_id, title, content):
        db = get_db()
        db.execute("INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)",
                   (user_id, title, content))
        db.commit(); db.close()

    @staticmethod
    def get_by_user(user_id):
        db = get_db()
        notes = db.execute("SELECT * FROM notes WHERE user_id = ?",
                           (user_id,)).fetchall()
        db.close()
        return notes
```

**app.py** — мінімальний Flask-сервер:

```python
from flask import Flask, jsonify
from database import init_db
app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
```

Перевірка: `curl http://localhost:5000/health` повертає `{"status": "ok"}`.

---

## Milestone 1: Моделювання загроз (Лекція 1)

### Мета
Створити каркас проєкту, додати CRUD для нотаток, провести STRIDE-аналіз SecureNotes.

### Контекст
Лекція 1 вводить CIA Triad (конфіденційність, цілісність, доступність), Identity / Authentication / Authorization та модель STRIDE для систематичного пошуку вразливостей. Тут ви застосуєте STRIDE до конкретної системи — SecureNotes.

### Кроки
1. Переконайтесь, що каркас із розділу "Налаштування середовища" працює (`/health` повертає 200).

2. Додайте ендпоінти для нотаток до `app.py` (поки без автентифікації):

```python
from flask import request
from models import Note

@app.route("/notes", methods=["POST"])
def create_note():
    data = request.get_json()
    # TODO: валідація полів title, content
    Note.create(user_id=1, title=data["title"], content=data["content"])
    return jsonify({"message": "Note created"}), 201

@app.route("/notes", methods=["GET"])
def list_notes():
    notes = Note.get_by_user(user_id=1)
    return jsonify([dict(n) for n in notes])
```

3. Намалюйте DFD (Data Flow Diagram) для SecureNotes з елементами:
   - **External Entity:** User, Third-party Client
   - **Process:** Flask API
   - **Data Store:** SQLite (users, notes)
   - **Data Flow:** HTTP-запити, SQL-запити

4. Для кожного елемента DFD застосуйте STRIDE. Створіть `docs/stride-analysis.md`:
   - External Entity → S (Spoofing), R (Repudiation)
   - Process → S, T, R, I, D, E
   - Data Store → T, R, I, D
   - Data Flow → T, I, D

5. Для кожної загрози визначте стратегію: Mitigate, Accept, Transfer або Avoid.

### Очікуваний результат
```bash
curl -X POST http://localhost:5000/notes \
  -H "Content-Type: application/json" \
  -d '{"title":"Перша нотатка","content":"Привіт, SecureNotes!"}'
# {"message":"Note created"}

curl http://localhost:5000/notes
# [{"id":1,"user_id":1,"title":"Перша нотатка","content":"Привіт, SecureNotes!"}]
```

### Контрольні запитання
1. Які загрози STRIDE найкритичніші для SecureNotes і чому?
2. Чому зараз будь-хто може читати та створювати нотатки будь-якого користувача? Яке це порушення з CIA Triad?

---

## Milestone 2: Хешування паролів та реєстрація (Лекція 2)

### Мета
Реалізувати реєстрацію користувачів з хешуванням паролів через Argon2id та логін з перевіркою пароля.

### Контекст
Лекція 2 пояснює SHA-256, rainbow tables, сіль, bcrypt та Argon2. Ви побачите на практиці, чому Argon2id — правильний вибір для паролів, а SHA-256 — ні: однаковий пароль дає однаковий SHA-256 хеш (уразливість до rainbow tables), тоді як Argon2id кожного разу генерує різний хеш завдяки вбудованій солі.

### Кроки
1. Створіть `auth.py`:

```python
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from models import User

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

def register_user(username, password):
    if User.find_by_username(username):
        raise ValueError("Username already exists")
    password_hash = ph.hash(password)
    User.create(username, password_hash)
    return {"message": f"User {username} registered"}

def verify_user(username, password):
    user = User.find_by_username(username)
    if not user:
        raise ValueError("User not found")
    try:
        ph.verify(user["password_hash"], password)
        return dict(user)
    except VerifyMismatchError:
        raise ValueError("Invalid password")
```

2. Додайте ендпоінти `POST /register` (201) та `POST /login` (200 / 401) до `app.py`.

3. Перевірте вміст БД — у полі `password_hash` має бути рядок типу `$argon2id$v=19$m=65536,t=3,p=4$...`, а не відкритий пароль.

4. Для порівняння: `hashlib.sha256("password123".encode()).hexdigest()` завжди повертає однаковий хеш — саме тому SHA-256 не підходить для паролів.

### Очікуваний результат
```bash
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"maksym.vytrebenko","password":"SecureP@ss2024"}'
# {"message":"User maksym.vytrebenko registered"}

curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"maksym.vytrebenko","password":"SecureP@ss2024"}'
# {"message":"Login successful","user_id":1}

curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"maksym.vytrebenko","password":"wrong"}'
# {"error":"Invalid password"}  (401)
```

### Контрольні запитання
1. Чому два виклики `ph.hash("SecureP@ss2024")` повертають різні рядки, хоча пароль однаковий?
2. Скільки часу знадобиться на brute force 8-символьного пароля при Argon2id з `memory_cost=65536`?

---

## Milestone 3: Шифрування нотаток, цифрові підписи та сертифікати (Лекція 3)

### Мета
Зашифрувати вміст нотаток AES-256-GCM перед збереженням у базі, додати RSA-підписи для нотаток (підтвердження авторства) та self-signed сертифікат для HTTPS.

### Контекст
Лекція 3 охоплює симетричне шифрування (AES у режимах CBC та GCM) та асиметричне шифрування (RSA, цифрові підписи, PKI). Зараз нотатки зберігаються у відкритому тексті — якщо базу вкрадуть, усі нотатки Максима Витребенька стануть публічними. AES-GCM забезпечує одночасно конфіденційність (шифрування) і цілісність (автентифікація через GCM tag). RSA-підпис доводить, що нотатку створив саме Максим Витребенько, а не хтось інший. Self-signed сертифікат захищає канал між клієнтом і сервером (TLS).

### Кроки

#### Частина A: AES-GCM шифрування

1. Оновіть схему БД — додайте поля `iv BLOB` та `encrypted INTEGER DEFAULT 0` до таблиці `notes` (або створіть БД заново).

2. Створіть `crypto.py`:

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# У production ключ зберігається у Vault / KMS, не в коді
MASTER_KEY = bytes.fromhex(os.environ.get("SECURENOTES_KEY", os.urandom(32).hex()))

def encrypt_note(plaintext: str) -> tuple[bytes, bytes]:
    """Повертає (nonce, ciphertext_with_tag)."""
    nonce = os.urandom(12)  # 96-bit nonce для GCM
    ciphertext = AESGCM(MASTER_KEY).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce, ciphertext

def decrypt_note(nonce: bytes, ciphertext: bytes) -> str:
    """Розшифровує та перевіряє GCM tag."""
    return AESGCM(MASTER_KEY).decrypt(nonce, ciphertext, None).decode("utf-8")
```

3. Оновіть `models.py` — метод `Note.create_encrypted(user_id, title, nonce, ciphertext)`.

4. Оновіть `POST /notes` — шифрувати content перед записом:

```python
from crypto import encrypt_note, decrypt_note

@app.route("/notes", methods=["POST"])
def create_note():
    data = request.get_json()
    nonce, ciphertext = encrypt_note(data["content"])
    Note.create_encrypted(user_id=1, title=data["title"], nonce=nonce, ciphertext=ciphertext)
    return jsonify({"message": "Encrypted note created"}), 201
```

5. Реалізуйте `GET /notes/<id>` — розшифровувати перед відправкою.

#### Частина B: RSA-підписи та self-signed сертифікат

6. Згенеруйте RSA-ключі:

```bash
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

7. Додайте до `crypto.py` функції підпису та верифікації:

```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def load_private_key():
    with open("keys/private.pem", "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key():
    with open("keys/public.pem", "rb") as f:
        return serialization.load_pem_public_key(f.read())

def sign_note(content: str) -> bytes:
    return load_private_key().sign(
        content.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())

def verify_signature(content: str, signature: bytes) -> bool:
    try:
        load_public_key().verify(
            signature, content.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False
```

8. Додайте поле `signature BLOB` до таблиці `notes`. Підписуйте при створенні.

9. Реалізуйте `GET /notes/<id>/verify` — повертає `{"valid": true/false}`.

10. Згенеруйте self-signed cert та запустіть Flask по HTTPS:

```bash
openssl req -x509 -newkey rsa:2048 -keyout keys/server-key.pem \
  -out keys/cert.pem -days 365 -nodes -subj "/CN=localhost/O=SecureNotes/C=UA"
```

```python
# app.py
if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000, ssl_context=("keys/cert.pem", "keys/server-key.pem"))
```

### Очікуваний результат
```bash
# AES-GCM шифрування:
curl -k -X POST https://localhost:5000/notes \
  -H "Content-Type: application/json" \
  -d '{"title":"Секретна","content":"PIN: 1234"}'
# {"message":"Signed and encrypted note created"}

# У БД content — нечитабельні байти:
python3 -c "import sqlite3; print(repr(sqlite3.connect('securenotes.db').execute('SELECT content FROM notes WHERE id=1').fetchone()[0]))"
# b'\x8f\xa3\x12...'

curl -k https://localhost:5000/notes/1
# {"id":1,"title":"Секретна","content":"PIN: 1234"}

# RSA-підпис:
curl -k https://localhost:5000/notes/1/verify
# {"valid":true,"signer":"SecureNotes RSA-2048"}

# HTTPS:
curl -k https://localhost:5000/health
# {"status":"ok"}  (HTTPS працює)
```

### Контрольні запитання
1. Чому для кожної нотатки генерується унікальний nonce? Що станеться, якщо використати однаковий nonce з тим самим ключем для двох нотаток?
2. Чим AES-GCM відрізняється від AES-CBC у контексті цілісності даних?
3. Чому для підпису використовується приватний ключ, а для перевірки — публічний, а не навпаки?
4. Чому браузер показує попередження для self-signed сертифіката? Що потрібно для його усунення?

---

## Milestone 4: Архітектура OAuth 2.0 (Лекція 4)

### Мета
Спроєктувати архітектуру OAuth 2.0 для SecureNotes: визначити 4 ролі, scopes, створити таблиці OAuth-клієнтів.

### Контекст
Лекція 4 вводить OAuth 2.0 як фреймворк авторизації з чотирма ролями: Resource Owner, Client, Authorization Server, Resource Server. Тут ви визначите, як ці ролі відображаються на SecureNotes, і підготуєте інфраструктуру для Authorization Code Flow.

### Кроки
1. Визначте ролі OAuth 2.0 у контексті SecureNotes:
   - **Resource Owner:** Максим Витребенько (власник нотаток)
   - **Client:** сторонній додаток ("NotesExporter")
   - **Authorization Server:** SecureNotes Auth (видає токени)
   - **Resource Server:** SecureNotes API (зберігає нотатки)

2. Визначте scopes у `oauth.py`:

```python
SCOPES = {
    "notes:read":   "Читання нотаток",
    "notes:write":  "Створення та редагування нотаток",
    "notes:delete": "Видалення нотаток",
    "profile":      "Читання профілю користувача",
}
```

3. Додайте таблиці до БД:

```python
conn.executescript("""
    CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id TEXT PRIMARY KEY,
        client_secret TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        name TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS authorization_codes (
        code TEXT PRIMARY KEY,
        client_id TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        scope TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        expires_at TIMESTAMP NOT NULL);
""")
```

4. Реалізуйте реєстрацію клієнтів:

```python
import secrets

def register_client(name, redirect_uri):
    client_id = secrets.token_hex(16)
    client_secret = secrets.token_hex(32)
    db = get_db()
    db.execute("INSERT INTO oauth_clients VALUES (?, ?, ?, ?)",
               (client_id, client_secret, redirect_uri, name))
    db.commit(); db.close()
    return {"client_id": client_id, "client_secret": client_secret}
```

5. Намалюйте діаграму Authorization Code Flow для SecureNotes з усіма кроками.

### Очікуваний результат
```bash
curl -k -X POST https://localhost:5000/oauth/clients \
  -H "Content-Type: application/json" \
  -d '{"name":"NotesExporter","redirect_uri":"http://localhost:8080/callback"}'
# {"client_id":"a1b2c3d4...","client_secret":"e5f6a7b8..."}
```

### Контрольні запитання
1. Чому `client_secret` генерується через `secrets.token_hex()`, а не `random.randint()`?
2. Яка різниця між scope `notes:read` та `notes:write`? Навіщо розділяти права?

---

## Milestone 5: Authorization Code Flow (Лекція 5)

### Мета
Реалізувати повний Authorization Code Flow: authorize endpoint, consent screen, обмін code на token.

### Контекст
Лекція 5 детально розглядає Authorization Code Flow — найбезпечніший grant type для серверних додатків. Ви реалізуєте всі кроки: redirect на Authorization Server, consent (згода користувача), видача одноразового authorization code, обмін code на access token через back-channel.

### Кроки
1. `GET /oauth/authorize` — показує consent screen:

```python
from flask import render_template_string, redirect

CONSENT_PAGE = """
<h2>SecureNotes Authorization</h2>
<p>Додаток <b>{{ client_name }}</b> запитує доступ:</p>
<ul>{% for s in scopes %}<li>{{ s }}</li>{% endfor %}</ul>
<form method="POST" action="/oauth/authorize">
    <input type="hidden" name="client_id" value="{{ client_id }}">
    <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
    <input type="hidden" name="scope" value="{{ scope }}">
    <input type="hidden" name="state" value="{{ state }}">
    <button name="consent" value="allow">Дозволити</button>
    <button name="consent" value="deny">Відхилити</button>
</form>
"""
# TODO: перевірити client_id, redirect_uri та автентифікацію користувача
```

2. `POST /oauth/authorize` — при "allow": згенерувати `code = secrets.token_urlsafe(32)`, зберегти в `authorization_codes` (expires 10 хв), redirect на `redirect_uri?code=...&state=...`. При "deny": redirect з `error=access_denied`.

3. `POST /oauth/token` з `grant_type=authorization_code`:
   - Перевірити `client_id` + `client_secret`
   - Перевірити `code` (існує, не прострочений, відповідає `client_id`)
   - Видалити `code` (one-time use)
   - Повернути `{"access_token":"...","token_type":"Bearer","expires_in":900}`

### Очікуваний результат
```bash
# 1. Відкрити: /oauth/authorize?client_id=CID&redirect_uri=...&scope=notes:read&state=xyz
# 2. Натиснути "Дозволити" → redirect: callback?code=AUTH_CODE&state=xyz
# 3. Обміняти code:
curl -k -X POST https://localhost:5000/oauth/token \
  -d "grant_type=authorization_code&code=AUTH_CODE&client_id=CID&client_secret=CSECRET"
# {"access_token":"...","token_type":"Bearer","expires_in":900,"scope":"notes:read"}
```

### Контрольні запитання
1. Чому authorization code можна використати лише один раз? Що буде при повторному використанні?
2. Навіщо потрібен параметр `state`? Яку атаку він запобігає?

---

## Milestone 6: JWT-токени (Лекція 6)

### Мета
Замінити випадкові access tokens на JWT з підписом RS256, додати middleware для валідації JWT при кожному запиті.

### Контекст
Лекція 6 розкриває JWT: структура header.payload.signature, алгоритми HS256/RS256, claims (iss, sub, exp, aud, scope). JWT дозволяє Resource Server перевірити токен без звернення до Authorization Server — достатньо публічного ключа.

### Кроки
1. Реалізуйте генерацію та декодування JWT в `auth.py`:

```python
import jwt, datetime
from crypto import load_private_key, load_public_key

def create_access_token(user_id, username, scope):
    payload = {
        "iss": "securenotes", "sub": str(user_id),
        "username": username, "scope": scope,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
    }
    return jwt.encode(payload, load_private_key(), algorithm="RS256")

def decode_access_token(token):
    return jwt.decode(token, load_public_key(), algorithms=["RS256"], issuer="securenotes")
    # Кидає jwt.ExpiredSignatureError або jwt.InvalidTokenError
```

2. Створіть `middleware.py`:

```python
from functools import wraps
from flask import request, jsonify, g
from auth import decode_access_token

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        try:
            g.current_user = decode_access_token(auth.split(" ", 1)[1])
        except Exception as e:
            return jsonify({"error": str(e)}), 401
        return f(*args, **kwargs)
    return decorated

def require_scope(scope):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if scope not in g.current_user.get("scope", "").split():
                return jsonify({"error": "Insufficient scope"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
```

3. Захистіть ендпоінти: `GET /notes` — `@require_auth @require_scope("notes:read")`, `POST /notes` — `@require_scope("notes:write")`.

4. Оновіть token endpoint — видавати JWT замість випадкових рядків.

### Очікуваний результат
```bash
TOKEN=$(curl -sk -X POST https://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"maksym.vytrebenko","password":"SecureP@ss2024"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -k https://localhost:5000/notes -H "Authorization: Bearer $TOKEN"
# [{"id":1,"title":"Секретна",...}]

curl -k https://localhost:5000/notes
# {"error":"Missing or invalid Authorization header"}  (401)
```

### Контрольні запитання
1. Чому RS256, а не HS256? Яка перевага асиметричного підпису для мікросервісів?
2. Чому claim `sub` містить ID, а не username?

---

## Milestone 7: Refresh Tokens та lifecycle (Лекція 7)

### Мета
Додати refresh tokens (зберігаються у БД), налаштувати expiry (15 хв access / 7 днів refresh), реалізувати `POST /oauth/revoke`.

### Контекст
Лекція 7 розглядає повний life cycle токенів. Refresh token вирішує дилему: access token має бути короткоживучим (безпека), але користувач не хоче логінитись кожні 15 хвилин (зручність).

### Кроки
1. Додайте таблицю `refresh_tokens`:

```python
conn.executescript("""
    CREATE TABLE IF NOT EXISTS refresh_tokens (
        token TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        client_id TEXT,
        scope TEXT NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        revoked INTEGER DEFAULT 0);
""")
```

2. Реалізуйте в `auth.py`:

```python
import secrets
from datetime import datetime, timedelta

def create_refresh_token(user_id, scope, client_id=None):
    token = secrets.token_urlsafe(64)
    expires_at = datetime.utcnow() + timedelta(days=7)
    db = get_db()
    db.execute("INSERT INTO refresh_tokens (token,user_id,client_id,scope,expires_at) VALUES (?,?,?,?,?)",
               (token, user_id, client_id, scope, expires_at))
    db.commit(); db.close()
    return token

def refresh_access_token(refresh_token_value):
    db = get_db()
    row = db.execute("SELECT * FROM refresh_tokens WHERE token=? AND revoked=0",
                     (refresh_token_value,)).fetchone()
    if not row: raise ValueError("Invalid or revoked refresh token")
    if datetime.fromisoformat(row["expires_at"]) < datetime.utcnow():
        raise ValueError("Refresh token expired")
    # TODO: refresh token rotation — видалити старий, створити новий
    user = db.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
    db.close()
    return create_access_token(user["id"], user["username"], row["scope"])
```

3. Оновіть `POST /oauth/token` — підтримка `grant_type=refresh_token`.
4. `POST /oauth/revoke` — встановити `revoked=1` для refresh token.
5. Оновіть login — повертати і `access_token`, і `refresh_token`.

### Очікуваний результат
```bash
curl -k -X POST https://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"maksym.vytrebenko","password":"SecureP@ss2024"}'
# {"access_token":"eyJ...","refresh_token":"dG9rZW4...","expires_in":900}

curl -k -X POST https://localhost:5000/oauth/token \
  -d "grant_type=refresh_token&refresh_token=dG9rZW4..."
# {"access_token":"eyJ...(новий)","token_type":"Bearer","expires_in":900}

curl -k -X POST https://localhost:5000/oauth/revoke -d "token=dG9rZW4..."
# {"message":"Token revoked"}
```

### Контрольні запитання
1. Чому access token живе 15 хвилин, а refresh token — 7 днів? Чому б не зробити access token на 7 днів?
2. Що таке refresh token rotation і яку атаку вона запобігає?

---

## Milestone 8: PKCE для публічних клієнтів (Лекція 8)

### Мета
Реалізувати PKCE (Proof Key for Code Exchange) для захисту SPA та мобільних додатків, де неможливо зберігати client_secret.

### Контекст
Лекція 8 пояснює, чому Authorization Code Flow без PKCE вразливий для публічних клієнтів. PKCE прив'язує token request до authorize request через криптографічний proof, без потреби в client_secret.

### Кроки
1. Концепція PKCE:
   - Клієнт генерує `code_verifier` (43-128 випадкових символів)
   - Обчислює `code_challenge = BASE64URL(SHA256(code_verifier))`
   - Authorize: надсилає `code_challenge` + `code_challenge_method=S256`
   - Token: надсилає `code_verifier` (server перевіряє: SHA256(verifier) == challenge)

2. Додайте поля `code_challenge TEXT`, `code_challenge_method TEXT` до `authorization_codes`.

3. Серверна валідація в `oauth.py`:

```python
import hashlib, base64

def verify_pkce(code_verifier: str, stored_challenge: str) -> bool:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return computed == stored_challenge
```

4. Оновіть `GET /oauth/authorize` — приймати `code_challenge` та `code_challenge_method`.

5. Оновіть `POST /oauth/token` — при наявності `code_challenge` перевіряти `code_verifier` замість `client_secret`.

6. Напишіть тестовий скрипт `test_pkce_client.py`:

```python
import secrets, hashlib, base64, requests

code_verifier = secrets.token_urlsafe(64)
digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
print(f"code_verifier:  {code_verifier}")
print(f"code_challenge: {code_challenge}")
# TODO: пройти authorize flow, отримати code, обміняти з code_verifier
```

### Очікуваний результат
```bash
python test_pkce_client.py
# code_verifier:  dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk...
# code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
# {"access_token":"eyJ...","token_type":"Bearer","expires_in":900}
```

### Контрольні запитання
1. Чому SPA не може безпечно зберігати `client_secret`? Де саме секрет був би видимий?
2. Що станеться, якщо атакуючий перехопить authorization code, але не має `code_verifier`?

---

## Milestone 9: OpenID Connect (Лекція 9)

### Мета
Додати шар ідентифікації поверх OAuth 2.0: ID Token з стандартними claims, UserInfo endpoint, OpenID Discovery.

### Контекст
Лекція 9: OAuth 2.0 — фреймворк авторизації, а не автентифікації. OpenID Connect (OIDC) додає стандартний спосіб отримати інформацію про користувача: ID Token (JWT) та UserInfo endpoint.

### Кроки
1. Створіть `oidc.py`:

```python
import jwt, datetime
from crypto import load_private_key

def create_id_token(user_id, username, email, client_id, nonce=None):
    now = datetime.datetime.utcnow()
    payload = {
        "iss": "https://localhost:5000", "sub": str(user_id),
        "aud": client_id, "exp": now + datetime.timedelta(hours=1),
        "iat": now, "name": username, "email": email,
    }
    if nonce:
        payload["nonce"] = nonce
    return jwt.encode(payload, load_private_key(), algorithm="RS256")
```

2. `GET /userinfo` (захищений `@require_auth`) — повертає `{sub, name, preferred_username, email}`.

3. Оновіть token endpoint: при `scope` що містить `openid`, додати `id_token` до відповіді.

4. `GET /.well-known/openid-configuration` — discovery document:

```python
@app.route("/.well-known/openid-configuration")
def openid_configuration():
    return jsonify({
        "issuer": "https://localhost:5000",
        "authorization_endpoint": "https://localhost:5000/oauth/authorize",
        "token_endpoint": "https://localhost:5000/oauth/token",
        "userinfo_endpoint": "https://localhost:5000/userinfo",
        "jwks_uri": "https://localhost:5000/.well-known/jwks.json",
        "scopes_supported": ["openid", "profile", "email", "notes:read", "notes:write"],
        "response_types_supported": ["code"],
        "id_token_signing_alg_values_supported": ["RS256"],
    })
```

5. (Додатково) Налаштуйте вхід через Google: зареєструйте додаток у Google Cloud Console (APIs & Services > Credentials), реалізуйте callback для обміну Google code на id_token.

### Очікуваний результат
```bash
curl -k https://localhost:5000/.well-known/openid-configuration
# {"issuer":"https://localhost:5000","authorization_endpoint":"..."}

curl -k https://localhost:5000/userinfo -H "Authorization: Bearer $TOKEN"
# {"sub":"1","name":"maksym.vytrebenko","email":"maksym@example.com"}
```

### Контрольні запитання
1. Чим ID Token відрізняється від Access Token? Хто є audience кожного з них?
2. Навіщо `nonce` в ID Token і яку атаку він запобігає?

---

## Milestone 10: Тестування на вразливості (Лекція 10)

### Мета
Провести pen-test SecureNotes на типові OAuth-вразливості: CSRF, Open Redirect, Token Leakage через Referer. Виявити та виправити кожну.

### Контекст
Лекція 10 — атаки на OAuth: CSRF, open redirect, token leakage, authorization code injection. Тепер ви станете "атакуючим" для власного додатка.

### Кроки
1. **CSRF (відсутній state):** відправте authorize request без `state`. Якщо сервер не повертає помилку — вразливість.

```bash
curl -k "https://localhost:5000/oauth/authorize?client_id=CID&redirect_uri=http://localhost:8080/callback&scope=notes:read"
# Має повернути {"error":"missing_state"} (400)
```

**Виправлення:** обов'язкова перевірка `state` в authorize endpoint.

2. **Open Redirect:** підміньте `redirect_uri` на `https://evil.com/steal`.

```bash
curl -k "https://localhost:5000/oauth/authorize?client_id=CID&redirect_uri=https://evil.com/steal&scope=notes:read&state=abc"
# Має повернути {"error":"invalid_redirect_uri"} (400)
```

**Виправлення:** exact match `redirect_uri` проти зареєстрованого в `oauth_clients`.

3. **Token Leakage:** перевірте, чи передаються токени в URL. **Виправлення:** токени тільки через back-channel або Authorization header.

4. **Code Injection:** спробуйте використати code від одного client_id з іншим. PKCE (Milestone 8) запобігає цьому.

5. Створіть `tests/test_security.py`:

```python
import requests
BASE = "https://localhost:5000"

def test_csrf_state_required():
    r = requests.get(f"{BASE}/oauth/authorize",
        params={"client_id":"test","redirect_uri":"http://localhost:8080/callback"},
        verify=False, allow_redirects=False)
    assert r.status_code == 400

def test_open_redirect_blocked():
    r = requests.get(f"{BASE}/oauth/authorize",
        params={"client_id":"test","redirect_uri":"https://evil.com","state":"abc"},
        verify=False, allow_redirects=False)
    assert r.status_code == 400
```

6. Запустіть: `pytest tests/test_security.py -v`.

### Очікуваний результат
```bash
pytest tests/test_security.py -v
# test_csrf_state_required PASSED
# test_open_redirect_blocked PASSED
# test_expired_token_rejected PASSED
```

### Контрольні запитання
1. Чому `state` має бути випадковим і прив'язаним до сесії, а не просто фіксованим рядком?
2. Чому exact match для `redirect_uri` безпечніший за prefix match? Наведіть приклад атаки при prefix match.

---

## Milestone 11: Мікросервісна архітектура (Лекція 11)

### Мета
Розділити SecureNotes на Auth Service (:5001), Notes Service (:5002), API Gateway (:5000) з token propagation.

### Контекст
Лекція 11 — OAuth у мікросервісній архітектурі: token propagation, service-to-service auth, API Gateway. У моноліті все просто — один процес. У мікросервісах потрібно передавати контекст автентифікації між сервісами.

### Кроки
1. Створіть `services/auth/app.py` (:5001) — реєстрація, логін, OAuth endpoints. Надає JWKS через `/.well-known/jwks.json` (публічний ключ у форматі JWK).

2. Створіть `services/notes/app.py` (:5002) — CRUD нотаток. Валідує JWT самостійно, завантажуючи public key з Auth Service JWKS:

```python
# services/notes/app.py
import requests, jwt

def get_public_key_from_jwks():
    """Завантажує public key з Auth Service."""
    resp = requests.get("http://localhost:5001/.well-known/jwks.json")
    # TODO: перетворити JWK у public key
    return public_key
```

3. Створіть `services/gateway/app.py` (:5000) — проксює запити:

```python
import requests as http_client
from flask import Flask, request, jsonify

NOTES_SERVICE = "http://localhost:5002"
AUTH_SERVICE = "http://localhost:5001"

@app.route("/notes", methods=["GET", "POST"])
def proxy_notes():
    headers = {}
    if "Authorization" in request.headers:
        headers["Authorization"] = request.headers["Authorization"]
    resp = http_client.request(request.method, f"{NOTES_SERVICE}/notes",
                               headers=headers, json=request.get_json())
    return jsonify(resp.json()), resp.status_code
```

4. Запустіть три сервіси в окремих терміналах.

5. Перевірте: запит до Gateway → Notes Service валідує JWT → повертає дані.

### Очікуваний результат
```bash
curl http://localhost:5000/notes -H "Authorization: Bearer $TOKEN"
# [{"id":1,"title":"Секретна",...}]  (через Gateway → Notes Service)

curl http://localhost:5002/notes
# {"error":"Unauthorized"}  (без токена)
```

### Контрольні запитання
1. Чому Notes Service валідує JWT самостійно (публічний ключ), а не запитує Auth Service при кожному запиті?
2. Якщо Auth Service недоступний — чи зможе Notes Service валідувати раніше видані JWT?

---

## Milestone 12: Захист веб-додатку (Лекція 12)

### Мета
Додати CSP headers, CORS, Secure/HttpOnly/SameSite cookies для refresh token, rate limiting.

### Контекст
Лекція 12 — XSS, CSRF, clickjacking, безпека cookies vs localStorage. Ідеальна реалізація OAuth марна, якщо XSS-атака вкраде токен з localStorage.

### Кроки
1. Створіть `security.py` з security headers:

```python
def configure_security(app):
    @app.after_request
    def set_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; frame-ancestors 'none'"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
```

2. CORS: `flask-cors` з explicit origins (не `*`), `supports_credentials=True`.

3. Перенесіть refresh token у HttpOnly cookie:

```python
from flask import make_response

response = make_response(jsonify({"access_token": access_token, "expires_in": 900}))
response.set_cookie("refresh_token", refresh_token,
    httponly=True, secure=True, samesite="Strict",
    max_age=7*24*3600, path="/oauth/token")
```

4. Rate limiting:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["100 per minute"])

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login(): ...

@app.route("/register", methods=["POST"])
@limiter.limit("3 per minute")
def register(): ...
```

### Очікуваний результат
```bash
curl -k -I https://localhost:5000/health
# Content-Security-Policy: default-src 'self'; ...
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff

# Rate limiting: 6-й login за хвилину — 429
for i in {1..6}; do curl -k -s -o /dev/null -w "%{http_code}\n" \
  -X POST https://localhost:5000/login -H "Content-Type: application/json" \
  -d '{"username":"t","password":"t"}'; done
# 401 401 401 401 401 429
```

### Контрольні запитання
1. Чому refresh token зберігається в HttpOnly cookie, а access token — ні? Де зберігати access token на клієнті?
2. Що робить CSP-директива `frame-ancestors 'none'` і від якої атаки вона захищає?

---

## Milestone 13: Фінальний аудит безпеки (Лекція 13)

### Мета
Провести аудит за OWASP-чеклістом, оновити STRIDE threat model, написати архітектурну документацію.

### Контекст
Лекція 13 підсумовує курс: проєктування безпечних систем, OWASP Top 10, оновлення threat model. Ви перевірите, чи всі загрози з Milestone 1 закриті.

### Кроки
1. Пройдіть OWASP-чеклист:
   - **A01 Broken Access Control:** JWT middleware, user_id перевірка, scopes, rate limiting
   - **A02 Cryptographic Failures:** Argon2id (паролі), AES-GCM (нотатки), RS256 (JWT), TLS
   - **A03 Injection:** параметризовані SQL (?, не f-string)
   - **A05 Security Misconfiguration:** CSP, CORS (не *), debug=False
   - **A07 Authentication Failures:** rate limiting, refresh rotation, revocation
   - **A08 Integrity Failures:** JWT підписи, one-time code, PKCE

2. Оновіть STRIDE з Milestone 1 — для кожної загрози вкажіть milestone:
   - **Spoofing** → Argon2id + JWT RS256 (M2, M6)
   - **Tampering** → AES-GCM + RSA signatures (M3)
   - **Repudiation** → RSA-підписи нотаток (M3)
   - **Information Disclosure** → AES-GCM + HTTPS + CSP (M3, M12)
   - **Denial of Service** → rate limiting (M12)
   - **Elevation of Privilege** → JWT scope validation + PKCE (M6, M8)

3. Задокументуйте фінальну архітектуру у `docs/security-architecture.md`:

```
┌──────────┐     ┌─────────────┐     ┌───────────────┐
│ Browser  │────→│ API Gateway │────→│ Notes Service │
│          │     │   :5000     │──┐  │   :5002       │
└──────────┘     └─────────────┘  │  └───────────────┘
                                  │  ┌───────────────┐
                                  └─→│ Auth Service  │
                                     │   :5001       │
                                     └───────────────┘
Рівні захисту:
  Transport:  TLS (HTTPS)
  Auth:       OAuth 2.0 + PKCE + OIDC
  Tokens:     JWT RS256 (15 min) + Refresh (7 days, HttpOnly cookie)
  Data:       AES-256-GCM (notes), Argon2id (passwords)
  Integrity:  RSA signatures (notes), GCM tag
  Web:        CSP, CORS, X-Frame-Options, rate limiting
```

4. Запустіть усі тести: `pytest tests/ -v`.

### Очікуваний результат
```bash
pytest tests/ -v
# test_auth.py: PASSED  |  test_crypto.py: PASSED
# test_oauth.py: PASSED |  test_security.py: PASSED
# OWASP checklist — всі пункти закриті
# STRIDE analysis — всі загрози мають mitigation
```

### Контрольні запитання
1. Які загрози з Milestone 1 залишились незакритими або закриті лише частково? Що потрібно для повного закриття?
2. Якби SecureNotes йшов у production, які ще механізми безпеки знадобилися б (назвіть щонайменше 3)?

---

## Фінальна структура проєкту

```
securenotes/
    app.py                      # Flask application + routing
    database.py                 # SQLite initialization
    models.py                   # User, Note models
    auth.py                     # Registration, login, JWT, refresh tokens
    crypto.py                   # AES-GCM encryption, RSA signing
    oauth.py                    # OAuth 2.0 (authorize, token, revoke, clients)
    oidc.py                     # OpenID Connect (ID token, UserInfo, discovery)
    middleware.py               # JWT validation, scope checking
    security.py                 # CSP, CORS, security headers, rate limiting
    keys/
        private.pem             # RSA private key
        public.pem              # RSA public key
        cert.pem                # Self-signed TLS certificate
        server-key.pem          # TLS private key
    services/
        auth/app.py             # Auth microservice (:5001)
        notes/app.py            # Notes microservice (:5002)
        gateway/app.py          # API Gateway (:5000)
    tests/
        test_auth.py
        test_crypto.py
        test_oauth.py
        test_security.py
    docs/
        stride-analysis.md      # STRIDE threat model
        oauth-design.md         # OAuth architecture design
        security-architecture.md
    requirements.txt
```

## Підсумок

За 13 milestone'ів ви побудували захищений API з:

- **Автентифікація:** Argon2id, JWT RS256
- **Шифрування:** AES-256-GCM, TLS
- **Цілісність:** RSA-підписи, GCM-tag
- **Авторизація:** OAuth 2.0, scopes, PKCE
- **Ідентифікація:** OpenID Connect, ID Token
- **Архітектура:** мікросервіси, API Gateway, token propagation
- **Веб-безпека:** CSP, CORS, HttpOnly cookies, rate limiting
- **Аудит:** STRIDE, OWASP checklist

Кожен механізм — відповідь на конкретну загрозу. Разом вони утворюють **defense in depth** — багаторівневий захист, де компрометація одного рівня не призводить до повного зламу системи.

### Додаткові ресурси

- RFC 6749 — The OAuth 2.0 Authorization Framework
- RFC 7519 — JSON Web Token (JWT)
- RFC 7636 — Proof Key for Code Exchange (PKCE)
- OpenID Connect Core 1.0 — https://openid.net/specs/openid-connect-core-1_0.html
- OWASP Top 10 — https://owasp.org/www-project-top-ten/
