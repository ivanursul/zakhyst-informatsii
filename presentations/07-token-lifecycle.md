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

Лекція 7. Access Token, Refresh Token, Token Lifecycle

Львівський національний університет імені Івана Франка
Спеціальність 113 — Прикладна математика

2025

---

# План лекції

1. Проблема — JWT не можна відкликати
2. Short-lived Access Tokens
3. Refresh Tokens
4. Token Storage Strategies
5. Token Revocation (RFC 7009)
6. Token Introspection (RFC 7662)
7. Refresh Token Rotation
8. Sliding Sessions
9. Logout — як правильно

---

# Проблема: вкрадений JWT

JWT — **stateless**. Сервер не зберігає список виданих токенів

Що відбувається, коли access token вкрадено?

```
┌──────────┐     вкрадений JWT      ┌──────────────────┐
│ Зловмис- │ ─────────────────────→ │  Resource Server  │
│   ник    │                        │  ✓ Підпис ОК     │
└──────────┘                        │  ✓ exp не минув   │
                                    │  ✓ Доступ надано! │
                                    └──────────────────┘
```

Сервер НЕ знає, що токен вкрадено. Єдиний захист — чекати, поки `exp` мине

---

# Сценарій: SecureNotes

Максим Витребенько видав JWT access token з терміном дії **24 години**

1. Олена залогінилась, отримала JWT
2. Підключилась до публічного Wi-Fi
3. Зловмисник перехопив access token
4. Олена змінила пароль

**Чи зупинить зміна пароля зловмисника?**

**Ні.** JWT self-contained — Resource Server перевіряє лише підпис та `exp`. Зловмисник має повний доступ ще 24 години

---

# Short-lived Access Tokens

**Ідея:** якщо не можна відкликати JWT — мінімізуємо час його дії

```
Довгоживучий токен (24 год):
|████████████████████████████████████████| вікно атаки

Короткоживучий токен (15 хв):
|██|                                      вікно атаки
```

| Тип додатку | Термін дії access token |
|---|---|
| Банківський додаток | 5 хвилин |
| SaaS-платформа | 10-15 хвилин |
| Внутрішній сервіс (B2B) | 15-30 хвилин |

---

# Нова проблема

Access token живе 15 хвилин

Просити користувача вводити логін і пароль кожні 15 хвилин?

Очевидно, це неприйнятно

Нам потрібен механізм **тихого оновлення** (silent refresh) без участі користувача

---

# Refresh Token

**Refresh Token** — довгоживучий токен (дні, тижні), який використовується **виключно** для отримання нового access token

- Надсилається тільки до Authorization Server (не до Resource Server)
- Зазвичай **opaque string** (не JWT)
- Зберігається в базі Authorization Server — **можна відкликати**

---

# Як працює refresh flow

```
Client ── access_token ──→ Resource Server
       ←── 200 OK ────────

       ... 15 хв ...

Client ── access_token ──→ Resource Server
       ←── 401 Expired ──

Client ── refresh_token ─→ Authorization Server
       ←── new access    ─
            token
```

Користувач нічого не помічає — оновлення відбувається у фоні

---

# Refresh Token Grant

```http
POST /oauth/token HTTP/1.1
Host: auth.securenotes.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=dGhpcyBpcyBhIHJlZnJlc2gg...
&client_id=securenotes-web
&client_secret=s3cr3t
```

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "bmV3IHJlZnJlc2ggdG9rZW4..."
}
```

---

# Access Token vs Refresh Token

| Властивість | Access Token | Refresh Token |
|---|---|---|
| Термін дії | 5-15 хвилин | дні або тижні |
| Куди надсилається | Resource Server | Authorization Server |
| Формат | JWT (self-contained) | opaque string |
| Stateful | ні | так (в БД) |
| Можна відкликати | складно (blacklist) | так (видалити з БД) |
| Частота використання | кожен запит | рідко (при refresh) |

---

# Token Storage: варіанти

| Місце зберігання | XSS | CSRF | Примітки |
|---|---|---|---|
| `localStorage` | вразливий | стійкий | JS має повний доступ |
| `sessionStorage` | вразливий | стійкий | не між вкладками |
| `httpOnly cookie` | стійкий | вразливий | потребує CSRF-захисту |
| In-memory (JS) | частково | стійкий | зникає при refresh |

---

# httpOnly cookie

```http
Set-Cookie: refresh_token=abc123;
  HttpOnly;
  Secure;
  SameSite=Strict;
  Path=/oauth/token;
  Max-Age=604800
```

- **HttpOnly** — `document.cookie` не бачить (захист від XSS)
- **Secure** — тільки через HTTPS
- **SameSite=Strict** — не надсилається з cross-origin запитів
- **Path=/oauth/token** — тільки до endpoint оновлення

---

# Рекомендована стратегія зберігання

```
┌──────────────────────────────────────┐
│          Браузер (клієнт)            │
│                                      │
│  Access Token  → in-memory (JS)      │
│  Refresh Token → httpOnly cookie     │
│                                      │
│  ✓ XSS не дістане refresh token      │
│  ✓ Access token зникає при reload    │
│  ✓ Перезавантаження → silent refresh │
└──────────────────────────────────────┘
```

Якщо сторінка перезавантажується — access token втрачається, клієнт отримує новий через refresh token cookie

---

# Token Revocation (RFC 7009)

```http
POST /oauth/revoke HTTP/1.1
Host: auth.securenotes.com
Authorization: Basic czNjcjN0OmNsaWVudF9zZWNyZXQ=

token=dGhpcyBpcyBhIHJlZnJlc2gg...
&token_type_hint=refresh_token
```

**Важливо:**

- Завжди повертає **200 OK** (навіть якщо токен не існує)
- Це **навмисно** — щоб атакуючий не міг перебирати валідні токени
- При відкликанні refresh token — інвалідувати пов'язані access tokens

---

# Blacklist для JWT access tokens

```
Client ── JWT ──→ Resource Server
                  │
                  ├── 1. Перевірити підпис
                  ├── 2. Перевірити exp
                  ├── 3. Перевірити jti     ┌───────────┐
                  │      у blacklist  ──────→│  Redis    │
                  │                          └───────────┘
```

JWT access token живе 15 хвилин — blacklist потрібно тримати максимум 15 хвилин

Допустимий trade-off між stateless та безпекою

---

# Token Introspection (RFC 7662)

Для **opaque tokens** — Resource Server запитує Authorization Server

```http
POST /oauth/introspect HTTP/1.1
Authorization: Basic czNjcjN0OmNsaWVudF9zZWNyZXQ=

token=mF_9.B5f-4.1JqM
```

Активний:

```json
{
  "active": true,
  "username": "maksym.vytrebenko",
  "scope": "read write",
  "exp": 1700000000
}
```

Неактивний:

```json
{ "active": false }
```

---

# JWT vs Opaque + Introspection

<div class="columns">
<div>

**JWT (self-contained)**

- Перевірка локально
- Дуже швидко
- Складно відкликати
- Великий розмір
- Висока масштабованість

</div>
<div>

**Opaque + Introspection**

- Запит до Auth Server
- Мережева затримка
- Легко відкликати
- Малий розмір
- Залежить від Auth Server

</div>
</div>

> Гібрид: JWT для звичайних запитів, introspection для критичних операцій

---

# Refresh Token Rotation

Кожен refresh видає **новий** refresh token, старий стає недійсним

```
Запит 1:
  refresh_token_v1 → Server
  ← access_token, refresh_token_v2    (v1 недійсний)

Запит 2:
  refresh_token_v2 → Server
  ← access_token, refresh_token_v3    (v2 недійсний)
```

Навіщо? Щоб **виявити крадіжку** через reuse detection

---

# Reuse Detection

```
Нормальний потік:
  Client:     v2 → Server → v3 ✓

Після крадіжки:
  Зловмисник: v2 → Server → v3a ✓
  Client:     v2 → Server → ВІДХИЛЕНО!
                             │
                     Reuse detected →
                     інвалідувати ВСЮ
                     сім'ю токенів
```

Повторне використання refresh token = **сигнал компрометації**

Реакція: інвалідувати всі refresh tokens цієї сесії, змусити перелогінитись

---

# Sliding Sessions

**Абсолютний термін** — протухає через N днів від видачі:

```
Видача              Протухає
  │                    │
  ▼────────────────────▼  незалежно від активності
```

**Ковзний термін** — продовжується при кожному refresh:

```
Видача    Активність    Нова межа
  │            │             │
  ▼────────────▼─────────────▼  продовжується
```

---

# Безпечна реалізація sliding sessions

Комбінація ковзного та абсолютного терміну:

```python
SLIDING_WINDOW = timedelta(days=30)
ABSOLUTE_LIFETIME = timedelta(days=90)

def is_session_valid(session):
    now = datetime.utcnow()
    # Ковзний: був refresh за останні 30 днів?
    if now - session["last_refresh"] > SLIDING_WINDOW:
        return False
    # Абсолютний: не минуло 90 днів від створення?
    if now - session["created_at"] > ABSOLUTE_LIFETIME:
        return False
    return True
```

**Абсолютна межа обов'язкова** — навіть при активному використанні сесія має завершитись

---

# Logout: checklist

```
┌──────────────────────────────────────┐
│          Logout Checklist            │
│                                      │
│  1. Видалити access token з пам'яті  │
│  2. Видалити refresh token cookie    │
│  3. Відкликати refresh token         │
│     на сервері (revoke)              │
│  4. Інвалідувати серверну сесію      │
│  5. (Опціонально) Blacklist JWT      │
└──────────────────────────────────────┘
```

Logout — це **не тільки очищення cookie**

---

# Типові помилки при logout

1. **Видалити cookie, не відкликати токен** — зловмисник зі скопійованим refresh token продовжує працювати

2. **Забути про інші пристрої** — "Вийти з усіх пристроїв" = інвалідувати ВСІ refresh tokens користувача

3. **Ігнорувати access token** — після logout JWT валідний ще до 15 хв. Для критичних систем — blacklist

4. **Не інвалідувати серверну сесію** — якщо є session store, його потрібно очистити

---

# Максим додає refresh tokens до SecureNotes

```python
@app.route("/oauth/revoke", methods=["POST"])
def revoke_and_logout():
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        token_hash = hashlib.sha256(
            refresh_token.encode()
        ).hexdigest()
        record = refresh_tokens_db.get(token_hash)
        if record:
            invalidate_family(record["family_id"])

    response = make_response(jsonify({}), 200)
    response.set_cookie(
        "refresh_token", "", max_age=0,
        httponly=True, secure=True, samesite="Strict",
    )
    return response
```

---

# Підсумки

- **Access token** — короткоживучий (5-15 хв), stateless JWT
- **Refresh token** — довгоживучий, stateful, можна відкликати
- **Зберігання:** access — in-memory, refresh — httpOnly cookie
- **Revocation** (RFC 7009) — стандартний endpoint, завжди 200 OK
- **Introspection** (RFC 7662) — перевірка стану opaque token
- **Rotation** — кожен refresh видає новий токен, reuse = компрометація
- **Sliding Sessions** — ковзний + абсолютний термін
- **Logout** — revoke + clear cookies + invalidate session

---

# Що далі?

**Лекція 8: PKCE та публічні клієнти**

- Публічні клієнти (SPA, мобільні) не можуть зберігати `client_secret`
- Authorization Code можна перехопити без додаткового захисту
- **PKCE** (Proof Key for Code Exchange) — вирішує проблему без секрету

> Refresh token + access token вирішують lifecycle. PKCE вирішує проблему **публічних клієнтів**

---

<!-- _class: title -->

# Дякую за увагу!

Питання?
