# Лекція 4. OAuth 2.0 — архітектура протоколу

## Зміст

1. [Чому OAuth існує — password anti-pattern](#1-чому-oauth-існує--password-anti-pattern)
2. [Чотири ролі OAuth 2.0](#2-чотири-ролі-oauth-20)
3. [Реєстрація клієнта (Client Registration)](#3-реєстрація-клієнта-client-registration)
4. [Scopes — гранулярний контроль доступу](#4-scopes--гранулярний-контроль-доступу)
5. [Огляд типів грантів (Grant Types)](#5-огляд-типів-грантів-grant-types)
6. [Redirect URIs — чому це важливо](#6-redirect-uris--чому-це-важливо)
7. [Модель загроз делегування (Threat Model)](#7-модель-загроз-делегування-threat-model)
8. [Підсумки](#8-підсумки)

---

## 1. Чому OAuth існує — password anti-pattern

### Міст від попередніх лекцій

У лекціях 1-4 ми побудували фундамент криптографічних примітивів: хеш-функції для цілісності (SHA-256, bcrypt, Argon2), симетричне шифрування для конфіденційності (AES-GCM), асиметричну криптографію для підписів та обміну ключами (RSA, ECDSA, Diffie-Hellman). Тепер ми маємо всі будівельні блоки. Питання: **як зібрати їх у протокол**, який вирішує реальну проблему?

### Сценарій: Максим і SecureNotes

Максим Витребенько проєктує сервіс **SecureNotes** — застосунок для зашифрованих нотаток. Користувачі хочуть імпортувати нотатки з Google Keep, експортувати у Dropbox, друкувати через сторонній сервіс. Як дати стороннім додаткам доступ до нотаток користувача?

### Password anti-pattern

**Наївний підхід:** користувач передає свій логін і пароль від SecureNotes сторонньому додатку.

```
┌──────────────┐     username + password     ┌──────────────┐
│  Користувач  │ ──────────────────────────→ │  Сторонній   │
│  (Максим)    │                             │  додаток     │
└──────────────┘                             │  (PrintApp)  │
                                             └──────┬───────┘
                                                    │
                                         Повний доступ до акаунту
                                                    │
                                                    ▼
                                             ┌──────────────┐
                                             │  SecureNotes │
                                             │  API         │
                                             └──────────────┘
```

Це **password anti-pattern** (RFC 6749, Section 1). Проблеми:

1. **Надмірний доступ** — сторонній додаток отримує повний доступ до акаунту, хоча потребує лише читання нотаток
2. **Неможливість відкликання** — щоб забрати доступ у одного додатка, Максим мусить змінити пароль, що зламає доступ усім іншим додаткам
3. **Поширення секрету** — пароль зберігається в кожному сторонньому додатку. Зламали один — скомпрометовано все
4. **Відсутність аудиту** — SecureNotes не може відрізнити запити від Максима і від стороннього додатка
5. **Порушення принципу найменших привілеїв** (Principle of Least Privilege) — додаток отримує більше прав, ніж потребує

### Що потрібно натомість

Нам потрібен протокол, який дозволяє:

- Надати **обмежений** доступ (лише читання нотаток, без видалення)
- **Відкликати** доступ окремому додатку без зміни пароля
- **Не передавати** пароль третій стороні
- **Логувати** дії кожного додатка окремо

Саме це і є **OAuth 2.0** — фреймворк делегованої авторизації (RFC 6749, 2012).

---

## 2. Чотири ролі OAuth 2.0

### Архітектура ролей

OAuth 2.0 визначає чотири чіткі ролі. Кожна роль має свою зону відповідальності.

```
┌─────────────────────────────────────────────────────────────────┐
│                        OAuth 2.0 Ролі                           │
│                                                                 │
│  ┌────────────────┐              ┌────────────────────────┐     │
│  │ Resource Owner │              │ Authorization Server   │     │
│  │ (Власник)      │──── довіра ──│ (Сервер авторизації)   │     │
│  └───────┬────────┘              └───────────┬────────────┘     │
│          │                                   │                  │
│       consent                          видає токени             │
│          │                                   │                  │
│  ┌───────▼────────┐              ┌───────────▼────────────┐     │
│  │ Client         │── код/токен ─│ Resource Server        │     │
│  │ (Додаток)      │              │ (Сервер ресурсів)      │     │
│  └────────────────┘              └────────────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

### Resource Owner (Власник ресурсів)

**Resource Owner** — це сутність, яка може надати доступ до захищеного ресурсу. Зазвичай це кінцевий користувач (end-user).

У нашому сценарії: **Максим Витребенько** — він володіє нотатками у SecureNotes і може дозволити або заборонити доступ до них.

Ключові аспекти:

- Resource Owner **приймає рішення** — саме він натискає "Дозволити" на consent screen
- Resource Owner **не передає credentials** стороннім додаткам
- Resource Owner може **відкликати** доступ у будь-який момент

### Client (Клієнт)

**Client** — це додаток, який запитує доступ до захищених ресурсів від імені Resource Owner. Client може бути веб-додатком, мобільним додатком, CLI-інструментом або іншим сервером.

OAuth 2.0 розрізняє два типи клієнтів за здатністю зберігати секрети:

| Тип клієнта | Опис | Приклад |
|---|---|---|
| **Confidential** | Може безпечно зберігати `client_secret` | Серверний додаток (backend) |
| **Public** | Не може зберігати секрети (код доступний користувачу) | SPA (JavaScript у браузері), мобільний додаток |

Ця різниця критична для вибору grant type та рівня безпеки. Confidential client може автентифікуватися перед Authorization Server за допомогою `client_secret`. Public client не може — будь-який секрет, вбудований у JavaScript або мобільний додаток, може бути витягнутий.

У нашому сценарії: **PrintApp** — сторонній додаток для друку, який хоче читати нотатки Максима. Якщо PrintApp — серверний додаток, він confidential. Якщо SPA — public.

### Authorization Server (Сервер авторизації)

**Authorization Server** — це сервер, який автентифікує Resource Owner, отримує його consent (згоду), і видає токени доступу (access tokens) клієнту.

Основні endpoint-и Authorization Server:

| Endpoint | Призначення |
|---|---|
| **Authorization endpoint** (`/authorize`) | Взаємодія з Resource Owner: автентифікація та consent |
| **Token endpoint** (`/token`) | Обмін authorization code на access token |
| **Revocation endpoint** (`/revoke`) | Відкликання токенів |
| **Introspection endpoint** (`/introspect`) | Перевірка валідності токена |

```python
# Приклад: структура Authorization Server endpoints
AUTHORIZATION_SERVER = {
    "authorization_endpoint": "https://securenotes.example/oauth/authorize",
    "token_endpoint": "https://securenotes.example/oauth/token",
    "revocation_endpoint": "https://securenotes.example/oauth/revoke",
    "introspection_endpoint": "https://securenotes.example/oauth/introspect",
}
```

У нашому сценарії: **SecureNotes Authorization Server** — частина інфраструктури SecureNotes, яка відповідає за видачу токенів.

### Resource Server (Сервер ресурсів)

**Resource Server** — це сервер, який зберігає захищені ресурси та приймає запити з access token.

Resource Server відповідає за:

- **Валідацію** access token (перевірка підпису, терміну дії, scope)
- **Перевірку scope** — чи має токен достатньо прав для запитуваної операції
- **Повернення** ресурсу або відмову з відповідним кодом помилки

```bash
# Приклад: запит до Resource Server з access token
curl -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9..." \
     https://securenotes.example/api/notes
```

У нашому сценарії: **SecureNotes API** — надає доступ до нотаток. Перевіряє, що токен дійсний і має scope `notes:read`.

### Важливе зауваження

Authorization Server і Resource Server можуть бути **одним і тим самим сервером** (типово для невеликих систем) або **різними серверами** (типово для великих систем, де Google OAuth — це Authorization Server, а Google Photos API — Resource Server).

---

## 3. Реєстрація клієнта (Client Registration)

### Навіщо реєстрація

Перш ніж Client зможе запитувати доступ, він повинен **зареєструватися** в Authorization Server. Це критично для безпеки: Authorization Server повинен знати, хто саме запитує доступ, і мати змогу верифікувати ідентичність клієнта.

### Процес реєстрації

Максим, як розробник PrintApp, реєструє свій додаток у SecureNotes:

```
┌────────────────────────────────────────────────────────────┐
│  Реєстрація клієнта                                        │
│                                                            │
│  Назва додатку:     PrintApp                               │
│  Тип клієнта:       confidential                           │
│  Redirect URIs:     https://printapp.example/callback      │
│  Scopes:            notes:read                             │
│                                                            │
│  ──────────────────────────────────────────────────────    │
│                                                            │
│  Результат:                                                │
│  client_id:     pa_7f3a2b1c9d4e                            │
│  client_secret: sk_X9mK4pL7qR2sT5uW8vY1zA3bC6dE0fG       │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### client_id

**client_id** — це публічний ідентифікатор клієнта. Він не є секретом і може бути видимий у URL-ах, запитах та логах.

Призначення:

- Унікально ідентифікує клієнта в Authorization Server
- Передається в authorization request, щоб Authorization Server знав, хто запитує
- Дозволяє показати користувачу на consent screen назву та інформацію про додаток

### client_secret

**client_secret** — це секретний ключ клієнта, аналог пароля. Використовується **тільки confidential клієнтами** для автентифікації при зверненні до token endpoint.

```python
# Приклад: обмін authorization code на access token
# client_secret передається у POST-запиті
import requests

response = requests.post(
    "https://securenotes.example/oauth/token",
    data={
        "grant_type": "authorization_code",
        "code": "SplxlOBeZQQYbYS6WxSbIA",
        "redirect_uri": "https://printapp.example/callback",
        "client_id": "pa_7f3a2b1c9d4e",
        "client_secret": "sk_X9mK4pL7qR2sT5uW8vY1zA3bC6dE0fG",
    }
)
token = response.json()
```

Правила безпеки для `client_secret`:

- **Ніколи** не вбудовувати у frontend-код (JavaScript, мобільні додатки)
- Зберігати на сервері у змінних середовища або secret manager
- Регулярно ротувати (замінювати на новий)
- Public клієнти **не мають** `client_secret` — для них використовується PKCE (розглянемо в лекції 6)

### redirect_uri

**redirect_uri** — це URL, на який Authorization Server перенаправляє Resource Owner після авторизації. Це один з найбільш критичних параметрів безпеки в OAuth.

```
Крок 1: Client перенаправляє на Authorization Server
   ──→ https://securenotes.example/oauth/authorize
        ?response_type=code
        &client_id=pa_7f3a2b1c9d4e
        &redirect_uri=https://printapp.example/callback
        &scope=notes:read

Крок 2: Після consent Authorization Server перенаправляє назад
   ──→ https://printapp.example/callback
        ?code=SplxlOBeZQQYbYS6WxSbIA
```

Redirect URI, зареєстрований при реєстрації, **повинен точно збігатися** з redirect URI у запиті авторизації. Чому — розглянемо в розділі 6.

---

## 4. Scopes — гранулярний контроль доступу

### Визначення

**Scope** — це механізм обмеження доступу, який визначає, які конкретно дії клієнт може виконувати з ресурсами. Scopes реалізують **принцип найменших привілеїв** (Principle of Least Privilege) — клієнт отримує лише ті права, які необхідні для виконання його завдання.

### Приклад: scopes для SecureNotes

```
┌─────────────────────────────────────────────────────────┐
│  SecureNotes Scopes                                      │
│                                                         │
│  notes:read      — читання нотаток                      │
│  notes:write     — створення та редагування нотаток     │
│  notes:delete    — видалення нотаток                    │
│  profile:read    — читання профілю користувача          │
│  profile:write   — редагування профілю                  │
│  sharing:manage  — керування спільним доступом          │
│                                                         │
│  PrintApp запитує: notes:read                           │
│  (мінімально необхідний доступ для друку)               │
└─────────────────────────────────────────────────────────┘
```

### Як працюють scopes

Scopes беруть участь на кількох етапах OAuth-потоку:

1. **Запит** — Client вказує бажані scopes в authorization request:

```
GET /oauth/authorize
    ?response_type=code
    &client_id=pa_7f3a2b1c9d4e
    &redirect_uri=https://printapp.example/callback
    &scope=notes:read profile:read
```

2. **Consent** — Authorization Server показує Resource Owner, які scopes запитує клієнт:

```
┌────────────────────────────────────────────┐
│  PrintApp хоче отримати доступ:            │
│                                            │
│  [x] Читати ваші нотатки  (notes:read)    │
│  [x] Читати ваш профіль   (profile:read)  │
│                                            │
│        [Дозволити]    [Відхилити]           │
└────────────────────────────────────────────┘
```

3. **Токен** — Access token містить видані scopes. Authorization Server може видати **менше** scopes, ніж запитано (наприклад, якщо адміністратор обмежив дозволи клієнта)

4. **Перевірка** — Resource Server перевіряє scope токена при кожному запиті:

```python
# Resource Server перевіряє scope
def get_notes(request):
    token = validate_access_token(request.headers["Authorization"])

    if "notes:read" not in token["scope"]:
        return {"error": "insufficient_scope"}, 403

    return get_user_notes(token["sub"])
```

### Конвенції іменування scopes

Різні провайдери використовують різні стилі:

| Провайдер | Стиль | Приклади |
|---|---|---|
| Google | URL-based | `https://www.googleapis.com/auth/drive.readonly` |
| GitHub | colon-separated | `repo:status`, `user:email` |
| Microsoft | slash-separated | `Files.Read`, `User.ReadWrite` |
| SecureNotes (наш) | colon-separated | `notes:read`, `profile:write` |

### Downscoping

**Downscoping** — це практика, коли клієнт запитує менше scopes, ніж має право. Наприклад, PrintApp зареєстрований із scopes `notes:read notes:write`, але при конкретному запиті авторизації запитує лише `notes:read`, бо для друку запис не потрібен. Це додатковий рівень принципу найменших привілеїв.

---

## 5. Огляд типів грантів (Grant Types)

### Що таке grant type

**Grant type** (тип гранту) — це метод, за яким клієнт отримує access token. Різні грант-типи призначені для різних сценаріїв використання та різних типів клієнтів.

### Authorization Code Grant

**Найбезпечніший і найпоширеніший** грант-тип для серверних та клієнтських додатків.

```
┌──────────┐                              ┌───────────────────┐
│ Resource │                              │  Authorization    │
│  Owner   │                              │  Server           │
└────┬─────┘                              └─────────┬─────────┘
     │  1. Максим натискає "Увійти"                 │
     │                                               │
     ▼                                               │
┌──────────┐  2. Redirect → /authorize               │
│  Client  │────────────────────────────────────────→│
│(PrintApp)│                                         │
└──────────┘                                         │
     │           3. Логін + Consent                   │
     │  ←───────────────────────────────────────────│
     │                                               │
     │           4. Redirect з authorization code     │
     │  ←───────────────────────────────────────────│
     │                                               │
     │  5. POST /token (code + client_secret)        │
     │  ────────────────────────────────────────────→│
     │                                               │
     │  6. Access Token                              │
     │  ←───────────────────────────────────────────│
     │                                               │
     │  7. GET /api/notes (Bearer token)             │
     │  ────────────────────────────────────────────→│ Resource
     │                                               │ Server
     │  8. Дані                                      │
     │  ←───────────────────────────────────────────│
```

**Чому це безпечно:**

- Authorization code — короткоживучий, одноразовий
- Обмін code на token відбувається **back-channel** (сервер-сервер), не через браузер
- Client автентифікується `client_secret` при обміні
- Access token **ніколи не потрапляє** в URL або browser history

### Implicit Grant (DEPRECATED)

**Застарілий** грант-тип, раніше використовувався для SPA.

```
Client → /authorize → Authorization Server
                         │
                         │ redirect з access token
                         │ у URL fragment (#)
                         ▼
         https://printapp.example/callback#access_token=eyJ...
```

**Чому deprecated:**

- Access token передається через **URL fragment** — він може потрапити в browser history, логи, referrer
- Немає автентифікації клієнта
- Немає refresh token
- **Замінений на Authorization Code + PKCE** (лекція 6)

### Client Credentials Grant

Призначений для **machine-to-machine** (M2M) комунікації, коли немає Resource Owner (користувача).

```python
# Приклад: сервіс аналітики запитує статистику SecureNotes
import requests

response = requests.post(
    "https://securenotes.example/oauth/token",
    data={
        "grant_type": "client_credentials",
        "client_id": "analytics_service",
        "client_secret": "sk_analytics_secret_key",
        "scope": "stats:read",
    }
)
access_token = response.json()["access_token"]
```

**Використання:** мікросервіси, cron jobs, backend-інтеграції — будь-який сценарій, де один сервіс запитує доступ до іншого без участі користувача.

### Resource Owner Password Credentials Grant (DEPRECATED)

**Застарілий** грант-тип, де клієнт безпосередньо збирає credentials користувача.

```
Client збирає username + password
         │
         │ POST /token (username, password, client_id)
         ▼
Authorization Server → Access Token
```

**Чому deprecated:**

- Повертає нас до password anti-pattern — клієнт бачить пароль користувача
- Допустимий лише коли клієнт і Authorization Server належать **одній організації** (наприклад, офіційний мобільний додаток SecureNotes)
- Навіть у такому випадку **рекомендовано використовувати Authorization Code + PKCE**

### Порівняння грант-типів

| Grant Type | Для кого | Потрібен секрет | Статус |
|---|---|---|---|
| **Authorization Code** | Серверні додатки, SPA (з PKCE) | Так (confidential) / PKCE (public) | **Рекомендований** |
| **Implicit** | SPA (legacy) | Ні | **Deprecated** |
| **Client Credentials** | Machine-to-machine | Так | **Активний** |
| **Resource Owner Password** | First-party додатки (legacy) | Так | **Deprecated** |

---

## 6. Redirect URIs — чому це важливо

### Роль redirect URI

Redirect URI — це точка повернення: після авторизації Authorization Server перенаправляє браузер Resource Owner на цей URI, передаючи authorization code (або токен). Саме через redirect URI клієнт отримує результат авторизації.

### Атака: підміна redirect URI

Якщо Authorization Server **не перевіряє** redirect URI строго, зловмисник може перехопити authorization code:

```
1. Зловмисник формує URL авторизації з підміненим redirect_uri:

   https://securenotes.example/oauth/authorize
     ?response_type=code
     &client_id=pa_7f3a2b1c9d4e
     &redirect_uri=https://evil.example/steal     ← підмінено!
     &scope=notes:read

2. Жертва переходить за посиланням, бачить легітимний consent screen SecureNotes

3. Жертва натискає "Дозволити"

4. Authorization Server перенаправляє на evil.example з кодом:
   https://evil.example/steal?code=SplxlOBeZQQYbYS6WxSbIA

5. Зловмисник обмінює code на access token
```

### Exact matching — захист

**Authorization Server повинен вимагати точного збігу** redirect URI із зареєстрованим значенням. Жодних wildcards, жодних часткових збігів.

```
Зареєстрований:  https://printapp.example/callback

Запит:           https://printapp.example/callback        ← OK
Запит:           https://printapp.example/callback?foo=bar ← FAIL
Запит:           https://printapp.example/callback/        ← FAIL
Запит:           https://evil.example/callback             ← FAIL
Запит:           http://printapp.example/callback          ← FAIL (не HTTPS)
```

### Правила для redirect URI

1. **Exact match** — redirect URI у запиті повинен **точно** збігатися із зареєстрованим
2. **Тільки HTTPS** — за винятком `http://localhost` для розробки
3. **Без wildcards** — жодних `*.example.com` або `https://example.com/*`
4. **Без фрагментів** — redirect URI не може містити `#fragment`
5. **Множинні URI** — клієнт може зареєструвати кілька redirect URI, але кожен запит повинен вказувати конкретний

```python
# Приклад: валідація redirect_uri на Authorization Server
REGISTERED_REDIRECT_URIS = [
    "https://printapp.example/callback",
    "https://printapp.example/auth/callback",
]

def validate_redirect_uri(requested_uri: str, client_id: str) -> bool:
    registered = get_registered_uris(client_id)
    # EXACT match — жодних часткових збігів
    return requested_uri in registered
```

### Спеціальні випадки

- **Localhost для розробки:** `http://localhost:8080/callback` — допускається HTTP, але порт повинен збігатися
- **Custom URL schemes для мобільних додатків:** `com.printapp.auth://callback` — використовуються для перенаправлення назад у мобільний додаток
- **Loopback redirect:** `http://127.0.0.1:{port}/callback` — для native desktop додатків (порт може бути динамічним, RFC 8252)

---

## 7. Модель загроз делегування (Threat Model)

### STRIDE для архітектури OAuth

У лекції 1 ми розглянули модель STRIDE. Тепер застосуємо її конкретно до архітектури OAuth 2.0, яку ми щойно побудували. Для кожної загрози визначимо вектор атаки та контрзаходи.

### Data Flow Diagram OAuth

```
┌──────────────┐                     ┌──────────────────────┐
│   Resource   │                     │  Authorization       │
│   Owner      │◄───── (F1) ────────│  Server              │
│   (Browser)  │────── (F2) ───────→│                      │
│              │                     │  /authorize          │
└──────┬───────┘                     │  /token              │
       │                             └──────────┬───────────┘
    (F3) redirect                               │
       │                                     (F5) token
       ▼                                        │
┌──────────────┐                     ┌──────────▼───────────┐
│   Client     │────── (F4) ───────→│  Resource Server     │
│   (PrintApp) │◄───── (F6) ────────│  (SecureNotes API)   │
└──────────────┘                     └──────────────────────┘

F1 = consent screen          F4 = API request + Bearer token
F2 = authorization grant     F5 = token validation
F3 = redirect + code         F6 = protected resource
```

### S — Spoofing (Підробка ідентичності)

| Вектор атаки | Ціль | Контрзахід |
|---|---|---|
| Фішинговий Authorization Server | Resource Owner вводить credentials на підробному сайті | TLS, перевірка сертифікатів, навчання користувачів |
| Підробка client_id | Зловмисник видає свій додаток за легітимний | Валідація redirect_uri (exact match), client_secret |
| Підміна redirect_uri | Перехоплення authorization code | Exact matching redirect URI |

```
Атака: зловмисник реєструє Client з назвою "SecureNotes Official"
       і підміняє redirect_uri

Захист:
  1. Authorization Server перевіряє redirect_uri (exact match)
  2. Consent screen показує реального розробника додатку
  3. client_secret відомий лише справжньому клієнту
```

### T — Tampering (Підробка даних)

| Вектор атаки | Ціль | Контрзахід |
|---|---|---|
| Модифікація authorization code в redirect | Отримати інший код | HTTPS, code одноразовий, прив'язаний до client_id |
| Зміна scope в запиті авторизації | Отримати ширший доступ | Authorization Server верифікує scopes, consent screen |
| Модифікація access token | Підвищення привілеїв | Цифрові підписи (JWS), перевірка на Resource Server |

### R — Repudiation (Заперечення)

| Вектор атаки | Ціль | Контрзахід |
|---|---|---|
| Клієнт заперечує запит scope | Уникнення відповідальності | Логування authorization requests з timestamps |
| Resource Owner заперечує consent | Оспорювання доступу | Зберігання consent records, audit log |

```python
# Приклад: логування authorization request
import logging
import datetime

def log_authorization_request(client_id, scopes, user_id, decision):
    logging.info(
        "OAuth authorization: client=%s scopes=%s user=%s decision=%s time=%s",
        client_id,
        scopes,
        user_id,
        decision,  # "granted" або "denied"
        datetime.datetime.utcnow().isoformat(),
    )
```

### I — Information Disclosure (Витік інформації)

| Вектор атаки | Ціль | Контрзахід |
|---|---|---|
| Authorization code в URL → логи сервера, referrer | Перехоплення коду | Код одноразовий, короткий TTL (10 хв) |
| Access token у browser history (Implicit flow) | Крадіжка токена | Не використовувати Implicit flow |
| Витік client_secret | Повний доступ від імені клієнта | Зберігати в secret manager, ротувати |
| Логи з токенами | Крадіжка з логів | Не логувати access tokens, маскувати |

```bash
# Неправильно — логуємо токен
echo "Access token: eyJhbGciOiJSUzI1NiJ9.eyJzdWIi..."

# Правильно — маскуємо
echo "Access token: eyJh...dWIi (masked)"
```

### D — Denial of Service

| Вектор атаки | Ціль | Контрзахід |
|---|---|---|
| Flood на /authorize | Перевантаження Authorization Server | Rate limiting per IP, CAPTCHA |
| Flood на /token | Вичерпання ресурсів | Rate limiting per client_id |
| Масова генерація authorization codes | Заповнення сховища | TTL на codes, обмеження per user |

### E — Elevation of Privilege (Підвищення привілеїв)

| Вектор атаки | Ціль | Контрзахід |
|---|---|---|
| Клієнт запитує scopes, які не були дозволені при реєстрації | Ширший доступ | Перевірка scopes проти зареєстрованих |
| Повторне використання authorization code | Повторне отримання токена | Код одноразовий, при повторному використанні — відкликати всі видані токени |
| Модифікація JWT claims | Зміна ролі/scopes | Перевірка підпису (RS256/ES256) |

```python
# Приклад: перевірка scope при обробці authorization request
ALLOWED_SCOPES_PER_CLIENT = {
    "pa_7f3a2b1c9d4e": {"notes:read", "profile:read"},
    "analytics_service": {"stats:read"},
}

def validate_requested_scopes(client_id: str, requested_scopes: set) -> set:
    allowed = ALLOWED_SCOPES_PER_CLIENT.get(client_id, set())
    if not requested_scopes.issubset(allowed):
        invalid = requested_scopes - allowed
        raise ScopeError(f"Client not allowed scopes: {invalid}")
    return requested_scopes
```

### Зведена таблиця загроз

| STRIDE | Загроза | Ймовірність | Вплив | Пріоритет |
|---|---|---|---|---|
| S | Підміна redirect_uri | Висока | Критичний | P0 |
| T | Модифікація access token | Середня | Критичний | P0 |
| I | Токени у логах | Висока | Високий | P1 |
| E | Повторне використання auth code | Середня | Високий | P1 |
| D | Flood на /token | Середня | Середній | P2 |
| R | Заперечення consent | Низька | Низький | P3 |

---

## 8. Підсумки

### Що ми розглянули

- **Password anti-pattern** — чому передача пароля третій стороні є фундаментальною помилкою
- **Чотири ролі OAuth 2.0** — Resource Owner, Client (confidential/public), Authorization Server, Resource Server
- **Client Registration** — client_id, client_secret, redirect_uri як основа довіри між клієнтом і сервером
- **Scopes** — гранулярний контроль доступу, принцип найменших привілеїв
- **Grant Types** — Authorization Code (рекомендований), Client Credentials (M2M), Implicit та ROPC (deprecated)
- **Redirect URIs** — exact matching як критичний механізм безпеки
- **STRIDE threat model** — систематичний аналіз загроз OAuth-архітектури

### Ключові висновки

1. OAuth 2.0 — це **фреймворк авторизації**, а не протокол автентифікації. Він вирішує проблему делегованого доступу
2. Розділення на чотири ролі забезпечує **чіткий поділ відповідальності** та мінімізує attack surface
3. **client_secret** — це секрет, який повинен зберігатися безпечно, але public клієнти взагалі його не мають
4. **Exact matching redirect URI** — одна з найважливіших перевірок безпеки в OAuth
5. З чотирьох грант-типів лише **Authorization Code** і **Client Credentials** рекомендовані для нових систем

### Що далі?

У наступній лекції — **Лекція 5: Authorization Code Flow у деталях** — ми покроково розберемо найважливіший грант-тип:

- **Authorization Code Flow** — кожен крок з HTTP-запитами та відповідями
- **PKCE** (Proof Key for Code Exchange) — розширення, яке робить Authorization Code безпечним для public клієнтів (SPA, мобільні додатки)
- **State parameter** — захист від CSRF атак
- **Access Token та Refresh Token** — структура, термін дії, ротація

Максим Витребенько інтегрує PrintApp із SecureNotes за допомогою Authorization Code + PKCE — побачимо кожен HTTP-запит і відповідь.

---

## Література

1. Dick Hardt. *RFC 6749 — The OAuth 2.0 Authorization Framework.* — IETF: 2012
2. Torsten Lodderstedt, John Bradley, Andrii Sakimura, Daniel Fett. *RFC 6819 — OAuth 2.0 Threat Model and Security Considerations.* — IETF: 2013
3. Daniel Fett, Brian Campbell, John Bradley, Torsten Lodderstedt. *OAuth 2.0 Security Best Current Practice.* — IETF: 2025
4. Aaron Parecki. *OAuth 2.0 Simplified.* — Lulu.com: 2020
5. Justin Richer, Antonio Sanso. *OAuth 2 in Action.* — Manning: 2017
