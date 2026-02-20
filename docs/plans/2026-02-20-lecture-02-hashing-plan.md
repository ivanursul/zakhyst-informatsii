# Lecture 2: Хешування та цілісність даних — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create lecture 2 (full text + Marp presentation) covering hashing, password attacks, and modern password hashing algorithms.

**Architecture:** Two files: `lectures/02-hashing.md` (full prose, ~450 lines) and `presentations/02-hashing.md` (Marp slides, ~25 slides). Both follow exact patterns from Lecture 1.

**Tech Stack:** Markdown, Marp presentation framework

---

### Task 1: Write the lecture text — Sections 1-2

**Files:**
- Create: `lectures/02-hashing.md`

**Step 1: Create the lecture file with TOC and Sections 1-2**

Write `lectures/02-hashing.md` with:

1. **Title:** `# Лекція 2. Хешування та цілісність даних`
2. **TOC (Зміст):** numbered list with anchor links to all 7 sections
3. **Section 1: Що таке хеш-функція і навіщо вона потрібна**
   - Opening question: "Ви завантажили файл з інтернету — як переконатися, що його ніхто не підмінив?"
   - Tie back to CIA Triad from Lecture 1 — hashing ensures **Integrity**
   - Definition of hash function: deterministic function that maps arbitrary input to fixed-size output
   - Key properties (list):
     - **Детермінованість** — однаковий вхід завжди дає однаковий вихід
     - **Фіксований розмір** — незалежно від розміру вхідних даних
     - **Односпрямованість** (one-way) — неможливо відновити вхідні дані з хешу
     - **Лавинний ефект** (avalanche effect) — зміна одного біта входу змінює ~50% бітів виходу
     - **Стійкість до колізій** (collision resistance) — практично неможливо знайти два різних входи з однаковим хешем
   - Bash code example showing avalanche effect:
     ```
     echo -n "Hello" | sha256sum
     → 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969
     echo -n "hello" | sha256sum
     → 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
     ```
   - Emphasize: one capital letter → completely different hash

4. **Section 2: SHA-256 — перший інструмент**
   - SHA = Secure Hash Algorithm, 256 = output size in bits (32 bytes, 64 hex characters)
   - Part of SHA-2 family (designed by NSA, published by NIST)
   - Intuition: think of it as a "digital fingerprint" — unique identifier for any data
   - Practical uses:
     - File integrity verification (checksums: `sha256sum file.zip`)
     - Git commit hashes (every commit = SHA-1 hash of content)
     - Blockchain (Bitcoin block mining = finding SHA-256 with leading zeros)
     - Digital signatures (sign the hash, not the whole document)
   - Python code example:
     ```python
     import hashlib
     data = "Захист інформації"
     hash_value = hashlib.sha256(data.encode('utf-8')).hexdigest()
     print(hash_value)
     ```
   - Transition question: "SHA-256 чудово підходить для перевірки цілісності файлів. А що, якщо використати його для зберігання паролів?"
   - ASCII diagram:
     ```
     ┌────────────────┐     ┌──────────────┐     ┌────────────────────┐
     │ Вхідні дані    │────→│  SHA-256     │────→│ 256-бітний хеш     │
     │ (будь-який     │     │  hash()      │     │ (64 hex символи)   │
     │  розмір)       │     └──────────────┘     │ e3b0c44298fc...    │
     └────────────────┘           ↑               └────────────────────┘
                                  │
                              Одностороння
                              функція — назад
                              неможливо!
     ```

**Format rules (match Lecture 1 exactly):**
- `---` horizontal rule separators between major sections
- ASCII diagrams using box-drawing characters (┌─┐│└┘▼→←)
- Code blocks with triple backticks and language tags
- GFM tables with alignment
- Bold for key terms on first use
- Ukrainian language throughout, English terms in parentheses on first mention

---

### Task 2: Write the lecture text — Section 3 (Password attacks)

**Files:**
- Modify: `lectures/02-hashing.md` (append)

**Step 1: Write Section 3**

**Section 3: Проблема — як зламати хеші паролів**

Content to write:

- **Database leak scenario:** Максим Витребенько працює в компанії, яка зберігає паролі як SHA-256 хеші. Базу даних зламали. Що бачить атакуючий?
- Table showing leaked database:
  | Користувач | SHA-256 хеш пароля |
  |---|---|
  | maksym.vytrebenko | `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` |
  | olena.koval | `ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f` |
  | admin | `8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918` |

- **Brute force attack:** SHA-256 designed to be FAST — GPU can compute billions of hashes per second. Table showing speeds:
  | Пристрій | Швидкість SHA-256 |
  |---|---|
  | CPU (сучасний) | ~50 млн хешів/сек |
  | GPU (NVIDIA RTX 4090) | ~10 млрд хешів/сек |
  | Спеціалізований ASIC | ~100+ млрд хешів/сек |

- At 10 billion/sec, a 6-character lowercase password (26^6 ≈ 309 million combinations) cracked in **0.03 seconds**
- **Dictionary attacks:** attackers don't start with random combinations — they use dictionaries of common passwords
- **Rainbow tables** — precomputed tables mapping hash→password. Instead of computing hashes on the fly, download a table with billions of pre-calculated hashes. Example: the hash `5e884898da...` is instantly recognized as `password` because it's in every rainbow table
- Key insight paragraph: SHA-256 is a **general-purpose** hash function designed to be fast. Speed is a feature for file checksums, but a vulnerability for passwords. The faster the hash, the faster the attacker.

---

### Task 3: Write the lecture text — Sections 4-5 (Salt, bcrypt, Argon2)

**Files:**
- Modify: `lectures/02-hashing.md` (append)

**Step 1: Write Section 4 (Salt)**

**Section 4: Сіль (Salt) — перший захист**

- Definition: salt = random value added to password before hashing: `hash(salt + password)`
- ASCII diagram:
  ```
  Без солі:
  "password123" ──→ SHA-256 ──→ ef92b778bafe...
  "password123" ──→ SHA-256 ──→ ef92b778bafe...  ← ОДНАКОВІ!

  З сіллю:
  "a1b2c3" + "password123" ──→ SHA-256 ──→ 7c4f8a91d3e2...
  "x9y8z7" + "password123" ──→ SHA-256 ──→ 1f3e5d7c9b0a...  ← РІЗНІ!
  ```
- Why it defeats rainbow tables: attacker needs a separate rainbow table for each unique salt — impractical
- How salt is stored: alongside the hash (salt is NOT secret, it just needs to be unique)
- Table showing database with salt:
  | Користувач | Сіль | Хеш |
  |---|---|---|
  | maksym.vytrebenko | `a1b2c3d4` | `7c4f8a91...` |
  | olena.koval | `e5f6g7h8` | `2d3e4f5a...` |
- **Why salt alone is not enough:** SHA-256 is still blazingly fast. Even with unique salts, attacker can brute-force each hash at billions per second. Salt stops rainbow tables, but not brute force.

**Step 2: Write Section 5 (bcrypt and Argon2)**

**Section 5: bcrypt та Argon2 — повільне хешування**

- **Key stretching** concept: intentionally make hashing slow
- Problem restated: we need a hash function that is slow enough to make brute-force impractical, but fast enough that a single user login doesn't take minutes

- **bcrypt (1999):**
  - Based on Blowfish cipher (no need to explain internals)
  - **Cost factor** (work factor): parameter that controls how slow the hash is. Cost = 12 means 2^12 = 4096 iterations
  - Built-in salt generation — no need to manage salt separately
  - Output format: `$2b$12$LJ3m4ys3Lg7E90WYOF3O2u8VYClVxcBqRKqhW8MiNAJG6SAPO2nJy`
    - `$2b$` = algorithm version
    - `12` = cost factor
    - next 22 chars = base64-encoded salt
    - remaining = hash
  - Python code example:
    ```python
    import bcrypt
    password = "supersecret".encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password, salt)
    # Перевірка
    bcrypt.checkpw(password, hashed)  # True
    ```
  - Cost factor impact table:
    | Cost factor | Ітерацій | Час хешування |
    |---|---|---|
    | 10 | 1 024 | ~100 мс |
    | 12 | 4 096 | ~300 мс |
    | 14 | 16 384 | ~1 сек |

- **Argon2 (2015, переможець Password Hashing Competition):**
  - Three dimensions of hardness:
    - **Час** (time cost) — кількість ітерацій
    - **Пам'ять** (memory cost) — скільки RAM потрібно для обчислення
    - **Паралелізм** (parallelism) — кількість потоків
  - Why **memory-hardness** matters: GPUs have thousands of cores but limited memory per core. If each hash computation requires 64 MB of RAM, a GPU with 10,000 cores would need 640 GB just for parallel hashing — impractical
  - ASCII diagram:
    ```
    bcrypt:                         Argon2:
    ┌──────────┐                    ┌──────────┐
    │ Повільний │                    │ Повільний │
    │ по часу   │                    │ по часу   │
    │           │                    │ + багато  │
    │           │                    │   RAM     │
    │           │                    │ + потоки  │
    └──────────┘                    └──────────┘
    GPU: може паралелити          GPU: не вистачає
         тисячі обчислень               пам'яті на ядро
    ```
  - Three variants: Argon2d (data-dependent), Argon2i (data-independent), Argon2id (hybrid, **recommended**)
  - Python code example:
    ```python
    from argon2 import PasswordHasher
    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
    hash = ph.hash("supersecret")
    ph.verify(hash, "supersecret")  # True
    ```

- **Comparison table:**
  | | SHA-256 | bcrypt | Argon2 |
  |---|---|---|---|
  | Призначення | загальне хешування | хешування паролів | хешування паролів |
  | Швидкість | дуже швидкий | повільний (налаштовується) | повільний (налаштовується) |
  | Вбудована сіль | ні | так | так |
  | Memory-hard | ні | ні | **так** |
  | GPU-стійкість | ні | частково | **так** |
  | Рекомендація | файли, підписи | паролі (legacy) | **паролі (сучасний стандарт)** |

---

### Task 4: Write the lecture text — Sections 6-7 (CSPRNG, Summary)

**Files:**
- Modify: `lectures/02-hashing.md` (append)

**Step 1: Write Section 6 (CSPRNG)**

**Section 6: CSPRNG — звідки береться випадковість**

- Opening: bcrypt and Argon2 generate salt automatically. But what makes a good salt? It must be **unpredictable**
- **PRNG vs CSPRNG:**
  - PRNG (Pseudo-Random Number Generator): `random.randint()` — deterministic, predictable if you know the seed. Fast, good for games and simulations
  - CSPRNG (Cryptographically Secure PRNG): `os.urandom()`, `secrets.token_hex()` — unpredictable even if you know previous outputs
- Why PRNG is dangerous for security: if attacker can predict the salt, rainbow tables become viable again
- Where does entropy come from?
  - Hardware events: mouse movement, keyboard timing, disk I/O timing, network packet arrival
  - OS entropy pool: `/dev/urandom` (Linux/macOS), `CryptGenRandom` (Windows)
  - Hardware RNG: Intel RDRAND instruction
- **Practical rules:**
  - Паролі/токени: `secrets.token_hex(32)` (Python) або `openssl rand -hex 32` (bash)
  - **Ніколи:** `random.random()`, `Math.random()`, `rand()` для криптографічних цілей
- Python code example:
  ```python
  import secrets
  import random

  # ПРАВИЛЬНО — для токенів, солей, ключів:
  token = secrets.token_hex(32)

  # НЕПРАВИЛЬНО — передбачуваний, НЕ для безпеки:
  bad_token = ''.join(str(random.randint(0,9)) for _ in range(32))
  ```

**Step 2: Write Section 7 (Summary)**

**Section 7: Підсумки**

- **Що ми розглянули** (bullet list):
  - Хеш-функції та їх ключові властивості
  - SHA-256 — швидке хешування для цілісності даних
  - Атаки на хеші паролів — brute force та rainbow tables
  - Сіль — захист від rainbow tables
  - bcrypt та Argon2 — повільне хешування для паролів
  - CSPRNG — криптографічно безпечна генерація випадкових значень

- **Ключові висновки** (numbered list):
  1. Хеш-функція — це «цифровий відбиток» даних: одностороння, детермінована, з лавинним ефектом
  2. SHA-256 підходить для перевірки цілісності, але **занадто швидкий** для зберігання паролів
  3. Сіль захищає від rainbow tables, але не від brute force — потрібне **повільне хешування**
  4. **Argon2id** — сучасний стандарт хешування паролів (memory-hard, GPU-стійкий)
  5. Для будь-яких криптографічних цілей використовуйте лише **CSPRNG** — ніколи `random()`

- **Що далі?** — preview of Lecture 3: Симетричне шифрування. AES (CBC, GCM)
  - Хешування — це одностороння функція: дані «в одну сторону». Але що, якщо нам потрібно **зашифрувати** дані так, щоб їх можна було **розшифрувати** назад?
  - **AES** (Advanced Encryption Standard) — symmetric block cipher
  - Режими шифрування: **CBC** (Cipher Block Chaining) та **GCM** (Galois/Counter Mode)
  - Expand abbreviations as done in Lecture 1

- **Література:**
  - Jean-Philippe Aumasson. *Serious Cryptography.* — No Starch Press: 2017
  - Niels Ferguson, Bruce Schneier. *Cryptography Engineering.* — Wiley: 2010
  - RFC 6234 — US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)
  - Password Hashing Competition — https://www.password-hashing.net/

---

### Task 5: Write the Marp presentation

**Files:**
- Create: `presentations/02-hashing.md`

**Step 1: Create the presentation file**

Use exact same YAML front matter and CSS from `presentations/01-introduction.md` (copy verbatim).

Write ~25 slides following this structure:

1. **Title slide** (`<!-- _class: title -->`)
   - `# Захист інформації: OAuth від фундаменту до впровадження`
   - `Лекція 2. Хешування та цілісність даних`
   - University + year

2. **Plan slide**
   - Numbered list of 6 topics matching lecture sections

3. **Що таке хеш-функція** — properties list

4. **Лавинний ефект** — two similar inputs → completely different hashes (bash example)

5. **SHA-256** — input → 256-bit digest, ASCII diagram

6. **Практичне використання SHA-256** — checksums, git, blockchain, digital signatures

7. **А що, якщо хешувати паролі?** — transition question

8. **Витік бази даних** — table with Максим's hashed password

9. **Brute force: швидкість GPU** — speed table (CPU vs GPU vs ASIC)

10. **Rainbow tables** — precomputed hash→password lookup, example

11. **Ключовий інсайт** — SHA-256 is too fast for passwords

12. **Сіль (Salt)** — ASCII diagram: without salt vs with salt

13. **Сіль у базі даних** — table showing salt + hash stored together

14. **Чому солі недостатньо** — still billions/sec per hash

15. **Key stretching — повільне хешування** — concept

16. **bcrypt** — cost factor, built-in salt, output format

17. **bcrypt: приклад** — Python code example

18. **Argon2** — three dimensions: time, memory, parallelism

19. **Чому memory-hardness важлива** — GPU memory limitation diagram

20. **Порівняльна таблиця** — SHA-256 vs bcrypt vs Argon2

21. **CSPRNG vs PRNG** — two-column layout (`<div class="columns">`)

22. **Практичні правила випадковості** — do's and don'ts code examples

23. **Підсумки** — bullet points of key takeaways

24. **Що далі?** — Lecture 3 preview (AES, CBC, GCM)

25. **Closing slide** (`<!-- _class: title -->`) — "Дякую за увагу! / Питання?"

Same formatting rules as Lecture 1 presentation:
- `---` between every slide
- ASCII diagrams using box-drawing characters
- Tables with GFM syntax
- `<div class="columns">` for two-column layouts
- `<!-- _class: title -->` for title/closing slides
- No decorative colors, monospace style

---

### Task 6: Review and commit

**Step 1: Verify both files**

- Read both files end-to-end
- Verify consistent use of "Максим Витребенько" persona
- Verify all abbreviations are expanded on first use
- Verify section numbering matches TOC
- Verify presentation slide count matches lecture content

**Step 2: Commit**

```bash
git add lectures/02-hashing.md presentations/02-hashing.md docs/plans/
git commit -m "Add lecture 2: hashing and data integrity (SHA-256, bcrypt, Argon2)"
```
