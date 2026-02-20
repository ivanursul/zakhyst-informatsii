# Design: Lecture 2 — Хешування та цілісність даних

## Overview

Second lecture in the "Захист інформації: OAuth від фундаменту до впровадження" course.
Covers hashing fundamentals, password storage attacks, and modern password hashing algorithms.

## Decisions

- **Depth:** Intuition-level, no math internals (Merkle-Damgard, compression functions)
- **Code examples:** Mix of ASCII diagrams + short code snippets (Python, bash)
- **HMAC:** Deferred to JWT lecture (Lecture 7)
- **Length:** ~400-500 lines, 7 sections (similar to Lecture 1)
- **Structure:** Problem-first spiral — each concept motivated by the previous one's weakness
- **Persona:** Максим Витребенько (same as Lecture 1)

## Lecture Sections

1. **Що таке хеш-функція і навіщо вона потрібна** — CIA Integrity tie-in, hash properties, first code example
2. **SHA-256 — перший інструмент** — fixed-size output, practical uses (checksums, git), Python example
3. **Проблема — як зламати хеші паролів** — database leak scenario, brute force (GPU speed), rainbow tables
4. **Сіль (Salt) — перший захист** — random prefix, defeats rainbow tables, still not enough (speed)
5. **bcrypt та Argon2 — повільне хешування** — key stretching, cost factor, memory-hardness, comparison table
6. **CSPRNG — звідки береться випадковість** — PRNG vs CSPRNG, entropy sources, practical rules
7. **Підсумки та що далі** — key takeaways, summary table, preview of Lecture 3 (AES)

## Presentation

~25 slides in Marp format, same CSS/style as Lecture 1 presentation.
Monospace, black-on-white, ASCII diagrams, no decorative colors.

## Files to Create

- `lectures/02-hashing.md` — full lecture text
- `presentations/02-hashing.md` — Marp presentation
