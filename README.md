# Захист інформації: OAuth від фундаменту до впровадження

Матеріали курсу "Захист інформації: OAuth від фундаменту до впровадження" для студентів спеціальності 113 — прикладна математика, Львівський національний університет імені Івана Франка.

## Структура

```
lectures/       — повні тексти лекцій (Markdown)
presentations/  — презентації до лекцій (Marp Markdown)
```

## Теми курсу

| # | Тема |
|---|------|
| 1 | Вступ. Проблема довіри в інтернеті. Identity, Authentication, Authorization. STRIDE |
| 2 | Хешування та цілісність даних. SHA-256, bcrypt, Argon2 |
| 3 | Симетричне шифрування. AES (CBC, GCM) |
| 4 | Асиметричне шифрування, підписи, PKI |
| 5 | OAuth 2.0: архітектура протоколу |
| 6 | Authorization Code Flow |
| 7 | JWT: токени зсередини |
| 8 | Access Token, Refresh Token, Token Lifecycle |
| 9 | PKCE та безпека публічних клієнтів |
| 10 | OpenID Connect |
| 11 | Атаки на OAuth та захист |
| 12 | OAuth у мікросервісній архітектурі |
| 13 | Безпека веб-додатків навколо OAuth |
| 14 | Проєктування безпечної системи. Підсумок |

## Презентації

Презентації створені у форматі [Marp](https://marp.app/) — Markdown Presentation Ecosystem. Для перегляду як слайдів:

- **VS Code:** встановити розширення [Marp for VS Code](https://marketplace.visualstudio.com/items?itemName=marp-team.marp-vscode)
- **CLI:** `npx @marp-team/marp-cli presentations/01-introduction.md`
- **GitHub:** файли відображаються як форматований Markdown
