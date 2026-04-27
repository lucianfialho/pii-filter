# @lucianfialho/pii-filter

Deterministic PII filtering for JSON payloads — redact or pseudonymize personal data before passing to LLMs or storing in logs.

## Install

```bash
npm install @lucianfialho/pii-filter
```

## Usage

```typescript
import { filterPii } from "@lucianfialho/pii-filter";

// Redact — removes PII irreversibly (GDPR: anonymization)
filterPii({ email: "user@example.com", age: 30 }, { mode: "redact" });
// → { email: "[REDACTED]", age: 30 }

// Pseudonymize — SHA256+salt, deterministic (GDPR: pseudonymization)
// salt is required — store it as a secret env var
filterPii({ email: "user@example.com" }, { mode: "pseudonymize", salt: process.env.PII_SALT! });
// → { email: "[a3f8c2d1e4b5f6a7]" }
```

## Modes

| Mode | Output | GDPR |
|---|---|---|
| `redact` | `[REDACTED]` or `[PRIVATE_EMAIL]` | Anonymization — outside GDPR scope |
| `pseudonymize` | `[sha256hex]` | Pseudonymization — reduced obligations (requires secret salt) |

## What gets detected

**By field name:** `email`, `phone`, `cpf`, `cnpj`, `password`, `token`, `api_key`, `name`, `address`, `birth_date`, and more.

**By value pattern (regex):** emails, Brazilian phone numbers, CPF, CNPJ, credit card numbers, API keys/secrets in `key=value` format.

## GDPR note

`pseudonymize` mode with a secret salt approximates anonymization — without the salt, hashes cannot be reversed. Keep `PII_SALT` secret and never log it.
