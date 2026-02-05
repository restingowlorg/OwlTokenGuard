
```md
# 🔐 Minimal Cryptography Library for Node.js

**OWASP ASVS Aligned (v11) · Framework-Agnostic · Clean Architecture · MVP Level 1**

A **minimal, opinionated cryptography library** for Node.js applications that provides:

- Secure encryption and decryption
- Strong password / data hashing
- Timing-safe verification
- Clear cryptographic boundaries
- Zero framework coupling

This library is intentionally **small** and designed to be used **only at security boundaries**, not scattered across application code.

---

## 🎯 Why This Library Exists

Most Node.js applications:

- Misuse `crypto` primitives
- Reuse IVs or salts incorrectly
- Mix hashing and encryption logic
- Leak crypto decisions across the codebase
- Treat cryptography as a utility instead of a security boundary

This library provides **one correct way** to do cryptography.

> **One rule:** Cryptography must be centralized and explicit.

---

## ✨ Key Features

- ✅ AES-256-GCM authenticated encryption
- ✅ Secure IV and salt generation
- ✅ PBKDF2-based hashing
- ✅ Timing-safe hash verification
- ✅ Strong domain modeling (no raw Buffers leaking everywhere)
- ✅ Framework-agnostic
- ✅ Node.js `crypto` only (no third-party crypto deps)
- ✅ OWASP ASVS aligned (v11)
- ✅ Very small API surface

---

## 📁 Folder Structure (MVP Level 1)

```

src/
├── index.ts
│
├── manager/
│   └── CryptoManager.ts
│
├── init/
│   └── createCryptoLibrary.ts
│
├── service/
│   └── CryptoService.ts
│
├── domain/
│   ├── CipherText.ts
│   └── HashValue.ts
│
├── contracts/
│   └── CryptoProvider.ts
│
├── infra/
│   └── node/
│       └── NodeCryptoAdapter.ts
│
├── config/
│   └── defaults.ts
│
├── errors/
│   └── CryptoError.ts
│
├── types/
│   └── index.ts
│
└── utils/
└── buffers.ts

````

---

## 🚀 Installation

```bash
npm install @restingowlorg/ossec-crypto
````

or

```bash
yarn add @restingowlorg/ossec-crypto
```

---

## 🧠 Core Concept

Instead of directly calling `crypto` throughout your application, you use **one cryptographic facade**:

```ts
const crypto = createCryptoLibrary({ masterKey });
```

All cryptographic operations flow through this boundary.

This guarantees:

* Correct algorithm usage
* Secure defaults
* Centralized cryptographic policy
* Easy auditing and review

---

## 🔌 Basic Usage

### Creating the Cryptography Library

```ts
import { createCryptoLibrary } from "@restingowlorg/ossec-crypto";

const crypto = createCryptoLibrary({
  masterKey: Buffer.from(process.env.MASTER_KEY!, "hex"),
});
```

> ⚠️ `MASTER_KEY` must be **32 bytes (256 bits)** and stored securely (env / vault / KMS).

---

### Encrypting Data

```ts
const cipherText = crypto.encrypt(
  Buffer.from("sensitive data")
);
```

---

### Decrypting Data

```ts
const plainText = crypto.decrypt(cipherText);

plainText.toString(); // "sensitive data"
```

---

### Hashing Data (Passwords / Secrets)

```ts
const hash = crypto.hash(
  Buffer.from("my-password")
);
```

---

### Verifying a Hash

```ts
const isValid = crypto.verifyHash(
  Buffer.from("my-password"),
  hash
);
```

Uses **timing-safe comparison** to prevent side-channel attacks.

---

## 🧪 Example Usage (Real Application Scenarios)

### Example 1: Encrypting Sensitive Data Before Database Storage

**Use case:** Encrypt PII or secrets before saving to the database.

```ts
const secretNote = "User private note";

const encrypted = crypto.encrypt(Buffer.from(secretNote));

await db.insert("notes", {
  value: encrypted.value,
  iv: encrypted.iv,
  authTag: encrypted.authTag,
});
```

✅ Plaintext never reaches the database
✅ Authenticated encryption prevents tampering

---

### Example 2: Decrypting Data After Retrieval

```ts
const record = await db.get("notes", { id });

const decrypted = crypto.decrypt({
  value: record.value,
  iv: record.iv,
  authTag: record.authTag,
});

console.log(decrypted.toString());
```

If data is modified or corrupted, decryption **fails safely**.

---

### Example 3: Password Hashing During Signup

```ts
const password = Buffer.from("StrongPassword123!");

const hash = crypto.hash(password);

await db.insert("users", {
  passwordHash: hash.value,
  passwordSalt: hash.salt,
});
```

✅ Unique salt per password
✅ Resistant to rainbow table attacks

---

### Example 4: Password Verification During Login

```ts
const user = await db.get("users", { email });

const isValid = crypto.verifyHash(
  Buffer.from("StrongPassword123!"),
  {
    value: user.passwordHash,
    salt: user.passwordSalt,
  }
);

if (!isValid) {
  throw new Error("Invalid credentials");
}
```

---

### Example 5: Using with Express.js (Security Boundary)

```ts
app.post("/secure-store", (req, res) => {
  const { data } = req.body;

  const encrypted = crypto.encrypt(Buffer.from(data));

  res.json({
    value: encrypted.value.toString("hex"),
    iv: encrypted.iv.toString("hex"),
    authTag: encrypted.authTag.toString("hex"),
  });
});
```

---

## 📦 Domain Models (Why They Matter)

### CipherText

```ts
CipherText {
  value: Buffer
  iv: Buffer
  authTag: Buffer
}
```

Prevents:

* Losing authentication tags
* Passing incomplete encrypted payloads
* Incorrect decryption usage

---

### HashValue

```ts
HashValue {
  value: Buffer
  salt: Buffer
}
```

Prevents:

* Salt reuse bugs
* Incorrect verification logic
* Primitive obsession

---

## 🔐 Secure Defaults

All cryptographic defaults are centralized in:

```
config/defaults.ts
```

Includes:

* AES-256-GCM
* Random IV per encryption
* PBKDF2 with high iteration count
* Strong digest algorithms

No magic numbers.
No hidden behavior.

---

## 🔍 OWASP ASVS Alignment (v11)

| Requirement Area        | Coverage              |
| ----------------------- | --------------------- |
| Cryptographic Storage   | ✅ AES-GCM encryption  |
| Key Management          | ✅ Explicit master key |
| Randomness              | ✅ crypto.randomBytes  |
| Password Storage        | ✅ PBKDF2 with salt    |
| Side-Channel Resistance | ✅ timingSafeEqual     |

---

## ⚠️ What This Library Does NOT Do

* ❌ No key management system (KMS)
* ❌ No key rotation
* ❌ No password policy enforcement
* ❌ No JWT handling
* ❌ No encoding / serialization opinions

This is **intentional**.

---

## 🧠 Design Philosophy

* Cryptography is **not a utility**
* Explicit is safer than convenient
* Domain models > raw primitives
* One secure way > many flexible ways

---

## 🧩 When to Use This Library

* Encrypting sensitive data at rest
* Hashing passwords or secrets
* Verifying credentials
* Application-level cryptographic boundaries

---

## 🧩 When NOT to Use It

* TLS / transport security
* High-performance bulk encryption
* Client-side cryptography
* Custom algorithm experimentation

---

## 📜 License

MIT

```