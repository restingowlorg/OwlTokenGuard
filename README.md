
```md
# 🔐 Minimal Cryptography Library for Node.js

**OWASP ASVS Aligned · Framework-Agnostic · Clean Architecture · MVP Level 1**

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

- ✅ AES-GCM authenticated encryption
- ✅ Secure IV and salt generation
- ✅ PBKDF2-based hashing
- ✅ Timing-safe hash verification
- ✅ Strong domain modeling (no raw Buffers leaking everywhere)
- ✅ Framework-agnostic
- ✅ Node.js `crypto` only (no third-party crypto deps)
- ✅ OWASP ASVS aligned
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
* Centralized policy
* Easy auditing

---

## 🔌 Basic Usage

### Creating the Library

```ts
import { createCryptoLibrary } from "@restingowlorg/ossec-crypto";

const crypto = createCryptoLibrary({
  masterKey: Buffer.from(process.env.MASTER_KEY!, "hex")
});
```

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

### Hashing Data (Passwords, Secrets)

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

Returns `true` or `false` using **timing-safe comparison**.

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
* Passing raw encrypted buffers without metadata
* Incorrect decryption attempts

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

All defaults live in one place:

```ts
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

## 🔍 OWASP ASVS Alignment

| Requirement Area        | Coverage              |
| ----------------------- | --------------------- |
| Cryptographic Storage   | ✅ Strong encryption   |
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

This is intentional.

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