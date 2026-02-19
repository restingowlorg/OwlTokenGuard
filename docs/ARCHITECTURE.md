---

# 🔐 OSSEC Cryptography Library

## Architectural Development Guide

---

# 1️⃣ Core Architectural Philosophy

This library follows:

* **Clean Architecture**
* **Domain-Driven Design (DDD-lite)**
* **Security by Design**
* **Fail Fast Principle**
* **Zero Insecure Defaults**

The cryptographic core must remain:

* Deterministic
* Explicit
* Stateless
* Framework-agnostic

---

# 2️⃣ High-Level Architecture

```
┌───────────────────────────────┐
│         Public API Layer      │
│  (createCryptoLibrary)        │
└───────────────┬───────────────┘
                │
┌───────────────▼───────────────┐
│         Service Layer         │
│  EncryptionService            │
│  HashingService               │
└───────────────┬───────────────┘
                │
┌───────────────▼───────────────┐
│          Domain Layer         │
│  CipherText                   │
│  HashValue                    │
│  SecureKey                    │
└───────────────┬───────────────┘
                │
┌───────────────▼───────────────┐
│        Infrastructure         │
│  Node Crypto Adapter          │
│  Random Generator             │
└───────────────────────────────┘
```

---

# 3️⃣ Layer Responsibilities

---

## 🔹 1. Public API Layer

**Purpose:**
Expose safe, minimal entry points.

Example:

```ts
const cryptoLib = createCryptoLibrary();
cryptoLib.encryption.encrypt(...)
```

Rules:

* No direct Node crypto usage here
* No business logic
* Only orchestration

---

## 🔹 2. Service Layer

Contains:

* `EncryptionService`
* `HashingService`

Responsibilities:

* Orchestrate cryptographic operations
* Validate inputs
* Enforce security policies
* Throw domain-specific errors

Rules:

* Must not expose raw crypto primitives
* Must not return raw strings (use domain objects)
* Must validate all parameters

---

## 🔹 3. Domain Layer

Contains value objects:

* `CipherText`
* `HashValue`
* `SecureKey`

Rules:

* Immutable
* No side effects
* Validate at construction
* No crypto logic inside domain models

Example:

```ts
export class CipherText {
  constructor(public readonly value: string) {
    if (!value) throw new Error("CipherText cannot be empty");
  }
}
```

---

## 🔹 4. Infrastructure Layer

Contains:

* Node.js crypto adapter
* Random IV generator
* Encoding helpers

Rules:

* Isolated
* Swappable (for browser version later)
* No business logic

Never allow direct `crypto` usage outside this layer.

---

# 4️⃣ Error Architecture

All errors must extend:

```
BaseCryptoError
```

Example hierarchy:

```
BaseCryptoError
 ├── InsecureConfigurationError
 ├── InsecureUsageError
 ├── EncryptionError
 ├── DecryptionError
 └── HashingError
```

Rules:

* Never throw raw `Error`
* Always use custom typed errors
* Never leak internal crypto details in messages

Bad:

```ts
throw new Error("Invalid IV length 12")
```

Good:

```ts
throw new EncryptionError("Invalid encryption configuration")
```

---

# 5️⃣ Security Design Principles

---

## ✅ 1. No Insecure Defaults

Bad:

```ts
algorithm = "aes-128-cbc"
```

Good:

```ts
algorithm = "aes-256-gcm"
```

---

## ✅ 2. Key Validation Mandatory

* Must validate length
* Must validate encoding
* Must reject weak keys

---

## ✅ 3. Always Use Authenticated Encryption

Prefer:

* AES-256-GCM
* ChaCha20-Poly1305

Avoid:

* ECB
* MD5
* SHA1

---

## ✅ 4. Randomness

Use:

```
crypto.randomBytes()
```

Never use:

```
Math.random()
```

---

# 6️⃣ Folder Structure Standard

```
src/
│
├── domain/
│   ├── CipherText.ts
│   ├── HashValue.ts
│
├── services/
│   ├── EncryptionService.ts
│   ├── HashingService.ts
│
├── errors/
│   ├── BaseCryptoError.ts
│   ├── InsecureUsageError.ts
│
├── infrastructure/
│   ├── NodeCryptoAdapter.ts
│
├── init/
│   └── createCryptoLibrary.ts
│
└── index.ts
```

---

# 7️⃣ Adding a New Feature (Example: Digital Signatures)

When adding new capability:

### Step 1 — Add Domain Object

```
SignatureValue.ts
```

### Step 2 — Add Service

```
SignatureService.ts
```

### Step 3 — Add Error Types

```
SignatureError.ts
```

### Step 4 — Wire in createCryptoLibrary

Never mix features into existing services.

---
