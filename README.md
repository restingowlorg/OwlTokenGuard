# owltokenguard

<p align="center">
  <img src="https://raw.githubusercontent.com/restingowlorg/OwlAuth/main/docs/assets/restingowl-logo.png" alt="owltokenguard logo" width="320" />
</p>

---

[![npm package](https://img.shields.io/badge/npm-%40restingowlorg%2Fowltokenguard-CB3837?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/@restingowlorg/owltokenguard) [![Node.js](https://img.shields.io/badge/node-%3E%3D18-339933?style=flat-square&logo=node.js&logoColor=white)](https://www.npmjs.com/package/@restingowlorg/owltokenguard) [![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Open-source OWASP-aligned token and session security library for Node.js.

owltokenguard, published as `@restingowlorg/owltokenguard`, gives your backend a focused token-management surface: access and refresh JWT issuance, signature-first verification, refresh-token rotation (RTR), session revocation, and freshness controls after account-security events. It ships Express and Fastify middleware and stays out of your persistence layer — you wire hooks for refresh storage and session termination.

- **Package:** `@restingowlorg/owltokenguard`
- **Latest stable tag:** `latest`
- **Prerelease tag:** `next`
- **Install:** `npm install @restingowlorg/owltokenguard`
- **Developer guide:** [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md)
- **Security model:** [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)
- **Security policy:** [SECURITY.md](SECURITY.md)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)

## What You Get

- **Access + refresh issuance:** Generate access JWTs and optional refresh JWTs from one `TokenManager`.
- **Refresh token rotation (RTR):** One-time refresh consumption with an OAuth-style token response.
- **Fail-shut verification:** Signature-first checks with issuer, audience, temporal, purpose, and algorithm allowlists.
- **Session revocation hooks:** Revoke by `jti`, raw token, cutoff timestamp, or custom policy — persistence is yours.
- **Reauthentication freshness:** Stamp and enforce `reauth_at` so sessions go stale after email or MFA changes.
- **Opaque reference tokens:** Issue high-entropy backend session references when you need non-JWT handles.
- **Optional payload encryption:** Encrypt JWT payloads before signing with a pluggable cipher (AES-256-GCM).
- **Framework middleware:** Express and Fastify verification middleware with a typed `auth` context.
- **Typed, predictable results:** Consistent shapes across issuance, rotation, verification, and termination.

## Support Matrix

| Area               | Current Support                          |
| ------------------ | ---------------------------------------- |
| Runtime            | Node.js 18, 20, and 22                   |
| Language           | TypeScript, JavaScript                   |
| Module output      | CommonJS                                 |
| Signing algorithms | HS256, HS512, RS256, ES256               |
| HTTP frameworks    | Express, Fastify                         |
| Core flows         | Issue, Verify, Rotate, Revoke, Terminate |

## Installation

```bash
npm install @restingowlorg/owltokenguard
```

## Quick Start

```ts
import { createTokenManager } from "@restingowlorg/owltokenguard";

const tokenManager = createTokenManager({
  algorithm: "HS256",
  hmacSecret: process.env.JWT_SECRET!,
  issuer: "https://issuer.example",
  trustedIssuers: ["https://issuer.example"],
  audience: "my-api",
  expiresInSeconds: 900,
  refreshTokenEnabled: true,
  refreshTokenExpiresInSeconds: 60 * 60 * 24 * 7,
  onSessionTerminate: async ({ jti }) => {
    // Remove session jti from your store (DB, cache, etc.)
    await sessionStore.revoke(jti);
  },
});

const issued = await tokenManager.generateAccessToken(
  { sub: "user-123", role: "admin" },
  { reauthAt: Math.floor(Date.now() / 1000) },
);

const verified = await tokenManager.verify(issued.token, { purpose: "access" });
console.log(verified.payload.sub); // "user-123"
```

## Package Boundary

owltokenguard is the token management library. It owns token-level cryptography: JWT signing, verification, registered claims such as `iss` and `aud`, token purpose checks, optional payload encryption, and opaque reference-token generation. OwlSessionGuard is the session management library and owns session records, storage adapters, idle and absolute timeouts, revoke-all behavior, device binding, breach response, and persistent refresh-token rotation state.

The refresh APIs in this package issue and validate refresh JWTs and expose hooks such as `onRefreshTokenIssued`, `consumeRefreshToken`, and `onSessionTerminate` as integration points. Back those hooks with the session-management library or an application-owned store; this package does not own durable session storage.

## Signing & Key Material

owltokenguard defaults to **RS256** at the library level; HS256/HS512 require a high-entropy HMAC secret (minimum 64 characters). ES256 requires the **P-256 / `prime256v1`** curve; RS256 verification rejects keys below **2048 bits**.

### Symmetric (HS256 / HS512)

```ts
import { createTokenManager } from "@restingowlorg/owltokenguard";

const tokenManager = createTokenManager({
  algorithm: "HS256",
  hmacSecret: process.env.JWT_SECRET!,
  expiresInSeconds: 900,
  allowedAlgorithms: ["HS256"],
  onSessionTerminate: async () => {},
});
```

### Asymmetric (RS256 / ES256)

```ts
import { createTokenManager } from "@restingowlorg/owltokenguard";

const tokenManager = createTokenManager({
  algorithm: "RS256",
  signingKey: {
    type: "asymmetric",
    privateKey: process.env.JWT_PRIVATE_KEY!,
    publicKey: process.env.JWT_PUBLIC_KEY!,
  },
  expiresInSeconds: 900,
  allowedAlgorithms: ["RS256"],
  onSessionTerminate: async () => {},
});
```

### Optional Payload Encryption

```ts
import {
  createTokenManager,
  Aes256GcmCipher,
} from "@restingowlorg/owltokenguard";

const encryptionKey = Buffer.from(
  process.env.PAYLOAD_ENCRYPTION_KEY!,
  "base64",
);

const tokenManager = createTokenManager({
  algorithm: "HS256",
  hmacSecret: process.env.JWT_SECRET!,
  expiresInSeconds: 900,
  payloadCipher: new Aes256GcmCipher(encryptionKey),
  onSessionTerminate: async () => {},
});
```

## Framework Integration

### Express

```ts
import express from "express";
import {
  createTokenManager,
  expressVerifyToken,
} from "@restingowlorg/owltokenguard";

const app = express();
app.use(express.json());

const manager = createTokenManager({
  algorithm: "HS256",
  hmacSecret: process.env.JWT_SECRET!,
  expiresInSeconds: 900,
  onSessionTerminate: async () => {},
});

const requireAccessToken = expressVerifyToken(manager, { purpose: "access" });

app.get("/api/me", requireAccessToken, (req, res) => {
  res.json({
    sub: req.auth?.payload.sub,
    jti: req.auth?.jti,
  });
});
```

### Fastify

```ts
import Fastify from "fastify";
import {
  createTokenManager,
  fastifyVerifyToken,
} from "@restingowlorg/owltokenguard";

const app = Fastify();

const manager = createTokenManager({
  algorithm: "HS256",
  hmacSecret: process.env.JWT_SECRET!,
  expiresInSeconds: 900,
  onSessionTerminate: async () => {},
});

const requireAccessToken = fastifyVerifyToken(manager, { purpose: "access" });

app.get("/api/me", { preHandler: requireAccessToken }, async (request) => {
  return {
    sub: request.auth?.payload.sub,
    jti: request.auth?.jti,
  };
});
```

## Core Usage

### Issue Access + Refresh Tokens

```ts
import type {
  AccessTokenResult,
  TokenResult,
} from "@restingowlorg/owltokenguard";

const issued: AccessTokenResult = await tokenManager.generateAccessToken(
  { sub: "user-123", role: "admin" },
  { reauthAt: Math.floor(Date.now() / 1000) },
);

// issued.token, issued.claims, issued.refreshToken, issued.refreshClaims

const combined: TokenResult = await tokenManager.generate({ sub: "user-123" });
// combined.token + combined.referenceToken
```

### Verify Tokens

```ts
import type { VerifyResult } from "@restingowlorg/owltokenguard";

const auth: VerifyResult = await tokenManager.verify(token, {
  purpose: "access",
  audience: "my-api",
  trustedIssuers: ["https://issuer.example"],
});
```

### Rotate Refresh Tokens (OAuth-style)

```ts
import type { RotateResult } from "@restingowlorg/owltokenguard";

const rotated: RotateResult = await tokenManager.rotate(refreshToken);

// RFC 6749-compatible payload for POST /auth/refresh:
// rotated.oauth = { access_token, token_type, expires_in, refresh_token }
```

Wire rotation persistence with `onRefreshTokenIssued` and `consumeRefreshToken` so each refresh JWT is stored once and consumed atomically on rotate.
Persistent refresh-token state, replay response, logout-all-devices, idle timeout, and absolute session lifetime should be implemented by OwlSessionGuard or your application session store.

### Store Token Digests, Not Raw Tokens

```ts
import { createTokenDigest } from "@restingowlorg/owltokenguard";

const digest = createTokenDigest(refreshToken, {
  pepper: process.env.TOKEN_DIGEST_PEPPER!,
});

await refreshTokenStore.save({ digest, subject: "user-123" });
```

Use token digests for lookup values when integrating with OwlSessionGuard or an application-owned session store. Prefer the peppered HMAC form for stored refresh-token records because it remains safer if the database leaks.

### Revoke and Terminate Sessions

```ts
// Logout-style: verify the token, then terminate its session
await tokenManager.revokeToken(refreshToken, { purpose: "refresh" });

// Server-side: terminate by jti or verified claims
await tokenManager.terminate({ jti: "session-jti" });

// Invalidate all tokens issued before a cutoff (logout-all-devices)
await tokenManager.terminate(claims, {
  sub: "user-123",
  invalidateBefore: Math.floor(Date.now() / 1000),
});
```

> **Note:** `onSessionTerminate` is **required** at config time. The library invokes it on explicit termination and during access-token rotation when `previousSession` is supplied. You implement storage removal — the library does not persist sessions for you.

## Session Revocation & Freshness Patterns

### A) Revoke by `jti`

Persist revoked `jti` values and reject them in `isSessionRevoked`.

### B) Invalidate tokens issued before a cutoff

Use `getTokensInvalidBefore(sub)` to reject any token where `iat` is strictly before the stored cutoff.

### C) Enforce reauthentication freshness (`reauth_at`)

When sensitive account data changes (email, MFA, recovery methods), bump a minimum freshness timestamp and reject tokens with stale `reauth_at`.

```ts
const minimumReauthAtBySub = new Map<string, number>();

const manager = createTokenManager({
  algorithm: "HS256",
  hmacSecret: process.env.JWT_SECRET!,
  expiresInSeconds: 900,
  getMinimumReauthAt: async (sub) => minimumReauthAtBySub.get(sub),
  onSessionTerminate: async () => {},
});

// On email change / MFA change:
minimumReauthAtBySub.set("user-123", Math.floor(Date.now() / 1000));
```

## OAuth Refresh Endpoint Example

```ts
app.post("/auth/refresh", async (req, res) => {
  const refreshToken = req.body?.refresh_token;
  if (!refreshToken) {
    return res.status(400).json({ error: "invalid_request" });
  }

  try {
    const result = await manager.rotate(refreshToken);
    return res.status(200).json(result.oauth);
  } catch {
    return res.status(401).json({ error: "invalid_grant" });
  }
});
```

## Configuration Options

### Core `TokenConfig`

| Option                         | Type                 | Purpose                                                            |
| ------------------------------ | -------------------- | ------------------------------------------------------------------ |
| `algorithm`                    | `SigningAlgorithm`   | Preferred signing algorithm (`HS*`, `RS256`, `ES256`)              |
| `issuer`                       | `string`             | Issuer claim (`iss`) stamped onto issued JWTs                      |
| `hmacSecret`                   | `string`             | Shared secret for symmetric signing (min 64 chars for `HS*`)       |
| `signingKey`                   | key material         | Private/public key material for asymmetric signing                 |
| `expiresInSeconds`             | `number`             | Access token `exp` offset (positive integer, validated at startup) |
| `refreshTokenEnabled`          | `boolean`            | Issue a refresh JWT alongside each access token                    |
| `refreshTokenExpiresInSeconds` | `number`             | Refresh token `exp` offset (required when refresh is enabled)      |
| `onSessionTerminate`           | hook **(required)**  | Persist session removal or cutoff invalidation                     |
| `onRefreshTokenIssued`         | hook                 | Persist refresh session metadata after issuance                    |
| `consumeRefreshToken`          | hook                 | Atomically mark a refresh token consumed during `rotate()`         |
| `isSessionRevoked`             | hook                 | Per-token revocation check during verification                     |
| `getTokensInvalidBefore`       | hook                 | Reject tokens with `iat` before a subject-level cutoff             |
| `requireReauthAtClaim`         | `boolean`            | Require `reauth_at` freshness marker on verify                     |
| `getMinimumReauthAt`           | hook                 | Reject tokens with stale `reauth_at`                               |
| `payloadCipher`                | `PayloadCipher`      | Optional payload encryption before signing                         |
| `maxTokenBytes`                | `number`             | Max JWT string size accepted on verify (default: 8192)             |
| `allowedAlgorithms`            | `SigningAlgorithm[]` | Verification allowlist (defaults to configured `algorithm`)        |
| `trustedIssuers`               | `string[]`           | Issuer allowlist for verification                                  |
| `audience`                     | `string \| string[]` | Audience claim stamped during issuance and expected on verify      |

### Verification Options (`verify`)

| Option                  | Type                            | Purpose                             |
| ----------------------- | ------------------------------- | ----------------------------------- |
| `purpose`               | `"access" \| "id" \| "refresh"` | Enforce token intent                |
| `audience`              | `string \| string[]`            | Override audience check             |
| `trustedIssuers`        | `string[]`                      | Override issuer allowlist           |
| `clockToleranceSeconds` | `number`                        | Temporal tolerance                  |
| `requireTemporalClaims` | `boolean`                       | Require `exp` and `nbf`             |
| `requireReauthAtClaim`  | `boolean`                       | Require `reauth_at` for this call   |
| `minimumReauthAt`       | `number`                        | Per-request reauth freshness cutoff |

## Response & Error Model

Verification and issuance return typed results (`AccessTokenResult`, `VerifyResult`, `RotateResult`, etc.).

Exported errors for application handling:

- `TokenGenerationError` — issuance or termination input failures
- `TokenVerificationError` — signature, claims, revocation, or freshness failures
- `SecurityConfigurationError` — invalid keys, algorithms, or config at startup
- `UntrustedKeySourceError` — untrusted `jku` / `x5u` header sources

Typical verify handler:

```ts
import { TokenVerificationError } from "@restingowlorg/owltokenguard";

try {
  await manager.verify(token, { purpose: "access" });
} catch (error) {
  if (error instanceof TokenVerificationError) {
    // return 401
  }
  throw error;
}
```

## OWASP Alignment

Here's what owltokenguard enforces in code, traced to [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html), [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), and [ASVS](https://owasp.org/www-project-application-security-verification-standard/) token/session controls.

### Token Verification

| Control                    | What the library does                                                                  | OWASP reference                            |
| -------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------ |
| Signature-first validation | Header and signature are verified before payload claims are trusted.                   | JWT Cheat Sheet — validate signatures      |
| Algorithm allowlist        | Only configured algorithms pass verification; `"none"` is blocked.                     | JWT Cheat Sheet — do not accept `none`     |
| Key confusion prevention   | HMAC algorithms require symmetric material; asymmetric algorithms require public keys. | ASVS — prevent algorithm/key confusion     |
| Temporal claim checks      | `exp`, `nbf`, and optional clock tolerance are enforced.                               | JWT Cheat Sheet — validate temporal claims |
| Issuer and audience        | Optional trusted issuers and audience checks on every verify.                          | JWT Cheat Sheet — validate `iss` and `aud` |
| Purpose separation         | Access, ID, and refresh token types can be enforced to prevent cross-use.              | OAuth / OIDC token_use separation          |
| Oversized token rejection  | JWT strings above 8 KB (configurable) are rejected before parsing.                     | DoS hardening — limit untrusted input size |
| Weak key rejection         | RS256 requires ≥2048-bit RSA keys; ES256 requires P-256 (`prime256v1`).                | Cryptographic key strength best practices  |

### Refresh Token Rotation

| Control                 | What the library does                                                                                   | OWASP reference                                 |
| ----------------------- | ------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| One-time refresh use    | `consumeRefreshToken` must atomically mark a refresh JWT consumed before rotation continues.            | Session Management — detect refresh token reuse |
| Rotation on refresh     | A successful rotate issues new access + refresh tokens and terminates the prior refresh session.        | OAuth 2.0 refresh token rotation (RTR)          |
| OAuth-compatible output | `rotate()` exposes an RFC 6749-style `{ access_token, token_type, expires_in, refresh_token }` payload. | OAuth 2.0 token response                        |

### Session Revocation & Freshness

| Control                      | What the library does                                                                                     | OWASP reference                                      |
| ---------------------------- | --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| Server-side revocation hooks | `isSessionRevoked`, `terminate`, and `revokeToken` let you invalidate sessions without waiting for `exp`. | Session Management — server-side session termination |
| Cutoff invalidation          | `getTokensInvalidBefore` rejects tokens issued before a stored cutoff (logout-all-devices).               | Session Management — invalidate active sessions      |
| Reauthentication freshness   | `reauth_at` is stamped at issuance and enforced via `getMinimumReauthAt` after account-security changes.  | Session Management — re-auth after credential change |

## Security Notes

The table above covers what this library actually does. It's **not** an OWASP certification, and it won't make your app ASVS-compliant on its own. You still need to handle:

- TLS and secure transport
- secure key storage and rotation
- refresh-token storage hardening in your database or cache
- brute-force protection, rate limits, and lockout on auth endpoints
- CSRF defenses where cookies carry tokens
- account recovery and MFA flows
- authorization and role enforcement beyond token verification

For the complete threat model, trust boundaries, and OWASP mapping, see
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md). To report a vulnerability,
follow [SECURITY.md](SECURITY.md).

## Roadmap

owltokenguard is part of the wider Resting Owl effort to ship secure-by-default tooling for Node.js backends.

What's coming next:

- **Deeper framework integrations:** First-party helpers for NestJS, Next.js API routes, and serverless runtimes
- **JWKS & key rotation:** Built-in JWKS fetch/rotation patterns for multi-tenant issuers
- **Stronger session stores:** Reference adapters and patterns for Redis, PostgreSQL, and MongoDB session persistence
- **Tighter owlauth pairing:** End-to-end examples combining `@restingowlorg/owlauth` login flows with owltokenguard session tokens
- **Broader Resting Owl package family:** Adjacent packages for rate limiting, audit logging, CSRF protection, and secrets management

## Releases

Releases use [Changesets](https://github.com/changesets/changesets) with `develop` → `staging` → `main` promotion and npm dist-tags `next` / `latest`. See [docs/RELEASE_DAY_RUNBOOK.md](docs/RELEASE_DAY_RUNBOOK.md) and [docs/DETAILED_RELEASE_SYNC_RUNBOOK.md](docs/DETAILED_RELEASE_SYNC_RUNBOOK.md).

```bash
npm run changeset          # record a user-facing change
npm run release:validate   # local quality gates before opening a PR
```

## Community

[![Website](https://img.shields.io/badge/restingowl.com-111827?style=flat-square&logo=googlechrome&logoColor=white)](https://restingowl.com/) [![LinkedIn](https://img.shields.io/badge/LinkedIn-0A66C2?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/showcase/restingowl/) [![GitHub](https://img.shields.io/badge/Source-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/restingowlorg/OwlTokenGuard) [![Issues](https://img.shields.io/badge/Issues-GitHub-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/restingowlorg/OwlTokenGuard/issues) [![Developer Guide](https://img.shields.io/badge/Developer_Guide-15803D?style=flat-square&logo=gitbook&logoColor=white)](docs/DEVELOPER_GUIDE.md)

## License

[MIT License](LICENSE)
