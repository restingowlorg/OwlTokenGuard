# `@restingowlorg/ossec-cryptography`

Open-source OWASP-aligned token and session security library for Node.js.

`@restingowlorg/ossec-cryptography` gives your backend a focused authentication-token surface:
access token issuance, refresh-token rotation, token verification, middleware integration, session revocation, and freshness controls for account-security events (email / MFA changes).

- **Package:** `@restingowlorg/ossec-cryptography`
- **Install:** `npm install @restingowlorg/ossec-cryptography`
- **Runtime:** Node.js 18+
- **Module output:** CommonJS

---

## What You Get

- **Access + refresh issuance:** Generate access JWTs and optional refresh JWTs from one manager.
- **Refresh token rotation (RTR):** One-time refresh consumption with OAuth-style token response.
- **Opaque reference tokens:** Generate high-entropy backend session references when needed.
- **Fail-shut verification:** Signature-first checks with issuer, audience, temporal, and purpose validation.
- **Session revocation hooks:** Revoke by `jti`, token, cutoff timestamp, or custom policy.
- **Reauthentication freshness:** Enforce `reauth_at` to mark stale sessions after email/MFA change.
- **Framework middleware:** Express and Fastify verification middleware with typed `auth` context.
- **Strong typing:** Predictable request/response shapes across generation, rotation, and verification.

---

## Support Matrix

| Area | Current Support |
| --- | --- |
| Runtime | Node.js 18+ |
| Language | TypeScript, JavaScript |
| Module output | CommonJS |
| Signing algorithms | HS256, HS512, RS256, ES256 |
| HTTP frameworks | Express, Fastify |
| Core flows | Issue, Verify, Rotate, Revoke, Terminate |

---

## Installation

```bash
npm install @restingowlorg/ossec-cryptography
```

---

## Quick Start

```ts
import { createTokenManager } from "@restingowlorg/ossec-cryptography";

const tokenManager = createTokenManager({
  algorithm: "HS256",
  hmacSecret: process.env.JWT_SECRET!,
  expiresInSeconds: 900,
  refreshTokenEnabled: true,
  refreshTokenExpiresInSeconds: 60 * 60 * 24 * 7,
});

const issued = await tokenManager.generateAccessToken(
  { sub: "user-123", role: "admin" },
  { reauthAt: Math.floor(Date.now() / 1000) },
);

const verified = await tokenManager.verify(issued.token, { purpose: "access" });
console.log(verified.payload.sub); // "user-123"
```

---

## Core API

### 1) Generate Access Token

```ts
const result = await tokenManager.generateAccessToken(
  { sub: "user-123", role: "admin" },
  {
    nbfOffsetSeconds: 0,
    reauthAt: Math.floor(Date.now() / 1000),
  },
);

// result.token
// result.claims
// result.refreshToken (if refreshTokenEnabled)
// result.refreshClaims (if refreshTokenEnabled)
```

### 2) Generate Access + Reference Token

```ts
const result = await tokenManager.generate({ sub: "user-123" });
// result.token + result.referenceToken
```

### 3) Verify Token

```ts
const auth = await tokenManager.verify(token, {
  purpose: "access",
  audience: "my-api",
  trustedIssuers: ["https://issuer.example"],
});
```

### 4) Rotate Refresh Token

```ts
const rotated = await tokenManager.rotate(refreshToken);

// OAuth-compatible response payload:
// rotated.oauth = {
//   access_token,
//   token_type: "Bearer",
//   expires_in,
//   refresh_token
// }
```

### 5) Revoke / Terminate Sessions

```ts
// Revoke using token (logout endpoint style)
await tokenManager.revokeToken(refreshToken, { purpose: "refresh" });

// Revoke using claims/jti
await tokenManager.terminate({ jti: "session-jti" });
```

---

## Express Example

```ts
import express from "express";
import {
  createTokenManager,
  expressVerifyToken,
} from "@restingowlorg/ossec-cryptography";

const app = express();
app.use(express.json());

const manager = createTokenManager({
  algorithm: "HS256",
  hmacSecret: process.env.JWT_SECRET!,
  expiresInSeconds: 900,
});

const requireAccessToken = expressVerifyToken(manager, { purpose: "access" });

app.get("/api/me", requireAccessToken, (req, res) => {
  res.json({
    sub: req.auth?.payload.sub,
    jti: req.auth?.jti,
  });
});
```

---

## Fastify Example

```ts
import Fastify from "fastify";
import {
  createTokenManager,
  fastifyVerifyToken,
} from "@restingowlorg/ossec-cryptography";

const app = Fastify();

const manager = createTokenManager({
  algorithm: "HS256",
  hmacSecret: process.env.JWT_SECRET!,
  expiresInSeconds: 900,
});

const requireAccessToken = fastifyVerifyToken(manager, { purpose: "access" });

app.get("/api/me", { preHandler: requireAccessToken }, async (request) => {
  return {
    sub: request.auth?.payload.sub,
    jti: request.auth?.jti,
  };
});
```

---

## Configuration Options

### Core `TokenConfig`

| Option | Type | Purpose |
| --- | --- | --- |
| `algorithm` | `SigningAlgorithm` | Select JWT signing algorithm (`HS*`, `RS256`, `ES256`) |
| `hmacSecret` | `string` | Shared secret for symmetric signing (`HS*`) |
| `signingKey` | key material | Private/public key material for asymmetric signing |
| `expiresInSeconds` | `number` | Access token expiration offset |
| `refreshTokenEnabled` | `boolean` | Enable refresh token issuance |
| `refreshTokenExpiresInSeconds` | `number` | Refresh token expiration offset |
| `payloadCipher` | `PayloadCipher` | Optional payload encryption before signing |
| `onRefreshTokenIssued` | hook | Persist refresh session metadata |
| `consumeRefreshToken` | hook | One-time refresh-token consumption check |
| `onSessionTerminate` | hook | Session revocation / cutoff persistence |
| `isSessionRevoked` | hook | Per-token revocation check at verification |
| `getTokensInvalidBefore` | hook | Reject tokens with `iat` before user cutoff |
| `requireReauthAtClaim` | `boolean` | Require `reauth_at` freshness marker |
| `getMinimumReauthAt` | hook | Reject stale tokens with low `reauth_at` |

### Verification Options (`verify`)

| Option | Type | Purpose |
| --- | --- | --- |
| `purpose` | `"access" \| "id" \| "refresh"` | Enforce token intent |
| `audience` | `string \| string[]` | Override audience check |
| `trustedIssuers` | `string[]` | Override issuer allowlist |
| `clockToleranceSeconds` | `number` | Temporal tolerance |
| `requireTemporalClaims` | `boolean` | Require `exp` and `nbf` |
| `requireReauthAtClaim` | `boolean` | Require `reauth_at` for this call |
| `minimumReauthAt` | `number` | Per-request reauth freshness cutoff |

---

## Session Revocation and Freshness Patterns

### A) Revoke by `jti`

Persist revoked `jti` values and reject them in `isSessionRevoked`.

### B) Invalidate All Tokens Issued Before Timestamp

Use `getTokensInvalidBefore(sub)` to reject any token where `iat < cutoff`.

### C) Enforce Reauthentication Freshness (`reauth_at`)

When sensitive account data changes (email, MFA, recovery methods), bump a minimum freshness timestamp and reject any token with stale `reauth_at`.

```ts
const minimumReauthAtBySub = new Map<string, number>();

const manager = createTokenManager({
  algorithm: "HS256",
  hmacSecret: process.env.JWT_SECRET!,
  expiresInSeconds: 900,
  getMinimumReauthAt: async (sub) => minimumReauthAtBySub.get(sub),
});

// On email change / MFA change:
minimumReauthAtBySub.set("user-123", Math.floor(Date.now() / 1000));
```

---

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

---

## Error Model

The package exports typed errors for robust handling:

- `TokenGenerationError`
- `TokenVerificationError`
- `SecurityConfigurationError`
- `UntrustedKeySourceError`

Typical pattern:

```ts
try {
  await manager.verify(token, { purpose: "access" });
} catch (error) {
  if (error instanceof TokenVerificationError) {
    // return 401
  }
  throw error;
}
```

---

## OWASP Alignment (Practical)

This library is built around secure defaults and fail-shut behavior for token handling:

- Signature-first verification before trust
- Strong algorithm controls and allowlists
- Strict issuer/audience/temporal checks
- Purpose checks (`access` vs `id` vs `refresh`)
- Replay-resistant refresh rotation via one-time consumption hook
- Server-controlled revocation and freshness invalidation paths

It is **not** an OWASP certification and does not replace full application controls.

---

## Security Notes

You still need to implement:

- TLS / secure transport
- secure key storage / rotation
- brute-force protection and rate limits
- CSRF protections where applicable
- account recovery hardening
- role/authorization enforcement

---

## Development

```bash
npm run test
npm run typecheck
npm run build
```

---

## License

MIT
