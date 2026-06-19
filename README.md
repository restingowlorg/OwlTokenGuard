# OwlTokenGuard

[![npm version](https://img.shields.io/npm/v/@restingowlorg/owltokenguard.svg)](https://www.npmjs.com/package/@restingowlorg/owltokenguard)
[![CI](https://github.com/restingowlorg/OwlTokenGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/restingowlorg/OwlTokenGuard/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/@restingowlorg/owltokenguard.svg)](./LICENSE)

Open-source OWASP-aligned token and session security library for Node.js.

`@restingowlorg/owltokenguard` gives your backend a focused authentication-token surface:
access token issuance, refresh-token rotation, token verification, middleware integration, session revocation, and freshness controls for account-security events (email / MFA changes).

- **Package:** `@restingowlorg/owltokenguard`
- **Install:** `npm install @restingowlorg/owltokenguard`
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

| Area               | Current Support                          |
| ------------------ | ---------------------------------------- |
| Runtime            | Node.js 18+                              |
| Language           | TypeScript, JavaScript                   |
| Module output      | CommonJS                                 |
| Signing algorithms | HS256, HS512, RS256, ES256               |
| HTTP frameworks    | Express, Fastify                         |
| Core flows         | Issue, Verify, Rotate, Revoke, Terminate |

---

## Installation

```bash
npm install @restingowlorg/owltokenguard
```

---

## Quick Start

```ts
import { createTokenManager } from "@restingowlorg/owltokenguard";

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
} from "@restingowlorg/owltokenguard";

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
} from "@restingowlorg/owltokenguard";

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

| Option                         | Type               | Purpose                                                |
| ------------------------------ | ------------------ | ------------------------------------------------------ |
| `algorithm`                    | `SigningAlgorithm` | Select JWT signing algorithm (`HS*`, `RS256`, `ES256`) |
| `hmacSecret`                   | `string`           | Shared secret for symmetric signing (`HS*`)            |
| `signingKey`                   | key material       | Private/public key material for asymmetric signing     |
| `expiresInSeconds`             | `number`           | Access token expiration offset                         |
| `refreshTokenEnabled`          | `boolean`          | Enable refresh token issuance                          |
| `refreshTokenExpiresInSeconds` | `number`           | Refresh token expiration offset                        |
| `payloadCipher`                | `PayloadCipher`    | Optional payload encryption before signing             |
| `onRefreshTokenIssued`         | hook               | Persist refresh session metadata                       |
| `consumeRefreshToken`          | hook               | One-time refresh-token consumption check               |
| `onSessionTerminate`           | hook               | Session revocation / cutoff persistence                |
| `isSessionRevoked`             | hook               | Per-token revocation check at verification             |
| `getTokensInvalidBefore`       | hook               | Reject tokens with `iat` before user cutoff            |
| `requireReauthAtClaim`         | `boolean`          | Require `reauth_at` freshness marker                   |
| `getMinimumReauthAt`           | hook               | Reject stale tokens with low `reauth_at`               |

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
npm install
npm run format        # Prettier write
npm run format:check  # Prettier check (CI gate)
npm run typecheck
npm run build
npm run test
npm run release:validate   # all gates in one command
```

Git hooks (Husky) enforce commit messages (Conventional Commits), secret
scanning, formatting, type safety, and push-time validation. See
[`docs/DEVELOPER_GUIDE.md`](./docs/DEVELOPER_GUIDE.md).

---

## Deployment & Releases

Releases use [Changesets](https://github.com/changesets/changesets) with a
three-branch model and npm trusted publishing (OIDC).

| Branch    | Role                  | npm dist-tag |
| --------- | --------------------- | ------------ |
| `develop` | Integration           | -            |
| `staging` | Prerelease validation | `next`       |
| `main`    | Stable releases       | `latest`     |

Record a user-facing change:

```bash
npm run changeset
```

Then follow the release flow:

- Quick checklist: [`docs/RELEASE_DAY_RUNBOOK.md`](./docs/RELEASE_DAY_RUNBOOK.md)
- Full process: [`docs/DETAILED_RELEASE_SYNC_RUNBOOK.md`](./docs/DETAILED_RELEASE_SYNC_RUNBOOK.md)

Automation:

- `CI` — format check, type check, build, tests on every PR
- `Security` — secret scan + dependency audit
- `CodeQL` — static analysis
- `Release` — prerelease (`next`) from `staging`, stable (`latest`) from `main`

Publishing uses npm trusted publishing, so no `NPM_TOKEN` / `NODE_AUTH_TOKEN`
secrets are required. The publish step needs Node 22.14.0+.

---

## License

MIT © Resting Owl
