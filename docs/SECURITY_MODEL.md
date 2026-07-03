# Security Model

`owltokenguard` is the token management library in the Resting Owl package
family. It provides cryptographic token issuance, verification, payload
encryption, token purpose enforcement, middleware verification helpers, and safe
token digest primitives for Node.js applications.

It does not replace application authorization, transport security, user
authentication, or durable session storage. Session lifecycle behavior belongs
to OwlSessionGuard or to the consuming application.

## Security Goals

- Issue signed JWT access and refresh tokens with approved algorithms.
- Verify signatures before trusting payload claims.
- Reject unsupported algorithms and the `none` algorithm.
- Prevent symmetric/asymmetric key confusion.
- Enforce issuer, audience, temporal claims, token purpose, and optional
  freshness checks.
- Keep encrypted application payloads confidential while preserving signed
  security claims needed for verification.
- Provide deterministic token digests so applications can avoid storing raw
  bearer or refresh tokens.
- Return generic public middleware errors by default.

## Non-Goals

- User authentication flows such as password login, magic links, or MFA.
- Application authorization and role decisions after token verification.
- Persistent session storage, device binding, idle timeout, absolute session
  lifetime, replay response, or revoke-all workflows.
- Network transport protection. Applications must still require HTTPS.
- Key management infrastructure, HSM integration, or automated JWKS rotation.

## Trust Boundaries

`owltokenguard` trusts only configuration supplied by the application at
startup: signing keys, HMAC secrets, allowed algorithms, issuer, audience,
trusted key-source domains, and integration callbacks.

Incoming JWTs, request headers, bearer tokens, encrypted payloads, `jku` and
`x5u` headers, and middleware request data are untrusted input. Verification
must fail shut before claims are trusted by application code.

## Threat Model

| Threat                              | Library control                                                                                  | Application responsibility                                     |
| ----------------------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------------------- |
| Token tampering                     | Signature-first verification and strict JWT parsing.                                             | Never trust decoded claims without `verify()`.                 |
| Algorithm downgrade or `none` usage | Algorithm allowlist and explicit `none` rejection.                                               | Configure a narrow `allowedAlgorithms` list.                   |
| Key confusion                       | HMAC algorithms require symmetric keys; RS256/ES256 require asymmetric keys.                     | Keep public and private key material separated.                |
| Weak HMAC secrets                   | HS256/HS512 secrets must be high entropy and at least 64 characters.                             | Store secrets in a secret manager and rotate when needed.      |
| Weak asymmetric keys                | RS256 rejects RSA keys below 2048 bits; ES256 requires P-256.                                    | Generate and rotate keys with approved tooling.                |
| Wrong-token use                     | `purpose` checks separate access, ID-style, and refresh JWTs.                                    | Protect API routes with the expected purpose.                  |
| Bearer token theft                  | Short expirations, purpose checks, token digests, and generic middleware errors reduce exposure. | Use HTTPS, secure storage, CSRF controls, and revocation.      |
| Refresh token replay                | `consumeRefreshToken` integration hook supports atomic one-time use.                             | Store rotation state in OwlSessionGuard or another safe store. |
| Payload disclosure                  | Optional AES-256-GCM payload encryption hides application claims inside `enc`.                   | Protect encryption keys and avoid putting secrets in tokens.   |
| Error probing                       | Middleware responses are generic by default.                                                     | Keep detailed auth failures in logs or private callbacks.      |

## OWASP Mapping

| Area                       | owltokenguard behavior                                                                     | OWASP reference                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------ |
| JWT signature validation   | Verifies signatures before returning trusted payloads.                                     | OWASP JWT Cheat Sheet: validate token integrity.                         |
| Algorithm allowlisting     | Allows only supported configured algorithms and rejects `none`.                            | OWASP JWT Cheat Sheet: prevent none-algorithm and confusion attacks.     |
| Temporal validation        | Enforces `exp`, `nbf`, `iat`, clock tolerance, and max token size.                         | OWASP JWT Cheat Sheet: validate registered claims and input size.        |
| Issuer and audience        | Supports configured `iss`, `aud`, `trustedIssuers`, and per-call audience overrides.       | OWASP JWT Cheat Sheet: validate expected issuer and audience.            |
| Token purpose separation   | Rejects refresh or ID-style tokens when access tokens are required.                        | OWASP ASVS token validation and OAuth/OIDC token use separation.         |
| Refresh token rotation     | Provides cryptographic refresh JWTs and integration hooks for one-time rotation state.     | OWASP Session Management Cheat Sheet: detect and respond to token reuse. |
| Server-side invalidation   | Exposes revocation, cutoff, and termination integration hooks.                             | OWASP Session Management Cheat Sheet: server-side session invalidation.  |
| Reauthentication freshness | Supports `reauth_at` stamping and minimum freshness checks after account-security changes. | OWASP ASVS: reauthentication after sensitive events.                     |
| Secret strength            | Validates HMAC entropy and asymmetric key type/strength.                                   | OWASP ASVS cryptographic key strength guidance.                          |
| Safe storage integration   | Provides SHA-256 and peppered HMAC token digest helpers.                                   | OWASP storage guidance: avoid storing raw credentials or bearer secrets. |

## Integration With OwlSessionGuard

Use owltokenguard for token cryptography and verification. Use OwlSessionGuard
for durable session lifecycle state:

- Active session records.
- Refresh-token rotation state.
- Replay detection and breach response.
- Logout-all-devices and administrative termination.
- Idle timeout and absolute session lifetime.
- Device or client binding.

When storing refresh-token records, store a digest created by
`createTokenDigest()` instead of the raw token. Prefer the peppered HMAC form
when the digest is persisted in a database.

## Operational Requirements

- Run on a supported Node.js version tested by CI: 18, 20, or 22.
- Use HTTPS in production.
- Keep private keys, HMAC secrets, and digest peppers in a secret manager.
- Rotate keys and secrets according to your organizational policy.
- Use short access-token lifetimes and persist refresh-token state server-side.
- Treat middleware `req.auth` and `request.auth` as authenticated identity data,
  not as authorization by itself.

## Known Limits

- DPoP sender-constrained tokens are roadmap work.
- `auth_time`, `acr`, and `amr` helper checks are roadmap work.
- Custom JWT implementation remains security-sensitive. Maintainers should
  periodically compare behavior against maintained JOSE libraries and consider
  independent review before major security claims.
