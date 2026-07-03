# Integration Boundary

This document defines the responsibility split between OwlTokenGuard and
OwlSessionGuard.

OwlTokenGuard is responsible for token construction and token validation. It
signs JWTs, verifies JWTs, validates algorithm and key material, stamps and
checks registered claims, enforces token purpose, optionally encrypts application
payloads, and exposes token-safe lookup primitives such as digests.

OwlSessionGuard is responsible for durable session state. It should own session
records, refresh-token rotation state, replay handling, idle timeout, absolute
session lifetime, device binding, logout-all-devices, breach response, and
storage adapters.

The practical rule is simple: OwlTokenGuard can tell whether a token is
cryptographically valid and intended for a purpose. OwlSessionGuard decides
whether the session behind that token is still active.

## Refresh Tokens

OwlTokenGuard may issue and verify refresh JWTs, but it does not store refresh
token state. Refresh-token state must live in OwlSessionGuard or in an
application-owned store.

The refresh integration points are:

- `onRefreshTokenIssued`: called after a refresh JWT is created. Use this to
  persist the refresh token `jti`, expiry, subject, and a token digest if the
  raw token must be looked up later.
- `consumeRefreshToken`: called at the start of rotation. This must perform an
  atomic compare-and-update in the session store so the same refresh token cannot
  be consumed twice.
- `onSessionTerminate`: called when a token/session identifier should be
  invalidated. Use this to delete a session record or persist an invalidation
  cutoff.

These hooks are deliberately storage-agnostic. They are contracts between the
token layer and the session layer, not an in-memory session implementation.

Production integrations should store a digest created by `createTokenDigest()`
instead of storing raw refresh or bearer tokens. Prefer the peppered HMAC digest
form when the digest is persisted in a database.

## Responsibility Split

### OwlTokenGuard owns

- JWT signing for access, ID-style, and refresh tokens.
- JWT verification with signature-first validation.
- Algorithm allowlisting and `none` algorithm rejection.
- Key-material validation for HMAC, RSA, and EC signing modes.
- Registered claim handling for `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`, and
  `token_use`.
- Token purpose enforcement for access, ID-style, and refresh tokens.
- Optional payload encryption while keeping security claims available outside
  `enc`.
- Opaque reference-token generation.
- Token digest generation for safe storage integration.
- Express and Fastify middleware that verifies tokens and attaches the verified
  auth context to the request.

### OwlSessionGuard owns

- Active session records.
- Refresh-token storage and rotation state.
- Atomic refresh-token consume semantics.
- Replay detection and response.
- Idle timeout and absolute session lifetime.
- Logout, logout-all-devices, and administrative termination.
- Device, client, or risk-signal binding.
- Database/cache adapters for session persistence.

## Verification Flow

A typical protected request should follow this sequence:

1. Middleware extracts the bearer token.
2. OwlTokenGuard verifies the token signature, algorithm, issuer, audience,
   temporal claims, and purpose.
3. Application code or OwlSessionGuard checks session state using the verified
   `sub`, `jti`, `iat`, `exp`, and any stored cutoff/revocation records.
4. Application authorization checks roles, permissions, or resource ownership.

Do not use decoded JWT payloads directly for authorization. Only use the result
returned by `verify()` or by framework middleware after successful verification.

## Out of Scope for OwlTokenGuard

The following features should not be implemented inside this package:

- Durable session database tables or cache schemas.
- Built-in Redis, PostgreSQL, MongoDB, or similar session adapters.
- Idle timeout and absolute session lifetime enforcement.
- Refresh-token replay response policy.
- User/device session listing APIs.
- Account recovery, MFA enrollment, or login policy.

Those features belong in OwlSessionGuard or in the consuming application.
