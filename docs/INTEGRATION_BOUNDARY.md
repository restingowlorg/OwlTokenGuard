# Integration Boundary

owltokenguard is the token management library. It owns token-level cryptography
for Node.js applications. It signs, verifies, and optionally encrypts JWT
payloads; stamps registered claims such as `iss` and `aud`; enforces token
purpose; and generates opaque reference-token values.

OwlSessionGuard is the session management library. Keep session records, durable
refresh-token rotation state, idle timeout, absolute session lifetime, device
binding, revoke-all behavior, breach response, and storage adapters in that
package.

## Refresh Tokens

This package can issue and verify refresh JWTs. It also exposes integration
hooks:

- `onRefreshTokenIssued` to persist a newly issued refresh-token identifier.
- `consumeRefreshToken` to atomically mark a refresh token as used during
  rotation.
- `onSessionTerminate` to notify the application that a token/session identifier
  should be removed or invalidated.

Those hooks are intentionally storage-agnostic. Production applications should
wire them to OwlSessionGuard or to an application-owned session store. The
cryptography package must not be treated as the durable source of truth for
active sessions.

## Responsibility Split

Cryptography library responsibilities:

- Sign access, ID-style, and refresh JWTs with approved algorithms.
- Verify signatures, algorithms, issuer, audience, temporal claims, freshness,
  and token purpose.
- Keep encrypted application payloads confidential while leaving security
  claims such as `iss`, `aud`, `exp`, `nbf`, `iat`, `jti`, and `token_use`
  available for verification.
- Generate high-entropy opaque reference values and token digests when exposed
  by this package.

Session-management library responsibilities:

- Store active session and refresh-token records.
- Enforce idle timeout and absolute session lifetime.
- Detect and respond to refresh-token replay.
- Implement logout, logout-all-devices, admin termination, and breach response.
- Bind sessions to devices, clients, or risk signals where required.
