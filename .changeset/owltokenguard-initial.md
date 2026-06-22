---
"@restingowlorg/owltokenguard": minor
---

Establish OwlTokenGuard as the public package identity and add the release
pipeline. Ships access/refresh token issuance, refresh token rotation (RTR)
with OAuth-style responses, fail-shut verification, opaque reference tokens,
session revocation (`terminate`/`revokeToken`), timestamp-based invalidation,
and `reauth_at` freshness enforcement, plus Express and Fastify middleware.
