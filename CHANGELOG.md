# @restingowlorg/owltokenguard

## 1.0.0-next.1

### Patch Changes

- ddcb8dd: Update OwlTokenGuard documentation for release readiness.

## 1.0.0-next.0

### Major Changes

- c972d3a: Establish OwlTokenGuard as the public package identity and add the release
  pipeline. Ships access/refresh token issuance, refresh token rotation (RTR)
  with OAuth-style responses, fail-shut verification, opaque reference tokens,
  session revocation (`terminate`/`revokeToken`), timestamp-based invalidation,
  and `reauth_at` freshness enforcement, plus Express and Fastify middleware.

Changelog entries are generated and maintained by Changesets. New versions are
appended here automatically by the release workflow when changesets are
consumed. See `docs/RELEASE_DAY_RUNBOOK.md` for the release process.
