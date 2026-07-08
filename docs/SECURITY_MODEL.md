# Security Model

This document defines the technical security model for
`@restingowlorg/owltokenguard`.

It is separate from `SECURITY.md`:

- `SECURITY.md` covers vulnerability reporting, response targets, and
  disclosure workflow.
- This document covers trust boundaries, technical controls, assumptions,
  and limits.

## Purpose

OwlTokenGuard is the token security component in the Resting Owl library set.
Its responsibility is token cryptography and token verification behavior for
Node.js applications.

## Security Goals

- Issue signed access and refresh JWTs using approved algorithms.
- Verify signatures before trusting payload claims.
- Prevent algorithm downgrade and key-confusion classes of failures.
- Enforce token intent with explicit purpose checks.
- Support refresh-token rotation and termination integration points.
- Support optional payload encryption with authenticated ciphering.
- Provide digest helpers so integrations avoid storing raw bearer tokens.

## Non-Goals

- User authentication flows (password, magic-link, MFA, recovery).
- Application authorization and role-policy decisions.
- Durable session storage and device/session lifecycle policy.
- Transport security controls such as TLS termination and network policy.
- Key-management infrastructure (HSM, KMS lifecycle automation, JWKS ops).

## Trust Boundaries

Trusted inputs at startup:

- Key material and algorithm selection.
- Issuer and audience policy configuration.
- Verification allowlists and hook implementations.

Untrusted runtime inputs:

- Incoming JWTs and token headers.
- Request authorization headers.
- Claims from client-controlled tokens before verification.
- Any remote-key references supplied by token headers.

Rule: claims are not trusted until signature and configured verification checks
complete successfully.

## Threats and Controls

| Threat                                | Library Control                                             | Integrator Responsibility                                |
| ------------------------------------- | ----------------------------------------------------------- | -------------------------------------------------------- |
| Token tampering                       | Signature-first verification and strict parsing             | Never consume unverified token payloads                  |
| Algorithm downgrade                   | Verification allowlist and explicit `none` rejection        | Configure only required algorithms                       |
| Key confusion                         | Symmetric and asymmetric key-path separation                | Keep key classes isolated in config and storage          |
| Weak key material                     | Runtime validation of HS/RS/ES key requirements             | Rotate secrets/keys and store in secure secret manager   |
| Wrong token usage                     | Purpose enforcement (`access`, `id`, `refresh`)             | Apply route-level purpose policy consistently            |
| Refresh replay                        | Rotation hooks with one-time consumption integration points | Persist rotation state atomically in session store       |
| Session continuation after risk event | Revocation and cutoff integration hooks                     | Implement revoke-all, cutoff, and breach response policy |
| Sensitive payload disclosure          | Optional AES-256-GCM payload cipher support                 | Protect encryption keys and avoid token overexposure     |
| Error probing                         | Generic middleware auth failure mode                        | Keep detailed diagnostics in private logs only           |

## OWASP Alignment

The model is aligned to OWASP JWT and session-management guidance through these
enforced behaviors:

- Signature validation before claim trust.
- Strict algorithm allowlisting and `none` rejection.
- Temporal checks (`exp`, `nbf`, `iat`) and size limits.
- Issuer and audience validation support.
- Token-purpose separation.
- Revocation and refresh-rotation integration hooks.

Alignment indicates design intent and implemented controls. It is not a formal
certification.

## Integration Boundary With OwlSessionGuard

OwlTokenGuard owns token-level cryptography and verification.

OwlSessionGuard (or an application-owned equivalent) should own:

- Session record persistence.
- Refresh-token rotation state.
- Replay detection response.
- Idle and absolute session lifetime.
- Administrative revoke-all and device/session policy.

Recommended pattern: store token digests instead of raw token values in durable
stores.

## Operational Assumptions

- Production traffic uses HTTPS.
- Secrets and signing keys are stored outside source control.
- Key rotation and incident response processes exist.
- Access token lifetime is short relative to refresh lifetime.
- Hook implementations are treated as security-critical code.

## Known Limits

- Sender-constrained token features (for example DPoP) are not implemented.
- Advanced authentication-context claim helpers (`auth_time`, `acr`, `amr`)
  are not yet first-class verification primitives.
- Security posture depends on integration quality for session storage and
  revocation workflows.
