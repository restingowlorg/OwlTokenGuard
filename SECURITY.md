# Security Policy

This is a token management library. Security bugs here can affect every
application that trusts issued or verified tokens, so we take reports seriously
and move fast on them.

**Do not open a public issue for a vulnerability.**

## Supported Versions

We apply security fixes to the current stable release (`latest`). Backports are
case-by-case. Severe token forgery, validation bypass, or key-confusion issues
may receive an out-of-band patch.

If you are using the `next` prerelease channel, include the exact prerelease
version in your report.

## Reporting a Vulnerability

Contact the maintainers directly through a private channel. If GitHub private
vulnerability reporting is enabled for the repository, use that. Otherwise,
email the Resting Owl maintainers through the private security contact published
by the organization.

When you report, include:

- What the issue is and where you found it.
- Which version or commit is affected.
- Your environment, including Node.js version and runtime framework.
- Steps to reproduce or a proof of concept.
- Expected impact, such as token forgery, token replay, authorization bypass,
  key confusion, payload disclosure, or denial of service.
- Any suggested fix, if you have one.

## Response Targets

| Severity | Acknowledgement | Triage   | Fix Target                   |
| -------- | --------------- | -------- | ---------------------------- |
| Critical | 24 hours        | 72 hours | Out-of-band patch ASAP       |
| High     | 2 business days | 5 days   | Next patch release or sooner |
| Medium   | 3 business days | 10 days  | Next scheduled release       |
| Low      | 5 business days | 15 days  | Best-effort, normal roadmap  |

These are targets, not service-level agreements. Maintainers will communicate
when a fix or coordinated disclosure needs more time.

## What Happens After You Report

1. We confirm receipt privately.
2. We validate impact and affected versions.
3. We prepare and test a fix privately.
4. We publish a patched release.
5. We publish disclosure and remediation guidance when appropriate.

## In Scope

- JWT signature verification bypasses.
- Algorithm allowlist or key-confusion failures.
- Acceptance of wrong-purpose tokens.
- Weak secret or key validation bypasses.
- Payload encryption or token digest flaws.
- Middleware behavior that leaks sensitive verification details.

## Out of Scope

- Bugs in unsupported or end-of-life versions.
- Application authorization logic outside this library.
- Session lifecycle storage bugs owned by OwlSessionGuard or the consuming
  application.
- Non-security bugs with no realistic security impact.

## Security Architecture

For the technical security boundary, threat model assumptions, control mapping,
and operational limits of this library, see
`docs/SECURITY_MODEL.md`.
