# Developer Guide

## Purpose

This project (`@restingowlorg/owltokenguard`) uses Git hooks to enforce commit
quality, code formatting, type safety, and push-time validation.

Hook management is implemented with Husky and follows Conventional Commits.

## Prerequisites

- Node.js 18+
- npm 9+
- Git

## One-Time Setup

```bash
npm install
npm run prepare
chmod +x .husky/commit-msg .husky/pre-commit .husky/pre-push
```

## Commit Message Standard

Use Conventional Commits:

```text
type(scope): description
```

Examples:

- `feat(core): add refresh token rotation`
- `fix(core): prevent reuse of consumed refresh token`
- `docs(docs): update usage examples`

Allowed types:

- `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`, `build`, `revert`

Allowed scopes:

- `api`, `db`, `ci`, `core`, `infra`, `config`, `test`, `common`, `docs`

Rules:

- Header length: 10 to 100 characters
- Body lines: max 100 characters
- Subject starts lowercase
- No period at the end

## Hook Behavior

### `commit-msg`

- Runs `commitlint`
- Blocks invalid commit messages

### `pre-commit`

Runs these checks in order:

1. Secret scan (`secretlint`)
2. File size check (max 5MB)
3. Package lock consistency (`npm ls`)
4. `lint-staged` (Prettier formatting on staged files)
5. Incremental TypeScript check (`tsc --noEmit --incremental`)

### `pre-push`

Runs these checks:

1. Blocks direct push to `develop`, `staging`, and `main`
2. Runs `npm run typecheck` and `npm run build` in parallel
3. Runs the test suite
4. Runs production security audit (`npm audit --omit=dev`)

In CI (`CI` or `GITHUB_ACTIONS`), critical vulnerabilities block push.

## Git Branching

Three-tier flow for all development work:

1. Create a feature branch from `develop`
2. Make commits on your feature branch
3. Push the feature branch and open a PR to `develop`
4. After merge to `develop` and validation in `staging`, the release workflow promotes `staging` -> `main`

Protected branches (no direct push):

- `develop` (integration branch, where feature PRs merge first)
- `staging` (validation branch, updated from develop at release time)
- `main` (stable releases only, updated via release workflow)

## Useful Commands

```bash
npm run typecheck
npm run build
npm run test
npm run format
npm run format:check
```

Before opening a PR:

```bash
npm run release:validate
```

For user-facing changes:

```bash
npm run changeset
```

## Troubleshooting

### Hooks not running

```bash
npm run prepare
git config core.hooksPath
```

### Commit message rejected

Use `type(scope): description` with an allowed type and scope.

### Push blocked on protected branch

Use feature branches and open a pull request. Do not push directly to
`develop`, `staging`, or `main`.

### Emergency bypass (local only)

```bash
SKIP_HOOKS=true git commit -m "chore(core): emergency hotfix"
SKIP_HOOKS=true git push
```

## Release Branches

- `develop`: integration branch where all feature PRs merge.
- `staging`: validation branch. Publishes prerelease builds to the npm `next` tag.
- `main`: stable release branch. Publishes to npm `latest` via the release workflow.

For the full release flow, see `docs/RELEASE_DAY_RUNBOOK.md` and
`docs/DETAILED_RELEASE_SYNC_RUNBOOK.md`.

## Team Rules

- Keep commits small and focused
- Do not commit secrets
- Keep files under 5MB
- Do not push directly to `develop`, `staging`, or `main`
- Run `npm run release:validate` locally before opening a PR
- Include a changeset for any user-facing changes
