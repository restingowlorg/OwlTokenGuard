# Release Day Runbook

A short operator checklist for releasing `@restingowlorg/owltokenguard`.

The detailed process and rationale live in
`docs/DETAILED_RELEASE_SYNC_RUNBOOK.md`. This page is the fast checklist.

## Branch and Dist-Tag Model

| Branch    | Role                  | npm dist-tag |
| --------- | --------------------- | ------------ |
| `develop` | Integration           | -            |
| `staging` | Prerelease validation | `next`       |
| `main`    | Stable releases       | `latest`     |

## Staging Phase (prerelease -> `next`)

1. Open and merge `develop` -> `staging`.
2. In GitHub Actions, run **Release** on `staging` with `release_mode=prerelease`.
3. Verify the prerelease:

   ```bash
   npm view @restingowlorg/owltokenguard dist-tags
   npm i @restingowlorg/owltokenguard@next
   node -e 'require("@restingowlorg/owltokenguard"); console.log("next OK")'
   ```

## Release Phase (stable -> `latest`)

1. Open and merge `staging` -> `main`.
2. The Release workflow on `main` opens a `changeset-release/main` bot PR.
3. Review and merge the bot PR. This publishes the stable version to npm `latest`
   and creates a GitHub Release.
4. Verify:

   ```bash
   npm view @restingowlorg/owltokenguard dist-tags
   npm i @restingowlorg/owltokenguard@latest
   node -e 'require("@restingowlorg/owltokenguard"); console.log("latest OK")'
   ```

## Post-Release Sync (required)

1. Open and merge `main` -> `develop` to sync version metadata, changelog, and
   consumed changesets.
2. Optionally remove a stale `next` tag once stable ships:

   ```bash
   npm dist-tag rm @restingowlorg/owltokenguard next
   ```

## Failure Handling

- Prerelease published nothing: branch baselines are stale. Sync `main` -> `develop`
  -> `staging`, then rerun the prerelease.
- Stable not on `latest`: confirm `staging` -> `main` merged and the bot PR merged.
- Auth: this repo uses npm trusted publishing (OIDC). Do not add `NPM_TOKEN`
  or `NODE_AUTH_TOKEN` secrets.
