# Detailed Release Sync Runbook

This runbook documents the full release flow for `@restingowlorg/owltokenguard`
when using long-lived `develop`, `staging`, and `main` branches together with
Changesets and npm trusted publishing.

It also covers the release-state sync step that must happen after a stable
release reaches `main`.

## Why This Runbook Exists

This repo uses:

- `develop` for ongoing integration work
- `staging` for prerelease validation and the npm `next` dist-tag
- `main` for stable releases and the npm `latest` dist-tag

Changesets creates release metadata on the branch being prepared for
publication. After a stable release lands on `main`, that branch can contain
release-only commits that do not automatically flow back to `develop`:

- version bumps
- changelog updates
- consumed changeset removals
- release PR merge commits

If `main` is not synced back into `develop`, the next prerelease can be cut from
the wrong baseline, causing Changesets to reuse an already-published version.

## Release Model

The expected branch flow is:

1. feature branch -> `develop`
2. `develop` -> `staging`
3. prerelease from `staging` -> npm `next`
4. `staging` -> `main`
5. Changesets release PR -> `main`
6. stable publish from `main` -> npm `latest`
7. `main` -> `develop` sync after stable release

## Standard Release Cycle

### Step 1: Merge feature work into develop

Open a PR from your feature branch to `develop`.

Requirements:

1. CI passes
2. Security workflow passes
3. User-facing changes include a changeset (`npm run changeset`)
4. Docs are updated if needed

### Step 2: Promote develop to staging

Open a PR from `develop` to `staging`.

Recommended PR title:

```text
chore(release): promote develop to staging for next release candidate
```

### Step 3: Trigger prerelease from staging

In GitHub Actions:

1. Open `Actions`
2. Select `Release`
3. Click `Run workflow`
4. Choose branch `staging`
5. Set `release_mode` to `prerelease`

Verify:

```bash
npm view @restingowlorg/owltokenguard dist-tags
npm view @restingowlorg/owltokenguard versions --json
```

Expected: `next` advances; `latest` is unchanged.

### Step 4: Validate the prerelease

```bash
mkdir -p /tmp/owltokenguard-next-check
cd /tmp/owltokenguard-next-check
npm init -y
npm i @restingowlorg/owltokenguard@next
node -e 'require("@restingowlorg/owltokenguard"); console.log("next install OK")'
```

### Step 5: Promote staging to main

Open a PR from `staging` to `main`.

Recommended PR title:

```text
chore(release): promote validated release candidate from staging to main
```

### Step 6: Merge the Changesets release PR

After `staging` merges into `main`, the Release workflow opens a bot PR from
`changeset-release/main`. Merge it. This publishes the stable version to npm
`latest`.

### Step 7: Verify the stable release

```bash
npm view @restingowlorg/owltokenguard dist-tags
npm view @restingowlorg/owltokenguard version
```

Then a clean install:

```bash
mkdir -p /tmp/owltokenguard-latest-check
cd /tmp/owltokenguard-latest-check
npm init -y
npm i @restingowlorg/owltokenguard@latest
node -e 'require("@restingowlorg/owltokenguard"); console.log("latest install OK")'
```

## Required Sync Step After Stable Release

### Step 8: Sync main back into develop

Open a PR from `main` to `develop`.

Recommended PR title:

```text
chore(release): sync main back into develop after stable release
```

Recommended PR description:

```md
## Summary

Syncs the released `main` branch back into `develop` after stable publication.

This brings release metadata back into the development line so future
Changesets-based prereleases and stable releases are cut from the correct
version baseline.

## Release Impact

- Type: patch
- User-facing change: no
- Breaking change: no

## Checklist

- [ ] `npm run release:validate` passes
- [ ] docs updated if needed
- [ ] changeset added for user-facing changes
- [ ] migration notes added for breaking changes
```

Merge this PR before preparing the next prerelease from `staging`.

## Failure Cases

### Prerelease publishes nothing

If prerelease logs say the version is already published, check whether:

1. `develop` and `staging` are behind `main` in release metadata
2. the `main` -> `develop` sync was skipped
3. the branch version baseline is stale

Fix: merge `main` -> `develop`, then `develop` -> `staging`, then rerun.

### npm latest still shows the old version

Check whether:

1. `staging` was merged into `main`
2. the Changesets bot PR was merged into `main`
3. npm `latest` advanced to the new stable version

## Authentication

This repo uses npm trusted publishing (OIDC). The release workflow clears
`NODE_AUTH_TOKEN` and `NPM_TOKEN`. Do not configure those secrets. The publish
step requires Node 22.14.0 or later.

## Recommended Ongoing Practice

1. release from `staging` to `main`
2. merge the Changesets bot PR to publish stable
3. immediately open `main` -> `develop`
4. merge that sync PR before the next release cycle starts
