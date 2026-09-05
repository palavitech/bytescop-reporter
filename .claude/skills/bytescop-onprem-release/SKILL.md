---
name: bytescop-onprem-release
description: Create a new BytesCop-Reporter on-prem release — calculates next version, updates VERSION and CHANGELOG, tags, and pushes.
argument-hint: "[patch|minor|major] or [specific version like 1.2.0]"
---

# BytesCop-Reporter On-Prem Release

You are orchestrating a release for the BytesCop-Reporter on-premises product.

## Step 1: Gather current state

- Read the current version from the `VERSION` file at the repo root
- Run `git tag -l 'v*' --sort=-version:refname` to list existing tags
- Run `git branch --show-current` to confirm the current branch
- Run `git status --porcelain` to check for uncommitted changes

## Step 2: Calculate next version

Parse the current version as MAJOR.MINOR.PATCH (semver).

If the user provided an argument (`$ARGUMENTS`):
- `patch` → increment PATCH (e.g., 1.0.0 → 1.0.1)
- `minor` → increment MINOR, reset PATCH (e.g., 1.0.1 → 1.1.0)
- `major` → increment MAJOR, reset MINOR and PATCH (e.g., 1.2.3 → 2.0.0)
- A specific version like `1.2.0` → use it directly (validate it's valid semver and greater than current)

If no argument was provided, default to `patch`.

## Step 3: Confirm with the user

Present:
- Current version: vX.Y.Z
- Next version: vX.Y.Z
- Branch: (current branch)
- Uncommitted changes: yes/no (if yes, warn and ask if they want to proceed)

Ask the user: **"Release vX.Y.Z? (yes/no)"**

Do NOT proceed without explicit confirmation.

## Step 4: Generate changelog entry

Run `git log` from the last tag (or all commits if no previous tag) to HEAD with format `--pretty=format:"- %s (%h)"`.

Ask the user if they want to edit/add to the changelog entry, or if the auto-generated one is fine.

## Step 5: Execute the release

1. Update `VERSION` file with the new version (just the number, no `v` prefix, with a trailing newline)
2. Update `CHANGELOG.md` — add a new `## [X.Y.Z] - YYYY-MM-DD` section at the top (below the header), with the changelog entries
3. Update `ui/src/assets/version.json` with `{"version": "X.Y.Z"}`
4. Stage the changed files: `git add VERSION CHANGELOG.md ui/src/assets/version.json`
5. Commit with message: `Release vX.Y.Z`
6. Create the tag: `git tag vX.Y.Z`

## Step 6: Push

Ask the user: **"Push the tag and commit to origin? This will trigger the GitHub Actions release workflow."**

If yes:
- `git push origin HEAD`
- `git push origin vX.Y.Z`

Show the user the GitHub releases URL: `https://github.com/palavitech/bytescop/releases`

## Important rules

- NEVER skip the confirmation steps
- NEVER force-push
- If there are uncommitted changes, warn but let the user decide
- If the tag already exists, abort and tell the user
- Always show what you're about to do before doing it
- Always merge `development` into `main` before tagging. The tag must be on `main`.
- After tagging, switch back to the `development` branch so the user continues work there
