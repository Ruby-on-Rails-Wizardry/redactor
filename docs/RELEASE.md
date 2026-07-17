# Release process

How to cut a version of **redactor**. Default branch is **`master`**.

A release is **not done** until the GitHub Release exists for the tag.

## Agent / human trigger phrases

When the user says any of the following, run this process **end-to-end** (do not stop after commit or push alone):

| Phrase | Action |
|--------|--------|
| **send it** | Full release checklist below |
| **ship it** | Same |
| **cut a release** | Same |

```text
test → changelog → version → docs → commit → tag → push master + tag → gh release create → CI green
```

## Preconditions

- [ ] Working tree clean (`git status`)
- [ ] On `master`, up to date with `origin/master` (or intentionally ahead)
- [ ] `mise run test` passes locally (coverage ≥ 90%)
- [ ] [TODO.md](../TODO.md) / [CHANGELOG.md](../CHANGELOG.md) `[Unreleased]` reflect what is shipping
- [ ] Version strings agree:
  - `pyproject.toml` → `project.version`
  - `redactor/__init__.py` → `__version__`
  - `redact version` prints the same value after install
- [ ] [`gh`](https://cli.github.com/) is installed and authenticated (`gh auth status`)
  - Needs `repo` scope and write access to `Ruby-on-Rails-Wizardry/redactor`

## Checklist

### 1. Stabilize

```bash
mise run test
# optional: mise run install-cli   # refresh local global CLI
```

Fix failures before proceeding.

### 2. Changelog

In [CHANGELOG.md](../CHANGELOG.md):

1. Move bullets from **`[Unreleased]`** into a new section:

   ```markdown
   ## [X.Y.Z] - YYYY-MM-DD
   ```

2. Leave empty **`[Unreleased]`** stubs (`Added` / `Changed` / `Fixed` / `Security`).

3. Update compare links at the bottom:

   ```markdown
   [Unreleased]: https://github.com/Ruby-on-Rails-Wizardry/redactor/compare/vX.Y.Z...HEAD
   [X.Y.Z]: https://github.com/Ruby-on-Rails-Wizardry/redactor/compare/vPREV...vX.Y.Z
   ```

### 3. Version bump

Set **X.Y.Z** consistently (semver):

| Change type | Bump |
|-------------|------|
| Breaking CLI/API | MAJOR |
| New features (patterns, flags, commands) | MINOR |
| Fixes / docs / tests only | PATCH |

Files:

- `pyproject.toml` — `version = "X.Y.Z"`
- `redactor/__init__.py` — `__version__ = "X.Y.Z"`

### 4. Docs sanity

- [ ] README behavior tables match new flags/patterns
- [ ] AGENTS.md contracts still accurate
- [ ] TODO.md checkboxes updated for shipped items
- [ ] `redact help` / `unredact -h` still sensible (epilog/examples)
- [ ] This file still matches how you actually release

### 5. Commit

```bash
git add -A
git status   # review; no redacted/dictionary secrets
git commit -m "Release X.Y.Z

<summary of user-visible changes>"
```

### 6. Tag

Annotated tag required:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z — short summary"
```

### 7. Push branch and tag

```bash
git push origin master
git push origin vX.Y.Z
```

### 8. Create the GitHub Release (**required**)

Publish notes from the changelog section for this version. Prefer extracting just that section:

```bash
# Extract notes between ## [X.Y.Z] and the next ## heading
awk '/^## \[X.Y.Z\]/{flag=1; next} /^## \[/{flag=0} flag' CHANGELOG.md > /tmp/release-notes.md

gh release create vX.Y.Z \
  --repo Ruby-on-Rails-Wizardry/redactor \
  --title "vX.Y.Z" \
  --notes-file /tmp/release-notes.md \
  --verify-tag
```

If the tag already exists on the remote but the release was skipped:

```bash
gh release create vX.Y.Z \
  --repo Ruby-on-Rails-Wizardry/redactor \
  --title "vX.Y.Z" \
  --notes-file /tmp/release-notes.md \
  --verify-tag
```

To replace notes on an existing release:

```bash
gh release edit vX.Y.Z --notes-file /tmp/release-notes.md
```

Confirm:

```bash
gh release view vX.Y.Z --repo Ruby-on-Rails-Wizardry/redactor
```

### 9. Verify CI

- GitHub Actions on the release commit/tag is green
- Release page shows correct notes:  
  https://github.com/Ruby-on-Rails-Wizardry/redactor/releases

### 10. Post-release

- [ ] `gh release list` shows `vX.Y.Z`
- [ ] New work goes under `[Unreleased]` again
- Optionally bump to the next development version only when you start that cycle

## What not to ship in a release commit

- Real secrets, `redacted/dictionary.yaml`, local `.venv/`
- Unrelated large refactors without changelog bullets
- Broken tests or coverage below the gate

## Quick one-liner reminder

```text
test → changelog → version → docs → commit → tag → push master + tag → gh release create → CI green
```

(Also the definition of **send it** / **ship it** / **cut a release**.)
