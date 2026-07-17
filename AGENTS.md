# AGENTS.md

Human docs and full behavior table: [README.md](README.md). Keep this file aligned when CLI contracts change.

## Product

| Command | Role |
|---------|------|
| `redact` | Patterns → placeholders → `redacted/<path>` + `dictionary.yaml` |
| `unredact` | Dictionary substitution → original paths |

Package + entry points in `pyproject.toml`. Runtime: `PyYAML`. Tests: pytest, coverage ≥90%. Default branch: **`master`**.

## Layout

```
redactor/
  redact.py      # DEFAULT_PATTERNS, BINARY_EXTENSIONS, DEFAULT_EXCLUDES, CLI
  unredact.py
  paths.py       # ALWAYS_SKIP_DIR_NAMES (includes .git), expand/walk/exclude globs
bin/             # wrappers only
tests/
```

`redacted/` is always under the **caller’s cwd**.

## Contracts (must stay true)

### Patterns (`redacted/patterns.yaml`)

- CLI: `redact patterns init|list|add|remove`
- Missing file → `DEFAULT_PATTERNS` (PEM, JWT, AWSKEY, BEARER, EMAIL, APIKEY, TOKEN, PASSWORD, IP, IP6, GOV)
- Present → that file only; validate with `re.compile`
- Order = application order; shape patterns first; EMAIL before GOV
- Assignment patterns use capturing groups for values; engine uses `extract_match_values`
- `patterns add` without file seeds defaults then sets name

### Allowlist (`redacted/allowlist.yaml`)

- CLI: `redact allowlist init|list|add|remove`
- Missing file → `DEFAULT_ALLOWLIST` (localhost / doc IPs)
- Present → that file only
- Exact string match; filtered in `collect_matches` / `_redact_content`

### Excludes (`redacted/exclude.yaml`)

- CLI: `redact exclude init|list|add|remove` (same shape as patterns)
- Missing file → **no extra globs**, but always-on skips still apply (below)
- `exclude init` → `DEFAULT_EXCLUDES` (includes `GIT` / `GIT_DIR` for `.git/**`, binaries, locks, …)
- `exclude add` without file starts from `{}`

### Always-on skips (even without exclude.yaml)

1. **Dirs:** any path component in `ALWAYS_SKIP_DIR_NAMES` (must include **`.git`**); walk also prunes `redacted/` as a source dir name
2. **Binary:** `BINARY_EXTENSIONS`; NUL-byte heuristic; UTF-8 decode failures
3. Explicit roots named `.git` or `redacted` produce no redact sources

### Redact batch

- Multi-file/dir share one dictionary for the run
- `-e`/`--exclude`, `-i`/`--include` (repeatable globs) combine with exclude.yaml
- `-q`/`--quiet` (summary only), `-v`/`--verbose` (match detail); always print `Summary:`
- `-n` / `--dry-run`: matches only, no writes; labels **NEW** vs **REUSED**
- `--new-only`: skip files with no secrets absent from the dictionary
- Errors → stderr, continue; exit 1 if any error; save dictionary if anything written
- On write: `ensure_redacted_gitignored()`

### Unredact batch

- Args are original paths; content from `redacted/<path>`
- Paste stdin only for a single expanded missing redacted file
- Errors → stderr, continue; exit 1 if any error

## Install / test

```bash
mise run setup
mise run test          # coverage fail_under 90
mise run install-cli   # refresh global tools after entry-point changes
```

CI (GitHub Actions on `master`): `.github/workflows/ci.yml` — install `.[dev]`, pytest+coverage, CLI smoke. Keep that workflow aligned with local test commands.

When shipping user-visible changes, update [CHANGELOG.md](CHANGELOG.md) under `[Unreleased]` (Keep a Changelog). Move entries into a version section when cutting a release.

## Security

- Never commit `dictionary.yaml` or real secrets
- Fake values only in tests/docs

## Style

- Implementation in `redactor/`, not `bin/`
- Minimal diffs; keep README behavior table and CLI help epilog in sync with code
