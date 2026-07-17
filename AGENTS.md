# AGENTS.md

Guidance for AI coding agents. Human-facing docs: [README.md](README.md).

## What this project is

Installable CLIs that redact sensitive values and restore them later:

| Command | Role |
|---------|------|
| `redact` | Patterns → placeholders → `redacted/<path>` + `redacted/dictionary.yaml` |
| `unredact` | Dictionary substitution → write originals at the given paths |

Package + `pyproject.toml` entry points. Runtime dep: `PyYAML`. Tests: pytest + coverage (≥90%).

## Layout

```
redactor/
  __init__.py       # __version__
  redact.py         # redact CLI, DEFAULT_PATTERNS, pattern management
  unredact.py       # restore CLI
  paths.py          # expand files/dirs (shared walk + skip rules)
bin/                # thin wrappers only
tests/
pyproject.toml      # package, console_scripts, coverage config
mise.toml           # setup / install / install-cli / test / test-fast
```

`redacted/` is created in the **caller’s cwd**, not next to the package install.

## Global install

```bash
mise run setup
# or: mise run install-cli
# or: uv tool install --force --editable .
```

- Entry points: `redact = redactor.redact:main`, `unredact = redactor.unredact:main`
- Editable install tracks this checkout; re-run `install-cli` if the clone moves
- Keep implementation in `redactor/`, not `bin/`

## Patterns

Prefer CLI (writes `redacted/patterns.yaml` in cwd):

```bash
redact patterns init|list|add|remove
```

1. File present → use only that file (validated / `re.compile`).
2. Else → `DEFAULT_PATTERNS` in `redactor/redact.py`.

Order is application order. `EMAIL` before `GOV` so `user@agency.gov` is an email first. `patterns add` seeds defaults if the file is missing; new names append at the end. `unredact` is pattern-agnostic.

## Redact / unredact contract

- Dictionary: `{ "PREFIX_hex8": "original", ... }` at `redacted/dictionary.yaml`
- Same original value → same placeholder (including across multi-file batches)
- `redact a b c` / dirs: one load/save of the dictionary for the batch
- Dirs: `redactor.paths.expand_paths` — skip `redacted/`, VCS, venv, `node_modules`, etc.
- Unredact args are **original** paths; content from `redacted/<path>`; paste only for a single expanded file
- Unredact overwrites the original path

## Security

- Treat `dictionary.yaml` and unredacted sources as sensitive; never commit/upload unless asked
- Keep `redacted/` gitignored (`ensure_redacted_gitignored()` on write)
- Use fake secrets in tests/examples

## Dependencies & checks

```bash
mise trust
mise run setup
mise run test          # pytest --cov; fail_under 90
```

When changing CLI or package behavior: update tests + docs/help strings, run `mise run test`. Re-run `install-cli` if entry points change.

## Style

- Small, imperative, dependency-light
- Implementation in `redactor/`; `bin/` wrappers only
- Minimal diffs
- **Default branch is `master` (not `main`).** Use `master` for base branches, PRs, and docs.
