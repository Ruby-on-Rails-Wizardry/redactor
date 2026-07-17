# Redact & Unredact

CLI tools that redact sensitive values in local files and restore them later.

- **`redact`** — match patterns → placeholders → write under `redacted/` and update `dictionary.yaml`
- **`unredact`** — replace placeholders using the dictionary → write originals back

Commands install on your `PATH` and work from any directory. All `redacted/` paths are relative to the **current working directory**.

## Install

**Requirements:** [mise](https://mise.jdx.dev/) (recommended) or Python 3.12+ and [uv](https://docs.astral.sh/uv/). Put `~/.local/bin` on your `PATH`.

```bash
# from this repo
mise trust          # first time only, if prompted
mise run setup      # Python/uv + package + global CLI (redact, unredact)
```

Without mise:

```bash
uv tool install --force --editable .
```

```bash
redact version
redact path/to/file
unredact path/to/file
```

| Task | Command |
|------|---------|
| Refresh CLI after pulls | `mise run install-cli` |
| Uninstall CLI | `mise run uninstall-cli` |
| Dev deps only | `mise run install` |
| Tests + coverage (≥90%) | `mise run test` |
| Tests only | `mise run test-fast` |

Default git branch: **`master`** (not `main`).

### Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history (Keep a Changelog).

### CI

GitHub Actions (`.github/workflows/ci.yml`) runs on push and pull requests to `master`:

1. Install package + dev deps (`pip install -e ".[dev]"`)
2. `pytest` with coverage (fails under 90%)
3. Smoke-check `redact version` and `unredact -h`

Same checks as local `mise run test`, plus a quick CLI smoke step.

## Behavior specification

### Redact

| Rule | Spec |
|------|------|
| **Inputs** | One or more files and/or directories |
| **Output** | `redacted/<path>` (layout preserved) + update `redacted/dictionary.yaml` |
| **Patterns** | `redacted/patterns.yaml` if present; else built-ins: `IP`, `EMAIL`, `APIKEY`, `TOKEN`, `PASSWORD`, `GOV` (order fixed; EMAIL before GOV) |
| **Placeholders** | `{NAME}_{8 hex chars}`; same secret → same placeholder for the whole batch |
| **Dir skips (always)** | Never walk/process path components: `.git`, `.hg`, `.svn`, `.venv`, `venv`, `__pycache__`, `.pytest_cache`, `node_modules`, `.tox`, `.mypy_cache`, `.ruff_cache`, `.eggs`, `dist`, `build`. Also prune source trees named `redacted/` (tool workspace). Explicit `redact .git` yields no files |
| **Path excludes** | Optional `redacted/exclude.yaml` (name → glob) plus CLI `-e` / `--exclude GLOB` (repeatable) |
| **Includes** | Optional `-i` / `--include GLOB` (repeatable); if any set, only matching paths are kept |
| **Binary skip (always)** | Known binary/image/audio/archive extensions; NUL-byte samples; non-UTF-8 decode |
| **Dry-run** | `-n` / `--dry-run`: print matches only (labels **NEW** vs **REUSED**); no writes |
| **New-only** | `--new-only`: act only when a secret is not already in the dictionary; skip files with no new secrets (dry-run lists NEW only) |
| **Output** | Default per-file messages + final `Summary: …` (includes `new=` / `reused=`). `-q` / `--quiet`: summary only on stdout. `-v` / `--verbose`: extra match detail. Errors always on stderr |
| **Errors** | Log to **stderr**, continue other files; exit **1** if any failed; dictionary still saved for successes |
| **`.gitignore`** | On write under `redacted/`, ensure `redacted/` is listed in `.gitignore` |

```bash
redact config.env
redact file1.txt file2.env src/
redact --dry-run src/
redact -n config.env
redact -n --new-only src/                  # preview only secrets not yet in dictionary
redact --new-only src/                    # write only files that introduce new secrets
redact -q src/                             # quiet (CI-friendly summary)
redact -v config.env                      # verbose match detail
redact --exclude 'vendor/**' --exclude '*.log' src/
redact --include '**/*.env' --include '**/*.yml' .
```

### Patterns CLI

File: `redacted/patterns.yaml` (`NAME: regex`). Order = application order.

```bash
redact patterns init | init --force
redact patterns list | list --yaml
redact patterns add NAME 'regex'     # seeds built-ins if file missing
redact patterns remove NAME [--ignore-missing]
```

Built-in defaults (also what `patterns init` writes):

| Name | Matches (summary) |
|------|-------------------|
| `IP` | Valid IPv4 (each octet 0–255), not arbitrary dotted numbers |
| `EMAIL` | email addresses |
| `APIKEY` | value after `API_KEY=` (≥8 `[A-Za-z0-9-_]` chars) |
| `TOKEN` | value after `TOKEN=` (≥6 `[A-Za-z0-9-_]` chars) |
| `PASSWORD` | after `PASSWORD=`: quoted string, or unquoted ≥4 non-space chars |
| `GOV` | hostnames ending in `.gov` |

### Exclude CLI

File: `redacted/exclude.yaml` (`NAME: glob`). Same subcommands as patterns.

```bash
redact exclude init | init --force   # starter set (git, images, archives, locks, …)
redact exclude list | list --yaml
redact exclude add NAME 'glob'       # creates empty file if missing, then adds
redact exclude remove NAME [--ignore-missing]
```

| When | Path globs from `exclude.yaml` | Always applied |
|------|--------------------------------|----------------|
| File **missing** | none | dir skips + binary heuristics |
| File **present** | yes | dir skips + binary heuristics |
| `exclude init` | writes `DEFAULT_EXCLUDES` (includes `GIT` / `GIT_DIR` → `.git/**`, images, pdf, zip, …) | — |

### Unredact

| Rule | Spec |
|------|------|
| **Args** | Original paths (not `redacted/…`) |
| **Read** | `redacted/<path>` + `redacted/dictionary.yaml` (required) |
| **Write** | Restored content at original path (overwrites) |
| **Dirs** | Same walk/skip rules as redact; if original tree missing, discover via `redacted/<dir>/` |
| **Paste** | Only when a **single** file is expanded and redacted copy is missing |
| **Errors** | stderr + continue; exit 1 if any failed |

```bash
unredact config.env
unredact a.txt b.env src/
```

## Help

```bash
redact help
redact help patterns
redact help patterns add
redact help exclude
redact version | -V | --version
unredact -h | --help
```

## Layout

```
redactor/                 # installable package
  redact.py               # CLI, DEFAULT_PATTERNS, BINARY_EXTENSIONS, DEFAULT_EXCLUDES
  unredact.py
  paths.py                # expand/walk; ALWAYS_SKIP_DIR_NAMES (.git, …)
bin/                      # thin wrappers
tests/
pyproject.toml
mise.toml
README.md
AGENTS.md

# created in the directory you run from (gitignored):
redacted/
  patterns.yaml           # optional
  exclude.yaml            # optional
  dictionary.yaml         # sensitive
  …                       # mirrored redacted files
```

## Security

- **`redacted/dictionary.yaml` is sensitive** — do not commit or share unless authorized.
- **`redacted/` is gitignored**; `redact` also appends `redacted/` to `.gitignore` when writing under `redacted/`.
- Patterns/excludes are config, not secrets; the dictionary is.

## License

Licensed under the [MIT License](LICENSE).
