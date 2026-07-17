# Redact & Unredact

CLI tools that redact sensitive values in local files and restore them later.

- **`redact`** — match patterns → placeholders → write under `redacted/` and update `dictionary.yaml`
- **`unredact`** — replace placeholders using the dictionary → write originals back

Commands are installable on your `PATH` and work from any directory. All `redacted/` paths are relative to your **current working directory**.

## Install

**Requirements:** [mise](https://mise.jdx.dev/) (recommended) or Python 3.12+ and [uv](https://docs.astral.sh/uv/). Ensure `~/.local/bin` is on your `PATH`.

```bash
# from this repo
mise trust          # first time only, if prompted
mise run setup      # Python/uv + package + global CLI (redact, unredact)
```

Without mise:

```bash
uv tool install --force --editable .
```

Then from anywhere:

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

## Usage

### Help and version

```bash
redact help                 # top-level usage and examples
redact help patterns        # patterns subcommand
redact help patterns add    # nested command help
redact version              # e.g. redact 0.1.0
redact -V / --version

unredact -h                 # unredact usage
unredact --help
```

### Redact files and directories

Writes `redacted/<path>` and updates `redacted/dictionary.yaml`. Uses `redacted/patterns.yaml` when present; otherwise built-in defaults.

```bash
redact config.env
redact file1.txt file2.env path/to/more.cfg   # multiple files
redact src/ configs/                          # directories (recursive)
redact app/ root.env                          # mix files and directories
```

- **Shared placeholders** across the whole batch (same secret → same placeholder).
- **Directory walks** skip `redacted/`, `.git/`, `node_modules/`, virtualenvs, caches, and similar paths.
- **Missing any path** → error; nothing is written for that run’s failed expansion.

### Manage patterns

Config file: `redacted/patterns.yaml` (name → regex). **Order matters** (applied top to bottom; e.g. `EMAIL` before `GOV`).

```bash
redact patterns init              # write built-in defaults
redact patterns init --force      # overwrite existing file
redact patterns list              # effective patterns (file or built-ins)
redact patterns list --yaml
redact patterns add NAME 'regex'  # add/update; seeds defaults if file missing
redact patterns remove NAME
redact patterns remove NAME --ignore-missing
```

Quote regexes for the shell:

```bash
redact patterns add GOV '\b(?:[A-Za-z0-9-]+\.)+gov\b'
```

You can edit `redacted/patterns.yaml` by hand; invalid regexes are rejected when loading.

### Unredact files and directories

Arguments are **original** paths (not paths under `redacted/`). Content is read from `redacted/<path>` and written back to `<path>`.

```bash
unredact config.env
unredact file1.txt file2.env
unredact src/                     # whole tree
```

- Requires `redacted/dictionary.yaml` (created by `redact`).
- Directories use the same recursive walk / skip rules as `redact`.
- If the original tree is gone, discovery can use `redacted/<dir>/`.
- **Single file** missing under `redacted/`: you may paste content on stdin (EOF to finish).
- **Multiple files**: missing redacted copy is an error.

## Layout

```
redactor/                 # installable package
  redact.py               # redact CLI, patterns, DEFAULT_PATTERNS
  unredact.py
  paths.py                # file/directory expansion
bin/                      # thin wrappers (need package installed)
tests/
pyproject.toml            # package + entry points
mise.toml
README.md
AGENTS.md

# created in the directory you run from (gitignored):
redacted/
  patterns.yaml           # optional pattern config
  dictionary.yaml         # sensitive placeholder map
  …                       # mirrored redacted files
```

## Security

- **`redacted/dictionary.yaml` is sensitive** (original values). Do not commit or share it unless authorized.
- **`redacted/` is gitignored.** The repo lists `redacted/`; `redact` also appends that entry to `.gitignore` if missing when it writes under `redacted/`.
- Pattern config is generally not secret; the dictionary is.

## Customization

Prefer `redact patterns …` (or edit `redacted/patterns.yaml`) for day-to-day rules. Built-in defaults live in `redactor/redact.py` as `DEFAULT_PATTERNS` until you `patterns init` or `patterns add`.

## License

Internal use only. Consult your component’s guidelines before external distribution.
