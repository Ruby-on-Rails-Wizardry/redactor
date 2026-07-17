# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Robust assignment matchers for `APIKEY` / `TOKEN` / `PASSWORD` (`=` or `:`, optional spaces, quotes, alternate key names)
- Shape-based patterns: `PEM`, `JWT`, `AWSKEY`, `BEARER`
- Vendor/token shapes: `GHTOKEN`, `GLPAT`, `STRIPE`, `SLACK`; AWS secret assignment `AWSSECRET`
- Connection-string / URL userinfo pattern `URLCREDS` (`scheme://user:pass@host`)
- IPv6 pattern `IP6` (compressed forms and `::1`)
- Allowlist CLI (`redact allowlist …`) and `redacted/allowlist.yaml` for never-redact strings
- Built-in allowlist defaults (localhost, RFC 5737 documentation IPs)
- Match engine `extract_match_values` for capturing-group patterns
- Project gap tracker: [TODO.md](TODO.md)

### Changed

- Version bump to 0.2.0 (in progress)
- Default pattern set order: shape secrets first, then credentials, then IPs, then GOV

### Fixed

### Security

## [0.1.0] - 2026-07-16

Initial public release of the `redact` / `unredact` CLI package.

### Added

- Installable package with console scripts `redact` and `unredact` (`pyproject.toml`, mise/uv setup)
- Redaction patterns with built-ins: `IP`, `EMAIL`, `APIKEY`, `TOKEN`, `PASSWORD`, `GOV`
- Pattern management CLI: `redact patterns init|list|add|remove` (`redacted/patterns.yaml`)
- Path exclude management CLI: `redact exclude init|list|add|remove` (`redacted/exclude.yaml`)
- Multi-file and recursive directory redaction/unredaction
- CLI path filters: `-e` / `--exclude`, `-i` / `--include` (repeatable globs)
- Dry-run mode: `-n` / `--dry-run` (match preview without writes)
- Output modes: `-q` / `--quiet`, `-v` / `--verbose`, final `Summary:` line
- Dictionary hygiene: dry-run labels **NEW** vs **REUSED**; `--new-only` for new secrets only
- Always-on skips for VCS/tool dirs (including `.git/`), binary/image extensions, NUL/non-UTF-8 files
- Resilient batches: log errors to stderr and continue; non-zero exit if any failed
- Stable placeholders with collision-safe generation (`PREFIX_` + unique hex)
- Auto-append `redacted/` to `.gitignore` when writing under `redacted/`
- Help/version commands for `redact`; usage help for `unredact`
- pytest suite with coverage gate (≥90%)
- GitHub Actions CI on `master` (tests, coverage, CLI smoke)
- MIT License

### Changed

- Tighter default patterns: valid IPv4 octets only; minimum lengths for API keys/tokens; password rules to reduce false positives

### Security

- Treat `redacted/dictionary.yaml` as sensitive; keep `redacted/` out of version control

[Unreleased]: https://github.com/Ruby-on-Rails-Wizardry/redactor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Ruby-on-Rails-Wizardry/redactor/releases/tag/v0.1.0
<!-- When releasing 0.2.0: move Unreleased notes into ## [0.2.0] - YYYY-MM-DD and add compare links. -->
