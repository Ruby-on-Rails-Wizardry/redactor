# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

### Security

<!-- Next changes go here. GitHub Release via `gh release create` is required at cut time (see docs/RELEASE.md). -->

## [0.3.0] - 2026-07-17

### Added

- Documented release process in [docs/RELEASE.md](docs/RELEASE.md)
- Allowlist CLI edge-case tests and batch error-path coverage
- README limitations / threat-model section (from 0.3.0 prep)

### Changed

- Package version **0.3.0**
- Docs layout lists `TODO.md`, `CHANGELOG.md`, allowlist rules (exact / glob / CIDR)

## [0.2.0] - 2026-07-17

### Added

- Robust assignment matchers for `APIKEY` / `TOKEN` / `PASSWORD` (`=` or `:`, optional spaces, quotes, alternate key names)
- Shape-based patterns: `PEM`, `JWT`, `AWSKEY`, `BEARER`
- Vendor/token shapes: `GHTOKEN`, `GLPAT`, `STRIPE`, `SLACK`; AWS secret assignment `AWSSECRET`
- HTTP header secrets: `HEADER` (`X-Api-Key`, `Private-Token`, …), `BASICAUTH`
- Connection-string / URL userinfo pattern `URLCREDS` (`scheme://user:pass@host`)
- IPv6 pattern `IP6` (compressed forms and `::1`)
- Allowlist CLI (`redact allowlist …`) and `redacted/allowlist.yaml`
- Allowlist rules: exact strings, globs (`* ?`), and CIDR networks
- Built-in allowlist defaults (localhost, RFC 5737 documentation IPs and `/24` CIDRs)
- Match engine `extract_match_values` for capturing-group patterns
- Project gap tracker: [TODO.md](TODO.md)

### Changed

- Default pattern set expanded and reordered: shape secrets first, then credentials, IPs, GOV
- Tighter IPv4 and credential length rules (from 0.1.x hardening line)

### Security

- Never-redact allowlist for localhost/documentation addresses to reduce false positives
- Still treat `redacted/dictionary.yaml` as sensitive

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

[Unreleased]: https://github.com/Ruby-on-Rails-Wizardry/redactor/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Ruby-on-Rails-Wizardry/redactor/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Ruby-on-Rails-Wizardry/redactor/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Ruby-on-Rails-Wizardry/redactor/releases/tag/v0.1.0
