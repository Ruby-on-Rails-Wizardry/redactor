# Project TODO / remaining gaps

Living list of product and pattern gaps. Check items off as they ship; keep
[CHANGELOG.md](CHANGELOG.md) `[Unreleased]` in sync for user-visible work.

## P1 — secret shapes & URLs

- [x] Cloud/token prefixes: GitHub `ghp_`/`gho_`/…, Stripe `sk_live_`/`sk_test_`, Slack `xox…`
- [x] AWS secret access key via assignment (`AWS_SECRET_ACCESS_KEY=…`)
- [x] URL userinfo + DB-style connection strings (`scheme://user:pass@host`)
- [x] GitLab `glpat-…` tokens

## P2 — headers, allowlist power, release

- [x] Header-style keys: `X-Api-Key`, `Private-Token`, `Authorization: Basic …`
- [x] CIDR / prefix or glob allowlist (not only exact strings) for private nets
- [x] Cut formal **0.2.0** release: finalize CHANGELOG section, tag `v0.2.0`, push
- [x] Document release process (`docs/RELEASE.md`)
- [x] Cut formal **0.3.0** release (docs, coverage, process)

## P3 — niche / polish

- [ ] IPv6 polish (IPv4-mapped, zone IDs); reduce any `::` false positives
- [ ] Broader gov TLDs (`.mil`, `.gov.uk`, `.gc.ca`) with fewer `*.gov.*` FPs
- [ ] Optional high-entropy “unknown secret” profile (off by default)
- [ ] `--patterns-file` / `--dictionary` / shared config path flags
- [ ] Stdin/stdout redaction mode
- [ ] `unredact version` parity with `redact`
- [ ] Dictionary file mode `0600` on write
- [x] Threat-model / limitations section in README
- [ ] CI lint job (e.g. ruff); optional multi-Python matrix

## Engine / correctness (backlog)

- [ ] Safer replacement than global `str.replace` for overlapping/partial matches
- [ ] Document idempotency expectations when re-running on already-redacted trees
- [ ] Custom-pattern guidance for capturing groups vs full-match

## Ops

- [ ] Ensure remote CI green after push
- [x] Coverage headroom if new code lands near the 90% floor (~93%+)
