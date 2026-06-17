[![PyPI](https://img.shields.io/pypi/v/credactor)](https://pypi.org/project/credactor/)
[![CI](https://github.com/rxb06/Credactor/actions/workflows/ci.yml/badge.svg)](https://github.com/rxb06/Credactor/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/licence-Apache%202.0-blue)](https://github.com/rxb06/Credactor/blob/main/LICENSE)

# Credactor

**The secret scanner that fixes what it finds.**

Most scanners stop at detection, they hand you a list and leave the cleanup to you. Credactor finds the hardcoded secret **and rewrites it in place**, so remediation is one command instead of a manual chore.

<img alt="Credactor — scan, redact, commit clean" src="https://raw.githubusercontent.com/rxb06/Credactor/main/docs/assets/credactor-banner.png" width="1280" height="320" />

```python
# Credactor finds this…
db_password = "h8Tq2vKp9mRz4Wd"

# …and rewrites it — by default, a loud sentinel that fails closed at runtime:
db_password = "REDACTED_BY_CREDACTOR"

# …or, with --replace-with env, real code that reads from the environment:
db_password = os.environ["DB_PASSWORD"]
```

> Redaction rewrites your **working tree**. If a secret has already been committed, rotate the key and scrub history too (e.g. `git filter-repo`) — a rewrite isn't a substitute for revoking a leaked credential.

---

## What makes it different

- **It redacts, not just reports.** In-place replacement — a loud `REDACTED_BY_CREDACTOR` sentinel by default, or language-aware environment-variable references (Python, JS/TS, Go, Java/Kotlin, Ruby, PHP, shell), e.g. `os.environ["KEY"]`. The reference parses as valid code; add the matching import (e.g. `import os`) if the file doesn't already have one.
- **Zero runtime dependencies.** Pure Python 3.11+ standard library — nothing to vet, no supply chain. (An optional extra adds detection for non-UTF-8 encodings.)
- **Fail-closed by design.** Atomic writes, automatic `.bak` backups, symlink-boundary and file-permission guards, and full-secret masking in every output. If a safe backup can't be written, the file is skipped — never silently rewritten.
- **Plugs into your workflow.** SARIF for GitHub Code Scanning, a read-only `--ci` gate with clear exit codes, a pre-commit hook (beta), and ingestion of Gitleaks / TruffleHog reports (BETA; more detectors incoming) — detect with anything, remediate with Credactor.

## Install

```bash
pip install credactor
```

Requires Python 3.11+. No other dependencies. Runs on Linux, macOS, and
Windows (CI-tested on Linux and Windows).

From source:

```bash
git clone https://github.com/rxb06/Credactor.git
cd Credactor
pip install -e .
```

`credactor` then works from any directory.

## Quick start

> Run `--dry-run` first and review the findings before redacting — false positives are possible, and under `--fix-all` a false positive gets rewritten. Suppress known-safe values with `# credactor:ignore` or a `.credactorignore` entry.

```bash
credactor --dry-run .                 # scan, change nothing
credactor .                           # scan, then redact interactively (y/n per finding)
credactor --fix-all .                 # redact everything after one confirmation
credactor --fix-all --yes .           # redact non-interactively (CI / scripts)
credactor --ci .                      # read-only gate: exit 1 on findings
credactor --replace-with env .        # redact to env-var references instead of the sentinel
```

### Pre-commit hook (beta)

> Hook integration is in beta — run `credactor --dry-run .` manually before relying on it alone.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/rxb06/Credactor
    rev: v2.4.0   # pin to the latest release tag
    hooks:
      - id: credactor
```

## Detection

| Category | Examples | Severity |
|---|---|---|
| Cloud provider keys | AWS (`AKIA…`), GCP (`AIza…`), Stripe (`sk_live_…`), Slack (`xoxb-…`) | Critical |
| Platform tokens | GitHub (`ghp_`, `github_pat_`), GitLab (`glpat-`), npm (`npm_`), PyPI (`pypi-`) | Critical |
| Private keys | PEM blocks (`-----BEGIN … PRIVATE KEY-----`) | Critical |
| JWTs | `eyJ…` three-segment tokens | High |
| Connection strings | URLs with inline credentials (`scheme://user:pass@host`) | High |
| Credential variables | `password = "…"`, `api_key = "…"`, `secret_key = "…"` | High/Medium/Low |
| XML attributes | `<add key="Password" value="…" />` | High/Medium/Low |
| High-entropy strings | quoted hex (32–64 chars) / Base64 (60+ chars) | Medium/Low |

Deterministic provider tokens (the prefixes above) are flagged regardless of entropy; heuristic detectors (JWTs, connection strings, hex, Base64) must clear an entropy floor. Standalone hex/Base64 is flagged only when quoted — an unquoted high-entropy value is caught only on a credential-named variable, which spares git SHAs and checksums. Full detection and severity rules: see the [Manual](https://github.com/rxb06/Credactor/blob/main/docs/manual.md#detection--severity).

> **Credactor's edge is remediation, not out-detecting every scanner.** Pair it with a dedicated detector for the broadest coverage — or run it standalone.

## Detect with another scanner, redact with Credactor (BETA)

Already run Gitleaks or TruffleHog? Feed their report in and Credactor redacts the combined set, deduplicated against its own findings (higher severity wins on overlap):

```bash
gitleaks dir . -f json -r gitleaks.json
credactor --from-gitleaks gitleaks.json --fix-all --yes .
```

`--from-gitleaks` / `--from-trufflehog` (or an `[ingest]` table in `.credactor.toml`) require a directory target. See the [CI Integration guide](https://github.com/rxb06/Credactor/blob/main/docs/ci_integration.md).

## More features

- Interactive or batch redaction; a custom replacement string via `--replacement`; `--scan-history` to scan git commit history
- Secure backups: `--secure-delete` (overwrite and remove the `.bak`; raises the bar against casual recovery, not a forensic guarantee) or `--secure-backup-dir` to store backups outside the repo
- Inline `# credactor:ignore` and `.credactorignore` allowlists (globs, `file:line`, value literals)
- Per-repo config via `.credactor.toml`
- 29 source/config/notes file types out of the box (`.txt` included); `--scan-json` to include JSON; `--fail-on-error` to fail when a file can't be read

## Scanned file types

> `.py` `.js` `.ts` `.jsx` `.tsx` `.sh` `.bash` `.env` `.env.*` `.cfg` `.ini` `.toml` `.yaml` `.yml` `.rb` `.go` `.java` `.php` `.cs` `.kt` `.tf` `.hcl` `.conf` `.config` `.properties` `.xml` `.pem` `.key` `.crt`

Plus SSH / private-key files matched by name (`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`). JSON is excluded by default (high false-positive rate from API responses) — add `--scan-json` to include it. A file named directly on the command line is scanned even if its extension isn't in this list.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings, or all resolved |
| `1` | Unresolved findings |
| `2` | Error — e.g. bad path, dangerous `--replacement`, `--ci --fix-all`, or `--fail-on-error` with unreadable files |

## Docs

| Document | Description |
|----------|-------------|
| [Setup Guide](https://github.com/rxb06/Credactor/blob/main/docs/setup.md) | Installation, configuration, CI/CD integration |
| [Manual](https://github.com/rxb06/Credactor/blob/main/docs/manual.md) | Complete reference: every flag, mode, combination, replacement & backup behaviour, detection/severity, exit codes, and limitations (behaviour test-verified) |
| [Examples](https://github.com/rxb06/Credactor/blob/main/docs/examples.md) | Common workflows with output |
| [CI Integration](https://github.com/rxb06/Credactor/blob/main/docs/ci_integration.md) | Pre-commit hooks, CI pipelines |
| [Security](https://github.com/rxb06/Credactor/blob/main/docs/security.md) | Threat model, hardening measures, known limitations |
| [Changelog](https://github.com/rxb06/Credactor/blob/main/CHANGELOG.md) | Version history |
| [Contributing](https://github.com/rxb06/Credactor/blob/main/CONTRIBUTING.md) | Development setup, code style, PR process |
| [Disclaimer](https://github.com/rxb06/Credactor/blob/main/docs/DISCLAIMER.md) | Limitations, safe usage, warranty |

## Licence

Apache 2.0. See [LICENSE](https://github.com/rxb06/Credactor/blob/main/LICENSE).
