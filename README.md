[![PyPI](https://img.shields.io/pypi/v/credactor)](https://pypi.org/project/credactor/)
[![CI](https://github.com/rxb06/credactor/actions/workflows/ci.yml/badge.svg)](https://github.com/rxb06/credactor/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/licence-Apache%202.0-blue)](https://github.com/rxb06/credactor/blob/main/LICENSE)

# Credactor

**Find the secret. Fix it. Commit clean.**

Secret scanners are good at sounding the alarm and not much help putting it out. They hand you a list of leaked credentials and leave the cleanup to you. Credactor closes the loop: it finds a hardcoded secret and rewrites it in place, so a leak goes from detection to fix in a single command.

Keeping credentials out of source code is a baseline security practice, not an optional one. Credactor makes that baseline cheap to hold, on your machine before a commit or in CI before a merge. Run it on its own, or alongside the scanners you already trust.

<img alt="Credactor: scan, redact, commit clean" src="https://raw.githubusercontent.com/rxb06/credactor/main/docs/assets/credactor-banner.png" width="1280" height="320" />

```python
# Credactor finds this:
db_password = "h8Tq2vKp9mRz4Wd"

# By default it rewrites the secret as a sentinel that fails loudly at runtime:
db_password = "REDACTED_BY_CREDACTOR"

# With --replace-with env, it writes a reference that reads from the environment:
db_password = os.environ["DB_PASSWORD"]
```

> Redaction rewrites files in your **working tree**. If a secret has already been committed, rotate the key and scrub history as well (for example, with `git filter-repo`). Rewriting a file is not a substitute for revoking a leaked credential.

---

## Why Credactor

- **Redaction, not just detection.** Most scanners stop at the finding. Credactor replaces the secret in place: a loud `REDACTED_BY_CREDACTOR` sentinel that fails at runtime by default, or a language-aware environment-variable reference (Python, JavaScript/TypeScript, Go, Java/Kotlin, Ruby, PHP, and shell) such as `os.environ["KEY"]`. The replacement is valid code. If the file does not already include the matching import (for example `import os`), add it.
- **Safe by default.** Atomic writes, automatic `.bak` backups, symlink-boundary and file-permission guards, and full-secret masking in every output. If a safe backup cannot be written, Credactor skips the file rather than rewrite it blind, and a crash mid-write leaves the original intact.
- **Zero runtime dependencies.** Pure Python 3.11+ standard library, plus an optional extra for non-UTF-8 encodings.
- **Built for the pipeline.** SARIF output for GitHub Code Scanning, a read-only `--ci` gate with precise exit codes, a pre-commit hook (beta), and ingestion of Gitleaks or TruffleHog reports (BETA, with more on the way). Detect with Gitleaks or TruffleHog, remediate with Credactor.

## Install

```bash
pip install credactor
```

Requires Python 3.11+. No other dependencies. Runs on Linux, macOS, and
Windows (CI-tested on Linux and Windows).

From source:

```bash
git clone https://github.com/rxb06/credactor.git
cd credactor
pip install -e .
```

`credactor` then works from any directory.

## Quick start

> Run `--dry-run` first and review the findings before redacting. False positives are possible, and under `--fix-all` a false positive gets rewritten. Suppress known-safe values with `# credactor:ignore` or a `.credactorignore` entry.

```bash
credactor --dry-run .                 # scan, change nothing
credactor .                           # scan, then redact interactively (y/n per finding)
credactor --fix-all .                 # redact everything after one confirmation
credactor --fix-all --yes .           # redact non-interactively (CI / scripts)
credactor --ci .                      # read-only gate: exit 1 on findings
credactor --replace-with env .        # redact to env-var references instead of the sentinel
```

### Pre-commit hook (beta)

> Hook integration is in beta. Run `credactor --dry-run .` manually before relying on it alone.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/rxb06/credactor
    rev: v2.4.0   # pin to the latest release tag
    hooks:
      - id: credactor
```

## Detection

Credactor detects the credential types that leak most often, and assigns each a severity so you can triage at a glance.

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

Deterministic provider tokens (the prefixes above) are flagged regardless of entropy. Heuristic detectors (JWTs, connection strings, hex, Base64) must clear an entropy floor. Standalone hex or Base64 is flagged only when quoted. An unquoted high-entropy value is caught only on a credential-named variable, which spares git SHAs and checksums. For the full detection and severity rules, see the [Manual](https://github.com/rxb06/credactor/blob/main/docs/manual.md#detection--severity).

> Credactor's native rule set is narrower than a dedicated scanner's, and some provider formats (for example SendGrid, Twilio, and Slack webhooks) are not detected. Its edge is remediation: pair it with Gitleaks or TruffleHog for the broadest detection, or run it on its own.

## Pair it with another scanner, redact the lot (BETA)

Credactor stands on its own, and it gets stronger in company. Already run Gitleaks or TruffleHog? Pass their report to Credactor and it redacts the combined set, deduplicated against its own findings (on overlap, the higher severity wins). One remediation pass covers your scan and theirs:

```bash
gitleaks dir . -f json -r gitleaks.json
credactor --from-gitleaks gitleaks.json --fix-all --yes .
```

`--from-gitleaks` / `--from-trufflehog` (or an `[ingest]` table in `.credactor.toml`) require a directory target. See the [CI Integration guide](https://github.com/rxb06/credactor/blob/main/docs/ci_integration.md).

## More features

- Interactive or batch redaction; a custom replacement string via `--replacement`; `--scan-history` to scan git commit history
- Secure backups: `--secure-delete` (overwrite and remove the `.bak`; raises the bar against casual recovery, not a forensic guarantee) or `--secure-backup-dir` to store backups outside the repo
- Inline `# credactor:ignore` and `.credactorignore` allowlists (globs, `file:line`, value literals)
- Per-repo config via `.credactor.toml`
- 29 source/config/notes file types out of the box (`.txt` included); `--scan-json` to include JSON; `--fail-on-error` to fail when a file cannot be read

## Scanned file types

> `.py` `.js` `.ts` `.jsx` `.tsx` `.sh` `.bash` `.env` `.cfg` `.ini` `.toml` `.yaml` `.yml` `.rb` `.go` `.java` `.php` `.cs` `.kt` `.tf` `.hcl` `.conf` `.config` `.properties` `.xml` `.pem` `.key` `.crt` `.txt`

Plus `.env.*` / `.env-*` variants (`.env.local`, `.env.production`) and SSH / private-key files (`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`), all matched by filename rather than extension. JSON is excluded by default because API responses produce a high false-positive rate; add `--scan-json` to include it. A file named directly on the command line is scanned even if its extension is not in this list.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings, or all resolved |
| `1` | Unresolved findings |
| `2` | Error (for example: bad path, dangerous `--replacement`, `--ci --fix-all`, or `--fail-on-error` with an unreadable file) |

## Supply-chain hardening

A security tool earns trust by being safe to install, not only safe to run. Credactor's build and release pipeline has controls at each step, and the artifacts are audited on every push, not just at release. Full detail in the [Security doc](https://github.com/rxb06/credactor/blob/main/docs/security.md#supply-chain-hardening).

- **Nothing to vet at install time.** Credactor declares zero runtime dependencies, so a default `pip install credactor` pulls in no third-party packages (the only add-on is the optional `[encoding]` extra).
- **Hash-pinned toolchain.** CI and build steps install from a `pip-compile --generate-hashes` lockfile via `pip install --require-hashes`, so a tampered dependency artifact fails the build. The build backend is covered too: releases run `python -m build --no-isolation` against a hash-pinned setuptools instead of fetching the backend fresh at publish time.
- **The artifacts must match the source.** On every push and before every publish, `scripts/audit_wheel.py` checks both the wheel and the sdist against the committed source: every `credactor/` file is compared byte for byte (sha256) to its `git HEAD` blob, and an added, missing, or altered package file, an unexpected file in the wheel, a stray `.py` in the sdist, or no artifact at all fails the gate. A build step cannot inject or alter the package's code without being caught.
- **Token-less publishing.** Releases reach PyPI through OIDC Trusted Publishing from a dedicated `pypi` environment, with no long-lived API token stored in the repo, and request signed build-provenance attestations (PEP 740 / Sigstore).
- **No mis-versioned release.** A pre-publish step blocks the upload unless `credactor.__version__` matches the release tag (compared with PEP 440 normalisation).
- **Pinned, least-privilege CI.** GitHub Actions are pinned to commit SHAs, and workflow tokens stay narrow: `contents: read` by default, with `id-token: write` granted only to the publish job.
- **Pins stay fresh.** Dependabot opens monthly grouped pull requests to update the pinned Actions and regenerate the hash-locked lockfile, so the frozen toolchain gets reviewed rather than left to rot.

## Docs

| Document | Description |
|----------|-------------|
| [Setup Guide](https://github.com/rxb06/credactor/blob/main/docs/setup.md) | Installation, configuration, CI/CD integration |
| [Manual](https://github.com/rxb06/credactor/blob/main/docs/manual.md) | Complete reference: every flag, mode, and combination, replacement and backup behaviour, detection and severity, exit codes, and limitations (behaviour test-verified) |
| [Examples](https://github.com/rxb06/credactor/blob/main/docs/examples.md) | Common workflows with output |
| [CI Integration](https://github.com/rxb06/credactor/blob/main/docs/ci_integration.md) | Pre-commit hooks, CI pipelines |
| [Security](https://github.com/rxb06/credactor/blob/main/docs/security.md) | Threat model, hardening measures, known limitations |
| [Changelog](https://github.com/rxb06/credactor/blob/main/CHANGELOG.md) | Version history |
| [Contributing](https://github.com/rxb06/credactor/blob/main/CONTRIBUTING.md) | Development setup, code style, PR process |
| [Disclaimer](https://github.com/rxb06/credactor/blob/main/docs/DISCLAIMER.md) | Limitations, safe usage, warranty |

## Licence

Apache 2.0. See [LICENSE](https://github.com/rxb06/credactor/blob/main/LICENSE).
