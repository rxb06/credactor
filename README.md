[![PyPI](https://img.shields.io/pypi/v/credactor)](https://pypi.org/project/credactor/)
[![CI](https://github.com/rxb06/credactor/actions/workflows/ci.yml/badge.svg)](https://github.com/rxb06/credactor/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](https://github.com/rxb06/credactor/blob/main/LICENSE)

# Credactor

**Find the secret. Fix it. Commit clean.**

Most secret scanners stop at the alert: you get a list of leaked credentials
and the cleanup is yours. Credactor finds hardcoded secrets and rewrites them
in place, so a leak in your working tree goes from found to fixed in one
command. It runs on your machine, as a pre-commit hook, or as a CI gate, and it
can also fix what Gitleaks, TruffleHog or Betterleaks find.

<img alt="Credactor: scan, redact, commit clean" src="https://raw.githubusercontent.com/rxb06/credactor/main/docs/assets/credactor-banner.png" width="100%" />

```python
# Before
db_password = "h8Tq2vKp9mRz4Wd"

# credactor --fix-all .   (default: a sentinel that fails loudly at runtime)
db_password = "REDACTED_BY_CREDACTOR"

# credactor --replace-with env --fix-all .   (read it from the environment)
db_password = os.environ["DB_PASSWORD"]
```

> **Redaction cleans your working tree.** It does not revoke the credential and
> does not touch git history. If a secret was ever committed or shared, rotate
> it, and rewrite history if you need it gone from there too (for example with
> `git filter-repo`).

## Why Credactor

- **It fixes, not just flags.** Each finding is replaced in place with a
  sentinel, your own marker, or an environment-variable lookup in the file's
  own language.
- **Careful writes.** Each edit is planned in memory, backed up first (mode
  `0600`), written to a temp file and renamed into place. A file that changed
  during the run, a path that leaves the scan root, or a private key block is
  skipped with a warning, and its finding stays reported.
- **Works with the scanner you already run.** Feed it a Gitleaks, TruffleHog or
  Betterleaks report and it fixes their findings and its own in one
  deduplicated pass.
- **Built for pipelines.** A read-only `--ci` gate with clear exit codes, SARIF
  2.1.0 with line and column locations for GitHub Code Scanning, a GitHub Action
  and a pre-commit hook. Secrets are masked in every report format, and text
  output is cleaned so a scanned file cannot inject escape sequences or CI
  workflow commands into your terminal or log.
- **Releases checked against their source.** Pure Python 3.11+ standard
  library with no runtime dependencies. Before a release reaches PyPI, every
  Credactor file in the wheel and sdist is compared byte for byte with the
  tagged source, and the package metadata must match `pyproject.toml` (see
  [Supply-chain hardening](#supply-chain-hardening)).

Where it is not the right tool on its own: its built-in rules cover the
credential formats that leak most often rather than hundreds of providers, and
it does not check whether a secret is live. A clean run means nothing matched
its rules, not that the code holds no secrets. Pair it with a dedicated scanner
for breadth (see [Bring your own scanner](#bring-your-own-scanner)).

## Install

```bash
pip install credactor
```

With [uv](https://docs.astral.sh/uv/), install it as a tool, or run it once
without installing:

```bash
uv tool install credactor
uvx credactor --dry-run .
```

Or with Homebrew on macOS and Linux:

```bash
brew install rxb06/tap/credactor
```

Needs Python 3.11 or newer. Tested in CI on Linux and Windows, Python 3.11 to
3.13. For files in encodings other than UTF-8, Latin-1 or simple UTF-16, add
the optional extra: `pip install 'credactor[encoding]'` or
`uv tool install 'credactor[encoding]'` (the Homebrew formula includes it).

## Quick start

**1. See what it finds.** Nothing is changed.

```bash
credactor --dry-run .
```

```text
======================================================================
  CREDENTIAL SCAN REPORT  --  2 finding(s) in 1 file(s)
======================================================================

  FILE: config.py
  ────────────────────────────────────────────────────────────
  Line    3  [HIGH]  [variable:db_password]
           db_password = "h8Tq[REDACTED]"
  Line    4  [CRITICAL]  [pattern:AWS access key]
           aws_key = "AKIA[REDACTED]"
```

Reports show only the first four characters of each secret.

**2. Fix them.** Review the findings first: `--fix-all` rewrites every one,
false positives included. To keep one, add `# credactor:ignore` to its line
(see [Suppress false positives](#suppress-false-positives)) or fix
interactively and answer `n`. Before each file is changed, a `.bak` copy is
written beside it so you can undo.

```bash
credactor .                          # ask y/N for each finding (needs a terminal)
credactor --fix-all .                # fix all after one confirmation
credactor --fix-all --yes .          # fix all, no prompt (scripts)
credactor --replace-with env --fix-all .   # environment lookups instead of the sentinel
```

Env mode writes the lookup, not the import: add `import os` or your language's
equivalent if the file lacks it. On Windows Git Bash, run the interactive mode
as `winpty credactor .`.

**3. Check, then clean up the backups.** Each `.bak` still holds the original
secret, and Credactor never edits your `.gitignore`, so a plain `git add .`
would stage it.

```bash
diff config.py.bak config.py         # check what changed
cp config.py.bak config.py           # undo
```

Add `*.bak` and `*.credactor.tmp` to `.gitignore` and delete the backups once
you are happy. To keep backups out of the tree from the start, pass
`--secure-backup-dir DIR` (a directory outside the repository) on the fix run.
`--secure-delete` wipes each backup instead, which leaves git as your only
undo.

## Commands at a glance

| Command | What it does | Changes files |
|---|---|---|
| `credactor --dry-run .` | Report findings | No |
| `credactor .` | Review and fix one finding at a time | Yes, on `y` |
| `credactor --fix-all .` | Fix every finding after one confirmation | Yes |
| `credactor --ci .` | Gate: exit 1 on findings | Never |
| `credactor --staged --ci .` | Gate only what is staged for commit | Never |
| `credactor --scan-history .` | Scan the last 100 file-changing commits | Never |
| `credactor --ci -f sarif . > results.sarif` | SARIF 2.1.0 for Code Scanning | Never |
| `credactor --ci -f json . > findings.json` | Machine-readable report | Never |

Every flag and combination is in the
[Manual](https://github.com/rxb06/credactor/blob/main/docs/manual.md).

## Use it in pre-commit and CI

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/rxb06/credactor
    rev: v2.7.5
    hooks:
      - id: credactor
```

```bash
pre-commit install
```

Every `git commit` then scans the staged content and is blocked if it holds a
credential. The hook never rewrites files. It needs pre-commit 3.2.0 or newer;
without the framework, see the
[standalone hook](https://github.com/rxb06/credactor/blob/main/docs/ci_integration.md#standalone-git-hook).

### GitHub Action

```yaml
steps:
  - uses: actions/checkout@v7
  - uses: rxb06/credactor@v2.7.5
```

The Action always runs with `--ci`, so it never rewrites the checkout. Findings
fail the step, and so does any error. To report to Code Scanning instead of
failing:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v7
  - uses: rxb06/credactor@v2.7.5
    with:
      format: sarif
      upload-sarif: true
      fail-on-findings: false
```

The [CI integration guide](https://github.com/rxb06/credactor/blob/main/docs/ci_integration.md)
lists every Action input and output and covers GitLab CI and plain shell steps.

## Bring your own scanner

Already running Gitleaks, TruffleHog or Betterleaks? Hand Credactor the report
and it fixes their findings together with its own, deduplicated (on a
duplicate, the higher severity is kept). Preview with `--dry-run` first, as for
a native scan.

```bash
gitleaks dir . -f json -r gl.json
credactor --from-gitleaks gl.json --fix-all --yes .

trufflehog filesystem . --no-verification --json > th.json
credactor --from-trufflehog th.json --fix-all --yes .

betterleaks dir . -f json -r bl.json
credactor --from-betterleaks bl.json --fix-all --yes .
```

Point Credactor at the same directory the scanner ran on, and regenerate the
report after the tree changes. A report holds every secret it found in
plaintext and is not scanned itself (`.json` needs `--scan-json`), so write it
outside the repository or delete it after the run. A finding Credactor cannot
place safely (no valid line number, a path under `.git`, a value too short to
match on its own) stays reported and is never written. Details and supported
versions are in the
[Manual](https://github.com/rxb06/credactor/blob/main/docs/manual.md#external-scanner-ingestion).

## What it detects

| Category | Examples | Severity |
|---|---|---|
| Cloud and SaaS keys | AWS (`AKIA…`, `ASIA…`), GCP (`AIza…`), Stripe live (`sk_live_…`, `rk_live_…`), Slack (`xoxb-…`, `xoxp-…`) | Critical |
| Platform tokens | GitHub (`ghp_`, `gho_`, `ghs_`, `github_pat_`), GitLab (`glpat-`), npm (`npm_`), PyPI (`pypi-`) | Critical |
| Private keys | PEM blocks (`-----BEGIN … PRIVATE KEY-----`, encrypted ones included), PGP private key blocks | Critical |
| JWTs | `eyJ…` three-segment tokens | High |
| Connection strings | URLs with inline credentials (`scheme://user:pass@host`) | High |
| Credential variables | `password = "…"`, `api_key = "…"`, `secret_key = "…"` | High, Medium or Low |
| XML attributes | `<add key="Password" value="…" />` | High, Medium or Low |
| Stripe test keys | `sk_test_…` | Medium |
| High-entropy strings | quoted hex (32 to 64 characters) or Base64 (60 or more) | Medium or Low |

Provider tokens are matched by their format, so they are found even in
comments and whatever their randomness. Heuristic matches must also look
random enough, and a bare hex or Base64 value is reported only when it is
quoted or assigned to a credential-named variable, which spares git SHAs and
checksums. Placeholders such as `changeme`, environment lookups and template
references are not flagged.

**Good to know:**

- **Private keys are reported, never rewritten.** Rotate the key and delete the
  block by hand; `--fix-all` counts it as failed.
- **History is read-only and capped.** `--scan-history` covers the 100 most
  recent file-changing commits, and warns when the repository has more than
  100 commits.
- **A fixed set of file types** is scanned: 29 code, config and text
  extensions plus `.env.*` and SSH key files (`id_rsa` and friends). JSON needs
  `--scan-json`, and anything else needs `extra_extensions` in
  `.credactor.toml`. A file you name directly is always scanned.
- **Gitignored files are skipped when walking a directory**, and that usually
  includes a local `.env`. The text report lists them, but `-f json` and
  `-f sarif` say nothing about them. To check one, name it directly:
  `credactor --dry-run .env`.
- **Some formats are out of scope natively**, for example SendGrid and Twilio
  keys and Slack webhooks, as are secrets built at runtime and values under 8
  characters.

The full rules are in the
[Manual](https://github.com/rxb06/credactor/blob/main/docs/manual.md#detection--severity),
and the threat model is in the
[Security doc](https://github.com/rxb06/credactor/blob/main/docs/security.md).

## How it rewrites

| `--replace-with` | Result | Use it when |
|---|---|---|
| `sentinel` (default) | `"REDACTED_BY_CREDACTOR"` | You want anything still using the secret to fail loudly |
| `env` | `os.environ["DB_PASSWORD"]` | The value should come from the environment |
| `custom` | `"<your marker>"` via `--replacement` | You have your own convention |

Env mode writes the lookup in the file's language: `os.environ[…]` in Python,
`process.env[…]` in JavaScript and TypeScript, `ENV[…]` in Ruby, and the native
form in Go, Java, Kotlin and PHP. Every other file type gets a `${VAR}`
placeholder, which is a real lookup only where something expands it (a shell
script, a `.env` loader, many config tools). In C# it stays a plain string,
and in Terraform it reads as a reference that does not exist, so the config
fails to validate; use the sentinel for both. The name comes from the finding:
`db_password` becomes `DB_PASSWORD`, and a known token type gets its own name,
so an AWS key becomes `AWS_ACCESS_KEY` whatever the variable was called. Where
a lookup would break the code (inside a larger string, say), the sentinel is
used instead.

## Suppress false positives

On the line itself, in a `#`, `//`, `/* */` or `<!-- -->` comment:

```python
example_key = "AKIAIOSFODNN7EXAMPLE"  # credactor:ignore
```

Or in a `.credactorignore` at the scan root:

```text
tests/fixtures/*
app/settings.py:42
```

An entry can be a glob, a `file:line`, or an exact value. A value that contains
`.`, `/`, `?` or `*` (a URL, a JWT, Base64) must be written as
`value:<literal>`, or it is read as a glob and has no effect. Findings from an
ingested report are filtered by `.credactorignore` only: an inline
`credactor:ignore` does not stop them. Thresholds, skipped directories and
extra file types go in a
[`.credactor.toml`](https://github.com/rxb06/credactor/blob/main/docs/setup.md).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings, or all of them fixed |
| `1` | Findings left unresolved |
| `2` | Error, such as a bad path, an invalid flag combination, an unreadable report or explicit `--config`, or `--staged` / `--scan-history` outside a git repository |

An unresolved finding never exits 0. A file Credactor could not read is only a
warning by default, so add `--fail-on-error` to a gate that must read every
file; it then exits 2. The full list is in the
[Manual](https://github.com/rxb06/credactor/blob/main/docs/manual.md#exit-codes).

## Supply-chain hardening

A tool that reads every secret in your repository should be safe to install,
not only safe to run. Several popular packages have shipped malicious releases
after an attacker got into their build or publishing pipeline: a tampered
build dependency, a stolen upload token, or a file slipped into the release
archive. Credactor's release pipeline has a specific check for each of those.

- **No runtime dependencies.** `pip install credactor` installs Credactor and
  nothing else (the optional `[encoding]` extra adds `charset-normalizer`), so
  there is no third-party code to vet at install time.
- **Every release is checked against its source.** In CI and again before
  publishing, `scripts/audit_wheel.py` compares every file in the wheel and
  sdist that comes from the repository byte for byte (sha256) with the
  committed source, and rejects anything else apart from the package metadata,
  which must match `pyproject.toml`. An extra or altered module, an injected
  dependency, a repointed command, or a file that is in the tarball but not in
  git fails the release.
- **Hash-pinned builds.** CI and release builds install their tools with
  `pip install --require-hashes`, build backend included, so a tampered
  dependency fails the build instead of reaching the package.
- **No upload token in the pipeline.** Releases go to PyPI through OIDC trusted
  publishing from a dedicated `pypi` environment, with Sigstore attestations,
  and only when the package version matches the release tag. The pipeline
  stores no long-lived PyPI token.
- **Locked-down CI.** Every GitHub Action is pinned to a commit SHA, workflow
  tokens default to read-only, checkouts keep no credentials, and Dependabot
  proposes updates monthly.
- **The Action installs outside your checkout.** The GitHub Action installs
  Credactor from the runner's temp directory with pip in isolated mode
  (`python -I`), then runs the installed command.

These checks show that what is published matches the source committed at the
release tag. They cannot make that source trustworthy or protect a build
machine that is already compromised; the
[Security doc](https://github.com/rxb06/credactor/blob/main/docs/security.md#supply-chain-hardening)
has the full detail and limits.

## Security

Report a vulnerability privately through
[GitHub Security Advisories](https://github.com/rxb06/credactor/security/advisories/new),
not a public issue. [SECURITY.md](https://github.com/rxb06/credactor/blob/main/SECURITY.md)
lists the supported versions, and the
[Security doc](https://github.com/rxb06/credactor/blob/main/docs/security.md)
covers the threat model, each hardening measure and the known limits.

## Docs

| Document | What is in it |
|---|---|
| [Manual](https://github.com/rxb06/credactor/blob/main/docs/manual.md) | Every flag, mode and combination, with verified behaviour |
| [Setup](https://github.com/rxb06/credactor/blob/main/docs/setup.md) | Installation and `.credactor.toml` |
| [CI integration](https://github.com/rxb06/credactor/blob/main/docs/ci_integration.md) | Pre-commit, the GitHub Action, other CI systems, ingestion |
| [Examples](https://github.com/rxb06/credactor/blob/main/docs/examples.md) | Common workflows with output |
| [Security](https://github.com/rxb06/credactor/blob/main/docs/security.md) | Threat model, hardening, known limits |
| [Disclaimer](https://github.com/rxb06/credactor/blob/main/docs/DISCLAIMER.md) | Safe usage and warranty |
| [Changelog](https://github.com/rxb06/credactor/blob/main/CHANGELOG.md) | Version history |
| [Contributing](https://github.com/rxb06/credactor/blob/main/CONTRIBUTING.md) | Development setup and pull requests |

## Licence

Apache 2.0. See [LICENSE](https://github.com/rxb06/credactor/blob/main/LICENSE).
