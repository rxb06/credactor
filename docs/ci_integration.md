# CI Integration Guide

## Recommended Workflow

Run Credactor manually before committing:

```bash
credactor --dry-run .
```

This gives you full control over findings before they enter git history. Review the output and suppress false positives with `# credactor:ignore` before you commit. A clean run means nothing matched Credactor's rules, not that the code holds no secrets.

Pre-commit hooks and CI pipelines automate this further, but a manual scan is the most reliable first step.

## Pre-commit Hook

> The hook reads the staged index blob, so it gates what you are about to commit
> and nothing else. A secret already in history is not re-flagged;
> `credactor --scan-history .` finds those.

### Pre-commit Framework

If you use [pre-commit](https://pre-commit.com), add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/rxb06/credactor
    rev: v2.7.5  # pin to a release tag
    hooks:
      - id: credactor
```

Then install the hook:

```bash
pre-commit install
```

Every `git commit` then scans the staged content and is blocked if it holds a credential. The hook never rewrites files. It needs pre-commit 3.2.0 or newer.

### Standalone Git Hook

No framework needed. Create `.git/hooks/pre-commit`:

```bash
#!/usr/bin/env bash
set -euo pipefail

if ! command -v credactor &>/dev/null; then
    echo "credactor not found. Install with: pip install credactor" >&2
    exit 1
fi

credactor --staged --ci
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

`--ci` exits 1 on findings, blocking the commit. `--staged` scans only staged files and is **read-only**: it forces dry-run, so no files are modified or backed up even if `--fix-all` is also passed.

## GitHub Action

The published action wraps the steps below, so a workflow does not have to write
its own install and argument plumbing:

```yaml
- uses: rxb06/credactor@v2.7.5
```

It is a composite action: it installs Credactor from PyPI, runs it, writes a job
summary, and applies the gate. It always passes `--ci`, so it forces read-only
and blocks `--fix-all`, and cannot rewrite the checkout.

SARIF upload to Code Scanning, reporting rather than gating:

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

Gating on a combined native and Gitleaks result:

```yaml
- name: Gitleaks scan
  run: gitleaks dir . -f json -r gitleaks.json
  continue-on-error: true

- uses: rxb06/credactor@v2.7.5
  with:
    from-gitleaks: gitleaks.json
```

| Input | Default | Purpose |
|---|---|---|
| `path` | `.` | Target to scan. Must be a directory when ingesting. |
| `working-directory` | `.` | Directory to run from; target and report paths resolve against it. |
| `version` | current release | Credactor version to install, or `latest`. |
| `python-version` | `3.11` | Python used to run Credactor. |
| `format` | `text` | `text`, `json` or `sarif`. |
| `output-file` | `credactor-results.<ext>` | Where to write a json/sarif report, after the scan. It must not be a symlink, must be a regular file or absent, and must resolve inside the workspace or the runner temp directory, or the step fails. Ignored for text. |
| `fail-on-findings` | `true` | Fail the step on findings. Errors fail regardless. |
| `fail-on-error` | `false` | Pass `--fail-on-error`. Do not combine with `format: sarif`. |
| `scan-json` | `false` | Pass `--scan-json`. |
| `scan-history` | `false` | Pass `--scan-history` (the 100 most recent file-changing commits). Needs `fetch-depth: 0`, excludes ingestion. |
| `config` | none | Explicit `.credactor.toml` path. |
| `verbose` | `false` | Pass `--verbose`. |
| `from-gitleaks` / `from-trufflehog` / `from-betterleaks` | none | Report to ingest. |
| `upload-sarif` | `false` | Upload to Code Scanning. Needs `format: sarif`. |
| `extra-args` | none | Raw flags the action does not model, split on whitespace. Quotes are not honoured, so an argument cannot contain a space. |

Outputs: `exit-code` (0 clean, 1 findings, 2 error), `findings-count` (json and
sarif only) and `report-file` (the physical path of the report, as a native
path on every OS, when one was written). A line break in `format`, the working
directory, `path`, `output-file`, `config` or a `from-*` input fails the step;
in `extra-args` it counts as a space. With json or sarif output, an exit 1
that produced no valid report is reported as an error (2).

Only exit 1 counts as a findings result. Any other non-zero code, including a
failed install, fails the step as an error rather than reporting a credential
that was never found.

## CI Pipeline

If you would rather call the CLI directly, or you are not on GitHub Actions, the
job has to install Credactor itself (the Action above does this for you). The
snippets below are single steps and assume a checkout and a Python 3.11+
environment with Credactor on the PATH. Pin the version so a new release cannot
change the gate under you:

```bash
pip install credactor==2.7.5
credactor --ci .
```

With uv, `uvx credactor@2.7.5 --ci .` installs and runs it in one step.

### GitHub Actions

Basic, fail on findings:

```yaml
- name: Credential scan
  run: credactor --ci .
```

Strict, also fail if files could not be scanned:

```yaml
- name: Credential scan
  run: credactor --ci --fail-on-error .
```

SARIF upload to Code Scanning. The upload needs `security-events: write`, which
the default token does not grant on repositories with read-only workflow
permissions:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - name: Credential scan
    run: credactor --ci --format sarif . > results.sarif
    continue-on-error: true

  - name: Upload SARIF
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: results.sarif
```

> The SARIF step omits `--fail-on-error` on purpose: with it, an unreadable
> file makes Credactor exit 2 and write an empty `results.sarif`, which the
> upload step then cannot parse. Gate on `--fail-on-error` in a separate step
> if you need it.

Use `--verbose` in CI to log suppressed findings for audit trails.

### GitLab CI

```yaml
credential-scan:
  image: python:3.12-slim
  script:
    - pip install credactor==2.7.5
    - credactor --ci --format json . > credential-report.json
  artifacts:
    when: always
    paths:
      - credential-report.json
```

> Credactor's JSON is its own `{ "findings": [...], "count": N }` schema, not
> GitLab CodeClimate/CodeQuality format, so it is kept as a plain downloadable
> artifact (`paths:`), not a `reports: codequality:` widget. To drive the Code
> Quality widget you would first convert each finding to a CodeClimate entry.
>
> `when: always` keeps the report when the job fails on findings (exit 1).
> Without it GitLab uploads artifacts only from passing jobs, so you would never
> get the report for a run that found something. The snippet leaves out
> `--fail-on-error` because a run that exits 2 writes an empty report. If you
> want that stricter gate, run it as a separate job.

### Generic

```bash
credactor --ci .
credactor --ci --fail-on-error .  # strict mode
```

### CI Security Notes

- `--ci` is read-only by design: it blocks `--fix-all` and forces `--dry-run`.
- A `.credactor.toml` that the upward search finds outside the project root is not loaded. Credactor logs an error and uses default settings. Outside CI you can load that file by naming it with `--config`. Under `--ci`, naming it with `--config` exits 2, so the gate never falls back to default settings without telling you.
- An explicit `--config` that is missing, unreadable or invalid TOML always exits 2, in CI or not. A discovered config that fails to parse only logs a warning, and the run continues with default settings.
- `--fail-on-error` makes files skipped due to permissions fail the run instead of being passed over quietly.
- Files matched by `.gitignore` are skipped when walking a directory. The text report lists them, but `-f json` and `-f sarif` do not, so name such a file directly if the gate must cover it.
- A passing gate means nothing matched Credactor's rules, not that the code holds no secrets. Pair it with a dedicated scanner (see [Ingesting External Scanner Findings](#ingesting-external-scanner-findings) below).
- `.credactorignore` is the **only** suppression layer applied to ingested findings. Inline `# credactor:ignore`, safe values, and entropy/length thresholds gate the native scan only.
- TruffleHog self-updates by default; pass `--no-update` in pipelines that pin a version.

## Ingesting External Scanner Findings

Credactor can ingest findings from [Gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog) and [Betterleaks](https://github.com/betterleaks/betterleaks), merge them into its own pipeline, and gate (or redact) on the combined set. Ingested findings are deduplicated against native Credactor findings, and on a duplicate the higher severity is kept. Ingestion behaviour is verified on **Linux**; Windows and macOS are untested (see the manual's supported-versions statement).

`--from-gitleaks`, `--from-trufflehog` and `--from-betterleaks` all **require a directory target** (the repository root) so report file paths resolve correctly. A file target exits with code 2. Ingestion also **cannot be combined with `--scan-history`** (exits 2): external reports reference on-disk files, history scanning references committed content.

**Run the scanner and Credactor against the same root.** The examples below run both from the repo root. A report generated at the root but ingested against a subdirectory target makes its findings miss: each is warned and skipped, with a run-level summary, but the run can still exit 0 and pass the gate. Pin TruffleHog to `filesystem` or `git` sources: records from any other source (`github`, `docker`, …) are skipped with a warning, not ingested. Pin Betterleaks to its `dir` or `git` subcommands for the same reason: findings from `stdin`, `github`, `gitlab`, `huggingface` and `s3` have no local file to redact and are skipped with a warning.

Run the external scanner first, then feed its report to Credactor as a CI gate:

```yaml
- name: Gitleaks scan
  run: gitleaks dir . -f json -r gitleaks.json
  continue-on-error: true

- name: Credactor gate (native + Gitleaks)
  run: credactor --ci --from-gitleaks gitleaks.json .
```

TruffleHog emits newline-delimited JSON:

```yaml
- name: TruffleHog scan
  run: trufflehog filesystem . --no-verification --no-update --json > trufflehog.json
  continue-on-error: true

- name: Credactor gate (native + TruffleHog)
  run: credactor --ci --from-trufflehog trufflehog.json .
```

[Betterleaks](https://github.com/betterleaks/betterleaks) scans with `dir` / `git` / `github` / `gitlab` / `huggingface` / `s3` / `stdin` subcommands; there is no `detect` subcommand:

```yaml
- name: Betterleaks scan
  run: betterleaks dir . -f json -r betterleaks.json
  continue-on-error: true

- name: Credactor gate (native + Betterleaks)
  run: credactor --ci --from-betterleaks betterleaks.json .
```

> Generate the Betterleaks report **without** its `--redact` flag. `--redact`
> rewrites `Secret` in the report itself, so the report no longer carries the
> value Credactor would match on the line. At its default the value becomes the
> literal `REDACTED`, and such a report is refused outright: the run is fatal
> (exit 2), the message names the flag rather than the tree, and no bytes are
> written. At a percentage the value is truncated instead, which fails as an
> ordinary stale finding (exit 1) with nothing written. Either way, regenerate
> the report without the flag. Gitleaks' `--redact` is treated on the same
> terms.

`--from-betterleaks` carries the same rules as the other two sources: a directory target (a file target exits 2), no `--scan-history`, the report path resolved against the working directory, and finding paths resolved against the target. Pin Betterleaks to the `dir` or `git` subcommands: findings from `stdin`, `github`, `gitlab`, `huggingface` and `s3` have no local file to redact, so they are skipped as unsupported sources with a run-level warning. A clean Betterleaks scan writes a literal `null` report rather than an empty array; Credactor reads that as zero findings, so a clean upstream scan passes the gate rather than failing it as a malformed report.

These examples write the report inside the workspace, which is fine for an ephemeral CI checkout that is discarded after the run. Anywhere the tree persists (local use, a reused runner), write the report **outside** the target tree: the report file holds the found secrets in plaintext, `.json` files are not scanned natively without `--scan-json`, and a finding pointing at the report itself is skipped (see the manual's ingestion section).

Under `--ci` the run is report-only: ingested findings are scanned, merged, and reported, and the run exits 1 if anything remains. To configure ingestion in `.credactor.toml` instead, add an `[ingest]` table (an empty path value is fatal, exit 2, the same as an empty flag):

```toml
[ingest]
from_gitleaks = "gitleaks.json"
from_trufflehog = "trufflehog.json"
from_betterleaks = "betterleaks.json"
```

All three keys can be set at once, and the matching CLI flag overrides each one.

> Report paths (on the flags and in `[ingest]` alike) resolve against the
> job's **working directory**, not the target or the config file's location.

## Automated Remediation (non-interactive)

`--ci` is a read-only gate and **cannot** be combined with `--fix-all`. To actually rewrite files in an unattended job, use `--fix-all` with `--yes` (`-y`) to skip the confirmation prompt. Without `--yes`, `--fix-all` aborts when stdin is not a TTY:

```bash
credactor --dry-run .          # preview first
credactor --fix-all --yes .    # then rewrite (writes .bak unless --no-backup)
```

Each `.bak` holds the original secret in plaintext, and Credactor never adds it to `.gitignore`, so a job that later runs `git add .` would commit the secret again. In a job that commits the result, pass `--secure-backup-dir` with a directory outside the checkout, or `--no-backup`. A private key block is reported but never rewritten: `--fix-all` counts it as failed and the run exits 1 until you remove the block by hand. Redaction does not revoke the credential or remove it from git history, so rotate anything real.

**Regenerate the report after redacting.** An external report is a snapshot: re-running with a consumed report exits 1 (`Reported value not found …`), and findings whose files were renamed or deleted since the scan are dropped with a warning. After a `--fix-all` run that ingested a report, re-run the scanner before gating again. This is the natural failure mode of a two-step scan→redact pipeline.

## Configuration

See the [Manual](manual.md) for the full list of CLI flags, config options, and suppression mechanisms.
