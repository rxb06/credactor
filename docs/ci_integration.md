# CI Integration Guide

## Recommended Workflow

Run Credactor manually before committing:

```bash
credactor --dry-run .
```

This gives you full control over findings before they enter git history. Review the output, suppress false positives with `# credactor:ignore`, then commit with confidence.

Pre-commit hooks and CI pipelines automate this further, but a manual scan is the most reliable first step.

## Pre-commit Hook (Beta)

> Hook-based scanning is in beta. Run `credactor --dry-run .` manually before relying on hooks exclusively.

### Pre-commit Framework

If you use [pre-commit](https://pre-commit.com), add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/rxb06/credactor
    rev: v2.6.0  # pin to a release tag
    hooks:
      - id: credactor
```

Then install the hook:

```bash
pre-commit install
```

Every `git commit` will now scan staged files automatically. The commit is blocked if credentials are found.

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

## CI Pipeline

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

SARIF upload to Code Scanning:

```yaml
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
  script:
    - credactor --ci --fail-on-error --format json . > credential-report.json
  artifacts:
    paths:
      - credential-report.json
  allow_failure: false
```

> Credactor's JSON is its own `{ "findings": [...], "count": N }` schema, not
> GitLab CodeClimate/CodeQuality format, so it is kept as a plain downloadable
> artifact (`paths:`), not a `reports: codequality:` widget. To drive the Code
> Quality widget you would first convert each finding to a CodeClimate entry.

### Generic

```bash
credactor --ci .
credactor --ci --fail-on-error .  # strict mode
```

### CI Security Notes

- `--ci` is read-only by design: it blocks `--fix-all` and forces `--dry-run`.
- `.credactor.toml` files discovered *implicitly* outside the project root are refused (SEC-29 / M14): in CI they are always refused — and an *explicit* `--config` pointing outside the project root is a **fatal error (exit 2)** under `--ci`, so the gate never silently falls back to defaults; in non-CI you can still load one by pointing `--config` at it explicitly.
- `--fail-on-error` ensures files skipped due to permissions are not silently ignored.
- `.credactorignore` is the **only** suppression layer applied to ingested findings — inline `# credactor:ignore`, safe values, and entropy/length thresholds gate the native scan only.
- TruffleHog self-updates by default; pass `--no-update` in pipelines that pin a version.

## Ingesting External Scanner Findings

Credactor can ingest findings from [Gitleaks](https://github.com/gitleaks/gitleaks) and [TruffleHog](https://github.com/trufflesecurity/trufflehog), merge them into its own pipeline, and gate (or redact) on the combined set. Ingested findings are deduplicated against native Credactor findings, and on a duplicate the higher severity is kept. Ingestion behaviour is verified on **Linux**; Windows and macOS are untested (see the manual's supported-versions statement).

Both `--from-gitleaks` and `--from-trufflehog` **require a directory target** (the repository root) so report file paths resolve correctly. A file target exits with code 2. Ingestion also **cannot be combined with `--scan-history`** (exits 2): external reports reference on-disk files, history scanning references committed content.

**Run the scanner and Credactor against the same root** — the examples below run both from the repo root. A report generated at the root but ingested against a subdirectory target makes its findings miss — each is warned and skipped, with a run-level summary, but the run can still exit 0 and pass the gate. Pin TruffleHog to `filesystem` or `git` sources: records from any other source (`github`, `docker`, …) are skipped with a warning, not ingested.

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
  run: trufflehog filesystem . --no-verification --json > trufflehog.json
  continue-on-error: true

- name: Credactor gate (native + TruffleHog)
  run: credactor --ci --from-trufflehog trufflehog.json .
```

These examples write the report inside the workspace, which is fine for an ephemeral CI checkout that is discarded after the run. Anywhere the tree persists (local use, a reused runner), write the report **outside** the target tree: the report file holds the found secrets in plaintext, `.json` files are not scanned natively without `--scan-json`, and a finding pointing at the report itself is skipped (see the manual's ingestion section).

Under `--ci` the run is report-only: ingested findings are scanned, merged, and reported, and the run exits 1 if anything remains. To configure ingestion in `.credactor.toml` instead, add an `[ingest]` table (an empty path value is fatal, exit 2 — same as an empty flag):

```toml
[ingest]
from_gitleaks = "gitleaks.json"
from_trufflehog = "trufflehog.json"
```

> Report paths — on the flags and in `[ingest]` alike — resolve against the
> job's **working directory**, not the target or the config file's location.

## Automated Remediation (non-interactive)

`--ci` is a read-only gate and **cannot** be combined with `--fix-all`. To actually rewrite files in an unattended job, use `--fix-all` with `--yes` (`-y`) to skip the confirmation prompt. Without `--yes`, `--fix-all` aborts when stdin is not a TTY:

```bash
credactor --dry-run .          # preview first
credactor --fix-all --yes .    # then rewrite (writes .bak unless --no-backup)
```

**Regenerate the report after redacting.** An external report is a snapshot: re-running with a consumed report exits 1 (`Reported value not found …`), and findings whose files were renamed or deleted since the scan are dropped with a warning. After a `--fix-all` run that ingested a report, re-run the scanner before gating again — this is the natural failure mode of a two-step scan→redact pipeline.

## Configuration

See the [Manual](manual.md) for the full list of CLI flags, config options, and suppression mechanisms.
