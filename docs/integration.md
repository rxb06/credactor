# Integration Guide

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
  - repo: https://github.com/rxb06/Credactor
    rev: v2.3.3  # pin to a release tag
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

`--ci` exits 1 on findings, blocking the commit. `--staged` scans only staged files and is **read-only** — it forces dry-run, so no files are modified or backed up even if `--fix-all` is also passed.

## CI Pipeline

### GitHub Actions

Basic — fail on findings:

```yaml
- name: Credential scan
  run: credactor --ci .
```

Strict — also fail if files could not be scanned:

```yaml
- name: Credential scan
  run: credactor --ci --fail-on-error .
```

SARIF upload to Code Scanning:

```yaml
- name: Credential scan
  run: credactor --ci --fail-on-error --format sarif . > results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```

Use `--verbose` in CI to log suppressed findings for audit trails.

### GitLab CI

```yaml
credential-scan:
  script:
    - credactor --ci --fail-on-error --format json . > credential-report.json
  artifacts:
    reports:
      codequality: credential-report.json
  allow_failure: false
```

### Generic

```bash
credactor --ci .
credactor --ci --fail-on-error .  # strict mode
```

### CI Security Notes

- `--ci` is read-only by design — it blocks `--fix-all` and forces `--dry-run`.
- `.credactor.toml` files discovered *implicitly* outside the project root are refused (SEC-29 / M14): in CI they are always refused; in non-CI you can still load one by pointing `--config` at it explicitly.
- `--fail-on-error` ensures files skipped due to permissions are not silently ignored.

## Configuration

See the [User Guide](user-guide.md) for the full list of CLI flags, config options, and suppression mechanisms.
