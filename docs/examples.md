# Examples

## 1. First scan of a repo

Check for leaks before starting work:

```bash
python -m credactor --dry-run /path/to/project
```

Shows findings without touching files.

```
Scanning: /path/to/project
  Note: Credactor scans forward (into subdirectories) only.
  For best results, point it at your project root directory.

======================================================================
  CREDENTIAL SCAN REPORT  --  5 finding(s) in 3 file(s)
======================================================================

  FILE: src/config.py
  ────────────────────────────────────────────────────────────
  Line   12  [CRITICAL]  [pattern:AWS access key]
           AWS_KEY = "AKIA[REDACTED]"
  Line   15  [HIGH]  [variable:db_password]
           db_password = "xK9#[REDACTED]"

  FILE: deploy/settings.yaml
  ────────────────────────────────────────────────────────────
  Line    8  [HIGH]  [pattern:connection string]
           database_url: "post[REDACTED]"

  FILE: src/auth.py
  ────────────────────────────────────────────────────────────
  Line   44  [CRITICAL]  [pattern:GitHub token]
           GITHUB_TOKEN = "ghp_[REDACTED]"
  Line   52  [HIGH]  [pattern:JWT token]
           refresh = "eyJh[REDACTED]"
```

## 2. Interactive cleanup

Review each finding and decide:

```bash
python -m credactor /path/to/project
```

```
  [1/5]  src/config.py  --  line 12
  Type     : pattern:AWS access key
  Severity : critical
  Value    : AKIA[REDACTED]

  Replace? [y/N]: y
  -> Replaced.
```

Creates `.bak` backups for every modified file.

## 3. Batch redact

Fix everything in one shot:

```bash
python -m credactor --fix-all /path/to/project
```

`--fix-all` asks for one confirmation before it rewrites files:

```
  --fix-all will modify 3 file(s) with 5 replacement(s).
  .bak backups will be created (contain original secrets).
  Tip: run with --dry-run first to preview changes.
  Proceed? [y/N]: y

======================================================================
  Summary:  5 replaced  |  0 failed  |  5 total
  Reminder: rotate / revoke any credentials that were just redacted.
======================================================================
```

In a script, CI job, or piped run there is no TTY to answer the prompt, so the run aborts. Pass `--yes` / `-y` to skip it:

```bash
python -m credactor --fix-all --yes /path/to/project
```

## 4. Replace with env vars

```bash
python -m credactor --fix-all --replace-with env /path/to/project
```

Before:

```python
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "s3cretP@ssw0rd"
```

After:

```python
AWS_KEY = os.environ["AWS_ACCESS_KEY"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
```

Language-aware: `.js` gets `process.env["AWS_ACCESS_KEY"]`, `.go` gets `os.Getenv("AWS_ACCESS_KEY")`, etc. The env-var name comes from the finding: a recognised provider key (the `AKIA…` pattern) maps to its canonical name (`AWS_ACCESS_KEY`), while a plain credential variable keeps its own name (`DB_PASSWORD`).

## 5. Pre-commit hook

Scan only staged files:

```bash
python -m credactor --staged --ci
```

`.git/hooks/pre-commit`:

```bash
#!/bin/sh
python -m credactor --staged --ci
```

Or with the pre-commit framework:

```yaml
repos:
  - repo: local
    hooks:
      - id: credactor
        name: credactor
        entry: python -m credactor --staged --ci
        language: python
        pass_filenames: false
        always_run: true
```

Clean output:

```
Scanning: /path/to/project

[OK] No hardcoded credentials detected at the current sensitivity (entropy floor 3.5). Review weak or short secrets manually.
```

Finding staged:

```
  FILE: src/new_feature.py
  ────────────────────────────────────────────────────────────
  Line    5  [CRITICAL]  [pattern:Stripe live key]
           STRIPE_KEY = "sk_l[REDACTED]"
```

Exit 1 blocks the commit.

## 6. GitHub Actions

Fail on findings:

```yaml
- name: Credential scan
  run: python -m credactor --ci .
```

Strict mode, which also fails if any files could not be scanned:

```yaml
- name: Credential scan
  run: python -m credactor --ci --fail-on-error .
```

Upload SARIF to Code Scanning (includes line and column annotations):

```yaml
- name: Credential scan
  run: python -m credactor --ci --fail-on-error --format sarif . > results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```

Save JSON as artifact:

```yaml
- name: Credential scan
  run: python -m credactor --ci --format json . > credential-report.json

- name: Upload report
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: credential-report
    path: credential-report.json
```

## 7. Git history scan

Find credentials in past commits (even if already removed from working tree):

```bash
python -m credactor --scan-history .
```

```
  FILE: src/old_config.py (commit a1b2c3d4e5f6)
  ────────────────────────────────────────────────────────────
  Line   22  [CRITICAL]  [pattern:AWS access key]
           AWS_SECRET = "AKIA[REDACTED]"
```

Scans last 100 commits. Findings include the commit hash.

If you find credentials in history, redacting the working tree isn't enough. Use `git filter-repo` or BFG Repo Cleaner to rewrite history, and rotate the leaked credentials.

## 8. Suppress false positives

Inline:

```python
def test_api_validates_key():
    fake_key = "AKIAIOSFODNN7EXAMPLE"  # credactor:ignore
    response = client.post("/auth", headers={"X-API-Key": fake_key})
    assert response.status_code == 200
```

Allowlist (`.credactorignore`):

```
# Test fixtures (glob; note ** behaves like * — fnmatch has no globstar)
tests/fixtures/**
tests/data/*.py

# Known false positive at a specific line
# (positional only — re-check after large edits, the line can drift)
config/defaults.py:42

# Hash that looks like a credential (bare value literal)
a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4

# A value containing . / ? or * (base64, JWT, connection string) must use the
# explicit value: prefix, otherwise it is treated as a glob/path:
value:eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123
```

Value-literal and `file:line` suppressions are intentionally noisy. Credactor logs a warning at load time for each kind so they get reviewed for detection-bypass.

## 9. Include JSON files

JSON is excluded by default (API responses cause too many false positives).
With `--scan-json`, every collected `.json` file is scanned, in CI, dry-run,
and interactive mode alike.

```bash
python -m credactor --ci --scan-json .     # read-only gate including JSON
python -m credactor --scan-json .          # interactive: findings go straight
                                           # to the per-finding Replace? prompt
```

## 10. Team config

`.credactor.toml`:

```toml
entropy_threshold = 3.0
min_value_length = 6

skip_dirs = ["third_party", "generated"]

extra_safe_values = ["test_token_abc_123", "mock_api_key_xyz"]

replacement = "TODO_REPLACE_WITH_ENV_VAR"
```

Picked up automatically from the scan target or any parent directory **up to the project root**. A config above the project root is refused unless passed explicitly with `--config` (non-CI).

## 11. XML config files

Detects credentials in XML attributes regardless of attribute order:

```xml
<configuration>
  <appSettings>
    <add key="DatabasePassword" value="s3cr3t-Db-P@ss-9XzQ" />
    <add value="my-ap1-k3y-secr3t" key="ApiKey" />
  </appSettings>
</configuration>
```

```
  FILE: web.config
  ────────────────────────────────────────────────────────────
  Line    3  [HIGH]  [xml-attr:DatabasePassword]
           <add key="DatabasePassword" value="s3cr[REDACTED]" />
  Line    4  [HIGH]  [xml-attr:ApiKey]
           <add value="my-a[REDACTED]" key="ApiKey" />
```

## 12. Private key detection

PEM blocks detected as a whole unit:

```python
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB...
-----END RSA PRIVATE KEY-----"""
```

```
  Line   1  [CRITICAL]  [pattern:private key block]
           PRIV[REDACTED]
```

Lines inside the block aren't scanned separately.

## 13. Ingest external scanner findings (BETA)

Merge findings from Gitleaks or TruffleHog into Credactor's redaction pipeline, so one tool both detects (across scanners) and redacts. Ingested findings are deduplicated against Credactor's native findings, keeping the higher severity.

```bash
# Run Gitleaks, then redact everything it (and Credactor) found
gitleaks dir . -f json -r gitleaks.json
python -m credactor --from-gitleaks gitleaks.json --fix-all --yes .

# TruffleHog NDJSON output, report-only gate
trufflehog filesystem . --no-verification --json > trufflehog.json
python -m credactor --from-trufflehog trufflehog.json --ci .
```

The target must be a **directory** (the repository root): file paths in the report are resolved relative to it, so a file target is rejected with exit 2. Ingestion also cannot be combined with `--scan-history`.

Pin the report paths in `.credactor.toml` instead of passing the flags:

```toml
[ingest]
from_gitleaks = "gitleaks.json"
from_trufflehog = "trufflehog.json"
```
