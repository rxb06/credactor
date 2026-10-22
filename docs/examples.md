# Examples

## 1. First scan of a repo

Check for leaks before starting work:

```bash
credactor --dry-run /path/to/project
```

Shows findings without touching files. If you installed with pip into the
active environment, `python -m credactor` works too.

Gitignored files, usually including a local `.env`, are skipped when walking a
directory. The text report lists them under "not scanned -- covered by
.gitignore", but `-f json` and `-f sarif` say nothing about them. To check one,
name it directly: `credactor --dry-run .env`. A clean run means nothing matched
Credactor's rules, not that the code holds no secrets, and Credactor does not
check whether a secret is live.

```
Scanning: /path/to/project
  Note: Credactor scans forward (into subdirectories) only.
  For best results, point it at your project root directory.

======================================================================
  CREDENTIAL SCAN REPORT  --  5 finding(s) in 3 file(s)
======================================================================

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

  FILE: src/config.py
  ────────────────────────────────────────────────────────────
  Line   12  [CRITICAL]  [pattern:AWS access key]
           AWS_KEY = "AKIA[REDACTED]"
  Line   15  [HIGH]  [variable:db_password]
           db_password = "xK9#[REDACTED]"

======================================================================
  ACTION REQUIRED: Rotate/revoke any real credentials above.
  Use environment variables or a secrets manager instead.
======================================================================
```

## 2. Interactive cleanup

Review each finding and decide:

```bash
credactor /path/to/project
```

```
  [1/5]  deploy/settings.yaml  --  line 8
  Type     : pattern:connection string
  Severity : high
  Value    : post[REDACTED]

  Replace? [y/N]: y
  -> Replaced.
```

Before each file is changed, a `.bak` copy is written beside it. The backup
holds the original secret in plaintext, and Credactor does not add it to
`.gitignore`, so a plain `git add .` would stage it. Add `*.bak` and
`*.credactor.tmp` to `.gitignore` and delete the backups once you have checked
the result, or pass `--secure-backup-dir DIR` (outside the repository) on the
fix run.

## 3. Batch redact

Fix everything in one shot:

```bash
credactor --fix-all /path/to/project
```

`--fix-all` asks for one confirmation before it rewrites files:

```
  --fix-all will modify 3 file(s) with 5 replacement(s).
  .bak backups will be created (contain original secrets).
  Tip: run with --dry-run first to preview changes.
  Proceed? [y/N]: y
[WARN] Plaintext backup created beside original file.
  Use --secure-delete to auto-wipe, --secure-backup-dir to store outside repo, or --no-backup to skip.
======================================================================
  Summary:  5 replaced  |  0 failed  |  5 total
  Reminder: rotate / revoke any credentials that were just redacted.
  SECURITY: .bak backup files contain original credentials in PLAINTEXT.
            Use --secure-backup-dir to store backups outside the repo,
            or --secure-delete to overwrite backups after verification.
            At minimum, delete .bak files before committing.
======================================================================
```

In a script, CI job, or piped run there is no TTY to answer the prompt, so the run aborts. Pass `--yes` / `-y` to skip it:

```bash
credactor --fix-all --yes /path/to/project
```

## 4. Replace with env vars

```bash
credactor --fix-all --replace-with env /path/to/project
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

Language-aware: `.js` and `.ts` get `process.env["AWS_ACCESS_KEY"]`, `.go` gets `os.Getenv("AWS_ACCESS_KEY")`, `.rb` gets `ENV['AWS_ACCESS_KEY']`, Java and Kotlin get `System.getenv(...)`, and PHP gets `getenv(...)`. Every other file type gets a `${AWS_ACCESS_KEY}` placeholder, which is a real lookup only where something expands it (a shell script, a `.env` loader, many config tools). In C# it stays a plain string, and in Terraform it reads as a reference that does not exist, so the config fails to validate; use the sentinel for both.

Env mode writes the lookup, not the import: the Python "After" above only runs if the file already has `import os`, so add it (or your language's equivalent) if it is missing. The env-var name comes from the finding: a recognised provider key (the `AKIA…` pattern) maps to its canonical name (`AWS_ACCESS_KEY`), while a plain credential variable keeps its own name (`DB_PASSWORD`).

## 5. Pre-commit hook

Scan only staged files:

```bash
credactor --staged --ci
```

`.git/hooks/pre-commit`:

```bash
#!/bin/sh
credactor --staged --ci
```

With the pre-commit framework, use the published hook:

```yaml
repos:
  - repo: https://github.com/rxb06/credactor
    rev: v2.7.5
    hooks:
      - id: credactor
```

Then run `pre-commit install`. The framework installs credactor into its own
hook environment, so you do not need to install it first. This hook needs
pre-commit 3.2.0 or newer, and it never rewrites files.

If credactor is already installed (pip, uv tool or Homebrew) and you would
rather run that copy, use a local hook:

```yaml
repos:
  - repo: local
    hooks:
      - id: credactor
        name: credactor
        entry: credactor --staged --ci
        language: system
        pass_filenames: false
        always_run: true
```

(`language: system` runs the `credactor` on your PATH, so install it first with
pip, uv tool or Homebrew. `language: python` would not work for a
`repo: local` hook: the framework builds an isolated hook venv that does not
contain credactor, so every commit would fail.)

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

The simplest route is the project's own Action. It always runs with `--ci`, so
it never rewrites the checkout, and it fails the step on findings or errors:

```yaml
steps:
  - uses: actions/checkout@v7
  - uses: rxb06/credactor@v2.7.5
```

See [ci_integration.md](ci_integration.md) for every Action input and output,
including SARIF upload with `upload-sarif: true`.

The examples below call the CLI directly. Install it first:

```yaml
- uses: actions/checkout@v7
- name: Install Credactor
  run: pip install credactor
```

Fail on findings:

```yaml
- name: Credential scan
  run: credactor --ci .
```

Strict mode, which also fails if any files could not be scanned:

```yaml
- name: Credential scan
  run: credactor --ci --fail-on-error .
```

Upload SARIF to Code Scanning (includes line and column annotations). Leave
`--fail-on-error` off here: when it fires the run exits 2 before the report is
written, and the upload step cannot parse the empty file. Gate on it in a
separate step if you need it. The upload step needs write access to security
events, so give the job this permissions block:

```yaml
permissions:
  contents: read
  security-events: write
```

```yaml
- name: Credential scan
  run: credactor --ci --format sarif . > results.sarif
  continue-on-error: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```

Save JSON as artifact:

```yaml
- name: Credential scan
  run: credactor --ci --format json . > credential-report.json

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
credactor --scan-history .
```

```
  FILE: src/old_config.py (commit a1b2c3d4e5f6)
  ────────────────────────────────────────────────────────────
  Line   22  [CRITICAL]  [pattern:AWS access key]
           AWS_SECRET = "AKIA[REDACTED]"
```

Scans the 100 most recent file-changing commits and warns if the repository has more than 100 commits.
The scan is read-only: it never rewrites files, even with `--fix-all`. Findings
include the commit hash.

If you find credentials in history, redacting the working tree isn't enough. Use `git filter-repo` or BFG Repo Cleaner to rewrite history, and rotate the leaked credentials.

## 8. Suppress false positives

Inline:

```python
def test_api_validates_key():
    fake_key = "AKIAIOSFODNN7EXAMPLE"  # credactor:ignore
    response = client.post("/auth", headers={"X-API-Key": fake_key})
    assert response.status_code == 200
```

The marker works in a `#`, `//`, `/* */` or `<!-- -->` comment on the same
line. Findings ingested from a Gitleaks, TruffleHog or Betterleaks report
(Example 13) are filtered by `.credactorignore` only: an inline
`credactor:ignore` does not stop them.

Allowlist (`.credactorignore`):

```
# Test fixtures (glob; note ** behaves like *, since fnmatch has no globstar)
tests/fixtures/**
tests/data/*.py

# Known false positive at a specific line
# (positional only: re-check after large edits, the line can drift)
config/defaults.py:42

# Hash that looks like a credential (bare value literal)
a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4

# A value containing . / ? or * (base64, JWT, connection string) must use the
# explicit value: prefix, otherwise it is treated as a glob/path:
value:eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123
```

Value-literal and `file:line` suppressions are intentionally noisy. Credactor logs a warning at load time for each kind so they get reviewed for detection-bypass.

## 9. Include JSON files

JSON files are skipped when walking a directory (API responses cause too many
false positives). A `.json` file you name directly is always scanned.
With `--scan-json`, every collected `.json` file is scanned, in CI, dry-run,
and interactive mode alike.

```bash
credactor --ci --scan-json .     # read-only gate including JSON
credactor --scan-json .          # interactive: findings go straight
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

Picked up from the scan target or up to 5 parent directories, stopping at the project root. The nearest file wins and is the only one loaded. A config found above the project root is refused: an error is printed and the scan uses defaults. You can load one explicitly with `--config` outside CI, but under `--ci` an outside-root `--config` exits 2. An explicit `--config` that is missing or invalid also exits 2, while a discovered config that fails to parse only warns.

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

Redaction **refuses** key blocks (fail closed): `--fix-all` or an interactive
`y` on this finding warns and counts it unresolved (exit 1), rather than
rewriting only the header line, which would leave the key material in the
file while the next scan reports it clean. Rotate the key and remove the
block manually.

## 13. Ingest external scanner findings

Merge findings from Gitleaks, TruffleHog or Betterleaks into Credactor's redaction pipeline, so one tool both detects (across scanners) and redacts. Ingested findings are deduplicated against Credactor's native findings, keeping the higher severity.

```bash
# Run Gitleaks, then redact everything it (and Credactor) found
gitleaks dir . -f json -r gitleaks.json
credactor --from-gitleaks gitleaks.json --fix-all --yes .

# TruffleHog NDJSON output, report-only gate
trufflehog filesystem . --no-verification --json > trufflehog.json
credactor --from-trufflehog trufflehog.json --ci .

# Betterleaks JSON report (use `betterleaks dir`, not `betterleaks detect`)
betterleaks dir . -f json -r bl.json
credactor --from-betterleaks bl.json --dry-run .
```

Preview with `--dry-run` before running `--fix-all`, as for a native scan. A
report holds every secret it found in plaintext and is not scanned itself
(`.json` needs `--scan-json`), so write it outside the repository (for example
`gitleaks dir . -f json -r /tmp/gitleaks.json`) or delete it after the run.
Regenerate the report whenever the tree changes.

The target must be a **directory** (the repository root): file paths in the report are resolved relative to it, so a file target is rejected with exit 2. Ingestion also cannot be combined with `--scan-history`. Multi-line findings (PEM private keys) are never redacted by either path: native ones are refused, ingested ones fail the line-based value match (both warned, exit 1); rotate the key and remove the block manually (see Example 12).

Pin the report paths in `.credactor.toml` instead of passing the flags:

```toml
[ingest]
from_gitleaks = "gitleaks.json"
from_trufflehog = "trufflehog.json"
from_betterleaks = "bl.json"
```

If you pin the report paths here, keep the reports out of version control,
since they contain the secrets in plaintext.
