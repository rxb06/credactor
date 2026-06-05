# User Guide

> **Important:** Credactor uses regex and entropy heuristics. False positives are possible, especially with low-severity findings. Always review findings before redacting. Use `--dry-run` for a non-destructive scan, and suppress known false positives with `# credactor:ignore` or `.credactorignore`.

## Usage

```bash
# Dry run first — review before modifying anything
credactor --dry-run .

# Scan a specific path
credactor /path/to/project
credactor src/config.py
```

In interactive mode each finding is shown and you choose whether to redact it:

```
  [1/3]  src/config.py  --  line 12
  Type     : variable:api_key
  Severity : high
  Value    : sk_l[REDACTED]

  Replace? [y/N]:
```

## CLI Flags

### Mode

| Flag | Description |
|------|-------------|
| `--version` | Show version and exit |
| `--ci` | Read-only mode: report findings and exit 1. Blocks `--fix-all` and forces `--dry-run` |
| `--dry-run` | Show findings without modifying anything |
| `--fix-all` | Redact all findings without prompts (cannot combine with `--ci`) |
| `--staged` | Scan only git-staged files (read-only — forces dry-run) |
| `--scan-history` | Scan git commit history |

### Output

| Flag | Description |
|------|-------------|
| `--format text` | Human-readable with colours (default) |
| `--format json` | Machine-readable JSON |
| `--format sarif` | SARIF 2.1.0 for GitHub Code Scanning |
| `--no-color` | Strip ANSI codes |

### Replacement

| Flag | Description |
|------|-------------|
| `--replace-with sentinel` | Use `REDACTED_BY_CREDACTOR` (default) |
| `--replace-with env` | Language-appropriate env var lookup |
| `--replace-with custom` | Use your own string |
| `--replacement STRING` | The custom string |
| `--no-backup` | Skip `.bak` file creation |
| `--secure-backup-dir PATH` | Store `.bak` files in a directory outside the repo |
| `--secure-delete` | Overwrite `.bak` files with random data and delete after successful replacement |

### Configuration

| Flag | Description |
|------|-------------|
| `--config PATH` | Explicit config file path |
| `--scan-json` | Include `.json` files |
| `--fail-on-error` | Exit 2 if any files could not be scanned (e.g. permission errors) |
| `--verbose` / `-v` | Show detailed scan activity on stderr: suppressed findings, skipped files, safe-value decisions |

## Replacement Modes

### Sentinel (Default)

```python
# Before
api_key = "sk_live_abc123def456"
# After
api_key = "REDACTED_BY_CREDACTOR"
```

Fails loudly at runtime instead of silently passing a wrong value.

### Environment Variable

`--replace-with env` picks the right syntax per language:

```python
# Python
api_key = os.environ["API_KEY"]
```

```javascript
// JavaScript / TypeScript
const apiKey = process.env["API_KEY"];
```

```go
// Go
apiKey := os.Getenv("API_KEY")
```

```java
// Java / Kotlin
String apiKey = System.getenv("API_KEY");
```

```ruby
# Ruby
api_key = ENV['API_KEY']
```

```php
// PHP
$api_key = getenv('API_KEY');
```

```bash
# Shell / .env / YAML / TOML
API_KEY=${API_KEY}
```

### Custom

```bash
credactor --replace-with custom --replacement "TODO_REPLACE_ME"
```

## Detection

| Category | Examples | Severity |
|----------|----------|----------|
| Cloud provider keys | AWS (`AKIA...`), GCP (`AIza...`), Stripe (`sk_live_...`), Slack (`xoxb-...`) | Critical |
| Platform tokens | GitHub (`ghp_`, `github_pat_`), GitLab (`glpat-`), npm (`npm_`), PyPI (`pypi-`) | Critical |
| Private keys | PEM blocks (`-----BEGIN RSA PRIVATE KEY-----`) | Critical |
| JWT tokens | `eyJ...` three-segment tokens | High |
| Connection strings | `postgresql://user:pass@host`, `mongodb+srv://...` | High |
| Variable assignments | `password = "..."`, `api_key = "..."` | High/Medium |
| XML attributes | `<add key="Password" value="..." />` | High |
| High-entropy strings | Hex (32–64 chars), Base64 (60+ chars) | Medium/Low |

### Severity Levels

| Level | Colour | Triggers |
|-------|--------|----------|
| Critical | Red | Deterministic match — provider prefix, PEM key. Near-zero false positives. |
| High | Red | Strong match — JWT, connection string, high-entropy password variable. |
| Medium | Yellow | Heuristic — hex string, Stripe test key, generic credential variable. |
| Low | Cyan | Weak heuristic — long Base64. Higher false positive rate. |

## Suppression

### Inline

Append `credactor:ignore` in any comment style:

```python
test_key = "abc123"  # credactor:ignore
```

```xml
<!-- credactor:ignore -->
<add key="Password" value="test_only" />
```

### Allowlist

`.credactorignore` supports these entry types:

```
# Glob patterns — suppress entire files
tests/fixtures/**
**/testdata/*.py

# File:line — suppress a specific line (positional; see note below)
src/config.py:42

# Value literals — suppress a value anywhere
test_fixture_token_value

# Explicit value literal — required for values containing . / ? * (base64,
# JWTs, connection strings), which would otherwise be read as a path/glob
value:aB3/xY9+zQ==.eyJhbGci
```

> **`file:line` is positional.** It matches by line number only — the value is
> not checked. If edits move a *different* secret onto a suppressed line it is
> silently suppressed, so re-check `file:line` entries after large changes (or
> use a `value:` literal instead). Credactor logs how many positional `file:line`
> suppressions are active on each run.

> **Unprefixed entries containing `. / ? *`** are treated as file paths/globs,
> not value literals. To allowlist a *value* with those characters, use the
> `value:` prefix.

### Suppression Audit Trail

Use `--verbose` to see every suppression decision on stderr:

```bash
credactor --verbose --dry-run .
```

Output includes `[SKIP]` lines with the reason:

```
  [SKIP] src/config.py:12 suppressed by inline credactor:ignore
  [SKIP] src/test_data.py suppressed by allowlist (file-level)
  [SKIP] src/app.py:45 suppressed by safe value heuristic
  [SKIP] src/db.py:8 suppressed by hash context
```

This is useful for auditing what Credactor chose NOT to flag — especially in CI where you want a complete record.

## Scanned File Types

`.py` `.js` `.ts` `.jsx` `.tsx` `.sh` `.bash` `.env` `.env.*` `.cfg` `.ini` `.toml` `.yaml` `.yml` `.rb` `.go` `.java` `.php` `.cs` `.kt` `.tf` `.hcl` `.conf` `.properties` `.xml`

JSON files are excluded by default due to high false-positive rates from API response data. Use `--scan-json` to include them.

## Auto-Skipped

**Directories:** `.git`, `__pycache__`, `node_modules`, `.venv`, `venv`, `.tox`, `dist`, `build`

**Files:** `package-lock.json`, `yarn.lock`, `poetry.lock`, `pnpm-lock.yaml`

**Values:** placeholders (`your_api_key`, `changeme`), env var references (`$VAR`, `${VAR}`), function calls, file paths, URLs without credentials, dynamic lookups (`os.getenv()`, Vault/SOPS refs)

## Backup and Safety

### How Backups Work

When Credactor replaces a credential in a file, it first creates a `.bak` copy of the original. This is your safety net — if a replacement goes wrong, you can restore the original.

```
src/config.py          ← modified (credential replaced)
src/config.py.bak      ← original (still contains the plaintext credential)
```

The replacement itself uses **atomic writes**: Credactor writes to a temporary file (`.credactor.tmp`), then renames it over the original in a single OS operation. If the process crashes mid-write, the original file is untouched. The temp file is cleaned up automatically via a `finally` block.

> **Note:** When backups are created without `--secure-delete` or `--secure-backup-dir`, Credactor prints a one-time warning reminding you that plaintext credentials remain on disc. Use `--secure-delete` to auto-wipe, `--secure-backup-dir` to store outside the repo, or `--no-backup` to skip backups entirely.

### Backup Modes

| Flag | Backup created? | Where? | Auto-deleted after replacement? |
|------|----------------|--------|--------------------------------|
| *(default)* | ✅ | `.bak` beside original | ❌ You must delete manually |
| `--secure-backup-dir /path` | ✅ | In `/path` (outside repo) | ❌ You must delete manually |
| `--secure-delete` | ✅ | `.bak` beside original | ✅ Overwritten with random bytes, then deleted |
| `--secure-backup-dir /path --secure-delete` | ✅ | In `/path` | ✅ Overwritten with random bytes, then deleted |
| `--no-backup` | ❌ | — | N/A |

### Recovering from Accidental Redaction

If you still have the `.bak` file:

```bash
# See what changed
diff src/config.py.bak src/config.py

# Restore the original
mv src/config.py.bak src/config.py
```

If you used `--no-backup` or `--secure-delete`, the original is gone. Your options:

```bash
# If not yet committed — restore from git
git checkout -- src/config.py

# If the pre-redaction version was committed
git show HEAD:src/config.py
```

### Will `.bak` Files Leak into Git?

No — Credactor's `.gitignore` includes `*.bak` and `*.credactor.tmp`. These files are ignored by default and will not appear in `git status` or get staged by `git add .`.

However, an explicit `git add --force *.bak` would override `.gitignore`. If you are worried about this:

- Use `--secure-delete` to auto-wipe backups after replacement
- Use `--secure-backup-dir /tmp/credactor-bak` to keep backups outside the repo
- Use `--no-backup` if you are confident and have git history as your safety net

### What `--secure-delete` Does

1. Reads the backup file's size
2. Overwrites the entire file with `os.urandom()` bytes (cryptographically random)
3. Calls `fsync()` to flush to disc
4. Deletes the file with `os.unlink()`

This prevents recovery of the plaintext credentials from the backup, even with disc forensics tools.

### Other Protections

- **File permissions preserved** — original `chmod` bits restored after replacement
- **Encoding auto-detected** — UTF-8, Latin-1, UTF-16 handled; round-trip safe with `surrogateescape`
- **UTF-8 BOM handled** — stripped before scanning, preserved in output
- **Bottom-to-top replacement** — line numbers stay correct when multiple credentials are in one file
- **Credential masking** — all output formats show only the first 4 characters. `full_value` never appears in logs, reports, or error messages
- **Crash-safe temp files** — `.credactor.tmp` files are cleaned up in a `finally` block even if the process crashes
- **Symlink boundary enforcement** — file symlinks resolving outside the scan root are skipped
- **SARIF output sanitised** — finding metadata is HTML-escaped to prevent injection in downstream consumers

## Output Formats

### Text

```
======================================================================
  CREDENTIAL SCAN REPORT  --  3 finding(s) in 1 file(s)
======================================================================

  FILE: src/config.py
  ────────────────────────────────────────────────────────────
  Line   12  [CRITICAL]  [pattern:AWS access key]
           api_key = "AKIA[REDACTED]"
  Line   15  [HIGH]  [variable:password]
           db_password = "xK9#[REDACTED]"
```

### JSON

```json
{
  "findings": [
    {
      "file": "src/config.py",
      "line": 12,
      "type": "pattern:AWS access key",
      "severity": "critical",
      "value": "AKIA[REDACTED]",
      "commit": null
    }
  ],
  "count": 1
}
```

### SARIF

SARIF 2.1.0 output for GitHub Code Scanning, VS Code SARIF Viewer, or any compatible tool. Includes precise line and column ranges for accurate code annotations.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No findings, or all resolved |
| `1` | Unresolved findings |
| `2` | Error, or files skipped with `--fail-on-error` |

## Not Flagged

These are treated as safe automatically:

- Placeholder values: `your_api_key`, `changeme`, `placeholder`, `TODO`, `change_this`
- Test/mock values: `test_password`, `mock_api_key`, `fake_secret`
- Env var references: `$VAR`, `${VAR}`, `os.getenv("KEY")`, `process.env.KEY`
- Template variables: `{{ vault_password }}`, `${SECRET}`, `{%...%}`
- Dynamic lookups: `config.get()`, `Variable.get()`, `keyring.get_password()`, Vault, SOPS, Doppler, 1Password (`op://`)
- Property access: `self.config.password`, `context.settings.apiKey`, `this.props.secret`
- Function calls: `get_secret()`, `generate_password(length, symbols)`
- Terraform references: `var.password`, `local.secret`, `module.db.password`, `data.*`
- Hash/digest variables: `password_hash`, `api_key_checksum`, `token_digest`
- Hash values: bcrypt (`$2b$...`), argon2 (`$argon2id$...`)
- File paths: `/home/user/.ssh/key`, `./config/secret.yaml`
- URLs without credentials: `https://api.example.com/v1/endpoint`
- Function definitions: `def get_password(self, password="default"):`
- IDE directories: `.idea/`, `.vscode/`, `.vs/`
- Low-entropy values (below 3.5 bits/char by default)
- Short values (under 8 characters)
- Already-redacted values: `REDACTED_BY_CREDACTOR`

If you encounter a false positive not listed above, suppress it with `# credactor:ignore` on the line or add the file pattern to `.credactorignore`. Consider [opening an issue](https://github.com/rxb06/Credactor/issues) so it can be fixed for everyone.
