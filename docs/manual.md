# Credactor Manual

Complete reference for every flag, mode, and combination. 
Reflects Credactor 2.5.0 (unreleased; see the [CHANGELOG](../CHANGELOG.md)). For limitations and safe usage see the
[Disclaimer](DISCLAIMER.md); for the threat model see [Security](security.md).

---

## Synopsis

```
credactor [options] [target]
```

- `target` — a **directory** or a **single file** to scan. Default: `.` (current
  directory). A directory is walked recursively; a single named file is scanned
  directly even if its extension is not in the default scan list.
- With no mode flag, Credactor runs **interactive** mode (prompts per finding).

```bash
credactor .                 # interactive scan of the current directory
credactor --dry-run src/    # preview only
credactor path/to/file.py   # scan one file
```

---

## Flag quick reference

| Flag | Group | Effect |
|------|-------|--------|
| `--version` | — | Print version, exit 0 |
| `-h`, `--help` | — | Print help, exit 0 |
| `--ci` | mode | Read-only gate: report, exit 1 on findings, no prompts; **forces `--dry-run`**, **blocks `--fix-all`** |
| `--dry-run` | mode | Report findings, modify nothing |
| `--fix-all` | mode | Batch-redact all findings after one confirmation |
| `--yes`, `-y` | mode | Skip the `--fix-all` confirmation (required non-interactively) |
| `--staged` | mode | Scan only git-staged files; **read-only (forces dry-run)** |
| `--scan-history` | mode | Scan up to 100 commits of git history; **read-only (forces dry-run)** |
| `--format`, `-f` | output | `text` (default) \| `json` \| `sarif` |
| `--no-color` | output | Strip ANSI colour from text output |
| `--replace-with` | replace | `sentinel` (default) \| `env` \| `custom` |
| `--replacement` | replace | The replacement string for `sentinel`/`custom` |
| `--no-backup` | replace | Do not create `.bak` backups |
| `--secure-backup-dir DIR` | replace | Move `.bak` backups into `DIR` |
| `--secure-delete` | replace | Wipe `.bak` backups after redaction |
| `--config PATH` | config | Use an explicit `.credactor.toml` |
| `--scan-json` | config | Also scan `.json` files |
| `--fail-on-error` | config | Exit 2 if any file could not be scanned |
| `--verbose`, `-v` | config | Log scan/suppression activity on stderr |
| `--from-gitleaks FILE` | ingest (BETA) | Ingest a Gitleaks JSON report |
| `--from-trufflehog FILE` | ingest (BETA) | Ingest a TruffleHog NDJSON report |

---

## Detection & severity

Every finding carries a severity, used for triage. Verified assignments (scan
with `-f json` and read the `severity` field):

| Severity | What earns it | Examples (verified) |
|----------|---------------|---------------------|
| **critical** | Deterministic provider prefixes and PEM private-key blocks — unambiguous, **no entropy floor** | AWS `AKIA…`, GCP `AIza…`, Stripe live `sk_live_…`, GitHub `ghp_`/`github_pat_`, GitLab `glpat-`, Slack `xox…`, npm `npm_`, PyPI `pypi-`, `-----BEGIN … PRIVATE KEY-----` |
| **high** | JWTs, connection strings, and credential variables whose name implies a secret | `eyJ…` JWT, `postgresql://user:pass@host`, `password`/`api_key`/`token`/`secret_key`/`access_key` `= …` |
| **medium** | Heuristic value matches and generic credential variables | quoted hex (32–64 chars), Stripe **test** key `sk_test_…`, `webhook_secret = …` |
| **low** | Weak heuristics and ID-type variables | quoted Base64 (≥60 chars), `client_id` / `tenant_id` / `app_id` |

In text output, severities are colour-coded — critical **bright magenta**
(distinct from high so the top two severities differ at a glance), high
**red**, medium **yellow**, low **cyan** (`--no-color`, or a non-terminal
stdout, disables this).

### Entropy model

- **Deterministic matches have no entropy floor.** Provider prefixes and PEM
  blocks flag regardless of randomness — a *format-valid placeholder also flags*
  (suppress via `.credactorignore`). Verified: a `ghp_…` token is found even with
  `entropy_threshold = 6.0`. These are also scanned **inside comments**, so a
  commented-out live-shaped key is still caught.
- **Each heuristic value detector has its own fixed floor, independent of the
  config threshold:** JWT 3.3, connection string 2.5, hex 3.5, Base64 3.8,
  Stripe-test 3.0 (bits/char). Verified: a JWT and a connection string are still
  found with `entropy_threshold = 6.0`. Unlike the deterministic matches, these
  are **not** scanned inside comments.
- **`entropy_threshold` (default 3.5) gates only variable-assignment and
  XML-attribute findings** — those caught by the *variable name* rather than a
  value pattern. Password-family variables (`password`, `passwd`, `passphrase`,
  `private_key`, `secret_key`) use a lower floor of `min(entropy_threshold, 3.0)`:
  verified, `password = "Summer2024!"` (entropy ≈ 3.1) is flagged **high** even at
  `entropy_threshold = 6.0` (the floor clamps at 3.0) — a memorable password
  below the default 3.5 is still caught.

Standalone hex/Base64 fires **only when the value is quoted**; an unquoted
high-entropy value is caught only when assigned to a credential-named variable
(verified: unquoted hex on `api_key = …` → `variable:api_key`; the same value
bare → nothing). This deliberately spares unquoted git SHAs and checksums.

---

## Scan modes

Exactly one *behaviour* applies per run; the precedence/forcing rules are in
[Flag combinations](#flag-combinations--precedence).

### Interactive (default)

`credactor <target>` with no mode flag walks each finding and prompts
`Replace? [y/N]`. `y` redacts that finding (creating a `.bak`), `n`/Enter skips.
Requires a TTY — piped stdin is rejected with exit 1 (use `--dry-run`/`--ci`
to report, or `--fix-all --yes` to redact unattended). Git Bash/mintty on
Windows is seen as a pipe by native Python; run `winpty credactor …` there.
Exit code is **1** if any finding is left unresolved, and **0** if all are
resolved or none were found.

Each finding is shown before its prompt (verified output):

```text
  [1/2]  config.py  --  line 1
  Type     : pattern:Stripe live key
  Severity : critical
  Value    : sk_l[REDACTED]

  Replace? [y/N]:
```

`y`/`yes` prints `-> Replaced.`; `n`/Enter prints `-- Skipped.`; Ctrl-C or EOF
stops and reports how many replacements were already applied.

### `--dry-run`

Reports findings and **modifies nothing**. Verified: a directory with one secret
exits **1** and the file is unchanged; a clean directory exits **0**.

```bash
credactor --dry-run .          # exit 1 if anything found, 0 if clean
```

### `--ci`

Pipeline gate. Forces read-only (`--dry-run`), suppresses prompts, exits 1 on
findings. Verified: `--ci` on a secret exits **1** and leaves the file unchanged.
**`--ci` + `--fix-all` is rejected with exit 2** (read-only by design).

```bash
credactor --ci .                       # exit 1 on findings, 0 clean
credactor --ci --fail-on-error .       # also exit 2 if files were unreadable
```

### `--fix-all` (+ `--yes`)

Batch-redacts every finding in one pass. Prints a summary and asks for **one**
confirmation (`Proceed? [y/N]`) before writing. Verified:

- `--fix-all --yes` redacts the secret and exits **0** (no per-finding prompts).
- Without `--yes`, a non-TTY stdin (pipe / CI / `</dev/null`) **aborts** — pass
  `--yes` to proceed unattended.
- ⚠ `--fix-all` acts on **every** finding, including false positives — see
  [Limitations](#limitations). Always `--dry-run` first.

```bash
credactor --fix-all .            # interactive confirm, then redact
credactor --fix-all --yes .      # unattended (CI / scripts)
```

### `--staged`

Scans only files staged in git (`git diff --cached`), reading the **staged index
blob**. **Read-only: it forces dry-run even with `--fix-all`** (a pre-commit hook
must never rewrite the tree mid-commit). Verified: `--staged --fix-all --yes` on a
staged secret exits **1** and leaves the working file **unmodified**. In a
non-git directory it exits **2** (see below).
Staged content gets the identical full scan as a working-tree file — PEM
blocks and secrets inside triple-quoted / template-literal strings included.
Staged `.json` files follow the same opt-in as the directory walk: scanned only
with `--scan-json`, otherwise skipped with a warning naming the file.

```bash
credactor --staged --ci          # canonical pre-commit gate
```

### `--scan-history`

Scans up to 100 commits of `git log -p`, reporting the commit hash where each
secret was introduced. Verified: finds a secret that was committed then removed
from the working tree. In a non-git directory it exits **2**.
On a repository deeper than 100 commits a `[WARN]` states that only the most
recent 100 were scanned — a truncated scan is never silently presented as a
full-history all-clear. The exit code is unaffected by the notice.
**Read-only: it forces dry-run even with `--fix-all`** — history findings
reference committed content, not files on disk, so they cannot be redacted in
place. To purge a committed secret, rewrite history (e.g. `git filter-repo`)
and rotate the key.

```bash
credactor --scan-history .
```

> **Non-git hard error:** `--staged` and `--scan-history` exit **2** when the
> target is not a git repository (verified) — a deliberate guard against a
> false-clean exit 0. `--scan-history` still works on a *bare* repository.

---

## Replacement strategies

Apply to `--fix-all` and interactive redaction. Verified outputs for the line
`api_key = "ghp_…"`:

| `--replace-with` | result | notes |
|------------------|--------|-------|
| `sentinel` (default) | `api_key = "REDACTED_BY_CREDACTOR"` | fails loudly at runtime; stays quoted |
| `env` | `api_key = os.environ["GITHUB_TOKEN"]` | language-aware reference (quotes consumed) |
| `custom` (+`--replacement X`) | `api_key = "X"` | your own string |

- **`--replacement` works in `sentinel` mode too** — it overrides the sentinel
  string (verified: `--replacement JUSTREPL` → `api_key = "JUSTREPL"`).
- **Env-mode variable naming derives from the finding**, not always the variable
  name: a *variable* finding `api_key = …` → `os.environ["API_KEY"]`; a *pattern*
  finding (a `ghp_…` token) → `os.environ["GITHUB_TOKEN"]`. Verified for Python
  (`os.environ[...]`), JS (`process.env[...]`), Ruby (`ENV[...]`); Java/Go/PHP
  forms are covered by the test suite.
- **Replacement is validated** (allowlist `[A-Za-z0-9_-]+`): a dangerous value
  (`bad;rm -rf`, markup, newlines, control chars) is **rejected with exit 2**
  (verified). This guards against injection into rewritten files. An **empty**
  `--replacement` (e.g. from an unset shell variable) is **also rejected with
  exit 2**: the allowlist requires `+` (one or more), so an empty value cannot
  silently excise the secret with no marker.
- Env-mode output is syntactically valid: a redacted `.py`/`.js`/`.rb` still
  parses (verified). Note it emits an env **reference** (e.g. `os.environ["KEY"]`),
  not the import it needs — add the matching import (e.g. `import os`) if the file
  doesn't already have one, or it will raise `NameError` at runtime.
- **Env mode falls back to the sentinel** when a finding is not a standalone
  quoted assignment — a bare token on its own line, or a secret embedded in a
  larger string (a `Bearer` header, a connection URL): inserting a code
  expression there would break syntax, so the value becomes
  `REDACTED_BY_CREDACTOR` instead. This sentinel fallback applies to the
  **language file types** (`.py`, `.js`, `.rb`), whose env reference is a code
  expression (`os.environ[…]`, `process.env[…]`, `ENV[…]`). In
  shell/config/plain-text file types (`.sh`, `.env`, `.yaml`, `.txt`) the env
  reference is the shell-style `${VAR}` form, which is valid in place, so a bare
  token there is rewritten to `${VAR}` (e.g. `${GITHUB_TOKEN}`) — and a quoted
  assignment keeps its quotes (`token = "${GITHUB_TOKEN}"`) — rather than the
  sentinel. Such findings still count as *replaced*.
  The duplicate-copy sweep also uses the sentinel in env mode, so a single
  env-mode run can legitimately leave a mix of `os.environ[…]` / `${…}` and
  sentinel styles in one file.
- **The duplicate-copy sweep never overrides an adjudication.** When a
  rewritten file still holds exact copies of a redacted value beyond the
  adjudicated findings (e.g. a detector deduplicated a repeated value, or a
  second occurrence sits on the finding's own line), they are cleared in the
  same pass and a `[WARN]` states how many. Adjudication owns the **line**:
  answering `n` in interactive review preserves that finding's whole line —
  including any copy of a *different* redacted value on it (recoverable from
  the `.bak`) — and the `replaced/skipped` summary always matches the file
  state. Two same-value findings on one line are prompted **once**; the
  answer covers every occurrence there. One edge: when a line carries both a
  skipped and an approved finding, the approval releases the line for the
  sweep of *approved* values (disclosed by the `[WARN]`) — the skipped
  finding's own value is never cleared.

---

## Backup & safety

By default Credactor writes a `.bak` copy of each modified file before changing
it. Verified behaviour:

| Flags | `.bak` beside file? | backup location | after redaction |
|-------|--------------------|------------------|-----------------|
| *(default)* | yes (contains the original secret) | next to the file | kept — delete manually |
| `--no-backup` | **no** | — | original is lost unless in git |
| `--secure-backup-dir DIR` | no | written into `DIR` as `<name>.<hash>.bak` | kept in `DIR` |
| `--secure-delete` | created then wiped | next to the file | overwritten with random bytes, deleted |

- **`--secure-backup-dir` fails closed.** If the directory is unwritable, or its
  path resolves through a symlink (leaf or any ancestor), Credactor refuses to
  leave an in-repo plaintext `.bak` — it **skips the file** (no backup, no
  redaction) and exits 1. Verified: a symlinked backup dir leaves the source
  file unredacted.
- `.bak` files contain the secret in **plaintext** — general scanners will flag
  them. Use `--secure-delete` or `--secure-backup-dir` (outside the repo) for a
  clean tree.

```bash
credactor --fix-all --secure-delete .                 # redact, wipe backups
credactor --fix-all --secure-backup-dir /tmp/cred-bak .
```

### Recovering an over-redaction

The `.bak` is your undo (verified):

```bash
diff src/config.py.bak src/config.py   # see exactly what changed
mv   src/config.py.bak src/config.py   # restore the original
```

With `--secure-backup-dir DIR`, the backup lives in `DIR` rather than beside the
file, and its name carries a short hash of the original path
(`config.py.<hash>.bak`) so two files with the same basename in different
directories never overwrite each other's backup. Recover by matching on that
basename (use `diff` to confirm the right copy before restoring):

```bash
ls DIR/config.py.*.bak                          # find the backup(s) for that file
diff DIR/config.py.<hash>.bak src/config.py     # confirm it is the right copy
cp   DIR/config.py.<hash>.bak src/config.py     # restore the original
```

With `--no-backup` or `--secure-delete` there is no `.bak` — recover from git:
`git checkout -- <file>` (uncommitted) or `git show HEAD:<file>` (committed).

### `.bak` files and git

The shipped `.gitignore` lists `*.bak` and `*.credactor.tmp` (`.gitignore:39,42`),
so backups and crash-residue temp files aren't staged by `git add .`. They still
hold **plaintext**, so a `git add --force` or a general secret scanner will
surface them — use `--secure-delete` or `--secure-backup-dir` (outside the repo)
for a clean tree.

### What `--secure-delete` does

On a successful redaction the `.bak` is overwritten with `os.urandom()` bytes,
`fsync`'d, then unlinked (`redactor.py:254`). Verified: no `.bak` remains
afterwards. It is wiped only when at least one replacement actually landed, and a
single-pass overwrite is **not** a forensic guarantee on copy-on-write / SSD /
journaling filesystems.

### Other safety properties (verified)

- **Atomic writes** — both the backup and the rewrite go through a temp file then
  `os.replace`, cleaned up in a `finally`; a mid-write crash leaves the original
  intact (`redactor.py:393`, backup at `:197`).
- **Permissions preserved** — a `chmod 600` file stays `600` after redaction.
- **Multiple secrets per file** — replaced bottom-to-top so line numbers stay
  valid.
- **Masking** — output shows only the first 4 characters (`AKIA[REDACTED]`); the
  full secret never appears in text, JSON, or SARIF.
- **Symlink boundary** — a file symlink resolving outside the scan root is
  skipped.
- **Encoding** — UTF-8 (including BOM), Latin-1, and UTF-16 with an
  ASCII-dominant payload (with or without BOM — recognised by its NUL
  byte-parity signature) work out of the box. ⚠ Other encodings (e.g. UTF-32,
  mixed-script UTF-16) need the optional `charset-normalizer` (`[encoding]`)
  extra (`pip install 'credactor[encoding]'`). Without it such a file is read
  as Latin-1 and its secrets can be missed — but Credactor prints a `[WARN]`
  whenever it cannot confirm a file's encoding and falls back to Latin-1, so
  the miss is not silent. A file whose detected multibyte encoding fails to
  decode mid-stream (e.g. truncated UTF-16) is treated as unreadable: warned,
  counted for `--fail-on-error`, never a silent all-clear. Install the extra
  for reliable detection on a non-UTF-8 codebase.

---

## Output formats

### `--format text` (default)

Human-readable report; the credential is masked to its first 4 characters +
`[REDACTED]`. `--no-color` strips ANSI codes (auto-disabled when stdout is not a
terminal). Verified output:

```text
======================================================================
  CREDENTIAL SCAN REPORT  --  2 finding(s) in 1 file(s)
======================================================================

  FILE: config.py
  ────────────────────────────────────────────────────────────
  Line    1  [CRITICAL]  [pattern:Stripe live key]
           api_key = "sk_l[REDACTED]"
  Line    2  [HIGH]  [variable:password]
           password = "Tr0u[REDACTED]"
```

### `--format json`

Machine-readable. Verified top-level keys: `findings`, `count`; each finding:
`file`, `line`, `type`, `severity`, `value` (masked), `commit`. The full secret
never appears (verified — masked in JSON and SARIF).

```bash
credactor --ci -f json . > findings.json
```

### `--format sarif`

SARIF **2.1.0** for GitHub Code Scanning. Verified: valid document
(`version` `2.1.0`, `runs[].tool.driver.name = Credactor`, `runs[].results`),
with column-level regions (`startColumn`/`endColumn`).

```bash
credactor --ci -f sarif . > results.sarif
```

> In non-CI, non-text runs Credactor reports and exits 1 (it does not enter
> interactive redaction with JSON/SARIF output). With an explicit `--fix-all`
> it redacts: stdout stays a single parseable JSON/SARIF document and the
> confirmation/summary text goes to stderr.

---

## Configuration

### `.credactor.toml`

Searched in the target directory and up to **5 parent directories** (stopping at
the project root). A config discovered **outside** the project root is refused
unless passed explicitly with `--config` (and always refused under `--ci`).
Verified keys:

| Key | Effect |
|-----|--------|
| `entropy_threshold` | Float 0.0–6.0 (default 3.5). Does **not** apply to deterministic provider prefixes — verified: `entropy_threshold = 6.0` still finds a `ghp_…` token. |
| `min_value_length` | Int 1–200 (default 8). Like `entropy_threshold`, does **not** apply to deterministic provider prefixes or PEM blocks (their regexes pin their own length — a `ghp_…` token is found even at 200); gates heuristic and assignment values only. Verified: a generic password assignment is suppressed at 200. |
| `skip_dirs` | List of directory names to skip (case-sensitive). |
| `skip_files` | List of file names to skip. Verified: `skip_files = ["app.py"]` → 0 findings. |
| `extra_extensions` | List of extra extensions to scan (lowercased; warn if a leading dot is missing). |
| `extra_safe_values` | List of values to never flag (case-insensitive). |
| `replacement` | Default custom replacement (an explicit `--replacement` wins). |
| `[ingest]` `from_gitleaks` / `from_trufflehog` | Report paths for ingestion. |

An unknown top-level key is ignored **with a warning** (typo guard — e.g. a
misspelled `entropy_treshold` does not silently scan at the default
sensitivity).

### `--config PATH`

Use a specific config file (verified: `--config cfg.toml` with
`min_value_length = 200` suppresses a generic password assignment). An explicit `--config` is honored
even outside the project root (non-CI). A `--config` path that cannot be
honored — it does not exist, is not a file, is unreadable, or contains invalid
TOML — is a **fatal error, exit 2**; it is never silently ignored. (A
*discovered* `.credactor.toml` that fails to parse is a different case: it
warns and the scan falls back to defaults, so a stray broken config elsewhere
in the tree never aborts a scan.)

### `--scan-json`

`.json` files are **not scanned by default** (high false-positive rate from API
data). Verified: a secret in a `.json` is found **only** with `--scan-json`
(0 → 1).

### Scanned file types

During a directory walk only these extensions are read:

`.py` `.js` `.ts` `.jsx` `.tsx` `.sh` `.bash` `.env` `.env.*` `.cfg` `.ini`
`.toml` `.yaml` `.yml` `.rb` `.go` `.java` `.php` `.cs` `.kt` `.tf` `.hcl`
`.conf` `.config` `.properties` `.xml` `.pem` `.key` `.crt` `.txt`

plus SSH / private-key files matched by name (`id_rsa`, `id_dsa`, `id_ecdsa`,
`id_ed25519`). `.json` is read only with `--scan-json` (in directory walks and
`--staged` alike). A file named **directly** on the command line is scanned
even if its extension is not in this list.

> **`.env.*` is a literal-filename rule, not an extension rule:** it matches
> dotfiles *named* `.env.<anything>` (`.env.production`, `.env-local`). A file
> like `x.env.production` has the extension `.production` and is **not**
> scanned in a walk — name it directly or add the extension via
> `extra_extensions`.

### `--fail-on-error`

Exit **2** if any file could not be scanned (permissions, encoding). Verified:
a directory whose only file is unreadable exits **0** without the flag (a warning
only) and **2** with it.

### `--verbose` / `-v`

Logs scan activity to stderr, including why findings were suppressed. Verified
sample: `[SKIP] …/app.py:2 suppressed by inline credactor:ignore`. Suppression
breadcrumbs name the kind: `inline`, `allowlist
(file-level|glob|file:line|value-literal)`, `safe value heuristic`, or
`hash context`. A whole-file allowlist match in a directory walk logs
`file-level`; the same entry matching on the per-line path logs `glob`.

---

## Suppression

### Inline

`credactor:ignore` in a `#`, `//`, `/* … */`, or `<!-- … -->` comment, **on the
same line** as the secret (per-line only — a directive on the line above does
not carry over). Other comment markers (`--`, `;`, `%`) are **not** recognised:

```python
test_key = "abc123"  # credactor:ignore
```

### `.credactorignore`

In the scan root — a `.credactorignore` is loaded only for a **directory scan**
(its root is the scanned directory). A single-file target (`credactor app.py`)
does **not** apply one; point Credactor at the directory instead, or use inline
`# credactor:ignore` (which works on any target). A single-file run that finds a
`.credactorignore` beside the target **warns** rather than silently ignoring it.
Entry types (verified against a 2-secret file, baseline 2):

| Entry | Example | Effect |
|-------|---------|--------|
| Glob (whole file) | `app.py` or `tests/**` | suppresses matching files → 0 |
| `file:line` | `app.py:2` | suppresses one line → 1 (positional only; the value is not checked) |
| Value literal | `test_fixture_value` | suppresses that exact value anywhere |
| `value:<literal>` | `value:aB3/xY9+zQ==` | value literal containing `. / ? *` (base64/JWT/connection strings) that would otherwise be read as a path/glob |

> **No globstar.** Matching uses `fnmatch`, which has no `**` semantics — `**`
> behaves like `*`, and `*` already crosses `/`. Catch-all patterns warn at load
> time. `file:line` and value-literal suppressions also log a warning so they get
> reviewed.

---

## What is not flagged

Beyond explicit suppression, Credactor auto-skips a range of values and
locations. Verified — each of the following yields 0 findings:

- **Safe values** — placeholders (`your_api_key`, `changeme`, `placeholder`,
  `TODO`, `change_this`), the literal strings `test_password` / `mock_api_key` /
  `fake_secret`, and the sentinel `REDACTED_BY_CREDACTOR`. These match by
  **value**: a real secret in a variable merely *named* `test_api_key` is still
  flagged.
- **Runtime references** (not hardcoded secrets) — env lookups (`${VAR}`,
  `os.getenv("…")`, `process.env.X`), templates (`{{ vault_password }}`), dynamic
  lookups (`config.get()`, `keyring.get_password()`, Vault/SOPS `ENC[AES256_GCM…]`,
  Doppler, 1Password `op://`), property access (`self.config.password`), function
  calls/defs (`get_secret()`, `def get_password(password="default")`), and
  Terraform refs (`var.password`, `local.secret`, `module.db.password`, `data.*`).
- **Hashes, not secrets** — three cases. (1) A credential-named variable whose
  name ends in `_hash`, `_hashed`, `_digest`, `_checksum`, `_fingerprint`, or
  `_hmac` (e.g. `secret_hash`). Two further suffixes, `_encrypted` and
  `_cipher`, suppress the *variable/entropy* detector but **not** the quoted-hex
  value detector — a quoted hex value on such a variable
  (`data_cipher = "<hex>"`) still flags as `pattern:hex credential` (medium).
  (2) Hash *values*
  (`$2b$…` bcrypt, `$argon2id$…`). (3) A quoted hex / high-entropy **value** on
  a line whose key names a hash/digest/checksum/commit/integrity/revision
  field. The key may end in a `_hash`-family suffix, or contain `md5`,
  `sha<digits>`, `commit`, `integrity`, `checksum`, `digest`, `rev`, or `sri`
  before the `=`/`:` (`md5 = "<hex>"`, `git_commit = "<sha>"`,
  `integrity: "sha384-…"`). The `sha`/`md5` forms need the keyword *immediately*
  before the delimiter (`md5sum`, `shasum`, bare `sha`, `sha256_value` still
  flag); the bare words match as substrings, so they also catch names merely
  containing them (`my_rev`, `precommit`). Case 3 gates the **value** detector
  only — it does **not** override a credential keyword (`secret_md5 = "…"` still
  flags) or a deterministic provider pattern (`rev = "AKIA…"` still flags).
  **Trade-off — false negative:** a *genuine* bare-hex / high-entropy secret in
  such a field (an HMAC in `integrity = "<hex>"`, a token in a `*_rev` variable)
  is **not** caught by the entropy detectors — the deliberate cost of not
  corrupting commit SHAs / SRI integrity hashes / lockfile checksums under
  `--fix-all`. `--dry-run` and allowlist if you keep raw secrets in such fields.
- **Non-credential shapes** — file paths, credential-free URLs, values under 8
  characters, and low-entropy values.

**Skipped locations** apply only while **walking a directory**:

- Directories: `.git`, `__pycache__`, `node_modules`, `.venv`, `venv`, `.tox`,
  `dist`, `build` (plus IDE/cache dirs).
- Lock files: `package-lock.json`, `yarn.lock`, `poetry.lock`, `pnpm-lock.yaml`.

> Point Credactor **directly** at a skipped file or directory and it is scanned
> anyway (verified) — the same rule that lets a named single file bypass the
> extension list.

---

## External scanner ingestion (BETA)

Ingest another scanner's report and run its findings through Credactor's redaction
pipeline. Verified end-to-end (gitleaks/trufflehog → ingest → redact → clean
re-scan).

```bash
gitleaks dir . -f json -r gl.json
credactor --from-gitleaks gl.json --fix-all --yes .

trufflehog filesystem . --no-verification --json > th.json
credactor --from-trufflehog th.json --ci .
```

> **`--no-verification` keeps trufflehog offline.** It still detects secrets but
> skips the live API calls that would otherwise validate each one, so nothing is
> sent to a third party (verified against trufflehog 3.95.x: findings report
> `Verified: false` and zero verification time). Drop it only if you want
> trufflehog to confirm secrets online. `gitleaks dir` likewise scans the
> working tree without reading git history (use `gitleaks git` for history).

Verified behaviour and **requirements**:

- Ingested findings are **merged** with native findings and **deduplicated**; on
  a same-location/value/commit duplicate the **higher severity is kept**.
- The target **must be a directory** (a *relative* report path resolves against the current working directory, not the target) —
  a **file target exits 2** (verified).
- Ingestion **cannot be combined with `--scan-history`** — **exits 2** (verified).
- Report paths can instead be set in `.credactor.toml` under `[ingest]`. A
  same-kind CLI `--from-*` flag takes **precedence over** an `[ingest]` entry
  (**CLI > config**, consistent with every other setting): when the flag is
  given, that `[ingest]` entry is ignored entirely (not merged, not even
  validated). An `[ingest]` entry applies only when no same-kind flag is
  passed — keep one source per kind.
- The report is **untrusted input**, with two distinct contracts:
  - *The report file itself* is read from the path you supply — **not** confined
    to the target. A **missing or unreadable** report path is a **fatal error,
    exit 2** (never silently ignored), for either scanner. For **Gitleaks** (one
    JSON document) invalid JSON or a wrong top-level type is **also fatal, exit
    2**. For **TruffleHog** (line-delimited NDJSON) each line is parsed
    independently and a malformed line is skipped (a mixed report still ingests
    its valid findings), but a **wholly-unparseable** report — content with no
    JSON object on any line (an HTML error page, a typo'd file, or a Gitleaks
    JSON array fed to `--from-trufflehog`) — is likewise **fatal, exit 2**,
    never a silent zero-findings all-clear; an empty report is a legitimate "no
    findings". Report size and finding count are capped.
  - *Each finding inside the report* has its secret-location path **confined to
    the target**: a finding whose path resolves outside is rejected as possible
    traversal (warned and skipped). A malformed individual finding entry is
    likewise skipped, and the run continues.

> Marginal value: Credactor redacts the **union** of (its native findings + the
> ingested ones). A secret only a *third* tool detects is not redacted — pair
> ingestion with the broadest detector.

---

## Exit codes

Verified across the scenarios above:

| Code | Meaning |
|------|---------|
| `0` | No findings, or all resolved/redacted |
| `1` | Unresolved findings detected (incl. `--dry-run`/`--ci`/`--staged`/`--scan-history` with findings) |
| `2` | Error: path not found; system/home/protected directory; explicit `--config` missing/unreadable/invalid-TOML; dangerous `--replacement`; `--ci --fix-all`; `--scan-history` + ingestion; ingestion with a file target; a missing/unreadable/unparseable ingestion report file; `--staged`/`--scan-history` outside a git repo; `--fail-on-error` with unreadable files |

---

## Flag combinations & precedence

Verified rules:

| Combination | Result |
|-------------|--------|
| `--ci` (any) | forces `--dry-run`; no prompts |
| `--ci --fix-all` | **rejected, exit 2** (CI is read-only) |
| `--dry-run --fix-all` | dry-run wins; `--fix-all` is ignored (warned), nothing modified |
| `--staged` (any) | forces dry-run; `--fix-all` is ignored (warned), file not modified |
| `--staged --ci` | read-only gate over staged files |
| `--scan-history` (any) | forces dry-run; `--fix-all` is ignored (warned) — history findings cannot be redacted in place |
| `--replacement` (CLI) vs `.credactor.toml` `replacement` | **CLI wins** (CLI > config > default) |
| `--from-gitleaks`/`--from-trufflehog` (CLI) vs `.credactor.toml` `[ingest]` | **CLI wins** (CLI > config); the same-kind `[ingest]` entry is ignored |
| `--replace-with custom` without `--replacement` | uses the default/config replacement |
| `--scan-history` + `--from-gitleaks`/`--from-trufflehog` | **rejected, exit 2** |
| `--from-*` with a **file** target | **rejected, exit 2** (needs a directory) |
| `--secure-backup-dir` + `--secure-delete` | backup moved to DIR, then wiped |
| `--no-backup` + `--fix-all` | redacts with no recovery copy (extra confirmation shown) |
| non-text `--format` in non-CI | reports and exits 1 (no interactive redaction) |
| non-text `--format` + `--fix-all` | `--fix-all` wins and redacts; stdout carries **only** the JSON/SARIF report, confirmation/summary text goes to stderr; exit 0 when all replaced |

---

## Limitations

(See the [Disclaimer](DISCLAIMER.md) and [Security model](security.md) for full
detail; these are the behaviours most likely to surprise.)

- **Recognised file types only.** Credactor scans a fixed extension allowlist
  (code/config types, plus `.txt` as of 2.5.0); secrets in unrecognised text
  types (`.md`, custom) are skipped unless added via `extra_extensions`.
  General-purpose scanners read every file.
- **False positives are rewritten under `--fix-all`.** Redaction acts on every
  finding, so a non-secret that matches a pattern (a git commit SHA, an example
  key, a format-valid placeholder) is replaced with the sentinel — silently
  changing correct code. `--dry-run` and allowlist first.
- **No verification.** Unlike some scanners, Credactor does not confirm a finding
  is a *live* credential; a finding may be expired/rotated/fake, and a clean run
  is not proof the code is secret-free.
- **`.bak` backups hold plaintext** (use `--secure-delete`/`--secure-backup-dir`).
- **Narrower provider rule set** than dedicated detectors — some provider formats
  (e.g. SendGrid, Twilio, Slack webhooks) are not natively detected. Pair with
  another scanner via ingestion (Gitleaks or TruffleHog today, more incoming) for breadth.
- **No cross-file or semantic analysis**; obfuscated/runtime-assembled secrets
  are missed.
- **`--scan-history` covers the most recent 100 commits.** Secrets introduced
  and removed earlier are out of scope; on a deeper repository a `[WARN]`
  says so. For full-history audits use a dedicated history scanner
  (e.g. `gitleaks git`), then remediate with Credactor.
- **Lines are matched up to 4096 characters.** Matching cost grows
  superlinearly with line length, so each line is truncated at 4096 chars
  before pattern matching — a secret past that column (e.g. at the end of a
  minified one-liner) is not detected. A `[WARN]` names every affected file;
  the warning also fires for staged blobs and history scans.
- **UTF-8 / Latin-1 / ASCII-payload UTF-16 by default.** Other encodings
  (UTF-32, mixed-script UTF-16, …) require the optional `charset-normalizer`
  (`[encoding]`) extra; without it such files are read as Latin-1 and their secrets
  can be missed (Credactor prints a `[WARN]` when it falls back to Latin-1).
