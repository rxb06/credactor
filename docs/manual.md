# Credactor Manual

Complete reference for every flag, mode, and combination. 
Reflects Credactor 2.6.0 (see the [CHANGELOG](../CHANGELOG.md)). For limitations and safe usage see the
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
| `--from-gitleaks FILE` | ingest | Ingest a Gitleaks JSON report |
| `--from-trufflehog FILE` | ingest | Ingest a TruffleHog NDJSON report |

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
**red**, medium **yellow**, low **cyan** (`--no-color`, the `NO_COLOR`
environment variable, or a non-terminal stdout disables this).

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
  are **not** scanned inside comments — where "comment" means a **full line
  starting with `#` or `//`**: a value in a `/* … */` block, on a ` * `
  continuation line, or in a trailing comment after code still flags.
- **`entropy_threshold` (default 3.5) gates only variable-assignment and
  XML-attribute findings** — those caught by the *variable name* rather than a
  value pattern. Password-family **variable assignments** (`password`,
  `passwd`, `passphrase`, `private_key`, `secret_key` — the clamp does *not*
  apply to XML attributes) use a lower floor of `min(entropy_threshold, 3.0)`:
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
Requires a TTY once there are findings to prompt for — piped stdin is then
rejected with exit 1, while a clean tree still reports and exits 0 (use `--dry-run`/`--ci`
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

`y`/`yes` prints `-> Replaced.`; `n`/Enter prints `-- Skipped.`; any other
answer re-prompts (`Please enter 'y' or 'n'.`); Ctrl-C or EOF stops and
reports how many replacements were already applied. The session opens with a
banner naming the prompt count (deduplicated, so it can be lower than the
report's finding count) and closes with a `Summary: X replaced | Y skipped |
Z total` block plus a rotate-credentials reminder; the first approval also
prints a `[WARN] Plaintext backup created…` pointer at
`--secure-delete`/`--secure-backup-dir`. Answering `y` on a **private key
block** finding is refused (see [Multi-line findings]) and counts as failed.

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
- **Private key blocks are refused** (warned, counted failed, exit 1) — see
  [Multi-line findings](#multi-line-findings).

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
The staged set is repo-wide but the scan is **scoped to the target
directory**: staged files outside it are skipped with a run-level `[WARN]`
naming the count — run `--staged` from the **repository root** (as the
shipped hooks do) to gate every staged change. A **file** target is rejected
(exit 2), and combining `--staged` with `--scan-history` is likewise
rejected (exit 2). Staging `.credactor.toml` or `.credactorignore` alongside
code triggers a `[WARN] Suppression/config files staged alongside code
changes … Review these for detection-bypass attempts.` — a deliberate
anti-bypass signal.
Staged content gets the identical full scan as a working-tree file — PEM
blocks and secrets inside triple-quoted / template-literal strings included.
Staged `.json` files follow the same opt-in as the directory walk: scanned only
with `--scan-json`, otherwise skipped with a warning naming the file.

```bash
credactor --staged --ci          # canonical pre-commit gate
```

### `--scan-history`

Scans up to the 100 most recent **file-changing** commits of `git log -p`,
reporting the commit hash where each secret was introduced. Verified: finds a
secret that was committed then removed from the working tree. In a non-git
directory it exits **2**; a **file** target is rejected (exit 2). In `-f
json`/`-f sarif` output a history finding's `file` field carries the
synthetic `path (commit <hash>)` form — the hash is also in the separate
`commit` field, so join pipelines on `commit`, not `file`.
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
- **A `.bak` is created even when every replacement fails.** The backup is
  written before the replacement pass, so a `--fix-all` run in which no value
  matches (typically a stale ingested report) still leaves a byte-identical
  plaintext `.bak` beside each touched file. Backups also inherit the original
  file's full mode, including a setuid bit. Delete strays before committing.

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

`.bak` backups and `*.credactor.tmp` temp files hold **plaintext** secrets,
and Credactor **never edits your repository's `.gitignore`** — in your own
project a plain `git add .` **will stage them**. Add `*.bak` and
`*.credactor.tmp` to your `.gitignore` (Credactor's own repo does exactly
that at `.gitignore:39,42`), or use `--secure-delete` /
`--secure-backup-dir` (outside the repo) for a clean tree.

### What `--secure-delete` does

On a successful redaction the `.bak` is overwritten with `os.urandom()` bytes,
`fsync`'d, then unlinked (`redactor.py:276`). Verified: no `.bak` remains
afterwards. It is wiped only when at least one replacement actually landed, and a
single-pass overwrite is **not** a forensic guarantee on copy-on-write / SSD /
journaling filesystems.

### Other safety properties (verified)

- **Atomic writes** — both the backup and the rewrite go through a temp file then
  `os.replace`, cleaned up in a `finally`; a mid-write crash leaves the original
  intact (`redactor.py:292`, backup at `:197`).
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
with column-level regions (`startColumn`/`endColumn`). Severity maps to
SARIF `level` as critical/high → `error`, medium → `warning`, low → `note`;
rule ids sanitise `:` to `-` (`pattern-AWS access key`,
`external-gitleaks-<rule>`).

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

Searched in the target directory and up to **5 parent directories** — the
**nearest** file found wins and is the only one loaded (no merging with
parent configs) — (stopping at
the project root). A config discovered **outside** the project root is refused
unless passed explicitly with `--config`. Under `--ci` an outside-root config
is always refused — and when it was named explicitly via `--config`, the
refusal is **fatal, exit 2** (like a missing or unparseable `--config`): a CI
gate must never silently fall back to defaults when the pipeline expected
config-driven settings or `[ingest]` sources. Verified keys:

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

Exit **2** if any file could not be scanned (permissions, encoding, a
non-regular file such as an in-tree FIFO) — including a directory that could
not be traversed (warned and counted).
Verified: a directory whose only file is unreadable exits **0** without the
flag (a warning only) and **2** with it. Two scope notes: size- and
type-based skips (the 50 MB per-file cap, unscanned extensions, `.json`
without `--scan-json`, `.gitignore`d files) are warned or noted but are
**not** errors and do not trip the flag; and when the flag fires, the run
exits **before** printing the findings report.

### `--verbose` / `-v`

Logs scan activity to stderr, including why findings were suppressed. Verified
sample: `[SKIP] …/app.py:2 suppressed by inline credactor:ignore`. Suppression
breadcrumbs name the kind: `inline`, `allowlist
(file-level|glob|file:line|value-literal)`, `safe value heuristic`, or
`hash context`. A whole-file allowlist match in a directory walk logs
`file-level`; the same entry matching on the per-line path logs `glob`.
Ingested findings filtered by the allowlist log the same
`suppressed by allowlist (<kind>)` breadcrumb (allowlist entries are the only
suppression layer that applies to them — see
[Suppression layers and ingested findings](#suppression-layers-and-ingested-findings)).

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
  field. The match is on the key's **ending** only: a key ending in a
  `_hash`-family suffix, or in `md5`, `sha<digits>`, `sha`, `commit`,
  `integrity`, `checksum`, `digest`, `rev`, `revision`, or `sri`
  (`md5 = "<hex>"`, `git_commit = "<sha>"`, `commit_sha = "<sha>"`,
  `revision = "<hex>"`, `integrity: "sha384-…"` — and, because only the
  ending is checked, `my_rev`, `precommit`, and `deploy_sha` too). A key
  merely *containing* a term elsewhere is untouched (`commit_id`,
  `rev_number`, `md5sum`, `sha256_value` still flag). Case 3 gates the **value** detector
  only — it does **not** override a credential keyword (`secret_md5 = "…"` still
  flags) or a deterministic provider pattern (`rev = "AKIA…"` still flags).
  **Trade-off — false negative:** a *genuine* bare-hex / high-entropy secret in
  such a field (an HMAC in `integrity = "<hex>"`, a token in a `*_rev` variable)
  is **not** caught by the entropy detectors — and that includes any variable
  simply *ending* in one of the terms (`*_rev`, `*_sha`, `precommit`) — the
  deliberate cost of not corrupting commit SHAs / revision pins / SRI
  integrity hashes / lockfile checksums under `--fix-all`. `--dry-run` and allowlist if you keep raw secrets in such fields.
- **Non-credential shapes** — file paths, credential-free URLs, values under 8
  characters, and low-entropy values.

**Skipped locations** apply only while **walking a directory**:

- Directories: `.git`, `__pycache__`, `node_modules`, `.venv`, `venv`, `.tox`,
  `dist`, `build` (plus IDE/cache dirs).
- Lock files: `package-lock.json`, `yarn.lock`, `poetry.lock`, `pnpm-lock.yaml`.
- Files matched by the repository's **`.gitignore`** (including nested ones
  met during the walk). Text output prints a `[N file(s) not scanned --
  covered by .gitignore]` block; **`-f json` / `-f sarif` emit no signal for
  these** — a gitignored `.env` full of secrets scans clean in machine
  formats, so audit with text output (or scan the file directly).
- Files over the **50 MB per-file cap** (warned; the cap also applies to
  staged blobs). The skip does not trip `--fail-on-error`.

> Point Credactor **directly** at a skipped file or directory and it is scanned
> anyway (verified) — the same rule that lets a named single file bypass the
> extension list.

---

## External scanner ingestion

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
> sent to a third party (verified across trufflehog 3.88.1–3.97.0: findings
> report `Verified: false` and zero verification time). Drop it only if you
> want trufflehog to confirm secrets online. `gitleaks dir` likewise scans the
> working tree without reading git history (use `gitleaks git` for history;
> below gitleaks 8.19 there is no `dir` subcommand — use
> `gitleaks detect --no-git -s . -f json`, whose report is identical on every
> field Credactor consumes).

Verified behaviour and **requirements**:

- Ingested findings are **merged** with native findings and **deduplicated**.
  On a same-location/value/commit duplicate the surviving finding's `type`
  follows a fixed priority — **native (any `pattern:*`, `variable:*`,
  `xml-attr:*`, or `multiline:*` type) > `external:gitleaks:*` >
  `external:trufflehog:*`** (processing order, not flag order) — and the
  **higher severity of the two is kept** (a TruffleHog `Verified: true`
  duplicate escalates a native medium to critical).
- Ingested findings carry the type strings **`external:gitleaks:<RuleID>`**
  and **`external:trufflehog:<DetectorName>`** in every output format (in
  SARIF rule ids the `:` is sanitised to `-`) — filter on these in `-f json`
  pipelines. Severity maps from a per-rule table for Gitleaks (with a
  `Tags` override); for TruffleHog, `Verified: true` is always **critical**.
- The target **must be a directory** — a **file target exits 2** (verified).
- **Path bases differ, deliberately:** the *report path* (flag or `[ingest]`
  entry) resolves against the **current working directory**, never the target
  or the config file's directory; the *finding paths inside the report*
  resolve against the **target**. A missing relative report path names the
  CWD-resolved location in its error.
- **The target must equal the directory the scanner ran against** (the
  monorepo rule). Pointing Credactor at a subdirectory while the report was
  generated at the repo root makes root-relative findings silently miss
  (warn + skip, and the run can exit 0) — or, worse, resolve to an
  equally-named nested file which is then redacted while the real secret
  survives. Run both tools from the same root.
- Ingestion **cannot be combined with `--scan-history`** — **exits 2** (verified).
- `--staged` **can** be combined with ingestion: staged-file findings and
  ingested working-tree findings merge into one report under the usual
  forced-read-only rules (`--fix-all` is ignored with a warning). See
  [Flag combinations](#flag-combinations--precedence).
- Report paths can instead be set in `.credactor.toml` under `[ingest]`. A
  same-kind CLI `--from-*` flag takes **precedence over** an `[ingest]` entry
  (**CLI > config**, consistent with every other setting): when the flag is
  given, that `[ingest]` entry's path is not used. The config must still be
  *valid*, though: an **empty** path value (`from_gitleaks = ""`) is
  **fatal, exit 2** — even when a same-kind flag is passed, since config
  parsing precedes the flag override — matching the empty-flag error; it
  must not silently disable a configured ingest gate. An `[ingest]` entry
  applies only when no same-kind flag is passed — keep one source per kind.
- **One report per kind.** Repeating `--from-gitleaks` (or `--from-trufflehog`)
  keeps only the **last** occurrence — earlier ones are dropped by standard
  flag parsing. Merge multiple reports upstream before ingesting.
- The report is **untrusted input**, with two distinct contracts:
  - *The report file itself* is read from the path you supply — **not** confined
    to the target. A **missing or unreadable** report path is a **fatal error,
    exit 2** (never silently ignored), for either scanner; a report path that
    exists but is not a regular file (a directory, a FIFO) is likewise fatal.
    For **Gitleaks** (one JSON document) invalid JSON or a wrong top-level type
    is **also fatal, exit 2**. For **TruffleHog** (line-delimited NDJSON) each
    line is parsed independently and a malformed line is skipped (a mixed
    report still ingests its valid findings), but a **wholly-unparseable**
    report — content with no JSON object on any line (an HTML error page, a
    typo'd file, or a Gitleaks JSON array fed to `--from-trufflehog`) — is
    likewise **fatal, exit 2**, never a silent zero-findings all-clear; the
    cross-feed errors hint at the mix-up. An **empty (0-byte) report** is a
    legitimate "no findings" **for TruffleHog only** — for **Gitleaks** an
    empty file is not valid JSON and is **fatal, exit 2** (a zero-findings
    Gitleaks run writes `[]`, which ingests as no findings; an empty file
    usually means the scanner step itself failed). **Caps:** a report **over 20,000,000 bytes is refused** (fatal,
    exit 2; a report of exactly 20,000,000 bytes parses — the boundary is
    inclusive), and findings beyond **10,000** are truncated with a warning.
  - *Each finding inside the report* has its secret-location path **confined to
    the target**: a finding whose path resolves outside is rejected as possible
    traversal (warned and skipped). A malformed individual finding entry is
    likewise skipped, and the run continues — with a run-level `[WARN] N …
    record(s) skipped as invalid` summary (either scanner; for TruffleHog
    this covers parsed records with unusable fields — an unparseable NDJSON
    *line* follows the parse contract above), so an all-invalid report is
    never byte-indistinguishable from a clean run. A finding whose
    path resolves **to the report file itself** is skipped to avoid
    self-corruption, with only a `-v` INFO note — **keep reports outside the
    target tree**: `.json` files are not scanned natively without
    `--scan-json`, so a report stored inside the target holds plaintext
    secrets the gate cannot see.
- **Only `filesystem` and `git` TruffleHog sources are ingested.** Records
  from any other source (`github`, `docker`, `s3`, …) are skipped, and a
  run-level `[WARN] N TruffleHog finding(s) skipped: unsupported source
  type(s) […]` is emitted so an all-unsupported report is never a silent
  all-clear.

### Stale reports

A report is a snapshot; ingest it against the same tree it was generated
from, and **regenerate it after redacting or after any tree change**:

- A finding whose value is no longer on its recorded line (a line was
  inserted, the secret rotated, or a prior run already redacted it) fails
  safely: warned, counted unresolved, **exit 1** — never a wrong-line
  replacement. Re-running with a consumed report therefore exits 1, not 0.
- A finding whose file was **deleted or renamed** since the scan is skipped at
  ingest with a missing-file warning and does not count as a finding — such a
  run can **exit 0 while the secret still exists at the renamed path**. A
  run-level `[WARN] N ingested finding(s) reference files that no longer
  exist…` summarises the drops so the gate's green is auditable. After a
  `--fix-all` in which replacements failed in files containing ingested
  findings, a second run-level `[WARN] N finding(s) in file(s) with ingested
  findings could not be applied…` points at regenerating the report.
- Reports are OS-specific: ingest them on the OS/checkout that produced them
  (Windows backslash paths are literal filename characters on Linux and miss
  gracefully).

### Suppression layers and ingested findings

Only **`.credactorignore`** entries (glob, `file:line`, value-literal,
`value:`) apply to ingested findings; suppressed ones are dropped before the
merge, with a `-v` breadcrumb naming the kind. Every other layer gates the
**native scan only** — an external scanner's verdict is otherwise trusted
verbatim:

| Layer | Applies to ingested findings? |
|---|---|
| `.credactorignore` (all entry kinds) | **yes** |
| Inline `# credactor:ignore` | no — the marked line is still reported and redacted |
| Built-in safe values (`changeme`, …) | no — a report naming a placeholder value drives a real redaction |
| `extra_safe_values` | no |
| `entropy_threshold` / `min_value_length` | no |
| `.gitignore` / skipped dirs (`node_modules`, …) | no — an explicit report beats walk-time exclusions; redaction then leaves `.bak` files inside those trees |

### Symlinks and `SymlinkFile`

An ingested finding whose path is a symlink **dereferences and redacts the
real file** (containment is checked after resolution). The native scan
differs on two points: it *scans* within-root symlinked files (only symlinks
resolving outside the root are skipped) but *refuses to redact* them — and
when a native finding at the symlink path wins deduplication over its
ingested duplicate, that refusal applies (warned, exit 1) instead of the
dereferenced redaction. In Gitleaks reports a non-empty `SymlinkFile` field
takes precedence over `File` unconditionally.

### Multi-line findings

Findings whose secret spans multiple lines (PEM private keys) are **reported
but never redacted** — for either origin. An *external* multi-line finding
fails the line-based value match (warned, exit 1). A *native*
`pattern:private key block` finding is **refused outright** (warned, counted
unresolved, exit 1): its match value is only the `-----BEGIN` header line, so
a line-based replacement would rewrite the header, leave the entire key
material in the file, and make the next scan report it clean. Rotate the key
and remove the block manually — redaction never half-eats a key block.

### Supported scanner versions

Tested ranges (report schemas verified identical on every consumed field):

| Scanner | Tested range | Fields consumed |
|---|---|---|
| Gitleaks | **8.18.4 – 8.27.2** | top-level array; `RuleID`, `File` (+`SymlinkFile` override), `StartLine`, `Secret`, `Match`, `Tags`, `Commit` |
| TruffleHog | **3.88.1 – 3.97.0** | per-line object; `Raw`, `DetectorName`, `Verified`, `SourceMetadata.Data.Filesystem.{file,line}`, `.Git.{file,line,commit}` |

Newer versions with additional JSON fields are ingested with the unknown
fields ignored. ⚠ TruffleHog **self-updates by default** — pass
`--no-update` in CI or anywhere a version is pinned.

Ingestion end-to-end behaviour is verified on **Linux** with **CPython 3.11,
3.12, 3.13, and 3.14** (3.11.16 / 3.12.14 / 3.13.15 / 3.14.x tested —
identical outcomes and exit codes in every cell). Windows and macOS ingestion
behaviour is untested.

> Marginal value: Credactor redacts the **union** of (its native findings + the
> ingested ones). A secret only a *third* tool detects is not redacted — pair
> ingestion with the broadest detector. Note also the overlap-tail class of
> limitation: any scanner that reports a *truncated or shorter substring* of the
> on-disk secret (e.g. a connection string cut at the port) leaves a live-looking
> tail after redaction — **silently**: the substring replacement itself
> succeeds, so nothing flags the leftover. Pair connection-string
> ingestion with native coverage (`--scan-json` where relevant).

---

## Exit codes

Verified across the scenarios above:

| Code | Meaning |
|------|---------|
| `0` | No findings, or all resolved/redacted |
| `1` | Unresolved findings detected (incl. `--dry-run`/`--ci`/`--staged`/`--scan-history` with findings) |
| `2` | Error: path not found; a target that is neither a regular file nor a directory (a FIFO/device); system/home/protected directory; explicit `--config` missing/unreadable/invalid-TOML, or refused under `--ci` (outside project root); dangerous `--replacement`; `--ci --fix-all`; `--scan-history` + ingestion; ingestion with a file target; a missing/unreadable/unparseable/oversized ingestion report file or an empty `--from-*` flag or `[ingest]` config value; `--staged`/`--scan-history` outside a git repo, combined with each other, or with a file target; `--fail-on-error` with unreadable files or undescendable directories |

Two adjacent notes: **Ctrl-C during a scan exits 130**; at an interactive
`Replace?` or `--fix-all` `Proceed?` prompt it is caught (the run reports and
exits by resolution, normally 1). **argparse usage errors** (unknown flag,
invalid choice, missing value) also exit **2** with usage text.

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
| `--from-gitleaks`/`--from-trufflehog` (CLI) vs `.credactor.toml` `[ingest]` | **CLI wins** (CLI > config); the same-kind `[ingest]` entry's path is not used (an *empty* config value is still fatal, exit 2) |
| `--replace-with custom` without `--replacement` | uses the default/config replacement |
| `--scan-history` + `--from-gitleaks`/`--from-trufflehog` | **rejected, exit 2** |
| `--staged` + `--from-gitleaks`/`--from-trufflehog` | allowed: staged-native and ingested working-tree findings merge into one read-only report (`--fix-all` still ignored with a warning) |
| `--from-*` with a **file** target | **rejected, exit 2** (needs a directory) |
| `--secure-backup-dir` + `--secure-delete` | backup moved to DIR, then wiped |
| `--no-backup` + `--fix-all` | redacts with no recovery copy (a DANGER banner is shown; still a single confirmation, and `--yes` skips it) |
| `--no-backup` + `--secure-backup-dir`/`--secure-delete` | **`--no-backup` wins** (warned; the secure-backup flags have no effect) |
| `--staged` + `--scan-history` | **rejected, exit 2** |
| `--staged`/`--scan-history` with a **file** target | **rejected, exit 2** (needs a directory) |
| non-text `--format` in non-CI | reports and exits 1 (no interactive redaction) |
| non-text `--format` + `--fix-all` | `--fix-all` wins and redacts; stdout carries **only** the JSON/SARIF report, confirmation/summary text goes to stderr; exit 0 when all replaced |

---

## Limitations

(See the [Disclaimer](DISCLAIMER.md) and [Security model](security.md) for full
detail; these are the behaviours most likely to surprise.)

- **Recognised file types only.** Credactor scans a fixed extension allowlist
  (code/config types, plus `.txt` as of 2.5.0); secrets in unrecognised text
  types (`.md`, custom) are skipped unless added via `extra_extensions`.
  General-purpose scanners read every file. **Ingestion is the exception in
  both directions:** an ingested finding is redacted regardless of extension
  (`.md`, `Dockerfile`, extensionless — the report extends coverage past the
  allowlist), and an explicit report also beats `.gitignore` and skip-dir
  exclusions — redaction then leaves plaintext `.bak` files inside those
  trees (see Backup & safety).
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
  another scanner via ingestion (Gitleaks or TruffleHog) for breadth.
- **Overlap-tail artifacts.** When any scanner (native or ingested) reports a
  shorter substring of a longer on-disk secret — overlapping rules, or a
  connection string truncated at the port — redacting the substring leaves a
  short live-looking tail on the line. The replacement itself succeeds, so
  **no warning flags the leftover** — review redacted lines by hand (the
  credential itself is dead once rotated) and pair connection-string
  ingestion with native coverage (`--scan-json` for JSON).
- **No cross-file or semantic analysis**; obfuscated/runtime-assembled secrets
  are missed.
- **`--scan-history` covers the most recent 100 commits.** Secrets introduced
  and removed earlier are out of scope; on a deeper repository a `[WARN]`
  says so. For full-history audits use a dedicated history scanner
  (e.g. `gitleaks git`), then remediate with Credactor.
- **Pathological content scans slowly.** Files made of very long
  low-diversity lines (wrapped base64 blobs, repeated-character runs, some
  minified/log content) can scan at ~0.1 MB/s — content-dependent, up to
  ~8× slower than prose-like text, so a worst-case file near the 50 MB cap
  can take minutes with no progress output. Typical trees scan at ~1 MB/s.
  Exclude such files via `skip_files`/`extra_extensions` and bound CI gates
  with a job timeout.
- **Lines are matched up to 4096 characters.** Matching cost grows
  superlinearly with line length, so each line is truncated at 4096 chars
  before pattern matching — a secret past that column (e.g. at the end of a
  minified one-liner) is not detected. A `[WARN]` names every affected file;
  the warning also fires for staged blobs and history scans.
- **UTF-8 / Latin-1 / ASCII-payload UTF-16 by default.** Other encodings
  (UTF-32, mixed-script UTF-16, …) require the optional `charset-normalizer`
  (`[encoding]`) extra; without it such files are read as Latin-1 and their secrets
  can be missed (Credactor prints a `[WARN]` when it falls back to Latin-1).
