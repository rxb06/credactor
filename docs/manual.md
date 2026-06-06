# Credactor Manual

Complete reference for every flag, mode, and combination — with the behaviour of
each **verified by running the tool**. Reflects the `develop` branch (the 2.4.0
line). For a gentler introduction see the [User Guide](user-guide.md); for
limitations and safe usage see the [Disclaimer](DISCLAIMER.md).

> Every example below was executed against a sandbox to confirm it behaves as
> described. Where behaviour is subtle (precedence, mutual exclusions, exit
> codes) the verified result is stated explicitly.

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
| `--scan-history` | mode | Scan up to 100 commits of git history |
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

## Scan modes

Exactly one *behaviour* applies per run; the precedence/forcing rules are in
[Flag combinations](#flag-combinations--precedence).

### Interactive (default)

`credactor <target>` with no mode flag walks each finding and prompts
`Replace? [y/N]`. `y` redacts that finding (creating a `.bak`), `n`/Enter skips.
Requires a TTY. Exit code = number of unresolved findings → 0 if all resolved/none,
1 otherwise.

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

```bash
credactor --staged --ci          # canonical pre-commit gate
```

### `--scan-history`

Scans up to 100 commits of `git log -p`, reporting the commit hash where each
secret was introduced. Verified: finds a secret that was committed then removed
from the working tree. In a non-git directory it exits **2**.

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
- **Replacement is validated** (allowlist `[A-Za-z0-9_-]`): a dangerous value
  (`bad;rm -rf`, markup, newlines, control chars) is **rejected with exit 2**
  (verified). This guards against injection into rewritten files.
- Env-mode output is syntactically valid: a redacted `.py`/`.js`/`.rb` still
  compiles/parses (verified).

---

## Backup & safety

By default Credactor writes a `.bak` copy of each modified file before changing
it. Verified behaviour:

| Flags | `.bak` beside file? | backup location | after redaction |
|-------|--------------------|------------------|-----------------|
| *(default)* | yes (contains the original secret) | next to the file | kept — delete manually |
| `--no-backup` | **no** | — | original is lost unless in git |
| `--secure-backup-dir DIR` | no | moved into `DIR` | kept in `DIR` |
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

---

## Output formats

### `--format text` (default)

Human-readable report; the credential is masked to its first 4 characters +
`[REDACTED]`. `--no-color` strips ANSI codes (auto-disabled when stdout is not a
terminal).

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
> interactive redaction with JSON/SARIF output).

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
| `min_value_length` | Int 1–200 (default 8). Verified: `min_value_length = 200` suppresses a 40-char token (0 findings). |
| `skip_dirs` | List of directory names to skip (case-sensitive). |
| `skip_files` | List of file names to skip. Verified: `skip_files = ["app.py"]` → 0 findings. |
| `extra_extensions` | List of extra extensions to scan (lowercased; warn if a leading dot is missing). |
| `extra_safe_values` | List of values to never flag (case-insensitive). |
| `replacement` | Default custom replacement (an explicit `--replacement` wins). |
| `[ingest]` `from_gitleaks` / `from_trufflehog` | Report paths for ingestion. |

### `--config PATH`

Use a specific config file (verified: `--config cfg.toml` with
`min_value_length = 200` drops findings to 0). An explicit `--config` is honored
even outside the project root (non-CI).

### `--scan-json`

`.json` files are **not scanned by default** (high false-positive rate from API
data). Verified: a secret in a `.json` is found **only** with `--scan-json`
(0 → 1).

### `--fail-on-error`

Exit **2** if any file could not be scanned (permissions, encoding). Verified:
a directory whose only file is unreadable exits **0** without the flag (a warning
only) and **2** with it.

### `--verbose` / `-v`

Logs scan activity to stderr, including why findings were suppressed. Verified
sample: `[SKIP] …/app.py:2 suppressed by inline credactor:ignore`. Suppression
breadcrumbs name the kind (`inline`, `allowlist (glob|file:line|value-literal)`,
`safe value heuristic`, `hash context`).

---

## Suppression

### Inline

`credactor:ignore` in any comment style, **on the same line** as the secret
(per-line only — a directive on the line above does not carry over):

```python
test_key = "abc123"  # credactor:ignore
```

### `.credactorignore`

In the scan root. Entry types (verified against a 2-secret file, baseline 2):

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

Verified behaviour and **requirements**:

- Ingested findings are **merged** with native findings and **deduplicated**; on
  a same-location/value/commit duplicate the **higher severity is kept**.
- The target **must be a directory** (report paths are resolved relative to it) —
  a **file target exits 2** (verified).
- Ingestion **cannot be combined with `--scan-history`** — **exits 2** (verified).
- Report paths can instead be set in `.credactor.toml` under `[ingest]`.
- The report file is **untrusted input**: paths are confined to the target
  (traversal rejected), missing/invalid paths are skipped, and the report is
  size/finding-count capped.

> Marginal value: Credactor redacts the **union** of (its native findings + the
> ingested ones). A secret only a *third* tool detects is not redacted — pair
> ingestion with the broadest detector.

---

## Exit codes

Verified across the scenarios above:

| Code | Meaning |
|------|---------|
| `0` | No findings, or all resolved/redacted |
| `1` | Unresolved findings detected (incl. `--dry-run`/`--ci`/`--staged` with findings) |
| `2` | Error: path not found; system/home/protected directory; dangerous `--replacement`; `--ci --fix-all`; `--scan-history` + ingestion; ingestion with a file target; `--staged`/`--scan-history` outside a git repo; `--fail-on-error` with unreadable files |

---

## Flag combinations & precedence

Verified rules:

| Combination | Result |
|-------------|--------|
| `--ci` (any) | forces `--dry-run`; no prompts |
| `--ci --fix-all` | **rejected, exit 2** (CI is read-only) |
| `--staged` (any) | forces dry-run; `--fix-all` is ignored (warned), file not modified |
| `--staged --ci` | read-only gate over staged files |
| `--replacement` (CLI) vs `.credactor.toml` `replacement` | **CLI wins** (CLI > config > default) |
| `--replace-with custom` without `--replacement` | uses the default/config replacement |
| `--scan-history` + `--from-gitleaks`/`--from-trufflehog` | **rejected, exit 2** |
| `--from-*` with a **file** target | **rejected, exit 2** (needs a directory) |
| `--secure-backup-dir` + `--secure-delete` | backup moved to DIR, then wiped |
| `--no-backup` + `--fix-all` | redacts with no recovery copy (extra confirmation shown) |
| non-text `--format` in non-CI | reports and exits 1 (no interactive redaction) |

---

## Limitations

(See the [Disclaimer](DISCLAIMER.md) and [Security model](security.md) for full
detail; these are the behaviours most likely to surprise.)

- **Recognised file types only.** Credactor scans a fixed extension allowlist
  (code/config types); secrets in unrecognised text types (`.txt`, `.md`, custom)
  are skipped unless added via `extra_extensions`. General-purpose scanners read
  every file.
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
  another scanner via ingestion for breadth.
- **No cross-file or semantic analysis**; obfuscated/runtime-assembled secrets
  are missed.
