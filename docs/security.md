# Security Model

Credactor is a **developer-side static analysis tool** that scans source files for hardcoded credentials. Understanding its trust boundaries is important for safe deployment.

## What Credactor Protects Against

- Accidentally committing hardcoded API keys, tokens, passwords, and private keys.
- Credentials in assignment statements, XML attributes, connection strings, PEM blocks, and multi-line strings.
- Re-flagging already-redacted values (the sentinel `REDACTED_BY_CREDACTOR` is in the safe-values list).
- **(BETA) Ingesting external scanner output:** findings from Gitleaks (`--from-gitleaks FILE`) or TruffleHog (`--from-trufflehog FILE`) are merged into the redaction pipeline, deduplicated against native findings (severity merged to the higher value on a duplicate), and still pass through `.credactorignore` suppression. Ingestion requires a **directory** target so report-relative file paths resolve correctly.

## What Credactor Does NOT Protect Against

- **Obfuscated credentials:** Base64-encoded secrets, encrypted blobs (other than SOPS), or credentials split across multiple files.
- **Runtime secrets:** Credentials injected via environment variables, secret managers, or APIs at runtime are intentionally ignored (these are the *correct* pattern).
- **Binary files:** Only text-based source files are scanned; binary formats (`.exe`, `.zip`, `.png`, etc.) are skipped.
- **Determined adversaries:** An attacker with write access to your codebase could craft evasion patterns. Credactor is a safety net, not a security boundary.

## Trust Boundaries

| Component | Trust Level | Notes |
|-----------|-------------|-------|
| Source files being scanned | Untrusted | May contain adversarial content; regex patterns are hardened against ReDoS |
| `.credactor.toml` config | Semi-trusted | Can adjust thresholds and safe-values; traversal limited to 5 parent dirs; an implicitly-discovered config outside the project root is refused (an explicit `--config` outside the root is honored, with a warning, only in non-CI) |
| `.credactorignore` | Semi-trusted | Can suppress findings for specific files, lines, or values |
| External scanner report (`--from-gitleaks` / `--from-trufflehog`, `[ingest]`) | Untrusted | Names on-disk files Credactor will redact; paths are normalised and confined to the target directory (traversal rejected), the report file itself is skipped (self-corruption guard), missing/invalid paths are dropped, and the report is size-capped before parsing and finding-count-capped after parsing to bound memory |
| CLI arguments | Trusted | Provided by the developer running the tool |
| Git history (`--scan-history`) | Untrusted | Parses `git log -p` output; input is sanitised |

## Hardening Measures

### v2.0.0

- **No shell injection:** All subprocess calls use list arguments, never `shell=True`.
- **File size guard:** Files over 50 MB are skipped to prevent OOM.
- **PEM block recovery:** Unclosed PEM blocks auto-reset after 100 lines to prevent scan suppression.
- **Config traversal limit:** Config file search stops after 5 parent directories.
- **Credential masking:** All output formats (text, JSON, SARIF) mask credential values; `full_value` never appears in user-facing output.
- **Safe-value precision:** Function call detection uses regex matching (`identifier(...)`) instead of naive substring checks.
- **Symlink safety:** `os.walk` does not follow symlinks by default.
- **Encoding safety:** Uses `errors='surrogateescape'` for lossless round-trip on non-UTF-8 files.

### v2.2.1

- **SEC-01**: Secure backup handling. `--secure-backup-dir` stores `.bak` files outside the repo; `--secure-delete` overwrites backups with random data before unlinking.
- **SEC-02**: Untrusted config handling. An implicitly-discovered `.credactor.toml` outside the git project root is refused (`[ERROR]` on stderr, config ignored). An explicit `--config` pointing outside the root is honored with a `[WARN]` in non-CI mode; in CI it is always refused (see SEC-29 / M14).
- **SEC-03**: Config parse failure surfacing. Warns on stderr instead of silently returning empty config.
- **SEC-04**: Subprocess path sanitisation. All `subprocess.run(cwd=...)` calls resolve paths via `Path.resolve()` before execution.
- **SEC-05**: File descriptor exhaustion. Scanning is sequential (one file handle at a time), so descriptor exhaustion cannot occur. (Earlier releases used a thread pool with an `EMFILE` fallback; it measured ≤1.3× and was removed in favour of the simpler, exhaustion-proof sequential scan.)
- **SEC-06**: ReDoS line-length guard. Lines longer than 4096 characters are truncated before regex pattern matching.
- **SEC-07**: Temp file leakage prevention. `.credactor.tmp` files are cleaned up via a `finally` block even on crashes.
- **SEC-08**: Forward-only scanning with expanded protected directories. 30+ system directories blocked across Linux, macOS, and Windows.
- **SEC-09**: Symlink race in backup creation. `_create_backup()` checks `os.path.islink()` before writing `.bak` files.
- **SEC-10**: Replacement string injection validation. `--replacement` values are checked against dangerous character patterns.
- **SEC-11**: Data loss safeguard for `--fix-all --no-backup`. Displays a prominent DANGER banner.
- **SEC-12**: Config injection bounds validation. `entropy_threshold` clamped to 0.0–6.0 and `min_value_length` to 1–200.
- **SEC-13**: Wildcard `.credactorignore` warning. Overly broad patterns trigger a `[WARN]`.
- **SEC-14**: `--replace-with env` semantic change warning.
- **SEC-15**: Best-effort advisory file lock (`fcntl.flock(LOCK_EX|LOCK_NB)`) attempted before the read-modify-write; on lock contention it proceeds unlocked, so it is a courtesy marker, not a hard TOCTOU guarantee.
- **SEC-16**: Terminal escape sequence sanitisation.
- **SEC-17**: NFS/network mount warning.
- **SEC-18**: Root user warning.
- **SEC-19**: Multiline ReDoS cap. Triple-quoted string blocks truncated to 8192 characters.
- **SEC-20**: Symlink in `--secure-backup-dir` validation.
- **SEC-21**: CI log prefix exposure. Credential masking shows only the first 4 characters.
- **SEC-22**: Setuid/setgid bit preservation.

### v2.3.0

- **SEC-23**: File symlink boundary enforcement. File symlinks resolving outside the scan root are skipped.
- **SEC-24**: SARIF output. `json.dumps` provides the injection safety; the masked preview in `message.text` is additionally HTML-escaped as defence-in-depth.
- **SEC-25**: Git history path traversal guard. Paths with `..` traversal sequences are rejected.
- **SEC-26**: CI read-only enforcement. `--ci` forces read-only operation (`--dry-run`); combining it with `--fix-all` is rejected as a hard error (exit 2), never a silent downgrade.
- **SEC-27**: Suppression audit trail. `--verbose` emits `[SKIP]` notices for every suppressed finding.
- **SEC-28**: Plaintext backup warning. One-time warning when backups are created without secure options.
- **SEC-29**: Config trust boundary enforcement in CI. External configs refused in CI mode.

### v2.3.2

- **SEC-30**: Env var name sanitisation. Non-identifier characters stripped from XML attribute keys. JS/TS uses bracket notation.
- **SEC-31**: Staged config tampering warning.
- **SEC-13b**: Extended broad pattern warning for extension-targeting wildcards.
- **SEC-09**: Atomic backup creation (updated). `tempfile.mkstemp()` + `os.replace()` eliminates TOCTOU race.
- **SEC-25/SEC-32**: Path traversal guard improvements. Component-level `..` check instead of substring.
- **SEC-15**: Windows file handle fix. Handle closed before `os.replace()` on Windows.
- **SEC-33**: Cross-platform path containment. `os.path.normpath()` then `os.sep` append after normalisation to prevent prefix collisions.
- **SEC-34**: Template safe-value closing delimiter. Requires matching `}`, `%}`, or `}}`. Fixes `$`-prefix bypass.
- **SEC-20**: Secure backup dir symlink (updated). Returns error and skips redaction instead of silent fallback.

### v2.3.3 (TTP Chain Audit, SEC-35 through SEC-39)

- **SEC-35**: SARIF output injection. HTML-escape the finding type in all SARIF rule fields (`id`, `shortDescription`, `fullDescription`) and the masked preview in the result message. Prevents XSS via attacker-controlled XML attribute names in downstream SARIF viewers. The whole document is JSON-encoded and only a short preview (first 4 chars + the literal `[REDACTED]`) ever appears; `artifactLocation.uri` is intentionally **not** HTML-escaped (it is a filesystem path consumed as data, not rendered as HTML).
- **SEC-36**: Terminal escape injection. Apply `sanitize_for_terminal()` to file paths, finding types, and raw source lines in text report output. Prevents ANSI escape-sequence injection via crafted filenames or source content.
- **SEC-37**: Bare `$` prefix. Reject `$` followed by a non-identifier character (`$/path`, `$+foo`, `$123abc`) so those aren't treated as env refs. A `$` followed by a valid identifier (`$VARNAME`) is still treated as an env reference by design. It cannot be distinguished from a real env var, so this does not stop a secret deliberately written as `$IDENTIFIER` (consistent with "not a security boundary").
- **SEC-38**: Config type confusion. Wrap `float()`/`int()` conversions in `apply_config_file()` with try/except. Prevents scan crash (DoS) from malformed `.credactor.toml` values.
- **SEC-39**: Config trust boundary (non-git). When no `.git` directory exists, fall back to comparing config location against the scan root. Prevents silent config loading from parent directories on non-git repos.

See `mydocs/vulnerability-chains.md` for the full chain analysis including attack narratives, scope, and false positives investigated.

### v2.4.0 (Phase 1–3 hardening + external ingestion)

**External-scanner ingestion (BETA), `credactor/ingest.py`:**

- **SEC-40a/b/c**: Ingested Gitleaks/TruffleHog reports are treated as untrusted. Each report file path is `normpath`+`resolve`d against the target and rejected if it escapes the target directory; a path equal to the report file itself is skipped (self-corruption guard); a missing-on-disk file is dropped; an embedded NUL or otherwise invalid path is skipped per-finding rather than aborting the batch. Reports are size-capped before parsing (bounding peak parse memory) and finding-count-capped after parsing, and non-UTF-8 (`U+FFFD`) secret fields are skipped.
- **Dedup severity merge**: native and external findings are deduplicated; on a duplicate at the same location, value, and commit context, the higher severity is kept, so a working-tree TruffleHog `Verified` (critical) duplicate does not downgrade the survivor. (Findings that differ only by commit are resolved by the working-tree-beats-committed rule, without a severity merge.) Ingested findings still pass through `.credactorignore` suppression.
- **Directory-target enforcement**: `--from-gitleaks` / `--from-trufflehog` exit 2 on a file target, a missing report, or when combined with `--scan-history`.

**CLI / config / suppression / backup:**

- **Non-git hard error**: `--staged` / `--scan-history` in a non-git directory exit 2 (was a false-clean exit 0).
- **`--staged` read-only**: forces dry-run even with `--fix-all` (which is warned and ignored), so a staged scan never rewrites the working tree.
- **Confirmation gate**: `--fix-all` requires a confirmation; without `--yes` / `-y` a non-TTY run aborts rather than silently rewriting files.
- **Config trust boundary (extends SEC-39)**: an implicitly-discovered `.credactor.toml` above the project root is refused in non-CI too; it is honoured only via an explicit `--config` (non-CI). CI always refuses it.
- **Secure-backup hardening**: `--secure-backup-dir` is refused if its path resolves through a symlink (leaf or any ancestor, excepting the well-known macOS `/tmp`, `/var`, `/etc` system symlinks), and fails closed (skips the file) when the directory is unwritable rather than leaving an in-repo plaintext `.bak`.
- **Replacement-string allowlist**: a custom replacement is validated against `[A-Za-z0-9_-]`, rejecting shell/markup/quote metacharacters, newlines, and control characters.
- **Config-input hardening (extends SEC-38)**: malformed list/table config shapes warn-and-skip instead of crashing or char-splitting a string value.
- **Suppression visibility**: value-literal and positional `file:line` suppressions warn at load time (the latter matches by line number only and can be defeated by line drift), and overly broad globs are flagged (`fnmatch` has no globstar, so `**` behaves as `*`). `.credactorignore` gains a `value:<literal>` prefix for values containing glob metacharacters.

This hardening shipped in **2.4.0** (Python 3.11+, uses stdlib `tomllib`).

### v2.5.0 (pre-commit parity, redaction safety, ingest + supply-chain hardening)

**Pre-commit (`--staged`) brought to parity with a working-tree scan** — closing silent false negatives at the gate:

- The staged scan runs the same `scanner.scan_lines()` pass as a working-tree scan (PEM blocks, multi-line strings included), enforces the same 50 MB file-size cap, and emits the same encoding warning on a NUL-bearing file whose encoding it cannot confirm — so the gate is no longer a quieter false negative than the tree scan.
- Staged blob lines are split with the same universal-newline `readlines()` the working-tree path uses, so a secret value embedding a form-feed, NEL, or Unicode line separator is no longer split across two lines and slipped past the gate.
- Lockfiles (`pnpm-lock.yaml` and the rest of `SKIP_FILES`) and configured `skip_files` are excluded before extension classification, exactly as in a directory walk.
- `--staged` and `--scan-history` are read-only (force dry-run; `--fix-all` is warned and ignored), and `--scan-history` warns when the repository is deeper than its 100-commit window so a truncated scan is distinguishable from a clean one.

**Redaction safety:**

- **Symlinked targets refused** — redaction skips (and counts unresolved) a symlinked file rather than following the link and rewriting a file outside the one named.
- **Empty / non-allowlisted `--replacement` rejected** (exit 2) before any file is touched, so a redaction can never delete the secret or inject metacharacters into surrounding code.
- **Hash fields are not auto-rewritten** — a quoted hex/Base64 value on a line keyed like a commit SHA, checksum, SRI integrity, digest, or revision field is left alone under `--fix-all` (key-scoped, with a credential-keyword veto so a genuine credential name still flags), so `--fix-all` cannot corrupt a lockfile checksum or SRI hash.
- **Value-global copy sweep** — after a rewrite, remaining word-boundary-delimited copies of a redacted value in the same file are cleared (bounded to that file, never overriding a skipped finding), so a deduplicated second copy is not left in plaintext.
- **Interactive backups are per-session** — a file is backed up once, on the first approval, so the `.bak` / `--secure-backup-dir` copy holds the true original of every approved finding rather than a partially-redacted intermediate from a later approval to the same file.
- **Machine-readable output stays clean** — `-f json` / `-f sarif` with `--fix-all` route the banner, prompts, and summary to stderr, keeping stdout a single parseable document.
- **TTY required** — interactive mode and the `--fix-all` confirmation require a TTY on stdin, so piped `y` input cannot auto-approve file rewrites.

**Ingest hardening (extends SEC-40):**

- A deeply-nested JSON report is a fatal error (exit 2) on both the Gitleaks and TruffleHog paths, instead of an uncaught `RecursionError`.
- A wholly-unparseable TruffleHog report (no JSON object on any line) is fatal, matching the Gitleaks path; a mixed report still ingests its valid findings.
- The report size cap is lowered from 100 MB to 20 MB, bounding `json.load` peak memory.
- An explicit `--from-*` overrides a config `[ingest]` entry, and an empty `--from-*` value is fatal (exit 2) rather than a silent no-op that could disable a config-sourced scan.

**Config trust:**

- An explicit `--config` that is missing, not a file, unreadable, or invalid TOML is a fatal error (exit 2) instead of a silent fall-back to default sensitivity; a *discovered* `.credactor.toml` that fails to parse still warns and falls back to defaults.
- Unknown top-level keys (and `[ingest]` keys) in `.credactor.toml` warn rather than being dropped silently, so a typo such as `entropy_treshold` cannot scan at the wrong sensitivity unnoticed.

**Detection robustness:**

- The connection-string detector matches in linear time on adversarial input (ReDoS path closed).
- BOM-less UTF-16 files are detected and scanned instead of being silently misread as UTF-8; a truncated/odd-length UTF-16 file follows the unreadable-file contract (warning, `--fail-on-error` exit 2, never a silent all-clear).
- A line past the 4096-character matching cap is reported with a `[WARN]` (naming the file on the working-tree, single-file, and `--staged` paths; a per-scan count on `--scan-history`), instead of scanning clean with no signal.

**Supply chain (see *Supply Chain Hardening* below):** the artifact audit now covers the **sdist** as strictly as the wheel (byte-for-byte against `git HEAD`, an archive-root-escape guard, and tracked non-package files verified too), and the PyPI publish workflow blocks an upload whose package version does not match the release tag (PEP 440 normalised).

This hardening shipped in **2.5.0**.

## Supply Chain Hardening

- **Artifact integrity audit:** `scripts/audit_wheel.py` verifies the wheel and sdist against the committed source: every `credactor/` file — and every tracked non-package file the sdist ships (`pyproject.toml`, `README`, `LICENSE`) — is hashed (sha256) against its `git HEAD` blob, and an extra file, a missing tracked file, an unexpected `.py` in the sdist, an sdist member whose path escapes the archive root, or no artifact at all each fail the gate. Byte-level comparison catches an in-place edit a file-name check would miss, and verifying the sdist's build config means a tampered `pyproject.toml` cannot ride along in a source distribution.
- **Version-tag gate:** the publish workflow blocks an upload unless `credactor.__version__` matches the release tag (PEP 440 normalised), so a mis-versioned release cannot reach PyPI.
- **SHA-pinned GitHub Actions:** All `uses:` references pin to commit SHAs, including `pypa/gh-action-pypi-publish`.
- **Hash-pinned CI dependencies:** Installed with `pip install --require-hashes`. This covers the build backend too: release artifacts are built with `python -m build --no-isolation` against the hash-pinned setuptools, not a backend downloaded fresh at publish time.
- **OIDC trusted publishing:** Short-lived tokens tied to this specific repo and workflow.
- **Sigstore attestations:** Published wheels include cryptographic provenance.
- **Dedicated publish environment:** Releases run only from a dedicated `pypi` GitHub environment, which scopes the OIDC trusted-publishing credentials to that environment.

## Known Limitations

- **NTFS alternate data streams:** On Windows, `--secure-delete` does not clear alternate data streams. Python has no cross-platform API for ADS enumeration.
- **Windows file locking:** Advisory locking (`fcntl`) is unavailable on Windows. Concurrent credactor processes modifying the same file are not protected.
- **String concatenation bypass:** `api_key = "sk_live_" + "rest"` evades detection. This is an architectural limitation of line-by-line scanning.
- **JSON excluded from directory scans:** `.json` files are skipped during a directory/recursive scan unless `--scan-json` is passed. This is intentional, to reduce false positives from API response data. A `.json` file named explicitly as the scan target is still scanned.
