# Security Model

Credactor is a **developer-side static analysis tool** that scans source files for hardcoded credentials. Understanding its trust boundaries is important for safe deployment.

## What Credactor Protects Against

- Accidentally committing hardcoded API keys, tokens, passwords, and private keys.
- Credentials in assignment statements, XML attributes, connection strings, PEM blocks, and multi-line strings.
- Re-flagging already-redacted values (the sentinel `REDACTED_BY_CREDACTOR` is in the safe-values list).

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

- **SEC-01** — Secure backup handling: `--secure-backup-dir` stores `.bak` files outside the repo; `--secure-delete` overwrites backups with random data before unlinking.
- **SEC-02** — Untrusted config handling: An implicitly-discovered `.credactor.toml` outside the git project root is refused (`[ERROR]` on stderr, config ignored). An explicit `--config` pointing outside the root is honored with a `[WARN]` in non-CI mode; in CI it is always refused (see SEC-29 / M14).
- **SEC-03** — Config parse failure surfacing: Warns on stderr instead of silently returning empty config.
- **SEC-04** — Subprocess path sanitisation: All `subprocess.run(cwd=...)` calls resolve paths via `Path.resolve()` before execution.
- **SEC-05** — File descriptor exhaustion protection: `EMFILE` errors in the thread pool trigger automatic sequential fallback.
- **SEC-06** — ReDoS line-length guard: Lines longer than 4096 characters are truncated before regex pattern matching.
- **SEC-07** — Temp file leakage prevention: `.credactor.tmp` files are cleaned up via a `finally` block even on crashes.
- **SEC-08** — Forward-only scanning with expanded protected directories: 30+ system directories blocked across Linux, macOS, and Windows.
- **SEC-09** — Symlink race in backup creation: `_create_backup()` checks `os.path.islink()` before writing `.bak` files.
- **SEC-10** — Replacement string injection validation: `--replacement` values are checked against dangerous character patterns.
- **SEC-11** — Data loss safeguard for `--fix-all --no-backup`: Displays a prominent DANGER banner.
- **SEC-12** — Config injection bounds validation: `entropy_threshold` clamped to 0.0–6.0 and `min_value_length` to 1–200.
- **SEC-13** — Wildcard `.credactorignore` warning: Overly broad patterns trigger a `[WARN]`.
- **SEC-14** — `--replace-with env` semantic change warning.
- **SEC-15** — TOCTOU file locking: Advisory `fcntl.flock()` lock held through atomic replacement.
- **SEC-16** — Terminal escape sequence sanitisation.
- **SEC-17** — NFS/network mount warning.
- **SEC-18** — Root user warning.
- **SEC-19** — Multiline ReDoS cap: Triple-quoted string blocks truncated to 8192 characters.
- **SEC-20** — Symlink in `--secure-backup-dir` validation.
- **SEC-21** — CI log prefix exposure: Credential masking shows only the first 4 characters.
- **SEC-22** — Setuid/setgid bit preservation.

### v2.2.2

- **SEC-23** — File symlink boundary enforcement: File symlinks resolving outside the scan root are skipped.
- **SEC-24** — SARIF output sanitisation: HTML-escaped via `html.escape()`.
- **SEC-25** — Git history path traversal guard: Paths with `..` traversal sequences are rejected.

### v2.3.0

- **SEC-26** — CI read-only enforcement: `--ci` blocks `--fix-all` and forces `--dry-run`.
- **SEC-27** — Suppression audit trail: `--verbose` emits `[SKIP]` notices for every suppressed finding.
- **SEC-28** — Plaintext backup warning: One-time warning when backups are created without secure options.
- **SEC-29** — Config trust boundary enforcement in CI: External configs refused in CI mode.

### v2.3.1

- **SEC-30** — Env var name sanitisation: Non-identifier characters stripped from XML attribute keys. JS/TS uses bracket notation.
- **SEC-31** — Staged config tampering warning.
- **SEC-13b** — Extended broad pattern warning for extension-targeting wildcards.
- **SEC-09** — Atomic backup creation (updated): `tempfile.mkstemp()` + `os.replace()` eliminates TOCTOU race.
- **SEC-25/SEC-32** — Path traversal guard improvements: Component-level `..` check instead of substring.
- **SEC-15** — Windows file handle fix: Handle closed before `os.replace()` on Windows.

### v2.3.2

- **SEC-33** — Cross-platform path containment: `os.path.normpath()` then `os.sep` append after normalisation to prevent prefix collisions.
- **SEC-34** — Template safe-value closing delimiter: Requires matching `}`, `%}`, or `}}`. Fixes `$`-prefix bypass.
- **SEC-20** — Secure backup dir symlink (updated): Returns error and skips redaction instead of silent fallback.

### TTP Chain Audit (SEC-35 through SEC-39)

- **SEC-35** — SARIF output injection: HTML-escape finding type in all SARIF rule fields (`id`, `shortDescription`, `fullDescription`). Prevents XSS via attacker-controlled XML attribute names in downstream SARIF viewers.
- **SEC-36** — Terminal escape injection: Apply `sanitize_for_terminal()` to file paths, finding types, and raw source lines in text report output. Prevents ANSI escape-sequence injection via crafted filenames or source content.
- **SEC-37** — Bare `$` prefix bypass: Validate that text after `$` matches POSIX env var name syntax (`[A-Za-z_][A-Za-z0-9_]*`). Prevents suppressing credentials by prefixing with `$`.
- **SEC-38** — Config type confusion: Wrap `float()`/`int()` conversions in `apply_config_file()` with try/except. Prevents scan crash (DoS) from malformed `.credactor.toml` values.
- **SEC-39** — Config trust boundary (non-git): When no `.git` directory exists, fall back to comparing config location against the scan root. Prevents silent config loading from parent directories on non-git repos.

See `mydocs/vulnerability-chains.md` for the full chain analysis including attack narratives, scope, and false positives investigated.

## Supply Chain Hardening

- **Wheel integrity audit:** `scripts/audit_wheel.py` verifies wheel contents match the git repo.
- **SHA-pinned GitHub Actions:** All `uses:` references pin to commit SHAs. Exception: `pypa/gh-action-pypi-publish` uses `release/v1` (Docker-based actions cannot be SHA-pinned).
- **Hash-pinned CI dependencies:** Installed with `pip install --require-hashes`.
- **OIDC trusted publishing:** Short-lived tokens tied to this specific repo and workflow.
- **Sigstore attestations:** Published wheels include cryptographic provenance.
- **Environment protection:** The `pypi` GitHub environment requires manual approval.

## Known Limitations

- **NTFS alternate data streams:** On Windows, `--secure-delete` does not clear alternate data streams. Python has no cross-platform API for ADS enumeration.
- **Windows file locking:** Advisory locking (`fcntl`) is unavailable on Windows. Concurrent credactor processes modifying the same file are not protected.
- **String concatenation bypass:** `api_key = "sk_live_" + "rest"` evades detection. This is an architectural limitation of line-by-line scanning.
- **JSON excluded by default:** Credentials in `.json` files are not scanned unless `--scan-json` is passed. This is intentional to reduce false positives from API response data.
