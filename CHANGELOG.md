# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Docs: clarified that external-scanner ingestion currently supports Gitleaks
  and TruffleHog, with more detectors planned — corrected README/manual wording
  that implied pairing with any scanner.

## [2.4.0] - 2026-06-07

### Added

- **External-scanner ingestion (BETA).** New `--from-gitleaks FILE` and
  `--from-trufflehog FILE` flags ingest findings from a Gitleaks JSON report or
  a TruffleHog NDJSON file and merge them into the redaction pipeline. Ingested
  findings are deduplicated against native findings; on a duplicate at the same
  location, value, and commit context the higher severity is kept (so a
  working-tree external `Verified` critical is not downgraded; findings differing
  only by commit are resolved working-tree-over-committed without a severity
  merge). Both flags require a **directory** target so report-relative paths
  resolve, and cannot be combined with `--scan-history`. The same paths can be
  set via an `[ingest]` table in `.credactor.toml` (`from_gitleaks` /
  `from_trufflehog`).
- `--yes` / `-y`: skips the `--fix-all` confirmation prompt for non-interactive
  / CI use. Without it, `--fix-all` aborts when stdin is not a TTY (pipe,
  `</dev/null`).
- `.credactorignore` gains an explicit `value:<literal>` prefix for suppressing
  secret values that contain glob metacharacters (`. / ? *`), which would
  otherwise be routed to path/glob matching. Overly broad globs (`*/*`,
  `**/*.*`, …) now warn at load time (note: `fnmatch` has no globstar, so `**`
  behaves as `*`).
- Detection recall: standalone key/cert files (`.pem` `.key` `.crt` and
  `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`), `.config` (web.config/app.config)
  files, Go `:=` short-variable assignments, compact JWTs, and multiple distinct
  secrets on a single line are now detected.

### Changed

- Verbose diagnostics in the external-scanner ingest paths (`--from-gitleaks`,
  `--from-trufflehog`) and the deduplication pass now flow through the central
  logger instead of raw `print(..., file=sys.stderr)`. Informational ingest
  messages display with the `[INFO]` prefix (previously `[WARN]`), and per-line
  suppression breadcrumbs route through `logger.debug` (`[SKIP]`). Output stays
  on stderr and default (non-verbose) runs are unchanged.
- `--staged` is now strictly read-only: a staged scan never rewrites the working
  tree, so `--fix-all` is ignored (with a warning) and the run is forced to
  dry-run. It still reports findings and exits 1.
- Config trust boundary tightened (extends SEC-29): an implicitly-discovered
  `.credactor.toml` outside the project root is now refused in non-CI mode too,
  not just in CI — it is honoured only when `--config` points at it explicitly.
- Deterministic provider prefixes (AWS, GCP, Stripe-live, GitHub, GitLab, Slack,
  npm, PyPI) and PEM blocks are no longer entropy-gated, so a format-valid token
  is flagged regardless of randomness, and provider prefixes are also scanned
  inside comment lines. Heuristic detectors (hex, Base64, JWT, connection
  strings) stay entropy-gated; this is a deliberate recall-over-precision trade
  for unambiguous tokens.
- **BREAKING:** Minimum Python version raised to **3.11**. Python 3.10
  support is dropped. Users on 3.10 must pin to credactor `< 2.4` or
  upgrade Python. Rationale: 3.10 reaches end-of-life in October 2026,
  and `tomllib` (3.11+ stdlib) replaces the previous hand-rolled TOML
  fallback parser, preserving the project's zero-runtime-dependency
  policy.

### Security

- **Redaction leak fix:** when the same secret value appeared more than once on
  a line but scanned to a single finding, an extra copy could be left in
  plaintext while the run reported success. A post-replacement sweep now removes
  any surviving standalone copy of a redacted value (bounded by non-word
  characters, so an adjacent longer token is never corrupted).
- **Replacement-string hardening:** a custom `--replacement` (or config
  `replacement`) is validated against an allowlist (`[A-Za-z0-9_-]`), rejecting
  shell/markup/quote metacharacters, newlines, and control characters that could
  inject into rewritten files. An explicit CLI `--replacement` now correctly
  overrides a config value.
- **Backup hardening:** `--secure-backup-dir` is refused when the path resolves
  through a symlink (leaf or any ancestor), and fails closed when the directory
  is unwritable — it never falls back to an in-repo plaintext `.bak`.
- **Config-input hardening:** a malformed `.credactor.toml` (a non-list list
  key, a non-string list element, an out-of-range scalar) no longer crashes or
  corrupts state — invalid values warn and fall back to defaults.
- `--staged` / `--scan-history` run outside a git repository now exits 2 instead
  of a false-clean exit 0.
- **Encoding false-clean made visible:** when a file's encoding cannot be
  positively confirmed (no `charset-normalizer` / `chardet` extra and not valid
  UTF-8), Credactor falls back to Latin-1, which silently misreads multibyte
  encodings such as UTF-16 and can miss their secrets. It now emits a `[WARN]`
  naming the file and recommending the encoding extra, so a non-UTF-8 file is no
  longer passed as a silent clean.
- **Ingest hardening (SEC-40a/b/c):** a report file-size guard before parsing,
  hardening against non-string path/secret fields, path-traversal and
  self-reference guards, symlink resolution with within-target containment,
  `.credactorignore` suppression of ingested findings, and graceful skipping of
  a finding with a missing file or an invalid (NUL-byte) path (skips the one
  finding rather than aborting the batch).

### Fixed

- Detection recall: recognise bare `secret`, `api_secret`, and `auth_secret`
  variable names (word-boundary matched, so `secretary` is not flagged), and
  treat HashiCorp `vault:` references as safe lookups rather than hardcoded
  secrets.

### Removed

- `credactor.config._basic_toml_parse` — replaced by stdlib `tomllib`.
  This was a private helper; no public API impact.

## [2.3.3] - 2026-04-09

### Fixed

- **SEC-35:** SARIF output injection — HTML-escape finding type in all SARIF rule fields to prevent XSS via attacker-controlled XML attribute names.
- **SEC-36:** Terminal escape injection — sanitise file paths, finding types, and raw source lines in text report output.
- **SEC-37:** Bare `$` prefix detection bypass — validate POSIX env var name syntax after `$` to prevent credential suppression.
- **SEC-38:** Config type confusion DoS — guard `float()`/`int()` conversions against malformed `.credactor.toml` values.
- **SEC-39:** Config trust boundary (non-git) — fall back to scan root when no `.git` exists, preventing silent config loading from parent directories.

### Added

- TTP-based vulnerability chain analysis (`mydocs/vulnerability-chains.md`).
- 21 new security tests covering SEC-35 through SEC-39.

## [2.3.2] - 2026-03-28

### Fixed

- **SEC-33:** Path containment prefix collision — `_is_within_root()` now appends `os.sep` after `normpath()` to prevent `/tmp/repo` matching `/tmp/repo_evil`.
- **SEC-34:** Template safe-value bypass — unclosed `${AKIA...` was falsely marked safe because the `$`-prefix check was too broad. Now requires matching closing delimiters.
- **SEC-20:** Secure backup dir symlink — now returns an error and skips redaction instead of silently falling back to an in-repo backup.
- **SEC-30:** Code injection via crafted XML attribute keys in `--replace-with env` mode. Env var names now stripped to `[A-Za-z0-9_]`. JS/TS uses bracket notation.
- **SEC-09:** Atomic backup creation via `mkstemp()` + `os.replace()` eliminates TOCTOU race.
- **SEC-25/SEC-32:** Path traversal guards now reject `..` as a path component, not a substring.
- **SEC-15:** Windows file handle released before `os.replace()` to prevent "Access Denied" errors.

### Added

- Security test suite (`tests/test_security.py`) covering path containment, symlink boundaries, CI enforcement, and template safe-value logic.
- **SEC-31:** Warning when `.credactor.toml` or `.credactorignore` are staged alongside code changes.
- **SEC-13b:** Warning on extension-targeting wildcard patterns in `.credactorignore`.
- Windows compatibility: drive root protection, permission test skip, `fcntl` handle fix.
- 7 new security tests for env var sanitisation and language-specific replacements.

## [2.3.0] - 2026-03-27

### Added

- **SEC-26:** `--ci` now enforces read-only mode — blocks `--fix-all` and forces `--dry-run`.
- **SEC-27:** `--verbose` / `-v` flag with suppression audit trail (`[SKIP]` notices on stderr).
- **SEC-28:** One-time plaintext backup warning when `--secure-delete` is not used.
- **SEC-29:** `.credactor.toml` from outside project root is blocked in CI mode.
- `--version` flag.
- Clean `KeyboardInterrupt` handling (exit 130, no traceback).
- Home directory scan protection (prevents hang on `~`).

### Fixed

- **SEC-23:** File symlinks resolving outside scan root are now skipped.
- **SEC-24:** SARIF output HTML-escaped to prevent injection in downstream consumers.
- **SEC-25:** Git history paths with `..` traversal sequences are rejected.

## [2.2.1] - 2026-03-27

### Added

- Supply chain hardening: wheel integrity audit, SHA-pinned GitHub Actions, hash-pinned CI dependencies, OIDC trusted publishing, Sigstore attestations.
- 22 security hardening measures (SEC-01 through SEC-22).

### Fixed

- Ruff lint compliance across all source files.

## [2.2.0] - 2026-03-26

### Added

- Initial public release.
- Multi-phase detection engine: regex signatures, entropy analysis, context-aware variable inspection.
- 14 credential patterns (AWS, GCP, Stripe, GitHub, GitLab, Slack, npm, PyPI, PEM, JWT, connection strings, hex, base64).
- Interactive and batch redaction modes.
- Language-aware env var replacement (Python, JS/TS, Go, Java, Ruby, PHP, shell).
- SARIF 2.1.0 output for GitHub Code Scanning.
- `.credactor.toml` configuration and `.credactorignore` suppressions.
- Parallel file scanning via `ThreadPoolExecutor`.
- Git staged file and history scanning.
- Pre-commit hook support (beta).

[Unreleased]: https://github.com/rxb06/Credactor/compare/v2.4.0...HEAD
[2.4.0]: https://github.com/rxb06/Credactor/compare/v2.3.3...v2.4.0
[2.3.3]: https://github.com/rxb06/Credactor/compare/v2.3.2...v2.3.3
[2.3.2]: https://github.com/rxb06/Credactor/compare/v2.3.0...v2.3.2
[2.3.0]: https://github.com/rxb06/Credactor/compare/v2.2.1...v2.3.0
[2.2.1]: https://github.com/rxb06/Credactor/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/rxb06/Credactor/releases/tag/v2.2.0
