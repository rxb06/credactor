# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
with one documented exception: dropping support for a near-end-of-life Python
version may happen in a **minor** release. Such a drop is always flagged
**BREAKING** in the release notes — if you must stay on an older Python, pin
below the release that dropped it (2.4.0 dropped Python 3.10, so:
`credactor<2.4`).

## [2.5.0] - 2026-06-21

### Changed (behaviour)

- `.txt` files are now scanned by default (in directory walks and `--staged`), previously skipped unless added via `extra_extensions`. **Upgrade impact:** repos with credential-shaped example text in `.txt` notes will see new findings, which fail a `--ci`/`--staged` gate and become `--fix-all` targets; preview with `--dry-run` and suppress via `.credactorignore` or `extra_safe_values`. `.md` stays excluded by default.
- An explicit `--from-gitleaks`/`--from-trufflehog` now takes precedence over a same-kind `.credactor.toml` `[ingest]` entry (CLI > config); previously the config entry won and the flag was silently ignored. An empty `--from-*` value (for example an unset shell variable) is now a fatal error (exit 2) rather than a silent no-op.
- The ingest report size cap is lowered from 100 MB to 20 MB, keeping ample headroom over realistic reports while bounding `json.load` memory use.

### Added

- Windows CI: the test job now runs on Linux and Windows across Python 3.11-3.13, exercising the package's existing Windows code paths. Platform support is declared explicitly (`OS Independent` classifier and a README line).
- CI installs `charset-normalizer`, so the `encoding` extra's detection path is now exercised by the test suite.
- `scripts/` is now covered by ruff and mypy strict in CI and `make lint`.
- A `.github/dependabot.yml` (monthly: github-actions and pip) to keep the SHA/hash-pinned CI dependencies refreshed.
- A `.pre-commit-config.yaml` for this repo's developers (ruff, mypy strict, and the credactor self-scan).
- PyPI sidebar links: `[project.urls]` now declares Issues, Changelog, and Documentation alongside Repository.
- The build-artifact audit (`scripts/audit_wheel.py`) now verifies the **wheel and sdist** against the committed source: every `credactor/` file is content-hashed (sha256) against its `git HEAD` blob, and an added, missing, or altered package file, any untracked member in the wheel, any untracked `credactor/` member or stray `.py` in the sdist, a sdist member whose path escapes the archive root, or no artifact at all fails the gate. Byte-level comparison catches an in-place code edit that the previous file-name check would have missed.
- Test coverage for three previously untested core paths: the interactive redaction flow, `--scan-json` end-to-end, and the non-UTF-8 (Latin-1) redaction round-trip.
- Unknown top-level keys in `.credactor.toml` now log a warning instead of being dropped silently (a typo such as `entropy_treshold` could otherwise scan at the wrong sensitivity unnoticed). The guard also covers the `[ingest]` table.
- A single-file target (`credactor app.py`) that finds a `.credactorignore` beside it now warns, since an allowlist file applies only to a directory scan.
- The PyPI publish workflow verifies the package version matches the release tag (PEP 440 normalised) before publishing.

### Fixed

- Redaction now refuses a symlinked target (warns and skips) rather than following the link and rewriting a file outside the one named. `--secure-backup-dir` backups are written directly inside the directory you pass (never beside the original, even momentarily), and each backup name is made unique per source path so two same-named files in different directories cannot clobber each other's backup.
- An empty or non-allowlisted `--replacement` is now rejected (exit 2) before any file is touched, instead of deleting the secret or injecting characters that could corrupt surrounding code.
- Quoted hex/Base64 values on a line keyed like a commit SHA, checksum, SRI integrity, digest, or revision field are no longer auto-rewritten under `--fix-all`; they are hash outputs, not credentials. A genuinely credential-named value is still flagged.
- The connection-string detector now matches in linear time on adversarial input, closing a ReDoS backtracking path.
- A deeply-nested JSON ingest report is now a fatal error (exit 2) for both the Gitleaks and TruffleHog paths, instead of an uncaught `RecursionError`.
- SARIF output now declares `columnKind: unicodeCodePoints`, so GitHub Code Scanning no longer mis-highlights lines containing astral-plane characters.
- A wholly-unparseable TruffleHog report (no JSON object on any line) is now a fatal error (exit 2), matching the Gitleaks path; a mixed report still ingests its valid findings, and an empty report is still a legitimate "no findings".
- An explicit `--config` that is missing, not a file, unreadable, or invalid TOML is now a fatal error (exit 2), instead of silently scanning at default sensitivity. A *discovered* `.credactor.toml` that fails to parse still warns and falls back to defaults.
- BOM-less UTF-16 files are now detected and scanned instead of being a silent miss (their NUL-interleaved ASCII payload previously read as UTF-8 and dissolved). A truncated or odd-length UTF-16 file that fails to decode follows the unreadable-file contract (warning, `--fail-on-error` exit 2, never a silent all-clear). **Upgrade impact:** real secrets in UTF-16 files will newly flag.
- `min_value_length` no longer gates deterministic critical patterns: provider tokens are found even at `min_value_length = 200`, matching the exemption `entropy_threshold` already had. **Upgrade impact:** placeholder provider keys silenced by a large `min_value_length` will flag again.
- Prefixed API-key variable names (`test_api_key`, `my_api_key`, `aws_api_key`, and similar) are now detected, as the manual already stated (safe values match by value, not name). Placeholder *values* remain auto-safe, and fixtures can be suppressed via `.credactorignore`/`extra_safe_values`/inline directives.
- A bare `token = "<value>"` assignment is now detected (high severity), matching the severity table; camelCase and underscore variants (`pageToken`, `csrf_token`, `max_tokens`) stay unmatched by design.
- Unquoted `password: ${DB_PASSWORD}` (the docker-compose/CI idiom) is no longer flagged. Only the complete `${NAME}` form is newly safe; `${VAR:-fallback}` and an unclosed `${` still flag.
- Interactive mode and the `--fix-all` confirmation now require a TTY on stdin, as the manual states. **Behaviour change:** `yes | credactor` / `echo y | credactor --fix-all` no longer work; use `--fix-all --yes`. On Git Bash/mintty, native Python sees a pipe, so use `winpty credactor ...` (or `--fix-all --yes`/`--dry-run`).
- `-f json`/`-f sarif` combined with `--fix-all` no longer corrupts the machine-readable stream: the confirmation banner, prompts, and summary now go to stderr for non-text formats (text output is unchanged).
- `--dry-run --fix-all` now warns that dry-run takes precedence and `--fix-all` is ignored, matching the signal the other read-only combinations already give.
- The post-redaction ".bak files contain plaintext" footer now reflects the backup mode, instead of printing unconditionally (it previously warned under `--no-backup` about files that never existed, and recommended `--secure-delete` when it was already in use).
- Lines longer than the 4096-character matching cap are now reported with a `[WARN]` naming the file, instead of scanning clean with no signal. Covers working-tree, single-file, `--staged`, and `--scan-history` paths.
- `--scan-history` now warns when the repository is deeper than its 100-commit window, so a truncated all-clear is no longer indistinguishable from a full clean scan. The window and exit code are unchanged.
- `.credactor.toml` discovery now reaches the documented five parent directories (an off-by-one previously stopped at four).
- Redaction now clears every unreported copy of a secret in a file it rewrites, not just the reported occurrence (for example a value a detector deduplicated). The sweep is value-global within each rewritten file, never opens other files, and never overrides a finding the user skipped; a `[WARN]` states how many extra copies were cleared.
- `--staged` now runs the same full scan as a working-tree scan (both share `scanner.scan_lines()`); a secret inside a triple-quoted or template-literal string previously passed the pre-commit gate undetected.
- Interactive review's Ctrl-C summary now says "replacement(s)" instead of "file(s)".
- `--scan-history` is now read-only (forces dry-run, like `--staged`); it previously flowed into redaction that failed on every finding. Passing `--fix-all` now warns and is ignored.
- `--staged` now honours `--scan-json`: a staged `.json` file is scanned with the flag and skipped without it, matching the directory walk. Lockfiles remain excluded either way.
- Git subprocess output is decoded as UTF-8 explicitly, so non-ASCII staged filenames are scanned on Windows instead of being mojibaked into the error list. History-scan decoding degrades stray bytes to U+FFFD rather than crashing.
- Staged blob content is universal-newline normalised before scanning, so CRLF blobs no longer leak literal `\r` into previews and lone-`\r` endings no longer skew multiline line numbers.
- The `--staged` pre-commit scan now enforces the same 50 MB file-size cap as the working-tree scan, and emits the same encoding warning on a NUL-bearing file whose encoding it cannot confirm, so the staged path is no longer a silently quieter false negative than the tree scan.
- README links now use absolute GitHub URLs; the relative links resolved against pypi.org (the README is the PyPI landing page) and returned 404s.
- The published sdist no longer ships a partial copy of the test suite (a new `MANIFEST.in` prunes `tests/`); the wheel was never affected.
- `build-system.requires` now demands `setuptools>=77`, the first version that understands the PEP 639 SPDX `license` string; the obsolete `wheel` requirement is dropped.
- `SECURITY.md`'s Supported Versions table now lists 2.4.x (it still said 2.3.x).
- The pre-commit hook manifest declares `minimum_pre_commit_version: 3.2.0`, matching its `stages: [pre-commit]` spelling.

### Changed

- Scan-speed fixes in three hot paths (no behaviour change on normal input): the assignment regex's variable-name capture is bounded to 128 chars (closing quadratic backtracking on long word runs); `detect_encoding` resolves the optional charset libraries once at import and short-circuits pure-ASCII files to UTF-8; and `.gitignore` matching computes the relative path once per base directory instead of once per rule.
- `ingest_trufflehog`'s per-record parse was extracted into `_parse_trufflehog_record` (same validation and log messages), now unit-testable and a readable template for future detector parsers.
- Removed an unreachable "unsafe replacement" regex guard in the redactor; the `re.sub` sanitiser on `[A-Za-z0-9_]`-stripped env names is the actual defence.
- `_log.configure` no longer takes an unused `no_color` parameter (log output has no colour).
- `--replacement` combined with `--replace-with env` now warns that the fixed string is never consulted, instead of silently ignoring it.
- Combining `--no-backup` with `--secure-backup-dir`/`--secure-delete` now warns that no backup is created, so those flags have no effect.
- The 'clean scan' message now has a single owner (`cli._emit_report`); the drifted duplicate in `report.print_report` was removed.
- CI now runs on the `develop` branch (push and pull request), where day-to-day work happens; previously only `main` was checked.
- `make lint` now runs the type checker as well as ruff, matching CI; CONTRIBUTING was aligned and no longer claims the code is auto-formatted (it is linted, not formatted).
- The version is single-sourced from `credactor.__version__` (pyproject declares `dynamic = ["version"]`), so pip metadata and `credactor --version` cannot drift apart.
- CI and publish builds run `python -m build --no-isolation` with setuptools hash-pinned in `requirements-ci.txt`, extending supply-chain pinning to the build backend.
- The PyPI publish action (`pypa/gh-action-pypi-publish`) is now pinned to a commit SHA like every other action, rather than a mutable `@release/v1` branch ref.
- Docs: clarified that external-scanner ingestion currently supports Gitleaks and TruffleHog, with more detectors planned (correcting wording that implied any scanner).
- The CHANGELOG preamble states the project's one SemVer exception explicitly: dropping a near-end-of-life Python version may happen in a minor release (always flagged BREAKING), as in 2.4.0.

### Removed

- The scanning thread pool. Detection is regex-CPU-bound and serialised by the GIL, so the 8-worker pool measured only 1.0-1.3x while carrying the project's trickiest code (a lock, a futures map, an EMFILE retry). Scanning is now sequential, and file-descriptor exhaustion is impossible by construction.
- The interactive `.json` file picker. `--scan-json` is already the explicit opt-in, so the numbered prompt was a redundant second gate (~70 lines); all modes now scan every collected `.json` uniformly. Note: a non-TTY `--scan-json` run without `--ci`/`--dry-run` previously hit EOF at the picker and silently skipped JSON (exit 0); it now scans them and exits 1.
- Internal simplifications with no behaviour change (a test-only `.gitignore` duplicate, the `log_verbose` wrapper, scanner config aliases, an unused `_evaluate_candidate` parameter, several unreachable guards, and the opportunistic `chardet` encoding-detection tier, which was never a declared dependency).
- The legacy repo-root `credential_redactor.py` shim; it was never shipped and nothing referenced it. `credactor` and `python -m credactor` cover every documented invocation.

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

---

**Yanked releases:** every release before 2.3.3 is yanked on PyPI
(2.0.0–2.3.2). The pre-2.2.0 uploads were unsupported early builds predating
the SEC-01…SEC-22 hardening and the wheel-audit publish gate; the rest are
superseded. Resolvers will only select **2.3.3** (the last release supporting
Python 3.10 — see the versioning note above) or **2.4.0+**; yanked versions
remain installable solely via exact `==` pins.

[2.5.0]: https://github.com/rxb06/credactor/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/rxb06/credactor/compare/v2.3.3...v2.4.0
[2.3.3]: https://github.com/rxb06/credactor/compare/v2.3.2...v2.3.3
[2.3.2]: https://github.com/rxb06/credactor/compare/v2.3.0...v2.3.2
[2.3.0]: https://github.com/rxb06/credactor/compare/v2.2.1...v2.3.0
[2.2.1]: https://github.com/rxb06/credactor/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/rxb06/credactor/releases/tag/v2.2.0
