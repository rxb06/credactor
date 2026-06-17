# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
with one documented exception: dropping support for a near-end-of-life Python
version may happen in a **minor** release. Such a drop is always flagged
**BREAKING** in the release notes — if you must stay on an older Python, pin
below the release that dropped it (2.4.0 dropped Python 3.10, so:
`credactor<2.4`).

## [2.4.1] - 2026-06-17

### Changed (behaviour)

- `.txt` files are now scanned by default (previously skipped unless added
  via `extra_extensions`), in directory walks and `--staged` alike. Notes
  and scratch files are a classic leak vector — the team's own efficacy
  benchmark flagged this blind spot — and a measured false-positive corpus
  (prose, TODO lists, LICENSE text, lorem, meeting notes, robots.txt,
  CMakeLists.txt, and a 338-hash-pin `requirements.txt`) produced **zero**
  `.txt`-specific findings: hash pins are protected by the quote-prefix and
  hash-context guards, a property now pinned by a regression test.
  **Upgrade blast radius:** repos with credential-shaped *example* text in
  `.txt` notes will see new findings on first run — those flip a `--ci` /
  `--staged` gate to a fail (exit 1) and become `--fix-all` rewrite targets
  (the example value is replaced in place, `.bak` kept). Preview with
  `--dry-run`, and suppress via `.credactorignore` (e.g. `docs/*.txt`) or
  `extra_safe_values` before redacting. `.md` remains out by default — it is
  example-credential-dense by convention; use `extra_extensions` to opt in.

### Added

- Windows CI: the test job now runs on Linux **and Windows** across Python
  3.11–3.13. The package always carried deliberate Windows code paths
  (drive-root guard, fcntl fallback, path-case handling) that no automated
  test had ever executed. Three tests gained platform guards to make the
  matrix green (POSIX permission bits, the macOS symlinked-`/etc` check, and
  a case-sensitivity assertion that inverts on NTFS by design); the platform
  support statement is now explicit: an `Operating System :: OS Independent`
  classifier and a README line (Linux, macOS, Windows — CI-tested on Linux
  and Windows).
- CI installs `charset-normalizer`, so the `encoding` extra's real detection
  path is finally exercised by the test suite — an upstream API change would
  previously have first surfaced as a crash on users' machines.
- `scripts/` is now covered by ruff and mypy strict in CI and `make lint`
  (the release-gating audit script was held to a lower bar than the package
  and had accumulated two lint errors and missing annotations, now fixed).
- A `.github/dependabot.yml` (monthly, github-actions + pip): the SHA-pinned
  actions and hash-pinned CI dependencies previously had nothing proposing
  updates — frozen-but-never-refreshed pins eventually mean running CI on
  tooling with known fixed bugs.
- A `.pre-commit-config.yaml` for this repo's own developers: ruff, mypy
  strict, and the credactor self-scan run at commit time via the dev
  environment's tools (`pre-commit install` once; CONTRIBUTING documents it).
- PyPI sidebar links: `[project.urls]` now declares Issues, Changelog, and
  Documentation alongside Repository.
- The wheel audit gate (`scripts/audit_wheel.py`) now also fails when `dist/`
  contains **no wheel at all** (a half-failed build previously produced a
  false "Wheel audit passed"), and checks the **reverse direction** — a
  tracked source file missing from the wheel is now an error, matching the
  script's "match exactly" contract.
- Test coverage for the three remaining untested core paths: the default
  interactive redaction flow (y/n/Enter, invalid-answer re-prompt, Ctrl-C
  mid-review, failed-replacement accounting), `--scan-json` end-to-end
  detection (exit 1 with the flag, 0 without), and the non-UTF-8 (latin-1)
  redaction round-trip (secret removed, every other byte preserved).
- Unknown top-level keys in `.credactor.toml` now log a warning instead of
  being dropped silently. Malformed known keys already warned; a typo'd key
  (e.g. `entropy_treshold`) was the one config mistake with no signal — for a
  security tool that can mean scanning at the wrong sensitivity unnoticed.
  The same guard now covers the `[ingest]` table (a typo'd `from_gitleaks`
  meant ingestion silently never ran).
- A single-file target (`credactor app.py`) that finds a `.credactorignore`
  beside it now warns. A `.credactorignore` is loaded only for a directory
  scan (its root is the scanned directory), so a file target applied none —
  previously silently, so a user expecting their allowlist to apply got no
  suppression and no signal. Inline `# credactor:ignore` still works on a file
  target; the manual now documents the directory-scan scope.

### Fixed

- A TruffleHog report (`--from-trufflehog`) that is wholly unparseable —
  content with no JSON object on any line (an HTML error page, a typo'd file,
  or a Gitleaks JSON array fed to the NDJSON path) — is now a fatal error
  (exit 2), matching the Gitleaks path. It previously skipped each bad line
  with only a `--verbose` `[INFO]` and exited 0 with `[OK] No hardcoded
  credentials` — a silent false-clean on a wrong/typo'd report for one of the
  two supported scanners. A *mixed* report still ingests its valid findings
  (per-line tolerance), and an empty report is still a legitimate "no findings".
- An explicit `--config` that exists but cannot be parsed — invalid TOML or an
  unreadable file — is now a fatal error (exit 2), matching the missing-file
  guard. It previously warned and silently scanned at default sensitivity, the
  same CI-gate-flip threat as a `--config` typo: a content typo in a tuned
  config dropped its `extra_extensions`/threshold settings and could flip a
  failing secret gate to a pass. Scoped to the explicit path only — a
  *discovered* `.credactor.toml` that fails to parse still warns and falls back
  to defaults, so a stray broken config elsewhere in the tree never aborts a
  scan.
- BOM-less UTF-16 files are no longer a *silent* miss on stock installs —
  they are now detected and scanned. NUL-interleaved ASCII (exactly what
  BOM-less UTF-16 with an ASCII payload is) is valid UTF-8, so the
  no-detector heuristic claimed `utf-8`, the secrets dissolved into
  NUL-riddled text no pattern can match, and the `[WARN]` the manual
  promises never fired — `--fail-on-error` passed too. NULs confined to one
  byte parity are now recognised as the UTF-16 byte-order signature (both
  endiannesses, BOM or not); other NUL-bearing content (UTF-32, stray NULs)
  keeps the loud Latin-1 fallback. A truncated / odd-length UTF-16 file that
  fails mid-decode now follows the unreadable-file contract (warning,
  `--fail-on-error` exit 2, never a silent all-clear) in **both** configs:
  with the `[encoding]` extra installed, charset-normalizer reports such a
  file as `utf-8` on its NUL-interleaved bytes, so a `utf-8`/`ascii` verdict
  on NUL-bearing content is now distrusted (genuine UTF-8/ASCII never contains
  NUL) and the UTF-16-signature / Latin-1 path decides — closing a silent
  false-negative the detector path otherwise hid. **Note on upgrade:** repos
  with real secrets in UTF-16 files will newly flag — a false-negative
  converted to a true positive.
- `min_value_length` no longer gates deterministic critical patterns. The
  PEM-header exemption is now keyed on severity, so AWS/GitHub/Stripe/…
  provider tokens — whose regexes pin their own length — are found even at
  `min_value_length = 200`, matching the exemption `entropy_threshold` has
  always had. Previously a user raising the knob to cut hex noise silently
  disabled all critical provider-prefix detection for tokens shorter than
  the limit. **Note on upgrade:** a tuned config that relied on a large
  `min_value_length` to silence placeholder provider keys will see those
  flag again (suppress via `.credactorignore`/`extra_safe_values`). At the
  default of 8 nothing changes.
- Prefixed API-key variable names (`test_api_key`, `my_api_key`,
  `aws_api_key`, `stripe_api_key`, `sendgrid_apikey`, …) are now detected.
  The manual has always stated that safe values match by *value* — "a real
  secret in a variable merely named `test_api_key` is still flagged" — but
  word boundaries cannot match after `_`, so every underscore-prefixed
  `*_api_key` silently passed a `--ci` gate with exit 0. The fix mirrors
  the prefix handling the `secret` family already had; the prefix demands
  an explicit `_`/`-` separator (`okapi_key`, `api_key_id` stay unmatched,
  pinned). **FP note on upgrade:** test fixtures assigning random-looking
  values to `test_api_key`-style names will now flag — exactly what the
  manual promises. Placeholder *values* (`test_api_key`, `your_api_key`,
  `changeme`, …) remain auto-safe, and `.credactorignore` globs
  (`tests/**`), inline `credactor:ignore`, and `extra_safe_values` cover
  intentional fixtures.
- Bare `token = "<value>"` is now detected (high severity), as the manual's
  severity table has always claimed. The variable-name detector carried
  every prefixed form (`api_token`, `auth_token`, `bot_token`, …) but not
  `token` itself, so a file whose only secret sat on a bare `token`
  assignment scanned clean with exit 0. The addition is deliberately a
  literal alternative: word boundaries cannot match after `_` or inside
  camelCase, so `csrf_token`, `next_page_token`, `pageToken`, `max_tokens`,
  `token_count` and `tokenizer` stay unmatched (pinned by tests — a
  prefix-tolerant variant would have dragged pagination cursors into HIGH).
  Hyphen/dot-delimited keys (`vault-token:` in k8s manifests) holding
  hardcoded high-entropy values now flag, which is the fail-closed
  direction. **Known FP from this:** a kebab/dot *cursor* key carrying a
  high-entropy but non-secret value — e.g. a `next-page-token` /
  `x-request-token` captured in an HTTP fixture — now flags HIGH, where the
  snake/camel forms (`next_page_token`, `pageToken`) do not; that is the
  deliberate cost of the literal `token` match. Placeholder fixtures and these
  cursor keys remain suppressible via the existing `.credactorignore` /
  `extra_safe_values` / inline mechanisms.
- Unquoted `password: ${DB_PASSWORD}` — the standard docker-compose/CI
  idiom — is no longer flagged. The unquoted-value capture stopped at `}`,
  so the safe-value check saw an *unclosed* `${DB_PASSWORD` and treated it
  as a hardcoded secret: a false positive that broke `--ci` gates and that
  `--fix-all` would have rewritten into a corrupted compose file. Only the
  complete pure-name form `${POSIX_NAME}` is newly safe; `${VAR:-fallback}`
  (the fallback can be a real secret) and unclosed `${…` keep flagging, both
  pinned by tests. This also stops credactor's own env-mode output on
  unquoted YAML from re-flagging on rescan.
- Interactive mode and the `--fix-all` confirmation now actually require a
  TTY on stdin, as the manual has always stated. There was no `isatty()`
  check anywhere: piping y-prefixed text into default mode answered the
  per-finding prompts and rewrote files, and the documented "non-TTY stdin
  aborts" held only for *empty* stdin (`</dev/null`), not for pipes with
  content. Both paths now exit 1 with a pointer to the unattended
  alternatives. **Behaviour change:** `yes | credactor` / `echo y |
  credactor --fix-all` automation stops working by design — use
  `--fix-all --yes`. Real terminals and pty wrappers (expect, CI ttys) are
  unaffected. Note for Git Bash/mintty on Windows: native Python sees mintty
  as a pipe, not a console, so interactive prompts there need `winpty
  credactor …` (or use `--fix-all --yes` / `--dry-run`).
- `-f json`/`-f sarif` combined with `--fix-all` no longer corrupts the
  machine-readable stream. The confirmation banner, the `--no-backup` DANGER
  box, the `Proceed?` prompt, and the replacement summary all printed to
  stdout *after* the report, so redirecting it produced an unparseable file;
  they now go to stderr whenever the format is not `text` (text-mode output
  is byte-identical). The previously undocumented precedence — `--fix-all`
  wins over the non-text report-and-exit-1 rule and redacts — is now stated
  in the manual's flag-combination matrix.
- `--dry-run --fix-all` now warns that dry-run takes precedence and
  `--fix-all` is ignored. The combination already behaved safely (report
  only, nothing modified) but did so silently, while the equivalent
  `--staged`/`--scan-history` combinations warn and `--ci --fix-all` is
  rejected — the signal is now consistent across all four.
- The post-redaction "SECURITY: .bak backup files contain original
  credentials in PLAINTEXT" footer now reflects the backup mode. It printed
  unconditionally — under `--no-backup` it warned about files that never
  existed, and under `--secure-delete` it recommended the very flag in use.
  It still prints for `--secure-backup-dir` (those backups are plaintext too,
  just stored elsewhere), and the rotate/revoke reminder remains in every mode.
- Lines longer than the 4096-character matching cap are now reported with a
  `[WARN]` naming the file (once per file, with a count). Content past the
  cap has never been pattern-matched — matching cost is superlinear in line
  length, so the cap stays — but a secret at the end of a minified one-liner
  previously scanned clean with no signal at all. The notice covers
  working-tree, single-file, `--staged`, and `--scan-history` paths.
- `--scan-history` now warns when the repository is deeper than its
  100-commit window. The truncated scan's all-clear was previously
  byte-identical to a fully-scanned clean repo — a secret introduced and
  removed more than 100 commits ago passed with an unqualified `[OK]` and
  exit 0. The window itself is unchanged (deep-history audits remain the
  domain of dedicated history scanners); the notice goes to stderr and never
  changes the exit code.
- `.credactor.toml` discovery now reaches the documented five parent
  directories. An off-by-one (the walk's first iteration was the target
  directory itself) silently stopped at four, so a root config in a deep
  monorepo was ignored without any diagnostic when scanning five levels down.
  The outside-project-root refusal is depth-independent and unaffected.
- An explicit `--config` path that does not exist (or is not a file) is now a
  fatal error (exit 2). It was previously ignored without any message — the
  scan silently ran at default sensitivity, so a typo'd `--config` in CI could
  drop `extra_extensions`/threshold settings and flip a failing secret gate to
  a pass. Scripts that relied on a sometimes-absent config falling back to
  defaults must now guard the flag themselves.
- Redaction now clears every **unreported** copy of a secret in a file it
  rewrites, not just the reported occurrence. When a detector deduplicates a
  value repeated on several lines (e.g. TruffleHog reports it once) and that
  report is ingested, a single `--fix-all` pass previously left the
  unreported duplicate copies live; the stray-copy sweep is now value-global
  within each touched file, so all such copies go in one pass (verified
  end-to-end: a 4-line duplicated secret → TruffleHog re-scan clean after
  one pass, was four). The sweep never overrides a finding's own
  adjudication, at line granularity: a copy the user explicitly skipped in
  interactive review — or one whose replacement failed — keeps its whole
  line (including copies of other redacted values on it), so the
  `replaced/skipped` summary always matches the file state; an end-of-review
  pass then clears approved values from lines whose own findings were also
  approved. Two same-value findings on one line are prompted once. When the
  sweep clears additional copies, a `[WARN]` states the count. Scope stays
  bounded to files being rewritten — other files are never opened by the
  sweep. Word-boundary anchoring protects a secret embedded in a larger *word*
  token (`<secret>more` is left alone), but a copy bounded by a non-word char
  (`<secret>-extended`, `<secret>.bak`) is swept too — over-redaction that
  fails safe, since the `.bak` keeps the original.
- `--staged` now runs the same full scan as a working-tree scan. The staged
  path previously used a reduced per-line loop that skipped the PEM-block and
  multi-line passes, so a secret inside a triple-quoted / template-literal
  string passed the pre-commit gate undetected. Both paths now share
  `scanner.scan_lines()`, so they cannot drift apart again.
- Interactive review's Ctrl-C message counted replacements but labelled them
  "file(s)"; it now says "replacement(s)".
- `--scan-history` is now read-only (forces dry-run, like `--staged`). It
  previously flowed into interactive/`--fix-all` redaction that failed on every
  finding: history findings carry a synthetic `file (commit abc123)` path that
  does not exist on disk. The scan reports findings and exits 1; purging a
  committed secret means rewriting history (e.g. `git filter-repo`) and
  rotating the key. Passing `--fix-all` now warns and is ignored.
- `--staged` now honours `--scan-json`: a staged `.json` file is scanned when
  the flag is set, and skipped **with a warning naming the file** when it is
  not. Previously staged `.json` files were skipped silently regardless of
  `--scan-json`, so a staged `credentials.json` with real secrets passed the
  pre-commit gate with a false all-clear. Lockfiles (`package-lock.json`)
  remain excluded either way, matching the directory walk.
- Git subprocess output is now decoded as UTF-8 explicitly (`--staged` listing,
  rev-parse, `--scan-history` log). On Windows the default decode uses the
  ANSI code page, which mojibakes non-ASCII staged filenames — the follow-up
  `git show` then fails and a staged secret in such a file landed in the
  error list instead of being scanned. History-scan decoding additionally
  degrades stray non-UTF-8 bytes to U+FFFD instead of crashing.
- Staged blob content is universal-newline normalized before scanning,
  matching how the file path reads from disk: CRLF blobs no longer leak
  literal `\r` into multiline findings' raw previews, and lone-`\r` line
  endings no longer skew the multiline pass's line numbering.
- README links now use absolute GitHub URLs. The README is the PyPI landing
  page, and its relative links (Docs table, Manual, CI guide, LICENSE)
  resolved against pypi.org and returned 404s on the live project page.
- The published sdist no longer ships a partial, un-collectable copy of the
  test suite: a new `MANIFEST.in` prunes `tests/` (setuptools' default
  template grabbed `tests/test*.py` without `conftest.py`, `tests/__init__.py`,
  or `tests/benchmark/`; the wheel was never affected).
- `build-system.requires` now demands `setuptools>=77` — the declared `>=68`
  floor could not actually build the project, because the PEP 639 SPDX
  `license` string is only understood from 77 (verified: 68 fails with
  "invalid pyproject.toml config: `project.license`"). The obsolete `wheel`
  requirement is dropped (setuptools >=70.1 builds wheels itself).
- `SECURITY.md`'s Supported Versions table now lists 2.4.x — it still said
  2.3.x, leaving the shipped release outside its own support policy.
- The pre-commit hook manifest declares `minimum_pre_commit_version: 3.2.0`:
  it uses the post-3.2 `stages: [pre-commit]` spelling, and older pre-commit
  versions failed manifest validation with a cryptic error instead of a
  clear version requirement.

### Changed

- Scan-speed fixes in three hot paths (no behavior change on normal input;
  all measured before/after):
  - The assignment regex's variable-name capture is bounded to 128 chars —
    unbounded, it backtracked quadratically on long unbroken word runs
    (minified JS, embedded blobs): a worst-case 4 KiB line cost ~288 ms,
    now ~31 ms.
  - `detect_encoding` resolves the optional charset libraries once at import
    instead of re-attempting the failed import twice per scanned file, and a
    pure-ASCII, NUL-free sample now short-circuits to UTF-8 before the
    statistical detectors (337 → 45 µs per file; also avoids a detector
    answering 'ascii' for a file whose first 8 KB merely happens to be
    ASCII). The NUL exclusion keeps BOM-less UTF-16 — whose ASCII payload is
    NUL-interleaved and passes `bytes.isascii()` — flowing to the detectors.
  - `.gitignore` matching computes the file's relative path once per
    `.gitignore` base directory instead of once per rule (278 → 44 µs per
    file at 25 rules; the gap grows linearly with rule count).
- `ingest_trufflehog`'s 126-line per-record parse was extracted verbatim into
  `_parse_trufflehog_record` — same validation steps and log messages, now
  unit-testable in isolation, and the template future detector parsers will
  copy is a readable loop instead of a monolith.
- Removed an unreachable "unsafe replacement" regex guard in the redactor:
  it ran on the output of `_derive_env_var_name`, which is already stripped
  to `[A-Za-z0-9_]`, so its lowercase keywords and shell metacharacters could
  never match — the `re.sub` sanitizer is (and was) the actual defense.
- `_log.configure` no longer takes a `no_color` parameter it never used —
  log output has no color; the flag only ever controlled report output.
- `--replacement` combined with `--replace-with env` now warns that the fixed
  string is never consulted (env mode generates language-aware references) —
  previously the flag was silently ignored.
- The 'clean scan' message has a single owner (`cli._emit_report`):
  `report.print_report`'s own empty-findings copy had already drifted from it
  and was removed (the CLI never reached it — it returns early on empty
  findings in text mode).
- CI now runs on the `develop` branch (push and pull request), where
  day-to-day work happens — previously only `main` was checked, so commits
  landed on the integration branch with zero automated verification.
- `make lint` runs the type checker as well as ruff, matching what CI
  enforces; CONTRIBUTING's checks section was aligned, and its Code Style
  section no longer claims the code is "Formatted with Ruff" (no
  auto-formatter is used — the codebase is linted, not formatted).
- The version is now single-sourced from `credactor.__version__` (pyproject
  declares `dynamic = ["version"]`), so pip metadata and `credactor --version`
  cannot drift apart on a release bump.
- CI and publish builds run `python -m build --no-isolation` with setuptools
  hash-pinned in `requirements-ci.txt`, so the build backend — the one package
  that writes every byte of the published wheel — is covered by the same
  supply-chain pinning as everything else.
- Docs: clarified that external-scanner ingestion currently supports Gitleaks
  and TruffleHog, with more detectors planned — corrected README/manual wording
  that implied pairing with any scanner.
- CHANGELOG preamble now states the project's one SemVer exception explicitly:
  dropping a near-end-of-life Python version may happen in a minor release
  (always flagged BREAKING), as occurred in 2.4.0.

### Removed

- The scanning thread pool. Detection is regex-CPU-bound and Python's GIL
  serialises it, so the 8-worker pool measured only a 1.0–1.3× speedup while
  carrying the trickiest code in the project (a lock, a futures map, and an
  EMFILE retry pass). Scanning is now sequential — same progress line, same
  per-file error handling, and file-descriptor exhaustion is impossible by
  construction.
- The interactive `.json` file picker. `--scan-json` is already the explicit
  opt-in, so the numbered selection prompt in plain interactive mode was a
  second gate on an already-gated path (~70 lines); all modes now scan every
  collected `.json` file uniformly. Note for script users: a non-TTY
  `--scan-json` run without `--ci`/`--dry-run` previously hit EOF at the
  picker and silently skipped JSON (exiting 0 on JSON-only findings) — the
  same invocation now scans them and exits 1.
- Internal simplifications with no behavior change: `load_gitignore_patterns`
  (a test-only duplicate of the walk that production inlines), the
  `log_verbose` rename-wrapper (call sites use the logger directly, with lazy
  %-formatting), scanner's `ENTROPY_THRESHOLD`/`MIN_VALUE_LENGTH` aliases
  (fallbacks read the config constants directly), `_evaluate_candidate`'s
  unused `config` parameter, an unreachable `TypeError` guard in
  `_synthesise_raw`, a no-op `try/except: raise` in `scan_file`, and two
  duplicate `${VAR}` branches in `_env_ref_for_language`.
- The legacy repo-root `credential_redactor.py` shim. It was never shipped in
  the wheel or sdist and no documentation referenced it; `credactor` and
  `python -m credactor` cover every documented invocation. The wheel audit's
  stale whitelist clause for it is gone too.

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

[2.4.1]: https://github.com/rxb06/Credactor/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/rxb06/Credactor/compare/v2.3.3...v2.4.0
[2.3.3]: https://github.com/rxb06/Credactor/compare/v2.3.2...v2.3.3
[2.3.2]: https://github.com/rxb06/Credactor/compare/v2.3.0...v2.3.2
[2.3.0]: https://github.com/rxb06/Credactor/compare/v2.2.1...v2.3.0
[2.2.1]: https://github.com/rxb06/Credactor/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/rxb06/Credactor/releases/tag/v2.2.0
