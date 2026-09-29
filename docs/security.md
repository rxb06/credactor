# Security Model

Credactor is a **developer-side static analysis tool** that scans source files for hardcoded credentials. Understanding its trust boundaries is important for safe deployment.

## What Credactor Protects Against

- Accidentally committing hardcoded API keys, tokens, passwords, and private keys.
- Credentials in assignment statements, XML attributes, connection strings, PEM blocks, and multi-line strings.
- Re-flagging already-redacted values (the sentinel `REDACTED_BY_CREDACTOR` is in the safe-values list).
- **Ingesting external scanner output:** findings from Gitleaks (`--from-gitleaks FILE`) or TruffleHog (`--from-trufflehog FILE`) are merged into the redaction pipeline, deduplicated against native findings (severity merged to the higher value on a duplicate), and still pass through `.credactorignore` suppression. Ingestion requires a **directory** target so report-relative file paths resolve correctly.

## What Credactor Does NOT Protect Against

- **Obfuscated credentials:** Base64-encoded secrets, encrypted blobs (other than SOPS), or credentials split across multiple files.
- **Runtime secrets:** Credentials injected via environment variables, secret managers, or APIs at runtime are intentionally ignored (these are the *correct* pattern).
- **Binary files:** During a directory scan, only files with recognised source and config extensions are read, so binary formats (`.exe`, `.zip`, `.png`, etc.) are skipped, by extension and not by binary-content detection. A binary file named directly on the command line bypasses that filter: it is still read (decoded as latin-1, with a warning) and scanned, so naming one is not a reliable way to exclude it. Credactor is not built to find secrets embedded in binaries.
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
- **PEM block recovery:** Unclosed PEM blocks auto-reset after a line cap (100 when introduced; 500 today) to prevent scan suppression.
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
- **SEC-12**: Config injection bounds validation. `entropy_threshold` is validated against 0.0–6.0 and `min_value_length` against 1–200; an out-of-range value warns and reverts to the default.
- **SEC-13**: Wildcard `.credactorignore` warning. Overly broad patterns trigger a `[WARN]`.
- **SEC-14**: `--replace-with env` semantic change warning.
- **SEC-15**: Best-effort advisory file lock (`fcntl.flock(LOCK_EX|LOCK_NB)`) attempted before the read-modify-write; on lock contention it proceeds unlocked, so it is a courtesy marker, not a hard TOCTOU guarantee. Under `--verbose`, a lock that could not be taken is logged with the reason.
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

### v2.4.0 (Phase 1–3 hardening + external ingestion)

**External-scanner ingestion, `credactor/ingest.py`:**

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

### Unreleased

- **Crashes exit 2 (T15a).** `cli.main` catches an unexpected exception, prints its traceback to stderr one line at a time through `sanitize_for_display`, and exits 2. Before, Python's default exit 1 looked like "findings found" to a gate. The GitHub Action already treated an exit 1 without a valid JSON or SARIF report as an error; this also covers the text format and direct CLI use.
- **Git failures fail closed (SR-14, extends L4).** After `git rev-parse` finds the repository, a failing `git diff --cached` (`--staged`) or `git log` (`--scan-history`), including a timeout, raises `GitUnavailableError` and exits 2. For history, `git rev-parse --verify -q HEAD` tells a repository with no commits yet (nothing to scan, logged at INFO, exit 0) from a real failure. Under `--staged`, a staged blob that cannot be read is fatal whatever `--fail-on-error` says, since the hook cannot call a commit clean that it could not read.
- **Ignore files (SR-13).** `.gitignore` and `.credactorignore` are read through `utils.read_aux_file`, with the checks `scan_file` applies to a scanned file: a symlink must resolve inside the scan root, the target must be a regular file (a FIFO would block `open()`, a device would read without end), and at most 1 MiB is read, with a warning. Cutting one short only drops patterns, so more is scanned. A refused file is warned and counted with the files that could not be scanned, so `--fail-on-error` gates on it.
- **Suppressed PEM headers (SR-08, extends the PEM block recovery above).** A private key header that is ignored inline or allowlisted does not open a key block, so the lines after it are scanned as usual. The body of a suppressed test key is unquoted base64 with no assignment and yields no findings. An inline-ignored header is logged under `--verbose`, as the allowlisted one already was.
- **Text report masking (extends #2/#29).** Every secret value found in a run is masked wherever it appears in the text report, not only the finding's own value at its first occurrence. A line holding a second credential, or the same one twice, shows none of them in full. Matching is longest value first, and a value that starts inside a match and ends past it extends the match, so neither a value that is a prefix of another nor two values that overlap can leave a tail visible; and masking works on the line as displayed: escape sequences are stripped first, then values are masked, and the line is cut to 120 characters last. A finding whose value is not on its stored line, or is under 4 characters, still shows the masked value alone. A stored line that ends with the start of a known value (the scanner keeps 4,096 characters of a line) has that tail masked too.
- **Display sanitizing (replaces `sanitize_for_terminal`, extends SEC-36).** Every untrusted string printed to a terminal or a CI log goes through `sanitize_for_display`: CSI and OSC escape sequences are removed whole, and every C0 control, DEL, every C1 control, U+2028, U+2029, the bidirectional controls (U+202A to U+202E, U+2066 to U+2069) and lone surrogates (undecodable bytes from `surrogateescape` or `os.fsdecode`, which a stream could write back out as raw C1 or bidi bytes, or refuse to encode) become `?`; TAB becomes a space. CI workflow command markers are then broken: `::` at the start of a line after whitespace (the GitHub runner trims leading whitespace before looking for it), and `##[` or `##vso[` anywhere in a line. This covers the text report (paths, types, source lines, the `.gitignore` skip list), the interactive prompt, the `Scanning:` line, and every log message: the log formatter sanitizes a copy of each record's arguments and breaks command markers in the whole message, while line breaks in the message template are kept. Masking marks every span where a known value stands in the raw text (so an escape sequence next to it cannot take a character from it) and every span where a value's displayed form shows once escape sequences are removed (so a value one split is caught after the removal joins it), merges the spans, masks each once and makes the rest displayable. An escape sequence a cut left unfinished at the end of a stored line is dropped first. Markers are broken last. JSON and SARIF escape control characters already, and write `##[` and `##vso[` as `#\u0023[` and `#\u0023vso[`, so a report printed to a job log carries no marker while the data it decodes to is unchanged.
- **Secrets in paths (SR-07).** A secret value found in the run is masked where it appears in a displayed path: the text report's `FILE:` line and its list of files skipped by `.gitignore` (printed once the findings are final), the JSON `file`, the SARIF `uri`, the interactive prompt and the dedup log line. Warnings printed while the scan runs name paths sanitized but not masked, since the values are not known yet. The text report and the SARIF message say that the path holds a secret. Paths and types are masked only with values that look like secrets rather than words or numbers (at least 8 characters, and not all digits, nor all letters in one case or capitalised), so a found password such as `production` does not change an unrelated directory or a rule id; source lines are masked with every value. The trade-off: a secret under 8 characters, or one that is a plain word or number, shows in a path or a report label. A masked SARIF `uri` no longer links to the file, which is accepted: the name is the leak. Names are not scanned, so a secret that appears only in a name is not found.
- **Report labels (extends #7).** An ingested finding's type carries the report's `RuleID` or `DetectorName`, and SARIF turns the type into a rule id, its descriptions and the result message. A label that is not a plain label (letters, digits, `.`, `_` or `-`, at most 64 characters), or is not a string, is reported as `unknown` with a per-parser warning; the finding is kept. Secret values found in the run are masked in the type in the text, JSON and SARIF reports, the interactive prompt and the dedup log, with the rule for names above (a value under 8 characters, or a plain word or number, is not used). A report's commit id is printed as is in JSON, so it is kept only if it is 7 to 64 hex characters (SHA-1 or SHA-256) and its first 12 characters share no run of 6 with the finding's secret; otherwise the finding is ingested without it and the parser warns with the count of the records it kept.

### v2.7.2 (ingestion correctness)

- **A scanner-redacted report cannot drive a redaction**: Gitleaks and Betterleaks both take a `--redact` flag that rewrites `Secret` inside the report, and at its default the value becomes the literal `REDACTED`. That placeholder was ingested as the value to redact and applied as a plain substring replacement, so every line holding the word was rewritten, Credactor's own `REDACTED_BY_CREDACTOR` sentinel included, and the run reported success and exited 0. Both parsers now refuse such a report: fatal exit 2, no bytes written. The truncated form the flag produces at a percentage is left alone, because it cannot match a line holding the full secret and a trailing `...` is ordinary content that a generic rule captures from an elided token in a README or a test fixture.
- **Ingested path fields are type-checked before they are believed**: a Betterleaks path field holding `0`, `false`, `[]`, `{}` or `null` was charged to the unsupported-source counter rather than counted as a malformed record, which told the operator a source type could not be ingested when the report was simply corrupt. The fields are now taken one at a time instead of through an `or` chain, which had skipped over such a value in every position but the last.
- **Symlink-first precedence holds under schema drift**: the path fields are ordered by role rather than by field generation, so a report that carries the new `Attributes['path']` while exposing the symlink only through the deprecated `SymlinkFile` mirror no longer dereferences to the real file. A real file outside the target root is dropped by the containment guard, which would have lost the redaction in silence.

### v2.7.1 (Betterleaks ingestion)

- **Un-redactable findings are accounted separately from malformed ones**: Betterleaks scans `stdin`, GitHub, GitLab, Hugging Face and S3, and those findings have no local file to rewrite. They are counted and summarised as unsupported sources rather than invalid records, so a wholly un-redactable report is never reported as a corrupt one, and never exits 0 in silence. The gate is the absence of a path, not the `resource` label: a `stdin` finding carries `resource: fs.content` with an empty path, so a label allowlist would have admitted it.
- **Run-level summaries are scoped to their own parser**: the CLI shares one statistics dict across all three ingest parsers and runs Betterleaks last, so rendering the unsupported-source label set from the shared dict reported another scanner's source types, and its truncation flag, as Betterleaks'. With the shared 20-entry cap already full, the Betterleaks label could be omitted entirely while its count was still reported.
- **Multi-part component secrets are disclosed, not silently half-redacted**: 26 of the 417 rules shipped with Betterleaks 1.8.1 declare components, so a single finding can carry a second secret on another line. Only the primary secret is ingested, and a run-level warning names the count rather than letting a half-redacted credential report success.
- **A clean upstream report is not a fatal one**: Betterleaks writes a top-level JSON `null` for a zero-finding scan where Gitleaks writes `[]`. Rejecting that as a non-array would have failed every clean scan with exit 2, turning a passing gate red and training operators to ignore it.

### v2.6.0 (ingestion GA hardening)

- **Silent-false-all-clear closures across ingestion** — run-level, default-visible summaries for every dropped-record class: invalid records (either scanner), unsupported TruffleHog sources, missing-file skips, and stale-report `--fix-all` failures. An all-invalid or all-unsupported report is no longer byte-indistinguishable from a clean run.
- **Config trust under `--ci` is fail-closed** — an explicit `--config` refused for being outside the project root is fatal (exit 2), and an empty `[ingest]` path value is fatal in any mode (parity with the fatal empty `--from-*` flag): neither mistake can silently degrade a configured gate.
- **Report-path guards** — the not-a-regular-file check runs at the library layer too (a FIFO report path raises instead of blocking `open()` forever), a dangling symlink is diagnosed as such, and a deleted working directory degrades to a clean exit 2 rather than a traceback.
- **Bounded untrusted-input accounting** — the unsupported-source type list repeats report-controlled strings and is now capped (20 entries × 60 chars with an omission marker); malformed `Filesystem`/`Git` records are labeled rather than miscounted.
- **Private-key blocks are refused by redaction (fail closed)** — the previous line-based rewrite replaced only the `-----BEGIN` header, reported success, and left the full key material in a file the next scan certified clean. Redaction now refuses, warns, and counts the block unresolved (exit 1): rotate the key and remove the block manually.
- **Hash-field guard covers `revision` and `…_sha` keys** — `revision = "<hex>"` and `commit_sha = "<hex>"` are no longer auto-rewritten by `--fix-all`, matching the v2.5.0 claim below (the credential-keyword veto still flags `api_key_sha`-style names).

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
- An explicit `--from-*` overrides a config `[ingest]` entry, and an empty `--from-*` value is fatal (exit 2) rather than a silent no-op that could disable a config-sourced scan; an empty `[ingest]` path value in the config itself is fatal for the same reason.

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

- **Artifact integrity audit:** `scripts/audit_wheel.py` verifies the wheel and sdist against the committed source. Every `credactor/` file, and every tracked non-package file the sdist ships (`pyproject.toml`, `README`, `LICENSE`), is hashed (sha256) against its `git HEAD` blob, so an in-place edit a file-name check would miss is caught and a tampered `pyproject.toml` cannot ride along in a source distribution. The wheel is treated as a closed set and its `.dist-info` metadata is content-checked, so an injected install-time dependency (`Requires-Dist`), a repointed console entry point, or an altered top-level module is rejected, and a bundled licence must match `HEAD`. The gate also rejects duplicate archive members, an unexpected or untracked file in either artifact, an sdist member whose path escapes the archive root, and any build that does not produce exactly one wheel and one sdist.
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
