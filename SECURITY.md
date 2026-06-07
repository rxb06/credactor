# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.4.x   | :white_check_mark: |
| < 2.4   | :x:                |

Only the latest minor release receives security patches. We recommend always running the most recent version.

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately using one of these methods:

1. **GitHub Security Advisories (preferred):** Use the "Report a vulnerability" button on the [Security tab](../../security/advisories/new) of this repository.
2. **Email:** Send details to the repository maintainer (see the commit history or profile for contact information).

### What to include

- A clear description of the vulnerability and its impact.
- Steps to reproduce, including any proof-of-concept files or commands.
- The affected version(s) and any configuration required to trigger the issue.
- If applicable, a suggested fix or mitigation.

### Response timeline

| Stage                          | Target    |
|--------------------------------|-----------|
| Acknowledgement of report      | 48 hours  |
| Initial triage and severity    | 5 days    |
| Patch release (critical/high)  | 14 days   |
| Patch release (medium/low)     | 30 days   |

We will keep you informed of progress and coordinate disclosure timing with you.

## Scope

The following are **in scope** for security reports:

- Detection bypasses (crafted input that evades scanning).
- Credential leakage in tool output (unmasked secrets in reports, logs, or error messages).
- File system safety issues (path traversal, symlink attacks, TOCTOU races).
- Denial of service (ReDoS, OOM, infinite loops).
- Configuration injection (malicious `.credactor.toml` or `.credactorignore` causing unsafe behaviour).
- Untrusted external-scanner reports ingested via `--from-gitleaks` / `--from-trufflehog` (path traversal, symlink escape, OOM/size-bomb, or self-corruption through crafted finding paths).

The following are **out of scope**:

- Known limitations listed in the [security model](docs/security.md#known-limitations).
- Vulnerabilities in dependencies (report these to the upstream project).
- Social engineering or phishing attacks.

## Disclosure Policy

We follow [coordinated vulnerability disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). After a fix is released, we will:

1. Publish a GitHub Security Advisory with full details.
2. Credit the reporter (unless they prefer anonymity).
3. Tag the fix commit and release a patched version.

## Security Model and Hardening

For the full security model, trust boundaries, hardening measures, and known limitations, see [docs/security.md](docs/security.md).

## Defensive measures ledger (SR-2 Stage A)

This ledger inventories every defensive marker that was originally present as an inline `# SEC-XX:` / `# CVE-XX` / `# HIGH-XX` / `# MED-XX` / `A1`–`A13` / `P2` comment in the source. The three-stage review is now **complete** (see the dated status note at the end of this section): Stage A catalogued every marker, Stage B decided per-row whether the inline comment was **K** (keep — explains an invariant) or **P** (purge from source — motivation now lives only here in the ledger), and Stage C executed the purge. This table is therefore the canonical record of the motivation behind each defence; the inline `# SEC-XX:`-style prefixes have already been removed from source for the P-marked rows.

### Format

`ID — one-line summary  ·  primary site(s)`

If an ID has multiple sites, the first is the primary defence; the rest are propagation/usage points.

> **Note:** Line numbers in the *Primary site(s)* column are a snapshot from the Stage A catalogue and may have drifted after the Stage C source sweep and later refactors. Treat them as approximate — locate each defence by its summary, not the exact line.

### SEC series

| ID | Summary | Primary site(s) |
|----|---------|-----------------|
| SEC-01 | Plaintext-backup residue mitigation: optional secure-delete + `--secure-backup-dir` move backups out of repo | `redactor.py:112,145,174,309` |
| SEC-02 | `.credactor.toml` trust boundary: load only from project root (`.git` ancestor) | `config.py:69,108,113` |
| SEC-03 | Surface config-file read failures instead of silently ignoring | `config.py:159` |
| SEC-04 | Resolve path before passing to subprocess (`git diff`, `git log`) | `walker.py:231,292` |
| SEC-05 | EMFILE fallback: re-scan files that failed to open due to fd exhaustion sequentially | `walker.py:183,205` |
| SEC-06 | Cap line length (4096) to bound regex backtracking on adversarial input | `scanner.py:83,215` |
| SEC-07 | Finally-block temp-file cleanup prevents plaintext credential residue on crash | `redactor.py:281,295` |
| SEC-09 | Atomic backup via `mkstemp` (`O_CREAT\|O_EXCL`) closes the symlink-race TOCTOU gap | `redactor.py:117` |
| SEC-10 | Validate replacement strings for code-injection metacharacters | `cli.py:278`, `redactor.py:18` |
| SEC-11 | Strong UI warning for `--fix-all --no-backup` (no recovery path) | `cli.py:363` |
| SEC-12 | Bound entropy threshold (0.0–6.0) and min-value-length (1–200) to valid ranges | `config.py:177,191` |
| SEC-13 | Warn on overly broad `.credactorignore` patterns (`*`, `**`, `**/*`) | `suppressions.py:59` |
| SEC-13b | Warn on extension-targeting wildcards covering scannable types (e.g. `**/*.py`) | `suppressions.py:64` |
| SEC-14 | Warn that `--replace-with env` changes string literals to function calls | `cli.py:295` |
| SEC-15 | Best-effort advisory file lock (`fcntl.LOCK_EX\|LOCK_NB`) attempted before read-modify-write; **proceeds unlocked on contention**, so it is a courtesy marker, not a hard TOCTOU guarantee | `redactor.py:215,244,313` |
| SEC-16 | Strip ANSI escapes and control chars from terminal output to prevent injection | `utils.py:88,96`, `redactor.py:369` |
| SEC-17 | Warn when target appears to be on a mounted/network volume (NFS/SMB atomicity) | `cli.py` (`_print_banner`) |
| SEC-18 | Warn when running as root (Unix only) — backup ownership concerns | `cli.py:289` |
| SEC-19 | Cap multiline block size (8 KiB) to prevent ReDoS on huge triple-quoted strings | `scanner.py:449,462` |
| SEC-20 | Refuse to use `--secure-backup-dir` if it's a symlink (untrusted destination) | `redactor.py:148` |
| SEC-22 | Preserve full mode bits (incl. setuid/setgid/sticky) when restoring permissions | `redactor.py:208` |
| SEC-23 | Skip file symlinks that resolve outside the scan root | `walker.py:103` |
| SEC-24 | HTML-escape masked preview in SARIF `message.text` | `report.py:200` |
| SEC-25 | Reject git-output paths containing `..` components | `walker.py:321` |
| SEC-26 | `--ci` implies `--dry-run` (read-only by design) — block `--fix-all` combo | `cli.py:269` |
| SEC-27 | Verbose audit trail when a finding is suppressed by inline `credactor:ignore` | `scanner.py:211` |
| SEC-28 | Warn once about plaintext backups when neither secure option is set | `redactor.py:137` |
| SEC-29 | Hard-block external-config loading in CI mode (no warning, refuse) | `config.py:113,134` |
| SEC-30 | Defence-in-depth: sanitise env var names to identifier charset before emitting | `redactor.py:46,77` |
| SEC-31 | Warn if `.credactor.toml` / `.credactorignore` is staged alongside code | `walker.py:247` |
| SEC-32 | Reject staged paths with `..` components (component-wise, not substring) | `walker.py:260` |
| SEC-33 | Cross-platform path-containment: normpath + os.sep boundary + normcase | `utils.py:82` (`is_within_root`), `config.py:113` |
| SEC-34 | Brace-syntax env-ref safe value requires matching closing delimiters | `scanner.py:109` |
| SEC-35 | JSON-encoding (`json.dumps`) provides the SARIF injection safety; finding type in rule fields is additionally HTML-escaped as defence-in-depth (SARIF fields are plain text, so most consumers render them as text) | `report.py:153` |
| SEC-36 | Sanitise file paths, finding types, raw source lines in text report output | `report.py:86,98` |
| SEC-37 | Reject `$` followed by a non-identifier character (`$/path`, `$+foo`, `$123abc`) so those aren't mistaken for env refs; a `$` + valid identifier (`$VARNAME`) is still treated as an env reference by design (cannot be distinguished from a real env var) | `scanner.py:117` |
| SEC-38 | Guard `float()`/`int()` conversions in `apply_config_file` against type confusion | `config.py:170,184` |
| SEC-39 | Fall back to scan root when no `.git` ancestor; warn (do not silently load) | `config.py:125` |
| SEC-40 | Top-level `--scan-history` vs ingest mutual exclusion; ingest is stdlib-json only | `cli.py:262`, `ingest.py:3` |
| SEC-40a | Top-level JSON must be a list (Gitleaks) / per-line dict (TruffleHog) | `ingest.py:168,224,366` |
| SEC-40b | Cap 10 000 findings + 100 MB file-size guard pre-`json.load()` | `ingest.py:20,169,188,231,367,384,435` |
| SEC-40c | Resolved external paths must be within target (covers symlink-escape) | `ingest.py:170,368` (via `_resolve_external_finding_path`) |

### CVE / HIGH / MED series

| ID | Summary | Primary site(s) |
|----|---------|-----------------|
| CVE-01 | Function-call detection: full value `identifier(...)` treated as runtime ref | `scanner.py:135` |
| CVE-02 | Unclosed PEM block — stop suppressing lines after 500-line cap | `scanner.py:34,409` |
| HIGH-02 | Path-like heuristic requires ≥3 slashes AND >20% slash density | `scanner.py:160` |
| HIGH-05 | 50 MB per-file scan cap to prevent OOM | `scanner.py:39` |
| HIGH-06 | Config file search depth cap (5 levels) to prevent shared-parent capture | `config.py:96` |
| MED-01 | Hunk-header parsing uses regex, not naive split on `+` | `walker.py:330` |

### Plan-tag series (A-N, P-N)

| ID | Summary | Primary site(s) |
|----|---------|-----------------|
| A1 | NDJSON memory guard: single-line GB blob must not OOM `json.loads` | `ingest.py:384` |
| A11 | `normcase()` for Windows defence-in-depth in path containment | `utils.py:99` |
| A13 | Skip findings whose resolved path is the report file itself (self-corruption guard) | `ingest.py:122,174,382` |
| P2 | Type-check commit field before slicing (non-string would crash dedup) | `ingest.py:305,497` |

### Review methodology (completed)

Each row above was reviewed and marked **K** (keep inline) where the source comment explains a non-obvious invariant *while reading that code* — for example "Append separator AFTER normpath to prevent prefix collision", which would otherwise look redundant. Rows were marked **P** (purge) where the inline comment was motivation/history now captured by this ledger and the source comment added nothing beyond the ticket prefix (e.g. "SEC-04: Resolve path before passing to subprocess", immediately followed by code that resolves the path). An automated sweep then removed the `SEC-XX:` / `CVE-XX:` / etc. prefixes from P-marked sites, preserving any substantive trailing comment text and deleting lines that had none.

**Stage B/C complete 2026-05-24**: 15 invariants retained inline (K); remaining tags purged from source (P). The test suite passed (425 tests at the time of the sweep; it has since grown to 600, all green).
