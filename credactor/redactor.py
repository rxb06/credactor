"""
File modification: backup, batch replacement, env-var mode.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

from ._log import logger
from .config import Config
from .types import Finding
from .utils import (
    detect_encoding,
    group_by_file,
    mask_secret,
    relativize,
    sanitize_for_terminal,
)


# ---------------------------------------------------------------------------
# Replacement value generation (#5, #30)
# ---------------------------------------------------------------------------
def _make_replacement(
    finding: Finding,
    config: Config,
    filepath: str,
) -> tuple[str, bool]:
    """Produce the replacement string and whether it consumes the source quotes.

    Returns ``(replacement, takes_quotes)``. ``takes_quotes`` is True only for a
    bare env expression (e.g. ``os.environ["X"]``) that would be left nested
    inside the original quotes if it merely replaced the bare value; it is False
    for ``${X}`` interpolations (shell/YAML belong inside the quotes) and for
    sentinel/custom modes (which stay quoted).

    Modes (config.replace_mode):
      - 'env':                 language-aware env var reference
                               (e.g. os.environ["VAR_NAME"]).
      - 'sentinel' / 'custom': returns config.custom_replacement
                               (default 'REDACTED_BY_CREDACTOR').
    """
    if config.replace_mode == 'env':
        # Derive env var name from the variable name in the finding.
        # _derive_env_var_name strips everything outside [A-Za-z0-9_] — that
        # re.sub is the injection defense for crafted finding types (a prior
        # regex guard here could never fire on the already-sanitized name and
        # was removed as dead code).
        var_name = _derive_env_var_name(finding)
        ext = Path(filepath).suffix.lower()
        ref = _env_ref_for_language(var_name, ext)
        # ${X} interpolations stay inside the source quotes; bare expressions
        # (os.environ[...], process.env[...], ...) replace the quoted literal.
        return ref, not ref.startswith('${')

    return config.custom_replacement, False


def _derive_env_var_name(finding: Finding) -> str:
    """Extract a reasonable env var name from the finding type."""
    ftype = finding.get('type', '')
    # variable:api_key -> API_KEY
    if ftype.startswith('variable:'):
        name = ftype.split(':', 1)[1]
        # Remove dotted prefixes (e.g. self.api_key -> api_key)
        if '.' in name:
            name = name.rsplit('.', 1)[1]
        raw = name.upper().replace('-', '_')
    # pattern:AWS access key -> AWS_ACCESS_KEY
    elif ftype.startswith(('pattern:', 'xml-attr:')):
        label = ftype.split(':', 1)[1]
        raw = label.upper().replace(' ', '_').replace('-', '_')
    # external:gitleaks:aws-access-token -> AWS_ACCESS_TOKEN
    elif ftype.startswith('external:'):
        label = ftype.rsplit(':', 1)[1]
        raw = label.upper().replace(' ', '_').replace('-', '_')
    else:
        return 'CREDENTIAL'

    # Strip non-identifier characters to prevent code injection via crafted
    # xml-attr keys (e.g. "password]);evil()//").  Env var names must be
    # alphanumeric + underscore only.
    sanitized = re.sub(r'[^A-Za-z0-9_]', '', raw)
    return sanitized if sanitized else 'CREDENTIAL'


def _env_ref_for_language(var_name: str, ext: str) -> str:
    """Generate a language-appropriate env var reference."""
    if ext in ('.py',):
        return f'os.environ["{var_name}"]'
    if ext in ('.js', '.ts', '.jsx', '.tsx'):
        return f'process.env["{var_name}"]'
    if ext in ('.rb',):
        return f"ENV['{var_name}']"
    if ext in ('.go',):
        return f'os.Getenv("{var_name}")'
    if ext in ('.java', '.kt'):
        return f'System.getenv("{var_name}")'
    if ext in ('.php',):
        return f"getenv('{var_name}')"
    # Shell, YAML/TOML/INI/config files, and every unrecognised extension all
    # take the same ${VAR} interpolation — one fallback covers them.
    return f'${{{var_name}}}'


def _replace_quoted(original: str, full_value: str, replacement: str) -> str:
    """Insert a bare env expression in place of a *quoted* credential literal,
    consuming the surrounding quotes so it isn't left nested inside them
    (api_key = "os.environ[...]" would be invalid syntax).

    When the value is not a standalone quoted literal — e.g. a secret embedded
    in a larger string such as a Bearer header or a connection URL — a bare
    expression cannot be inserted without breaking the surrounding quotes, so
    the secret is replaced with the sentinel instead (always valid).
    """
    for q in ('"', "'"):
        token = f'{q}{full_value}{q}'
        if token in original:
            other = '"' if q == "'" else "'"
            # If the bare expression carries `other`-quotes and the matched
            # token is itself nested inside an enclosing `other`-quoted literal
            # (so `other` still appears once the token is removed), inlining the
            # expression would break that outer string — e.g.
            # auth = "Bearer 'KEY'"  ->  auth = "Bearer os.environ["X"]".
            # Fall back to the sentinel, which is always valid.
            if other in replacement and other in original.replace(token, '', 1):
                break
            return original.replace(token, replacement, 1)
    return original.replace(full_value, 'REDACTED_BY_CREDACTOR', 1)


# ---------------------------------------------------------------------------
# Backup (#1)
# ---------------------------------------------------------------------------
def _system_symlink_prefixes() -> tuple[tuple[str, str], ...]:
    """macOS aliases ``/tmp``, ``/var``, ``/etc`` to ``/private/*`` via stable
    system symlinks; a backup dir under them (e.g. the documented
    ``--secure-backup-dir /tmp/...``) is benign and must not be rejected.

    Computed once at import; empty on Linux where these are real directories.
    """
    pairs: list[tuple[str, str]] = []
    for root in ('/tmp', '/var', '/etc'):
        try:
            if os.path.islink(root):
                pairs.append((root, os.path.realpath(root)))
        except OSError:
            pass
    return tuple(pairs)


_SYSTEM_SYMLINK_PREFIXES = _system_symlink_prefixes()


def _backup_dir_via_unsafe_symlink(path_str: str) -> bool:
    """True if *path_str* reaches its real location through a symlink the tool
    cannot vouch for (M11).

    The previous guard checked only the leaf component with ``os.path.islink``,
    so a symlinked PARENT with a real leaf dir slipped through and let the backup
    escape. This compares the fully-resolved path against the lexical path,
    excepting only the well-known macOS system-temp symlinks so the documented
    ``--secure-backup-dir /tmp/...`` workflow is not falsely rejected. A
    not-yet-created dir with no symlink in its path is allowed (``realpath``
    resolves the existing prefix and appends the rest lexically).
    """
    abspath = os.path.abspath(path_str)
    expected = abspath
    for src, dst in _SYSTEM_SYMLINK_PREFIXES:
        if abspath == src or abspath.startswith(src + os.sep):
            expected = dst + abspath[len(src):]
            break
    return os.path.realpath(path_str) != expected


def _create_backup(filepath: str, config: Config) -> str | None:
    """Create a .bak copy of the file. Returns backup path or None on failure.

    When ``config.secure_backup_dir`` is set, the backup is placed
    in that directory instead of beside the original file.
    """
    bak = filepath + '.bak'

    # Atomic backup via mkstemp (O_CREAT|O_EXCL prevents symlink race);
    # prior approach used islink() + copy2() with a TOCTOU gap.
    dir_name = os.path.dirname(filepath) or '.'
    tmp_bak: str | None = None
    try:
        fd, tmp_bak = tempfile.mkstemp(dir=dir_name, suffix='.credactor.bak')
        os.close(fd)
        shutil.copy2(filepath, tmp_bak)
        os.replace(tmp_bak, bak)
        tmp_bak = None  # rename succeeded
    except OSError as exc:
        logger.warning('Could not create backup %s: %s', bak, exc)
        if tmp_bak is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp_bak)
        return None

    if not config.backup_warn_shown and not config.secure_delete and not config.secure_backup_dir:
        logger.warning(
            'Plaintext backup created beside original file.\n'
            '  Use --secure-delete to auto-wipe, --secure-backup-dir to store '
            'outside repo, or --no-backup to skip.',
        )
        config.backup_warn_shown = True

    if config.secure_backup_dir:
        # M11: refuse if the backup dir reaches its target through a symlink —
        # leaf OR any ancestor. The prior os.path.islink() check inspected only
        # the leaf, so a symlinked PARENT could silently redirect the backup
        # outside the intended directory. Return None so the caller skips
        # redaction for this file.
        if _backup_dir_via_unsafe_symlink(config.secure_backup_dir):
            logger.error(
                '--secure-backup-dir resolves through a symlink (possible attack): %s\n'
                '  Refusing to proceed — backup security cannot be guaranteed.',
                config.secure_backup_dir,
            )
            # Clean up the in-repo backup we already created
            with contextlib.suppress(OSError):
                os.unlink(bak)
            return None
        dest_dir = Path(config.secure_backup_dir).resolve()
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = str(dest_dir / Path(bak).name)
            shutil.move(bak, dest)
            return dest
        except OSError as exc:
            # L10: fail-closed (matches the symlink branch above). The user
            # asked for backups OUTSIDE the repo; if that's impossible, do NOT
            # silently leave a plaintext .bak inside the repo and redact anyway.
            # Clean up the in-repo bak and return None so the caller skips this
            # file (no backup, no redaction).
            logger.error(
                'Could not move backup to %s: %s — refusing to leave a plaintext '
                'backup inside the repo; skipping this file.', dest_dir, exc)
            with contextlib.suppress(OSError):
                os.unlink(bak)
            return None
    return bak


def _secure_delete(filepath: str) -> None:
    """Overwrite file with random bytes before unlinking."""
    try:
        size = os.path.getsize(filepath)
        with open(filepath, 'wb') as fh:
            fh.write(os.urandom(size))
            fh.flush()
            os.fsync(fh.fileno())
        os.unlink(filepath)
    except OSError as exc:
        logger.warning('Secure delete failed for %s: %s', filepath, exc)


# ---------------------------------------------------------------------------
# Batch replacement per file (#14)
# ---------------------------------------------------------------------------
def _write_atomic(filepath: str, lines: list[str], encoding: str) -> bool:
    """Write *lines* via a temp file + ``os.replace`` so a mid-write crash
    leaves the original intact. Returns False (after logging) on failure."""
    dir_name = os.path.dirname(filepath) or '.'
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.credactor.tmp')
        with os.fdopen(fd, 'w', encoding=encoding, errors='surrogateescape', newline='') as fh:
            fh.writelines(lines)
        os.replace(tmp_path, filepath)
        tmp_path = None  # rename succeeded — nothing to clean up
        return True
    except OSError as exc:
        logger.error('Cannot write %s: %s', filepath, exc)
        return False
    finally:
        if tmp_path is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)


def _final_file_sweep(
    filepath: str,
    approved: list[Finding],
    preserve_lines: set[int],
    config: Config,
) -> None:
    """End-of-review sweep over one file with the session's full knowledge.

    The per-approval sweeps exclude every other known finding line statically
    (a prompt may still be pending), so a copy of approved value A sitting on
    finding B's line survives even after B itself is approved. This pass
    re-sweeps the file for ALL approved values, preserving only the lines
    whose findings were skipped, failed, or never adjudicated (interrupt).
    Changes remain covered by the .bak taken at the first replacement.
    """
    try:
        encoding = detect_encoding(filepath)
        with open(filepath, encoding=encoding, errors='surrogateescape', newline='') as fh:
            lines = fh.readlines()
    except (OSError, UnicodeDecodeError) as exc:
        logger.error('Cannot read %s: %s', filepath, exc)
        return
    before = list(lines)
    _sweep_stray_copies(lines, approved, config, preserve_lines, filepath)
    if lines == before:
        return
    try:
        orig_mode: int | None = os.stat(filepath).st_mode
    except OSError:
        orig_mode = None
    if _write_atomic(filepath, lines, encoding) and orig_mode is not None:
        with contextlib.suppress(OSError):
            os.chmod(filepath, orig_mode)


def _sweep_stray_copies(
    lines: list[str],
    file_findings: list[Finding],
    config: Config,
    preserved: set[int],
    filepath: str,
) -> None:
    """Clear remaining exact copies of redacted values beyond the
    adjudicated findings.

    The per-finding replace handles one occurrence each, but the same secret
    literal can survive — a second occurrence on the finding's own line, a
    trailing comment elsewhere, or (the common case) a detector that
    DEDUPLICATED repeated copies and reported the value only once. Lines in
    ``preserved`` (1-based) are never touched: they belong to known findings
    whose own adjudication — an explicit interactive skip, a pending prompt,
    or a failed replacement — owns them. Scope is bounded to this one file.
    """
    stray = ('REDACTED_BY_CREDACTOR' if config.replace_mode == 'env'
             else config.custom_replacement)
    values = {f['full_value'] for f in file_findings if f['full_value']}
    if not values:
        return
    # One compiled alternation (longest value first so a short value can't
    # shadow a longer one). Word-boundary anchors protect a secret embedded in
    # a larger *word* token (123456789), but a copy bounded by a non-word char
    # (secret-extended, secret.bak) is still swept — fail-safe over-redaction
    # pinned by test_sweep_redacts_value_in_nonword_bounded_token. The
    # replacement is a
    # function so a custom string with backreference-like text (e.g. '\\1')
    # is inserted literally, not as a regex template. On the finding's own
    # line the literal is already gone (replaced above), so re.subn is a
    # no-op there; duplicate copies on other lines are what this catches.
    pat = re.compile(
        r'(?<!\w)(?:'
        + '|'.join(re.escape(v) for v in sorted(values, key=len, reverse=True))
        + r')(?!\w)'
    )
    stray_count = 0
    for idx in range(len(lines)):
        if idx + 1 in preserved:
            continue
        lines[idx], n = pat.subn(lambda _m: stray, lines[idx])
        stray_count += n
    if stray_count:
        # Default-visible (stderr): the file was modified beyond the
        # adjudicated findings — the summary alone would under-report it.
        # ("additional", not "unreported": a second occurrence on a finding's
        # own line is also cleared here.)
        logger.warning(
            '%s: also cleared %d additional cop%s of redacted value(s) '
            'beyond the adjudicated finding(s) (value-global sweep).',
            filepath, stray_count, 'y' if stray_count == 1 else 'ies',
        )


def batch_replace_in_file(
    filepath: str,
    file_findings: list[Finding],
    config: Config,
    *,
    sweep_exclude_lines: frozenset[int] = frozenset(),
) -> tuple[int, int]:
    """Replace all findings in a single file in one read-modify-write pass.

    Applies replacements bottom-to-top to preserve line numbers.
    ``sweep_exclude_lines`` — 1-based lines owned by known findings NOT being
    replaced in this call (interactive skips / not-yet-prompted findings);
    the duplicate-copy sweep leaves them untouched.
    Returns (replaced_count, failed_count).

    Addresses #1 (backup), #14 (batch), #16 (encoding-aware).
    """
    if not file_findings:
        return 0, 0

    # #16 — detect encoding
    encoding = detect_encoding(filepath)

    # Preserve file permissions (include setuid/setgid/sticky bits)
    try:
        orig_stat = os.stat(filepath)
        orig_mode = orig_stat.st_mode & 0o7777  # full mode including setuid/setgid
    except OSError:
        orig_mode = None

    # Acquire advisory file lock to mitigate TOCTOU races between read and
    # replace.  Uses fcntl on Unix; on Windows fcntl is unavailable so the
    # handle is closed immediately to avoid blocking os.replace().
    lock_fh = None
    try:
        lock_fh = open(filepath, 'r')  # noqa: SIM115
        try:
            import fcntl
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:
            # Windows: fcntl unavailable — close handle to avoid blocking
            # os.replace() which cannot overwrite an open file on Windows.
            lock_fh.close()
            lock_fh = None
        except OSError:
            pass  # Lock contention — proceed without lock
    except OSError:
        pass

    try:
        try:
            # newline='' preserves each line's original terminator (CRLF/LF) so
            # redaction never normalizes line endings on untouched lines.
            with open(filepath, encoding=encoding, errors='surrogateescape', newline='') as fh:
                lines = fh.readlines()
        except (OSError, UnicodeDecodeError) as exc:
            # UnicodeDecodeError: a detected multibyte encoding (e.g.
            # truncated UTF-16) failing mid-stream must fail THIS file only —
            # an ingested finding pointing at such a file previously aborted
            # the whole redaction run mid-loop.
            logger.error('Cannot read %s: %s', filepath, exc)
            return 0, len(file_findings)

        # #1 — backup before modifying (immediately after read)
        bak: str | None = None
        if not config.no_backup:
            bak = _create_backup(filepath, config)
            if bak is None:
                logger.error('Backup failed for %s — skipping replacements.', filepath)
                return 0, len(file_findings)

        replaced = 0
        failed = 0
        failed_lines: set[int] = set()

        # Sort by line number descending so earlier replacements don't shift later ones
        sorted_findings = sorted(file_findings, key=lambda f: f['line'], reverse=True)

        for finding in sorted_findings:
            lineno = finding['line']
            full_value = finding['full_value']
            idx = lineno - 1

            if idx >= len(lines):
                logger.warning('Line %d out of range in %s — skipping.', lineno, filepath)
                failed += 1
                failed_lines.add(lineno)
                continue

            original = lines[idx]
            if full_value not in original:
                logger.warning(
                    'Value no longer found on line %d in %s (already replaced?).', lineno, filepath,
                )
                failed += 1
                failed_lines.add(lineno)
                continue

            replacement, takes_quotes = _make_replacement(finding, config, filepath)
            if takes_quotes:
                lines[idx] = _replace_quoted(original, full_value, replacement)
            else:
                lines[idx] = original.replace(full_value, replacement, 1)
            replaced += 1

        # H10 + value-global sweep: see _sweep_stray_copies. Lines owned by
        # known findings the caller did not approve here (sweep_exclude_lines)
        # and lines whose own replacement just failed keep their content —
        # each finding's adjudication owns its line.
        if replaced:
            _sweep_stray_copies(lines, file_findings, config,
                                set(sweep_exclude_lines) | failed_lines,
                                filepath)

        if not _write_atomic(filepath, lines, encoding):
            return 0, len(file_findings)

        # Restore original file permissions
        if orig_mode is not None:
            with contextlib.suppress(OSError):
                os.chmod(filepath, orig_mode)

        if bak and config.secure_delete and replaced > 0:
            _secure_delete(bak)

        return replaced, failed
    finally:
        if lock_fh is not None:
            lock_fh.close()


def replace_single(
    filepath: str,
    finding: Finding,
    config: Config,
    *,
    sweep_exclude_lines: frozenset[int] = frozenset(),
) -> bool:
    """Replace a single finding. Used in interactive mode.

    Returns True on success.
    """
    replaced, _ = batch_replace_in_file(
        filepath, [finding], config, sweep_exclude_lines=sweep_exclude_lines)
    return replaced > 0


# ---------------------------------------------------------------------------
# Interactive review
# ---------------------------------------------------------------------------
def interactive_review(
    findings: list[Finding],
    root: str,
    config: Config,
) -> int:
    """Walk through every finding and ask the user whether to replace it.

    Returns the number of unresolved findings (for exit-code use).
    """
    root_path = Path(root).resolve()

    # Two same-value findings on one line cannot be adjudicated separately —
    # line-granularity exclusion can't represent them, and the first 'y'
    # would clear the copy a later 'n' refers to. One prompt owns the
    # (file, line, value) triple; its answer covers every occurrence there.
    seen: set[tuple[str, int, str]] = set()
    deduped: list[Finding] = []
    for f in findings:
        key = (f['file'], f['line'], f['full_value'])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    findings = deduped

    total = len(findings)
    replaced = 0
    skipped = 0

    # Every known finding's line, per file: when one finding is approved, the
    # duplicate-copy sweep must not touch lines owned by the OTHERS — their
    # fate belongs to their own prompts (an explicit 'n' must stick).
    lines_by_file: dict[str, set[int]] = {}
    for f in findings:
        lines_by_file.setdefault(f['file'], set()).add(f['line'])

    # Approved findings per file, for the end-of-review sweep: a copy of an
    # approved value on ANOTHER approved finding's line is preserved by the
    # static per-approval exclusion above and must be cleared once that
    # line's own adjudication has resolved.
    approved_by_file: dict[str, list[Finding]] = {}

    def _run_final_sweeps() -> None:
        for fp, approved in approved_by_file.items():
            preserve = lines_by_file[fp] - {f['line'] for f in approved}
            _final_file_sweep(fp, approved, preserve, config)

    replacement_desc = config.custom_replacement
    if config.replace_mode == 'env':
        replacement_desc = 'env var reference'

    print(f'{"=" * 70}')
    print(f'  INTERACTIVE REDACTION  --  {total} credential(s) found')
    print(f"  Answer y to replace each value with '{replacement_desc}', n (or Enter) to skip.")
    print(f'{"=" * 70}\n')

    for i, finding in enumerate(findings, 1):
        rel = relativize(finding['file'], root_path)

        masked = mask_secret(finding['full_value'])

        safe_rel = sanitize_for_terminal(rel)
        safe_type = sanitize_for_terminal(finding['type'])
        safe_masked = sanitize_for_terminal(masked)

        print(f'  [{i}/{total}]  {safe_rel}  --  line {finding["line"]}')
        print(f'  Type     : {safe_type}')
        print(f'  Severity : {finding.get("severity", "medium")}')
        print(f'  Value    : {safe_masked}')
        print()

        while True:
            try:
                answer = input("  Replace? [y/N]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                # Completes the already-approved adjudications only: pending
                # and skipped findings' lines are preserved by construction.
                _run_final_sweeps()
                print(f'\n\n  Interrupted — {replaced} replacement(s) already '
                      f'applied. No further changes will be made.')
                if replaced and not config.no_backup and not config.secure_delete:
                    # Same invariant as the summary footer: under
                    # --secure-delete each .bak was wiped after its
                    # replacement, so there is nothing to point at.
                    print('  .bak backups exist for modified files.')
                _print_summary(replaced, skipped, total, config)
                return total - replaced

            if answer in ('y', 'yes'):
                others = lines_by_file[finding['file']] - {finding['line']}
                ok = replace_single(finding['file'], finding, config,
                                    sweep_exclude_lines=frozenset(others))
                if ok:
                    print('  -> Replaced.\n')
                    replaced += 1
                    approved_by_file.setdefault(finding['file'], []).append(finding)
                else:
                    print('  -> Replacement failed -- skipping.\n')
                    skipped += 1
                break
            elif answer in ('n', 'no', ''):
                print('  -- Skipped.\n')
                skipped += 1
                break
            else:
                print("  Please enter 'y' or 'n'.")

    _run_final_sweeps()
    _print_summary(replaced, skipped, total, config)
    return total - replaced


def fix_all(
    findings: list[Finding],
    root: str,
    config: Config,
) -> int:
    """Replace all findings without prompting (#33).

    Returns the number of unresolved findings.
    """
    # Group by file for batch replacement
    by_file = group_by_file(findings)

    total_replaced = 0
    total_failed = 0

    for filepath, file_findings in by_file.items():
        replaced, failed = batch_replace_in_file(filepath, file_findings, config)
        total_replaced += replaced
        total_failed += failed

    _print_summary(total_replaced, total_failed, len(findings), config, label='failed')
    return total_failed


def _print_summary(
    replaced: int, other: int, total: int, config: Config, label: str = 'skipped',
) -> None:
    # Mirror _handle_fix_all's stream choice: with -f json/sarif the report on
    # stdout must stay a single parseable document, so the summary goes to
    # stderr. Interactive review is text-only, where this is still stdout.
    out = sys.stdout if config.output_format == 'text' else sys.stderr
    print(f'{"=" * 70}', file=out)
    print(f'  Summary:  {replaced} replaced  |  {other} {label}  |  {total} total',
          file=out)
    if replaced:
        print('  Reminder: rotate / revoke any credentials that were just redacted.',
              file=out)
        # The plaintext warning only applies when a .bak can still exist:
        # --no-backup never writes one and --secure-delete wipes it. It stays
        # for --secure-backup-dir — those backups are plaintext too, just
        # elsewhere. (A failed secure-delete already logs its own warning.)
        if not config.no_backup and not config.secure_delete:
            print('  SECURITY: .bak backup files contain original credentials in PLAINTEXT.',
                  file=out)
            print('            Use --secure-backup-dir to store backups outside the repo,',
                  file=out)
            print('            or --secure-delete to overwrite backups after verification.',
                  file=out)
            print('            At minimum, delete .bak files before committing.', file=out)
    print(f'{"=" * 70}\n', file=out)
