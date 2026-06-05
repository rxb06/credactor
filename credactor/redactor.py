"""
File modification: backup, batch replacement, env-var mode.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import tempfile
from pathlib import Path

from ._log import logger
from .config import Config
from .types import Finding
from .utils import detect_encoding, sanitize_for_terminal

_UNSAFE_REPLACEMENT_RE = re.compile(
    r'[`$\\;|&]|__import__|eval\s*\(|exec\s*\(|system\s*\(|subprocess'
)



# ---------------------------------------------------------------------------
# Replacement value generation (#5, #30)
# ---------------------------------------------------------------------------
def _make_replacement(
    finding: Finding,
    config: Config,
    filepath: str,
) -> str:
    """Produce the replacement string for a credential finding.

    Modes (config.replace_mode):
      - 'env':                 language-aware env var reference
                               (e.g. os.environ["VAR_NAME"]).
      - 'sentinel' / 'custom': returns config.custom_replacement
                               (default 'REDACTED_BY_CREDACTOR').
    """
    if config.replace_mode == 'env':
        # Derive env var name from the variable name in the finding
        var_name = _derive_env_var_name(finding)
        ext = Path(filepath).suffix.lower()
        # Validate the sanitised var name (not the full replacement, which
        # intentionally contains shell metacharacters like ${} for
        # shell/YAML/config files).
        if _UNSAFE_REPLACEMENT_RE.search(var_name):
            return 'REDACTED_BY_CREDACTOR'
        return _env_ref_for_language(var_name, ext)

    return config.custom_replacement


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
    elif ftype.startswith('pattern:') or ftype.startswith('xml-attr:'):
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
    if ext in ('.sh', '.bash', '.env') or ext.startswith('.env'):
        return f'${{{var_name}}}'
    if ext in ('.yaml', '.yml', '.toml', '.cfg', '.ini', '.conf'):
        return f'${{{var_name}}}'
    # Fallback
    return f'${{{var_name}}}'


# ---------------------------------------------------------------------------
# Backup (#1)
# ---------------------------------------------------------------------------
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
        dest_dir = Path(config.secure_backup_dir).resolve()
        # Refuse if secure-backup-dir is a symlink — return None so caller
        # skips redaction for this file.
        if os.path.islink(config.secure_backup_dir):
            logger.error(
                '--secure-backup-dir is a symlink (possible attack): %s\n'
                '  Refusing to proceed — backup security cannot be guaranteed.',
                config.secure_backup_dir,
            )
            # Clean up the in-repo backup we already created
            with contextlib.suppress(OSError):
                os.unlink(bak)
            return None
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = str(dest_dir / Path(bak).name)
            shutil.move(bak, dest)
            return dest
        except OSError as exc:
            logger.warning('Could not move backup to %s: %s', dest_dir, exc)
            # Fall through — backup still exists at original location
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
def batch_replace_in_file(
    filepath: str,
    file_findings: list[Finding],
    config: Config,
) -> tuple[int, int]:
    """Replace all findings in a single file in one read-modify-write pass.

    Applies replacements bottom-to-top to preserve line numbers.
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
        with open(filepath, encoding=encoding, errors='surrogateescape') as fh:
            lines = fh.readlines()
    except OSError as exc:
        logger.error('Cannot read %s: %s', filepath, exc)
        if lock_fh:
            lock_fh.close()
        return 0, len(file_findings)

    # #1 — backup before modifying (immediately after read)
    bak: str | None = None
    if not config.no_backup:
        bak = _create_backup(filepath, config)
        if bak is None:
            logger.error('Backup failed for %s — skipping replacements.', filepath)
            if lock_fh:
                lock_fh.close()
            return 0, len(file_findings)

    replaced = 0
    failed = 0

    # Sort by line number descending so earlier replacements don't shift later ones
    sorted_findings = sorted(file_findings, key=lambda f: f['line'], reverse=True)

    for finding in sorted_findings:
        lineno = finding['line']
        full_value = finding['full_value']
        idx = lineno - 1

        if idx >= len(lines):
            logger.warning('Line %d out of range in %s — skipping.', lineno, filepath)
            failed += 1
            continue

        original = lines[idx]
        if full_value not in original:
            logger.warning(
                'Value no longer found on line %d in %s (already replaced?).', lineno, filepath,
            )
            failed += 1
            continue

        replacement = _make_replacement(finding, config, filepath)
        lines[idx] = original.replace(full_value, replacement, 1)
        replaced += 1

    # Atomic write: write to temp file, then rename over original.
    # Prevents corruption if process crashes mid-write.
    dir_name = os.path.dirname(filepath) or '.'
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.credactor.tmp')
        with os.fdopen(fd, 'w', encoding=encoding, errors='surrogateescape') as fh:
            fh.writelines(lines)
        os.replace(tmp_path, filepath)
        tmp_path = None  # rename succeeded — nothing to clean up
    except OSError as exc:
        logger.error('Cannot write %s: %s', filepath, exc)
        if lock_fh:
            lock_fh.close()
        return 0, len(file_findings)
    finally:
        if tmp_path is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)

    # Restore original file permissions
    if orig_mode is not None:
        with contextlib.suppress(OSError):
            os.chmod(filepath, orig_mode)

    if bak and config.secure_delete and replaced > 0:
        _secure_delete(bak)

    if lock_fh:
        lock_fh.close()

    return replaced, failed


def replace_single(
    filepath: str,
    finding: Finding,
    config: Config,
) -> bool:
    """Replace a single finding. Used in interactive mode.

    Returns True on success.
    """
    replaced, _ = batch_replace_in_file(filepath, [finding], config)
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
    total = len(findings)
    replaced = 0
    skipped = 0

    replacement_desc = config.custom_replacement
    if config.replace_mode == 'env':
        replacement_desc = 'env var reference'

    from .utils import mask_secret

    print(f'{"=" * 70}')
    print(f'  INTERACTIVE REDACTION  --  {total} credential(s) found')
    print(f"  Answer y to replace each value with '{replacement_desc}', n (or Enter) to skip.")
    print(f'{"=" * 70}\n')

    for i, finding in enumerate(findings, 1):
        try:
            rel = Path(finding['file']).relative_to(root_path)
        except ValueError:
            rel = Path(finding['file'])

        masked = mask_secret(finding['full_value'])

        safe_rel = sanitize_for_terminal(str(rel))
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
                print(f'\n\n  Interrupted — {replaced} file(s) already '
                      f'modified. No further changes will be made.')
                if replaced and not config.no_backup:
                    print('  .bak backups exist for modified files.')
                _print_summary(replaced, skipped, total)
                return total - replaced

            if answer in ('y', 'yes'):
                ok = replace_single(finding['file'], finding, config)
                if ok:
                    print('  -> Replaced.\n')
                    replaced += 1
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

    _print_summary(replaced, skipped, total)
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
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f['file'], []).append(f)

    total_replaced = 0
    total_failed = 0

    for filepath, file_findings in by_file.items():
        replaced, failed = batch_replace_in_file(filepath, file_findings, config)
        total_replaced += replaced
        total_failed += failed

    _print_summary(total_replaced, total_failed, len(findings))
    return total_failed


def _print_summary(replaced: int, skipped: int, total: int) -> None:
    print(f'{"=" * 70}')
    print(f'  Summary:  {replaced} replaced  |  {skipped} skipped  |  {total} total')
    if replaced:
        print('  Reminder: rotate / revoke any credentials that were just redacted.')
        print('  SECURITY: .bak backup files contain original credentials in PLAINTEXT.')
        print('            Use --secure-backup-dir to store backups outside the repo,')
        print('            or --secure-delete to overwrite backups after verification.')
        print('            At minimum, delete .bak files before committing.')
    print(f'{"=" * 70}\n')
