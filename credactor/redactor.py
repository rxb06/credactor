"""
File modification: backup, batch replacement, env-var mode.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import os
import re
import stat
import string
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

from ._log import logger
from .config import DEFAULT_REPLACEMENT, Config
from .patterns import _is_hash_context_at, _known_format
from .suppressions import AllowList, has_inline_suppression
from .types import Finding
from .utils import (
    OutputMasker,
    detect_encoding,
    group_by_file,
    in_git_dir,
    is_within_root,
    mask_secret,
    relativize,
    sanitize_for_display,
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
    # T15b: the name is text the scanned file or a report supplied, so it can
    # spell the secret itself, and written into the file it would leave a copy
    # behind. Letters and digits are compared, ignoring case and separators,
    # so a provider prefix such as sk_live_ is not taken for the secret.
    name = re.sub(r'[^A-Z0-9]', '', sanitized.upper())
    value = re.sub(r'[^A-Z0-9]', '', _credential_part(finding.get('full_value', '')).upper())
    shares = any(
        name[i : i + _ENV_NAME_SHARED] in value for i in range(len(name) - _ENV_NAME_SHARED + 1)
    )
    # A reported secret can be shorter than the shared run, so a name that
    # holds the whole of it falls back too.
    holds = len(value) >= _ENV_NAME_HELD and value in name
    return sanitized if sanitized and not shares and not holds else 'CREDENTIAL'


# A derived env var name that shares this many letters and digits in a row
# with the secret, or holds the whole of a secret at least _ENV_NAME_HELD long
# (the shortest secret an ingested report may give), is not used.
_ENV_NAME_SHARED = 8
_ENV_NAME_HELD = 4
_PEM_ARMOR_RE = re.compile(r'-----(?:BEGIN|END)[^-]*-----')
_URL_USERINFO_RE = re.compile(r'^[A-Za-z][A-Za-z0-9+.-]*://([^@/]*)@')


def _credential_part(value: str) -> str:
    """The part of *value* that is secret, for the env var name check: a URL
    keeps only its password (its user when there is none), and a PEM block
    drops its armor lines. The scheme, host and armor name what the value
    is, which is also what the variable name says."""
    value = _PEM_ARMOR_RE.sub('', value)
    url = _URL_USERINFO_RE.match(value)
    if url:
        user, _, rest = url.group(1).partition(':')
        value = rest or user
    return value


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


def _replace_quoted(original: str, full_value: str, replacement: str, at: int) -> str:
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
        pos = original.find(token)
        if pos >= 0:
            # SR-25: only a plain literal takes the bare expression. A letter
            # before the opening quote is a string prefix (b, r, f, u) that
            # would glue onto the expression (bos.environ). A quote right after
            # the closing one, spaces allowed, is a longer quote run ("""...""")
            # or implicit concatenation, either of which would leave a stray
            # literal next to the expression. A token inside a literal opened
            # earlier on the line (a JSON document held in a single-quoted
            # string) would turn into code text inside that string.
            before = original[pos - 1] if pos else ''
            end = pos + len(token)
            following = original[end:].lstrip(' \t')[:1]
            if before.isalpha() or following in ('"', "'") or _inside_literal(original, pos):
                break
            other = '"' if q == "'" else "'"
            # If the bare expression carries `other`-quotes and the matched
            # token is itself nested inside an enclosing `other`-quoted literal
            # (so `other` still appears once the token is removed), inlining the
            # expression would break that outer string — e.g.
            # auth = "Bearer 'KEY'"  ->  auth = "Bearer os.environ["X"]".
            # Fall back to the sentinel, which is always valid.
            if other in replacement and other in original.replace(token, '', 1):
                break
            return original[:pos] + replacement + original[end:]
    return original[:at] + DEFAULT_REPLACEMENT + original[at + len(full_value) :]


# The scanners that write the reports are Go programs, whose word boundary is
# ASCII, so a token right next to CJK text is still a whole token.
_WORD_CHARS = frozenset(string.ascii_letters + string.digits + '_')


def _inside_literal(line: str, pos: int) -> bool:
    """Whether *pos* on *line* falls inside a string literal opened earlier on
    the line. A backslash escapes the next character inside a literal."""
    open_quote = ''
    i = 0
    while i < pos:
        ch = line[i]
        if open_quote:
            if ch == '\\':
                i += 2
                continue
            if ch == open_quote:
                open_quote = ''
        elif ch in '"\'`':
            open_quote = ch
        i += 1
    return bool(open_quote)


def _value_position(line: str, finding: Finding) -> int | None:
    """Where on *line* the finding's value is replaced, or None.

    A native value comes from an anchored pattern match, so its first
    occurrence is it. An ingested value is whatever the report says (SR-15),
    so only an occurrence that stands as a whole token counts: no ASCII letter,
    digit or underscore on either side, so 'pass' is never replaced inside
    'password'. The search is linear in the length of the line.
    """
    value = finding['full_value']
    at = line.find(value)
    if at < 0 or not finding['type'].startswith('external:'):
        return at if at >= 0 else None
    while at >= 0:
        end = at + len(value)
        before = line[at - 1] if at else ''
        after = line[end] if end < len(line) else ''
        if before not in _WORD_CHARS and after not in _WORD_CHARS:
            return at
        at = line.find(value, at + 1)
    return None


def _holds_key_marker(text: str) -> bool:
    """Whether *text* holds a BEGIN or END private key marker (SR-17).

    Checked on each finding's value and on every line a replacement would
    change, never on the finding's type alone: a report can call a key's BEGIN
    line anything. Rewriting part of a marker line leaves the key material in
    the file with its header gone, so the next scan reports the file clean.
    """
    upper = text.upper()
    return 'PRIVATE KEY' in upper and ('-----BEGIN' in upper or '-----END' in upper)


def _is_key_block(text: str) -> bool:
    """Whether *text* holds a whole private key, a BEGIN marker with an END
    marker after it, as a service-account JSON file keeps one on one line.
    Replacing such a value removes the key and both markers."""
    upper = text.upper()
    begin = upper.find('-----BEGIN')
    return begin >= 0 and 'PRIVATE KEY' in upper and upper.find('-----END', begin) > begin


def _replace_one(
    lines: list[str],
    finding: Finding,
    config: Config,
    filepath: str,
    marker_lines: dict[int, bool],
) -> str:
    """Replace *finding* in *lines*, warning when it cannot be. Returns
    'replaced', 'failed', or 'refused' for a replacement refused on purpose.
    *marker_lines* caches, per line index, whether the line holds a key marker
    (a replacement never adds one, and a marker line is only ever changed when
    the whole key goes)."""
    lineno = finding['line']
    value = finding['full_value']
    idx = lineno - 1
    if idx < 0 or idx >= len(lines):
        # Line 0 is an unknown line (PA-05); index -1 would be the last.
        logger.warning('Line %d out of range in %s; skipping.', lineno, filepath)
        return 'failed'
    original = lines[idx]
    at = _value_position(original, finding)
    if at is None and value in original:
        logger.warning(
            'Reported value on line %d in %s appears only inside a longer word, '
            'so it is not replaced there. Check the report.',
            lineno,
            filepath,
        )
        return 'refused'
    if at is None:
        if finding['type'].startswith('external:'):
            # K-5/K03: for an ingested finding this is almost always a stale
            # report (line drift, rotated value, .git/objects noise) or a
            # multi-line value, so name the real causes.
            logger.warning(
                'Reported value not found on line %d in %s: stale report '
                '(file changed since the scan), multi-line value, or '
                'already redacted. Regenerate the scanner report and re-run.',
                lineno,
                filepath,
            )
        else:
            logger.warning(
                'Value no longer found on line %d in %s (already replaced?).',
                lineno,
                filepath,
            )
        return 'failed'
    replacement, takes_quotes = _make_replacement(finding, config, filepath)
    if takes_quotes:
        new_line = _replace_quoted(original, value, replacement, at)
    else:
        new_line = original[:at] + replacement + original[at + len(value) :]
    if idx not in marker_lines:
        marker_lines[idx] = _holds_key_marker(original)
    if marker_lines[idx] and (not _is_key_block(value) or _holds_key_marker(new_line)):
        # SR-17: a marker line changes only when the replacement takes the
        # whole key with it.
        logger.warning(
            '%s:%d: not rewritten: the line holds a private key marker, and changing '
            'it would leave the key in the file while the next scan reports it clean. '
            'Rotate the key and remove the block manually.',
            filepath,
            lineno,
        )
        return 'refused'
    lines[idx] = new_line
    return 'replaced'


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
            expected = dst + abspath[len(src) :]
            break
    return os.path.realpath(path_str) != expected


def _create_backup(filepath: str, config: Config, data: bytes) -> str | None:
    """Write *data*, the bytes the rewrite read, as the file's .bak. Returns
    the backup path or None on failure.

    SR-23: the backup goes into a fresh mkstemp file, created 0600, and nothing
    copies the source's mode over it, so a readable or setuid source never
    gives a readable or setuid backup. Writing the bytes that were read, not
    copying the file again, also means the backup is exactly what was edited.

    With ``config.secure_backup_dir`` the backup is written DIRECTLY into that
    directory (never beside the original, not even momentarily) via
    ``_create_backup_in_secure_dir``. Otherwise it is placed beside the file.
    """
    if config.secure_backup_dir:
        return _create_backup_in_secure_dir(filepath, config, data)

    bak = filepath + '.bak'

    # Atomic backup via mkstemp (O_CREAT|O_EXCL prevents symlink race);
    # prior approach used islink() + copy2() with a TOCTOU gap.
    dir_name = os.path.dirname(filepath) or '.'
    tmp_bak: str | None = None
    try:
        fd, tmp_bak = tempfile.mkstemp(dir=dir_name, suffix='.credactor.bak')
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
        os.replace(tmp_bak, bak)
        tmp_bak = None  # rename succeeded
    except OSError as exc:
        logger.warning('Could not create backup %s: %s', bak, exc)
        if tmp_bak is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp_bak)
        return None

    if not config.backup_warn_shown and not config.secure_delete:
        logger.warning(
            'Plaintext backup created beside original file.\n'
            '  Use --secure-delete to auto-wipe, --secure-backup-dir to store '
            'outside repo, or --no-backup to skip.',
        )
        config.backup_warn_shown = True
    return bak


def _create_backup_in_secure_dir(filepath: str, config: Config, data: bytes) -> str | None:
    """Create the .bak DIRECTLY inside ``config.secure_backup_dir``.

    A plaintext copy never lands beside the original at any instant — this
    closes the crash-window leak the flag exists to prevent (S2). Fails closed
    (returns None -> caller skips the file, no redaction) when the dir is
    reached through a symlink (leaf OR any ancestor) or cannot be written; in
    neither failure case is anything written inside the repo.
    """
    secure_dir = config.secure_backup_dir
    if secure_dir is None:  # caller only invokes us when it is set
        return None
    if _backup_dir_via_unsafe_symlink(secure_dir):
        logger.error(
            '--secure-backup-dir resolves through a symlink (possible attack): %s\n'
            '  Refusing to proceed — backup security cannot be guaranteed.',
            secure_dir,
        )
        return None
    dest_dir = Path(secure_dir).resolve()
    # R1: the destination must be unambiguous per source file. Deriving it from
    # the basename alone (Path(filepath).name + '.bak') flattens the whole tree
    # into one namespace, so two sources sharing a basename in different dirs
    # (a/config.py, b/config.py) map to the same .bak and the second os.replace
    # silently clobbers the first file's only recovery copy. Append a short,
    # stable hash of the ABSOLUTE source path so distinct sources never collide,
    # while keeping the readable basename for the user. The hash is stable across
    # runs for the same source (re-running overwrites that source's own backup,
    # which is the intended behaviour).
    digest = hashlib.sha256(os.path.abspath(filepath).encode('utf-8')).hexdigest()[:12]
    dest = str(dest_dir / f'{Path(filepath).name}.{digest}.bak')
    tmp: str | None = None
    try:
        _prepare_backup_dir(dest_dir, config)
        fd, tmp = tempfile.mkstemp(dir=str(dest_dir), suffix='.credactor.bak')
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
        os.replace(tmp, dest)
        tmp = None  # rename succeeded
        return dest
    except OSError as exc:
        # L10: fail-closed. The user asked for backups OUTSIDE the repo; if that
        # is impossible, do NOT redact — and nothing was ever written in-repo.
        logger.error(
            'Could not write backup to %s: %s — refusing to proceed; skipping this file.',
            dest_dir,
            exc,
        )
        if tmp is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
        return None


def _prepare_backup_dir(dest_dir: Path, config: Config) -> None:
    """Create a missing --secure-backup-dir as 0700 (SR-23), or warn once when
    an existing one is open to other users. mkdir applies the umask, so
    the mode is set again after it."""
    if not dest_dir.exists():
        dest_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(dest_dir, 0o700)
        return
    # Windows has no such bits: chmod there only toggles read-only.
    if os.name != 'posix' or config.backup_dir_warn_shown:
        return
    mode = stat.S_IMODE(dest_dir.stat().st_mode)
    if mode & 0o077:
        logger.warning(
            '--secure-backup-dir %s is open to other users (mode %o), and the '
            'backups in it hold the secrets in plaintext. Restrict it with chmod 700.',
            dest_dir,
            mode,
        )
        config.backup_dir_warn_shown = True


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
def _write_atomic(
    filepath: str,
    data: bytes,
    guard: Callable[[], bool] | None = None,
) -> bool:
    """Write *data* via a temp file + ``os.replace`` so a mid-write crash
    leaves the original intact. *guard*, when given, runs once the temp file
    is complete and just before the rename; if it returns False the temp
    file is removed and nothing is published. Returns False (after logging a
    write error) on failure."""
    dir_name = os.path.dirname(filepath) or '.'
    tmp_path: str | None = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.credactor.tmp')
        with os.fdopen(fd, 'wb') as fh:
            fh.write(data)
        if guard is not None and not guard():
            return False
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


def _rewrite_file(
    filepath: str,
    config: Config,
    edit: Callable[[list[str]], bool],
    *,
    verb: str,
    backup: bool,
    root: str | None = None,
) -> str:
    """The one write path (PA-14). Every rewrite goes through here: a batch
    replacement, an interactive approval, and the end-of-review sweep.

    It refuses a symlink (S1), takes the advisory lock (SEC-15), and reads the
    file once, as bytes, keeping each line's terminator (SR-24). *edit* then
    changes the lines in memory and returns whether it changed anything. A
    file with nothing to change is left alone: no backup, no write, so its
    inode, hard links and extended attributes are kept. Otherwise the backup
    is written from the bytes that were read (SR-23) when *backup* is set and
    backups are on, a failed backup aborting the file. Just before publishing,
    the file is checked against what was read: write modes assume no other
    writer, and a file changed on disk meanwhile is left as it now is.
    The new content is published atomically (PA-02), the original mode is
    restored with its special bits, and under --secure-delete the backup is
    then wiped.

    With *root*, the path must also still reach a file inside it through real
    directories only (SR-20), checked just before the backup and again just
    before the rename, so a directory on the path swapped for a symlink cannot
    send the backup or the write outside the scan root.

    Returns 'written', 'unchanged', or 'failed' when the file was refused or
    could not be read, backed up or written (each logged).
    """
    # S1: os.replace would rewrite the LINK node, not the file it points at,
    # so the secret would remain in the target while we report success.
    if os.path.islink(filepath):
        logger.warning(
            'Refusing to %s symlink %s: os.replace would rewrite the link, not its '
            'target, so the secret would remain in the target file. Resolve the '
            'symlink and re-run.',
            verb,
            filepath,
        )
        return 'failed'

    # #16: detect the encoding
    encoding = detect_encoding(filepath)

    # Preserve file permissions (include setuid/setgid/sticky bits)
    try:
        orig_stat = os.stat(filepath)
        orig_mode: int | None = orig_stat.st_mode & 0o7777
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
            # Windows: fcntl is unavailable, so close the handle to avoid blocking
            # os.replace() which cannot overwrite an open file on Windows.
            lock_fh.close()
            lock_fh = None
        except OSError as exc:
            # SEC-15: the lock is best effort. When it cannot be taken (usually
            # contention), record why (visible under --verbose) and proceed
            # unlocked (SR-01).
            logger.info('%s: advisory lock not taken (%s), proceeding unlocked', filepath, exc)
    except OSError:
        pass

    try:
        try:
            with open(filepath, 'rb') as fh:
                data = fh.read()
                seen = _identity(os.fstat(fh.fileno()))
            # newline='' keeps each line's original terminator (CRLF/LF) so
            # redaction never normalizes line endings on untouched lines. The
            # wrapper decodes as it splits, so no second copy of the whole
            # text is held next to the bytes.
            with io.TextIOWrapper(
                io.BytesIO(data), encoding=encoding, errors='surrogateescape', newline=''
            ) as reader:
                lines = reader.readlines()
        except (OSError, UnicodeDecodeError) as exc:
            # UnicodeDecodeError: a detected multibyte encoding (e.g.
            # truncated UTF-16) failing mid-stream must fail THIS file only.
            logger.error('Cannot read %s: %s', filepath, exc)
            return 'failed'

        if not edit(lines):
            return 'unchanged'

        # Encode before any backup or check, so content the file's encoding
        # cannot hold (an undecodable byte kept as a lone surrogate, which
        # UTF-16 refuses) fails this file here instead of ending the run.
        try:
            new_data = ''.join(lines).encode(encoding, errors='surrogateescape')
        except UnicodeError as exc:
            logger.error('Cannot write %s: the new content cannot be encoded (%s).', filepath, exc)
            return 'failed'

        def still_safe() -> bool:
            return _still_safe_to_write(filepath, root, seen)

        if not still_safe():
            return 'failed'

        # #1: back up before writing, from the bytes that were read.
        bak: str | None = None
        if backup and not config.no_backup:
            bak = _create_backup(filepath, config, data)
            if bak is None:
                logger.error('Backup failed for %s; skipping replacements.', filepath)
                return 'failed'

        if not _write_atomic(filepath, new_data, guard=still_safe):
            if bak:
                _discard_backup(bak, config)
            return 'failed'

        # Restore original file permissions
        if orig_mode is not None:
            with contextlib.suppress(OSError):
                os.chmod(filepath, orig_mode)

        if bak and config.secure_delete:
            _secure_delete(bak)

        return 'written'
    finally:
        if lock_fh is not None:
            lock_fh.close()


def _discard_backup(bak: str, config: Config) -> None:
    """Remove the backup made for a file that was then not written. The file
    is unchanged, so the backup has nothing to undo, and it holds the secret
    in plaintext: wiped first under --secure-delete."""
    if config.secure_delete:
        _secure_delete(bak)
    else:
        with contextlib.suppress(OSError):
            os.unlink(bak)
    logger.info('%s: removed, since the file it backs up was not rewritten.', bak)


def _identity(st: os.stat_result) -> tuple[int, int, int, int]:
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def _changed_on_disk(filepath: str, seen: tuple[int, int, int, int]) -> bool:
    """Whether *filepath* is no longer the file that was read (SR-24): its
    size, mtime or inode moved, or it is gone."""
    try:
        return _identity(os.stat(filepath)) != seen
    except OSError:
        return True


def _still_safe_to_write(filepath: str, root: str | None, seen: tuple[int, int, int, int]) -> bool:
    """Warn and return False when *filepath* must not be written now: it left
    the scan root (SR-20), or it is not the file that was read (SR-24)."""
    if root is not None and _outside_root(filepath, root):
        logger.warning(
            '%s is not inside the scan root through real directories (a '
            'directory on its path may have been moved or replaced by a '
            'symlink), so it is not rewritten.',
            filepath,
        )
        return False
    if _changed_on_disk(filepath, seen):
        logger.warning(
            '%s changed on disk while it was being redacted, so it is not '
            'rewritten. Re-run once nothing else is editing it.',
            filepath,
        )
        return False
    return True


def _outside_root(filepath: str, root: str) -> bool:
    """Whether *filepath* no longer reaches a file inside *root* by real
    directories: it resolves outside the root, or a component between the
    root and the file is a symlink. A link above the root does not count."""
    real_root = os.path.realpath(root)
    if not is_within_root(os.path.realpath(filepath), real_root):
        return True
    path = os.path.abspath(filepath)
    for base in (os.path.abspath(root), real_root):
        if is_within_root(path, base):
            break
    else:
        # Inside the root only once resolved: something on the way is a link.
        return True
    prefix = base
    for part in Path(os.path.relpath(path, base)).parts:
        if part == os.curdir:
            continue
        prefix = os.path.join(prefix, part)
        if os.path.islink(prefix):
            return True
    return False


def _final_file_sweep(
    filepath: str,
    approved: list[Finding],
    preserve_lines: set[int],
    config: Config,
    *,
    root: str | None = None,
) -> bool:
    """End-of-review sweep over one file with the session's full knowledge.

    The per-approval sweeps exclude every other known finding line statically
    (a prompt may still be pending), so a copy of approved value A sitting on
    finding B's line survives even after B itself is approved. This pass
    re-sweeps the file for ALL approved values, preserving only the lines
    whose findings were skipped, failed, or never adjudicated (interrupt).
    It is written through the same path as every other rewrite. It makes no
    backup: the first approval to the file made one, and under
    --secure-delete that one is already wiped, so changes here are not
    recoverable (by design for --secure-delete).

    Returns False when the file needed a change that could not be written, so
    copies of approved values may remain in it.
    """
    counts = _SweepCounts()

    def edit(lines: list[str]) -> bool:
        nonlocal counts
        before = list(lines)
        own = frozenset(f['line'] for f in approved)
        counts = _sweep_stray_copies(lines, approved, config, preserve_lines, filepath, own)
        return lines != before

    if _rewrite_file(filepath, config, edit, verb='sweep', backup=False, root=root) == 'failed':
        return False
    _report_sweep(filepath, counts, config)
    return True


def _sweep_stray_copies(
    lines: list[str],
    file_findings: list[Finding],
    config: Config,
    preserved: set[int],
    filepath: str,
    own_lines: frozenset[int] = frozenset(),
) -> _SweepCounts:
    """Clear remaining exact copies of redacted values beyond the
    adjudicated findings, and return what was cleared and kept, for the
    caller to report once the file is written.

    The per-finding replace handles one occurrence each, but the same secret
    literal can survive — a second occurrence on the finding's own line, a
    trailing comment elsewhere, or (the common case) a detector that
    DEDUPLICATED repeated copies and reported the value only once. Lines in
    ``preserved`` (1-based) are never touched: they belong to known findings
    whose own adjudication — an explicit interactive skip, a pending prompt,
    or a failed replacement — owns them. Scope is bounded to this one file.
    ``own_lines`` are the lines whose findings were just replaced: a
    credactor:ignore marker does not stop the sweep there, since the finding
    itself was redacted on that line.
    """
    stray = DEFAULT_REPLACEMENT if config.replace_mode == 'env' else config.custom_replacement
    values = {f['full_value'] for f in file_findings if f['full_value']}
    if not values:
        return _SweepCounts()
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
        + r')(?!\w)',
        re.ASCII,
    )
    # SR-21: only a value the shape heuristics alone recognise can be a hash
    # output; a known-format token is a credential under any key.
    exemptable = {v: not _known_format(v) for v in values}
    stray_count = 0
    kept: list[int] = []
    hashed: list[int] = []
    for idx in range(len(lines)):
        line = lines[idx]
        if idx + 1 in preserved:
            continue
        matches = list(pat.finditer(line))
        # SR-22: a line the user marked credactor:ignore is not swept, unless
        # a finding on it was just replaced.
        if not matches or (idx + 1 not in own_lines and has_inline_suppression(line)):
            continue
        parts: list[str] = []
        pos = 0
        n = 0
        for match in matches:
            if exemptable[match.group(0)] and _hash_keyed(line, match.start()):
                # SR-21: a copy in a hash, commit or revision field is kept,
                # as the scanner keeps it.
                hashed.append(idx + 1)
                continue
            parts += (line[pos : match.start()], stray)
            pos = match.end()
            n += 1
        if not n:
            continue
        if _holds_key_marker(line):
            # SR-17: a marker line is never changed, not even by the sweep.
            kept += [idx + 1] * n
            continue
        lines[idx] = ''.join(parts) + line[pos:]
        stray_count += n
    return _SweepCounts(stray_count, tuple(hashed), tuple(kept))


class _SweepCounts(NamedTuple):
    """What a sweep did: copies cleared, and the line of each copy kept
    because it is keyed as a hash (SR-21) or sits on a key marker line
    (SR-17)."""

    cleared: int = 0
    kept_hash: tuple[int, ...] = ()
    kept_marker: tuple[int, ...] = ()


def _report_sweep(filepath: str, counts: _SweepCounts, config: Config) -> None:
    """Log what the sweep did to a file whose rewrite went through (or was not
    needed). A kept copy is reported once per run, however many sweeps of the
    file see it, so interactive review does not repeat it per approval."""

    def new(kind: str, kept_lines: tuple[int, ...]) -> int:
        count = 0
        for lineno in sorted(set(kept_lines)):
            key = (filepath, kind, lineno)
            if key not in config.sweep_kept_reported:
                config.sweep_kept_reported.add(key)
                count += kept_lines.count(lineno)
        return count

    hashed = new('hash', counts.kept_hash)
    if hashed:
        logger.warning(
            '%s: kept %d cop%s of redacted value(s) keyed as a hash, commit or '
            'revision, which the scanner does not report either.',
            filepath,
            hashed,
            'y' if hashed == 1 else 'ies',
        )
    kept = new('marker', counts.kept_marker)
    if kept:
        logger.warning(
            '%s: left %d cop%s of redacted value(s) on lines that hold a private key '
            'marker; remove them by hand.',
            filepath,
            kept,
            'y' if kept == 1 else 'ies',
        )
    if counts.cleared:
        # Default-visible (stderr): the file was modified beyond the
        # adjudicated findings, and the summary alone would under-report it.
        # ("additional", not "unreported": a second occurrence on a finding's
        # own line is also cleared here.)
        logger.warning(
            '%s: also cleared %d additional cop%s of redacted value(s) '
            'beyond the adjudicated finding(s) (value-global sweep).',
            filepath,
            counts.cleared,
            'y' if counts.cleared == 1 else 'ies',
        )


# How far back the key of a value is looked for: room for the longest key the
# key pattern takes (128), its quotes, the operator and some spacing. Looking
# back further cost time in proportion to the value's offset on the line.
_KEY_WINDOW = 256


def _hash_keyed(line: str, start: int) -> bool:
    """Whether the value starting at *start* on *line* is keyed like a hash,
    commit or revision field, by the scanner's own rule (a credential keyword
    in the key vetoes it)."""
    at = start - 1 if start and line[start - 1] in '"\'' else start
    lo = max(0, at - _KEY_WINDOW)
    return _is_hash_context_at(line[lo:at], at - lo)


def _writable_findings(filepath: str, file_findings: list[Finding]) -> tuple[list[Finding], int]:
    """Split off the findings that must not be written here, warning for
    each; returns the rest and how many were refused."""
    # SR-16: nothing under .git (repository metadata and hooks, not source) is
    # ever rewritten, whoever passed the finding in. The whole path counts, as
    # given and resolved, so neither a root at or inside .git nor a linked
    # directory into it gets past.
    if in_git_dir(filepath, os.sep) or in_git_dir(os.path.realpath(filepath), os.sep):
        logger.warning('%s: not rewritten: the path is inside .git.', filepath)
        return [], len(file_findings)
    writable: list[Finding] = []
    for f in file_findings:
        if f.get('refuse_reason'):
            # Marked at ingest: reported, never written.
            logger.warning('%s:%d: not rewritten: %s.', filepath, f['line'], f['refuse_reason'])
        elif f['type'].endswith('private key block') or (
            _holds_key_marker(f['full_value']) and not _is_key_block(f['full_value'])
        ):
            # The finding carries only its BEGIN header line as the match
            # value: a line-based replacement would rewrite the header, leave
            # the key material and END marker in the file, and, with the
            # header gone, the next scan would report the file clean. SR-17:
            # the value decides, so an ingested header typed by a report's
            # rule id is refused too; the type is only an extra trigger. A
            # value holding the whole block (BEGIN to END on one line) takes
            # the key with it, so it may be replaced.
            logger.warning(
                '%s:%d: refusing to redact a multi-line private key block: '
                'replacing its header line would leave the key material in the '
                'file while the next scan reports it clean. Rotate the key and '
                'remove the block manually.',
                filepath,
                f['line'],
            )
        elif '\n' in f['full_value'] or '\r' in f['full_value']:
            # A replacement works within one line; a value holding a line break
            # cannot match there, and one ending in it would join two lines.
            logger.warning(
                '%s:%d: not rewritten: the value spans lines, so it cannot be '
                'replaced within one. Fix it by hand.',
                filepath,
                f['line'],
            )
        else:
            writable.append(f)
    return writable, len(file_findings) - len(writable)


def batch_replace_in_file(
    filepath: str,
    file_findings: list[Finding],
    config: Config,
    *,
    sweep_exclude_lines: frozenset[int] = frozenset(),
    skip_backup: bool = False,
    root: str | None = None,
    tally: dict[str, int] | None = None,
    allowlist: AllowList | None = None,
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

    writable, refused = _writable_findings(filepath, file_findings)
    if refused:
        # Re-enter with the refused findings stripped, so every downstream
        # outcome (success, symlink refusal, read/write errors) counts them
        # unresolved.
        replaced, failed = batch_replace_in_file(
            filepath,
            writable,
            config,
            sweep_exclude_lines=sweep_exclude_lines,
            skip_backup=skip_backup,
            root=root,
            tally=tally,
            allowlist=allowlist,
        )
        if tally is not None:
            tally['refused'] = tally.get('refused', 0) + refused
        return replaced, failed + refused

    # S6: the CLI validates the replacement at its front door, but a library
    # caller building a Config directly skips that — re-check at the sink so an
    # out-of-charset (or empty) string is never written into a file.
    config.validate_replacement()

    # SR-22: lines a .credactorignore file:line entry names are the user's
    # call, so the copy sweep leaves them as they are.
    if allowlist is not None:
        sweep_exclude_lines = sweep_exclude_lines | allowlist.suppressed_lines(filepath)

    counts = (0, 0)
    refused_here = 0
    sweep = _SweepCounts()

    def edit(lines: list[str]) -> bool:
        nonlocal counts, refused_here, sweep
        replaced, failed, refused_here, sweep = _apply_findings(
            lines, file_findings, config, filepath, sweep_exclude_lines
        )
        counts = (replaced, failed)
        return replaced > 0

    # skip_backup: interactive mode backs a file up once per session, on the
    # FIRST approval; later approvals to the same file must NOT re-create the
    # .bak (the per-file backup name is stable, so a second write would clobber
    # it with the already-redacted file and lose the earlier secret's
    # original). The first approval's .bak already holds every line's true
    # original.
    outcome = _rewrite_file(
        filepath, config, edit, verb='redact', backup=not skip_backup, root=root
    )
    if outcome == 'failed':
        # Refused, or unreadable, not backed up, or not written: every finding
        # stays unresolved, and nothing the edit planned is reported as done.
        return 0, len(file_findings)
    if tally is not None:
        tally['refused'] = tally.get('refused', 0) + refused_here
    _report_sweep(filepath, sweep, config)
    return counts


def _apply_findings(
    lines: list[str],
    file_findings: list[Finding],
    config: Config,
    filepath: str,
    sweep_exclude_lines: frozenset[int],
) -> tuple[int, int, int, _SweepCounts]:
    """Replace each finding on *lines* in place, bottom to top so earlier
    replacements do not shift later ones, then sweep stray copies. Returns
    (replaced, failed, refused on purpose, what the sweep did)."""
    replaced = 0
    failed = 0
    refused_here = 0
    failed_lines: set[int] = set()
    replaced_lines: set[int] = set()
    replaced_values: set[str] = set()
    refused_values: set[str] = set()
    marker_lines: dict[int, bool] = {}

    for finding in sorted(file_findings, key=lambda f: f['line'], reverse=True):
        outcome = _replace_one(lines, finding, config, filepath, marker_lines)
        if outcome == 'replaced':
            replaced += 1
            replaced_values.add(finding['full_value'])
            replaced_lines.add(finding['line'])
            continue
        failed += 1
        failed_lines.add(finding['line'])
        if outcome == 'refused':
            refused_here += 1
            refused_values.add(finding['full_value'])
    # H10 + value-global sweep: see _sweep_stray_copies. Lines owned by known
    # findings the caller did not approve here (sweep_exclude_lines) and lines
    # whose own replacement just failed keep their content: each finding's
    # adjudication owns its line. A value refused on its own line (inside a
    # longer word, or on a key marker line) and not replaced anywhere drives no
    # sweep either: it was never confirmed as a token here.
    sweep = _SweepCounts()
    if replaced:
        unconfirmed = refused_values - replaced_values
        sweep = _sweep_stray_copies(
            lines,
            [f for f in file_findings if f['full_value'] not in unconfirmed],
            config,
            set(sweep_exclude_lines) | failed_lines,
            filepath,
            frozenset(replaced_lines),
        )
    return replaced, failed, refused_here, sweep


def replace_single(
    filepath: str,
    finding: Finding,
    config: Config,
    *,
    sweep_exclude_lines: frozenset[int] = frozenset(),
    skip_backup: bool = False,
    root: str | None = None,
    allowlist: AllowList | None = None,
) -> bool:
    """Replace a single finding. Used in interactive mode.

    Returns True on success.
    """
    replaced, _ = batch_replace_in_file(
        filepath,
        [finding],
        config,
        sweep_exclude_lines=sweep_exclude_lines,
        skip_backup=skip_backup,
        root=root,
        allowlist=allowlist,
    )
    return replaced > 0


# ---------------------------------------------------------------------------
# Interactive review
# ---------------------------------------------------------------------------
def interactive_review(
    findings: list[Finding],
    root: str,
    config: Config,
    allowlist: AllowList | None = None,
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

    # Back up each file at most once per interactive session: the first approval
    # to a file creates the .bak (its true original); later approvals to the
    # SAME file pass skip_backup=True so the per-file backup is not overwritten
    # with the already-redacted file (which would lose the earlier secret's
    # original). batch_replace_in_file backs up once per call, and interactive
    # calls it once per approval — hence the per-session guard.
    backed_up_files: set[str] = set()

    def _run_final_sweeps() -> int:
        """Sweep each file with approvals; return how many could not be
        written, so copies of approved values may remain in them."""
        unwritten = 0
        for fp, approved in approved_by_file.items():
            preserve = lines_by_file[fp] - {f['line'] for f in approved}
            if allowlist is not None:
                preserve |= allowlist.suppressed_lines(fp)
            if not _final_file_sweep(fp, approved, preserve, config, root=root):
                unwritten += 1
        if unwritten:
            logger.warning(
                '%d file(s) may still hold copies of approved values: the '
                'end-of-review sweep could not rewrite them (see above). Each '
                'counts as unresolved.',
                unwritten,
            )
        return unwritten

    replacement_desc = config.custom_replacement
    if config.replace_mode == 'env':
        replacement_desc = 'env var reference'

    print(f'{"=" * 70}')
    print(f'  INTERACTIVE REDACTION  --  {total} credential(s) found')
    print(f"  Answer y to replace each value with '{replacement_desc}', n (or Enter) to skip.")
    print(f'{"=" * 70}\n')

    # PA-04, SR-07: the type (an ingested one holds a report's label) and the
    # path can hold a secret.
    masker = OutputMasker(f['full_value'] for f in findings)

    for i, finding in enumerate(findings, 1):
        rel = relativize(finding['file'], root_path)

        masked = mask_secret(finding['full_value'])

        safe_rel = masker.show_name(rel)
        safe_type = masker.show_name(finding['type'])
        safe_masked = sanitize_for_display(masked)

        print(f'  [{i}/{total}]  {safe_rel}  --  line {finding["line"]}')
        print(f'  Type     : {safe_type}')
        print(f'  Severity : {finding.get("severity", "medium")}')
        print(f'  Value    : {safe_masked}')
        print()

        # SR-16: nothing to ask about a finding that must not be rewritten.
        if finding.get('refuse_reason'):
            print(f'  -- Not rewritten: {sanitize_for_display(finding["refuse_reason"])}.\n')
            skipped += 1
            continue

        while True:
            try:
                answer = input('  Replace? [y/N]: ').strip().lower()
            except (KeyboardInterrupt, EOFError):
                # Completes the already-approved adjudications only: pending
                # and skipped findings' lines are preserved by construction.
                unwritten = _run_final_sweeps()
                print(
                    f'\n\n  Interrupted — {replaced} replacement(s) already '
                    f'applied. No further changes will be made.'
                )
                if replaced and not config.no_backup and not config.secure_delete:
                    # Same invariant as the summary footer: under
                    # --secure-delete each .bak was wiped after its
                    # replacement, so there is nothing to point at.
                    print('  .bak backups exist for modified files.')
                _print_summary(replaced, skipped, total, config)
                return total - replaced + unwritten

            if answer in ('y', 'yes'):
                fpath = finding['file']
                others = lines_by_file[fpath] - {finding['line']}
                ok = replace_single(
                    fpath,
                    finding,
                    config,
                    sweep_exclude_lines=frozenset(others),
                    skip_backup=fpath in backed_up_files,
                    root=root,
                    allowlist=allowlist,
                )
                if ok:
                    backed_up_files.add(fpath)
                    print('  -> Replaced.\n')
                    replaced += 1
                    approved_by_file.setdefault(fpath, []).append(finding)
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

    unwritten = _run_final_sweeps()
    _print_summary(replaced, skipped, total, config)
    return total - replaced + unwritten


def fix_all(
    findings: list[Finding],
    root: str,
    config: Config,
    allowlist: AllowList | None = None,
) -> int:
    """Replace all findings without prompting (#33).

    Returns the number of unresolved findings.
    """
    # Group by file for batch replacement
    by_file = group_by_file(findings)

    total_replaced = 0
    total_failed = 0
    failed_in_ingested_files = 0

    for filepath, file_findings in by_file.items():
        tally = {'refused': 0}
        replaced, failed = batch_replace_in_file(
            filepath, file_findings, config, root=root, tally=tally, allowlist=allowlist
        )
        total_replaced += replaced
        total_failed += failed
        if failed and any(f['type'].startswith('external:') for f in file_findings):
            # A finding refused on purpose is not a sign of a stale report, so
            # it does not count toward the hint below.
            failed_in_ingested_files += max(failed - tally['refused'], 0)

    _print_summary(total_replaced, total_failed, len(findings), config, label='failed')
    if failed_in_ingested_files:
        # K-5: per-finding warns scroll past — one run-level pointer at the
        # most likely cause. Counted per file containing ingested findings, not
        # run-wide: failures confined to purely-native files must not blame a
        # report that applied cleanly (and send the user regenerating it).
        logger.warning(
            '%d finding(s) in file(s) with ingested findings could not be '
            'applied — if the tree changed since the scan, the report is '
            'stale: regenerate it and re-run.',
            failed_in_ingested_files,
        )
    return total_failed


def _print_summary(
    replaced: int,
    other: int,
    total: int,
    config: Config,
    label: str = 'skipped',
) -> None:
    # Mirror _handle_fix_all's stream choice: with -f json/sarif the report on
    # stdout must stay a single parseable document, so the summary goes to
    # stderr. Interactive review is text-only, where this is still stdout.
    out = sys.stdout if config.output_format == 'text' else sys.stderr
    print(f'{"=" * 70}', file=out)
    print(f'  Summary:  {replaced} replaced  |  {other} {label}  |  {total} total', file=out)
    if replaced:
        print('  Reminder: rotate / revoke any credentials that were just redacted.', file=out)
        # The plaintext warning only applies when a .bak can still exist:
        # --no-backup never writes one and --secure-delete wipes it. It stays
        # for --secure-backup-dir — those backups are plaintext too, just
        # elsewhere. (A failed secure-delete already logs its own warning.)
        if not config.no_backup and not config.secure_delete:
            print(
                '  SECURITY: .bak backup files contain original credentials in PLAINTEXT.', file=out
            )
            print(
                '            Use --secure-backup-dir to store backups outside the repo,', file=out
            )
            print(
                '            or --secure-delete to overwrite backups after verification.', file=out
            )
            print('            At minimum, delete .bak files before committing.', file=out)
    print(f'{"=" * 70}\n', file=out)
