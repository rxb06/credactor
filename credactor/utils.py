"""
Utility functions: entropy calculation and file encoding detection.

Addresses: #16 (encoding detection), #28 (optimized entropy)
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

from ._log import logger

if TYPE_CHECKING:
    from .types import Finding


def log_verbose(msg: str) -> None:
    """Emit *msg* at DEBUG level via the credactor logger.

    The handler level (WARNING by default, DEBUG after configure(verbose=True))
    determines whether the message reaches stderr.
    """
    logger.debug(msg)


def entropy(s: str) -> float:
    """Shannon entropy in bits per character (optimized with Counter)."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in Counter(s).values())


def detect_encoding(filepath: str) -> str:
    """Detect the encoding of a file, falling back to utf-8.

    Tries charset_normalizer first, then chardet, then falls back to utf-8.
    """
    raw = b''
    try:
        with open(filepath, 'rb') as fh:
            raw = fh.read(8192)
    except OSError:
        return 'utf-8'

    if not raw:
        return 'utf-8'

    # Try charset_normalizer (lighter, no C deps)
    try:
        import charset_normalizer
        result = charset_normalizer.from_bytes(raw).best()
        if result and result.encoding:
            return str(result.encoding)
    except ImportError:
        pass

    # Try chardet
    try:
        import chardet
        det = chardet.detect(raw)
        if det and det.get('encoding') and det.get('confidence', 0) > 0.7:
            return str(det['encoding'])
    except ImportError:
        pass

    # Heuristic: try to decode as utf-8
    try:
        raw.decode('utf-8')
        return 'utf-8'
    except UnicodeDecodeError:
        pass

    # Last resort: latin-1 never fails to decode, but for a multibyte encoding
    # (e.g. UTF-16) it silently misreads the bytes, so secrets can be missed and
    # a clean scan is not proof of safety. We could not positively confirm the
    # encoding here, so warn — installing the optional encoding extra
    # (pip install "credactor[encoding]") enables real detection and avoids this.
    logger.warning(
        'could not confirm encoding of %s; reading as latin-1 — if it is UTF-16 '
        'or another multibyte encoding, secrets may be missed. For reliable '
        'detection install the encoding extra: pip install "credactor[encoding]"',
        sanitize_for_terminal(filepath),
    )
    return 'latin-1'


def is_within_root(path_str: str, root_str: str) -> bool:
    """Cross-platform path containment check.

    On Windows, git returns forward-slash paths but Path.resolve() returns
    backslash paths.  Normalise both sides so the startswith() boundary
    check works regardless of separator style.

    Appends os.sep AFTER normpath to prevent prefix collision
    (e.g. /tmp/repo must not match /tmp/repo_evil).

    os.path.normcase() is added for Windows defense-in-depth — it
    lowercases paths on Windows (NTFS case-insensitive) so that a path
    differing only in case from the root is not incorrectly treated as
    outside it.  normcase() is a no-op on Linux (case-sensitive) and
    macOS (Path.resolve() at all call sites already returns canonical case
    via the OS, so paths entering here are already case-consistent).
    """
    norm_path = os.path.normcase(os.path.normpath(path_str))
    norm_root = os.path.normcase(os.path.normpath(root_str))
    return norm_path == norm_root or norm_path.startswith(norm_root + os.sep)


def mask_secret(value: str, *, visible: int = 4) -> str:
    """Mask a secret value, showing only the first `visible` characters."""
    if len(value) <= visible:
        return '[REDACTED]'
    return value[:visible] + '[REDACTED]'


_CONTROL_CHAR_TABLE = str.maketrans(
    {c: '?' for c in range(32) if c not in (9, 10, 13)}  # keep tab, LF, CR
)
_ANSI_ESC_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')


def sanitize_for_terminal(s: str) -> str:
    """Strip ANSI escape sequences and control characters to prevent terminal
    injection via crafted filenames or values."""
    s = _ANSI_ESC_RE.sub('', s)
    return s.translate(_CONTROL_CHAR_TABLE)


def preview(val: str, n: int = 60) -> str:
    """Truncated, safe-for-display version of *val* (adds an ellipsis when longer
    than *n*). Shared by the native scanner and external ingest so every
    ``value_preview`` is formatted identically, with one truncation length."""
    return val[:n] + ('...' if len(val) > n else '')


def relativize(path: str, root_path: Path) -> str:
    """Return *path* made relative to *root_path* as a str, or the original path
    string if it lies outside the root. Callers pass an already-resolved
    *root_path* so ``resolve()`` is not paid per finding."""
    try:
        return str(Path(path).relative_to(root_path))
    except ValueError:
        return path


def group_by_file(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Group *findings* by their ``file`` key, preserving input order within each
    file. Callers that need sorted output sort the returned dict themselves."""
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f['file'], []).append(f)
    return by_file


def read_lines(filepath: str, *, errors: str = 'surrogateescape') -> list[str]:
    """Read *filepath* with its detected encoding and return its lines.

    The *errors* mode is explicit: ``surrogateescape`` for files that may be
    rewritten (scanner), ``replace`` for read-only display (ingest). ``OSError``
    is left to propagate so callers keep their own error handling."""
    encoding = detect_encoding(filepath)
    with open(filepath, encoding=encoding, errors=errors) as fh:
        return fh.readlines()
