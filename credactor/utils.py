"""
Utility functions: entropy calculation and file encoding detection.

Addresses: #16 (encoding detection), #28 (optimized entropy)
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Config


def log_verbose(config: Config | None, msg: str) -> None:
    """Emit *msg* at DEBUG level via the credactor logger.

    The handler level (WARNING by default, DEBUG after configure(verbose=True))
    determines whether the message reaches stderr.  The ``config`` parameter is
    kept for call-site compatibility; it is no longer consulted at runtime.
    """
    from ._log import logger
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
            return result.encoding
    except ImportError:
        pass

    # Try chardet
    try:
        import chardet
        det = chardet.detect(raw)
        if det and det.get('encoding') and det.get('confidence', 0) > 0.7:
            return det['encoding']
    except ImportError:
        pass

    # Heuristic: try to decode as utf-8
    try:
        raw.decode('utf-8')
        return 'utf-8'
    except UnicodeDecodeError:
        pass

    # Try latin-1 as a last resort (it never fails, but may be wrong)
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


def mask_secret(value: str, visible: int = 4) -> str:
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
