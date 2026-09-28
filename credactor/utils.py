"""
Utility functions: entropy calculation and file encoding detection.

Addresses: #16 (encoding detection), #28 (optimized entropy)
"""

from __future__ import annotations

import bisect
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

from ._log import logger

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .types import Finding

# Optional encoding-detection libraries, resolved ONCE at import. The previous
# per-call `import` inside detect_encoding re-ran the failed lookup twice for
# every scanned file when neither library is installed (the default).
try:
    import charset_normalizer
except ImportError:
    charset_normalizer = None  # type: ignore[assignment]


def entropy(s: str) -> float:
    """Shannon entropy in bits per character (optimized with Counter)."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in Counter(s).values())


def utf16_variant(raw: bytes) -> str | None:
    """Return ``'utf-16-le'``/``'utf-16-be'`` when *raw* carries the UTF-16
    byte-order signature — NULs confined to one byte parity — else ``None``.

    Genuine text never contains NUL, yet NUL-interleaved ASCII (BOM-less
    UTF-16 with an ASCII-dominant payload) is *valid UTF-8*, so any UTF-8
    probe must run this check first or the secrets dissolve into NUL-riddled
    text no pattern can match. Shared by ``detect_encoding`` and the staged
    blob decode so working-tree and ``--staged`` scans cannot drift.
    """
    if b'\x00' not in raw:
        return None
    nul_even = raw[::2].count(0)
    nul_odd = raw[1::2].count(0)
    if nul_even == 0 and nul_odd > len(raw) // 4:
        return 'utf-16-le'
    if nul_odd == 0 and nul_even > len(raw) // 4:
        return 'utf-16-be'
    return None


def detect_encoding(filepath: str) -> str:
    """Detect the encoding of a file, falling back to utf-8.

    Uses charset_normalizer when the optional ``[encoding]`` extra is installed,
    then the UTF-16 signature check, then falls back to utf-8 / latin-1.
    """
    raw = b''
    try:
        with open(filepath, 'rb') as fh:
            raw = fh.read(8192)
    except OSError:
        return 'utf-8'

    if not raw:
        return 'utf-8'

    # Fast path: a pure-ASCII sample is always valid UTF-8, so skip the
    # statistical detectors entirely (they dominate per-file cost and may
    # answer 'ascii', which would then fail on non-ASCII bytes later in a
    # file whose first 8 KB happens to be plain ASCII). The NUL check is
    # load-bearing: bytes.isascii() is True for \x00, and BOM-less UTF-16
    # with an ASCII payload is exactly NUL-interleaved ASCII — without it,
    # such a file would short-circuit to utf-8 and its secrets would decode
    # to NUL-riddled text no pattern can match, silently. Genuine ASCII text
    # never contains NUL.
    if raw.isascii() and b'\x00' not in raw:
        return 'utf-8'

    # Genuine UTF-8/ASCII never contains NUL, but charset_normalizer can
    # mis-report a truncated or odd-length UTF-16 file as utf-8 on its
    # NUL-interleaved bytes. Trusting that verdict short-circuits the UTF-16
    # signature / latin-1 checks below and silently dissolves the secret into
    # mojibake no pattern can match (MV-1). So a utf-8/ascii verdict on
    # NUL-bearing bytes is distrusted here and left to those checks. (Valid
    # UTF-16 answers utf-16-*, UTF-32 answers utf-32 — both still trusted.)
    nul = b'\x00' in raw

    # Try charset_normalizer (lighter, no C deps)
    if charset_normalizer is not None:
        result = charset_normalizer.from_bytes(raw).best()
        if result and result.encoding:
            enc = str(result.encoding)
            if not (nul and enc.replace('_', '-').lower() in ('utf-8', 'ascii')):
                return enc

    variant = utf16_variant(raw)
    if variant:
        return variant
    if b'\x00' not in raw:
        # Heuristic: try to decode as utf-8 — but only for NUL-free bytes.
        # NUL-bearing content that isn't UTF-16 (UTF-32, stray NULs) must
        # fall through to the loud latin-1 fallback, never claim utf-8.
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
        filepath,
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


# Shorter known values are not masked inside other text: they would match
# ordinary words, and mask_secret shows nothing of them anyway.
KNOWN_MIN_LEN = 4


class KnownSecrets:
    """Every known secret value, indexed once so it can be masked in any
    number of texts (SR-05).

    A regex alternation of the values costs O(len(text) x len(values)) per
    text. Here the values are grouped by their first ``KNOWN_MIN_LEN``
    characters and kept sorted, so finding the longest value at a position
    is a dict lookup and a binary search, whatever the number of values.
    """

    def __init__(self, values: Iterable[str]) -> None:
        by_prefix: dict[str, set[str]] = {}
        for v in values:
            if len(v) >= KNOWN_MIN_LEN:
                by_prefix.setdefault(v[:KNOWN_MIN_LEN], set()).add(v)
        self._index = {prefix: sorted(vs) for prefix, vs in by_prefix.items()}
        self._longest = {prefix: max(map(len, vs)) for prefix, vs in by_prefix.items()}

    def _match_at(self, text: str, i: int) -> int:
        """Length of the longest known value that starts at ``text[i]``, or 0."""
        prefix = text[i : i + KNOWN_MIN_LEN]
        values = self._index.get(prefix)
        if values is None:
            return 0
        s = text[i : i + self._longest[prefix]]
        # The largest value <= s is the longest one that s starts with, if s
        # starts with it. If not, no known value longer than their common
        # prefix can start s either, so search again for that prefix.
        while True:
            k = bisect.bisect_right(values, s)
            if k == 0:
                return 0
            v = values[k - 1]
            if s.startswith(v):
                return len(v)
            common = 0
            while s[common] == v[common]:
                common += 1
            s = s[:common]

    def redact(self, text: str, *, limit: int | None = None) -> str:
        """Return *text* with every occurrence of every known value masked.

        Matches are leftmost-longest, and a value that starts inside a match
        and ends past it extends the match, so no value's tail is left
        showing; the masked span shows only its first characters. A mask is
        never masked again. With *limit*, the result is the first *limit*
        characters of the fully masked text, and only as much of *text* is
        read as those need; truncating after masking means a value cut at the
        edge never shows in part.
        """
        out: list[str] = []
        size = 0
        i = 0
        n = len(text)
        while i < n and (limit is None or size < limit):
            length = self._match_at(text, i)
            if not length:
                out.append(text[i])
                size += 1
                i += 1
                continue
            end = i + length
            p = i + 1
            while p < end:
                end = max(end, p + self._match_at(text, p))
                p += 1
            masked = mask_secret(text[i:end])
            out.append(masked)
            size += len(masked)
            i = end
        result = ''.join(out)
        return result if limit is None else result[:limit]


# SR-06. Escape sequences are removed whole: CSI, and OSC ended by BEL or ST.
# A lone or unknown ESC is left to the table below.
_ESCAPE_SEQ_RE = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)')
# Every C0 control (LF and CR included), DEL, every C1 control (NEL and the
# one-byte CSI included), the Unicode line and paragraph separators, and the
# bidirectional embedding, override and isolate controls, which can make a
# name display in a different order than its bytes. Lone surrogates too:
# undecodable bytes arrive as them (surrogateescape, os.fsdecode), and a
# stream that writes them back out would emit those raw bytes, while a
# strict one would raise. TAB becomes a space: it cannot break a line, and
# source lines are often indented with it.
_DISPLAY_TABLE = str.maketrans(
    dict.fromkeys(
        [
            *range(0x09),
            *range(0x0A, 0x20),
            0x7F,
            *range(0x80, 0xA0),
            0x2028,
            0x2029,
            *range(0x202A, 0x202F),
            *range(0x2066, 0x206A),
            *range(0xD800, 0xE000),
        ],
        '?',
    )
    | {0x09: ' '}
)
# CI workflow command markers. The GitHub runner reads '::' at the start of a
# line after trimming leading whitespace, and '##[' anywhere in a line; Azure
# Pipelines reads '##vso[' anywhere.
_CI_MARKER_RE = re.compile(r'##(?=\[|vso\[)', re.IGNORECASE)
_LINE_COMMAND_RE = re.compile(r'^([^\S\r\n]*):(?=:)', re.MULTILINE)


def display_chars(s: str) -> str:
    """Remove terminal escape sequences from *s*, replace every control,
    line-break, bidi and lone surrogate character with '?', and TAB with a
    space.

    Apart from whole escape sequences, each character maps on its own, so a
    secret and a line that holds it stay consistent: mask the output of this
    (``KnownSecrets``), then pass the result through ``defuse_ci_commands``.
    """
    return _ESCAPE_SEQ_RE.sub('', s).translate(_DISPLAY_TABLE)


def defuse_ci_commands(s: str) -> str:
    """Break CI workflow command markers in *s*, so that no line of it can be
    read as a command: '##[' and '##vso[' anywhere, and '::' at the start of a
    line after whitespace."""
    s = _CI_MARKER_RE.sub('#?', s)
    return _LINE_COMMAND_RE.sub(r'\1?', s)


def defuse_json_ci_commands(text: str) -> str:
    """Write the '##' of every '##[' and '##vso[' in JSON *text* as
    ``#\\u0023``, so no line of it can be read as a CI command while the data
    it decodes to is unchanged. Only for JSON text: a '#' can only occur
    inside a string there, and a line cannot start with '::'."""
    return _CI_MARKER_RE.sub(lambda _: '#\\u0023', text)


def sanitize_for_display(s: str) -> str:
    """Make an untrusted string safe to print to a terminal or a CI log (SR-06):
    ``display_chars`` then ``defuse_ci_commands``."""
    return defuse_ci_commands(display_chars(s))


# A known value masks a path or a type only if it looks like a secret, not a
# word: a found password such as 'production' must not mask an unrelated
# directory (breaking its SARIF link) or change a rule id between runs.
_NAME_VALUE_MIN = 8
# Raw text is masked this far before it is made displayable, which bounds the
# work for a very long line; a value crossing the bound is masked whole first.
_FIRST_PASS_LIMIT = 4096


def _distinctive(value: str) -> bool:
    return (
        len(value) >= _NAME_VALUE_MIN
        and any(c.isdigit() for c in value)
        and any(c.isalpha() for c in value)
    )


def name_secrets(values: Iterable[str]) -> KnownSecrets:
    """The known values that may mask a path or a type (see ``OutputMasker``)."""
    return KnownSecrets(v for v in values if _distinctive(v))


class OutputMasker:
    """Masks a run's known secret values wherever a report shows text
    (SR-05, PA-04, SR-07).

    Source lines are masked with every known value; paths and types only
    with distinctive ones. For display, text is masked in its raw form,
    then made displayable, then masked again in its displayed form, then
    has CI command markers broken: removing an escape sequence can take the
    first character of a value (only the raw pass sees it whole) or join the
    two halves of a value it split (only the second pass sees it whole).
    """

    def __init__(self, values: Iterable[str]) -> None:
        every = set(values)
        self._lines = KnownSecrets(every)
        self._lines_shown = KnownSecrets(display_chars(v) for v in every)
        self._names = name_secrets(every)
        self._names_shown = KnownSecrets(display_chars(v) for v in every if _distinctive(v))

    @staticmethod
    def _show(raw: KnownSecrets, shown: KnownSecrets, text: str, limit: int | None) -> str:
        first = raw.redact(text, limit=None if limit is None else _FIRST_PASS_LIMIT)
        return defuse_ci_commands(shown.redact(display_chars(first), limit=limit))

    def show_line(self, text: str, *, limit: int | None = None) -> str:
        """*text* (a source line) masked and made safe to display."""
        return self._show(self._lines, self._lines_shown, text, limit)

    def show_name(self, text: str) -> str:
        """*text* (a path or a type) masked and made safe to display."""
        return self._show(self._names, self._names_shown, text, None)


def preview(val: str, n: int = 60) -> str:
    """*val* cut to *n* characters, with an ellipsis when longer. Truncated,
    NOT masked: for most secrets the result is the whole secret, so never
    display or log it; use ``mask_secret``. Shared by the native scanner and
    external ingest so every ``value_preview`` is formatted identically, with
    one truncation length."""
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
