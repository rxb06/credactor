"""
Suppression mechanisms: inline comments and .credactorignore file.

Addresses: #3 (inline suppression), #4 (allowlist file)
"""

import fnmatch
import os
import re
from pathlib import Path

from ._log import logger
from .patterns import SCAN_EXTENSIONS, SUPPRESS_RE


def has_inline_suppression(line: str) -> bool:
    """Return True if the line contains a ``credactor:ignore`` comment."""
    return bool(SUPPRESS_RE.search(line))


class AllowList:
    """Loads and matches entries from a ``.credactorignore`` file.

    Supported entry formats::

        # comment
        path/to/file.py          # ignore entire file (glob)
        path/to/file.py:42       # ignore specific file + line number
        **/test_*.py             # glob pattern
        secret_value_literal     # ignore a specific value anywhere
    """

    def __init__(self, root: str) -> None:
        self._file_globs: list[str] = []
        self._file_line: dict[str, set[int]] = {}
        self._value_literals: set[str] = set()
        self._root = Path(root).resolve()
        self._load()

    def _load(self) -> None:
        ignore_path = self._root / '.credactorignore'
        if not ignore_path.is_file():
            return
        try:
            with ignore_path.open(encoding='utf-8', errors='replace') as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # M12: an explicit `value:<literal>` entry suppresses a value
                    # containing . / ? * (base64, JWTs, connection strings) that
                    # the char-based routing below would otherwise send to
                    # glob/path matching, leaving it un-allowlistable.
                    if line.startswith('value:'):
                        literal = line[len('value:'):]
                        if literal:
                            self._value_literals.add(literal)
                        continue
                    # file:line entry
                    if ':' in line:
                        parts = line.rsplit(':', 1)
                        if parts[1].isdigit():
                            path_str = parts[0]
                            lineno = int(parts[1])
                            self._file_line.setdefault(path_str, set()).add(lineno)
                            continue
                    # glob-like or plain path
                    if any(c in line for c in ('*', '?', '/', os.sep, '.')):
                        # L6b: fnmatch has no globstar, so ** behaves like * and
                        # patterns like */* and **/*.* match very broadly yet
                        # evaded the narrow list. Flag a catch-all: an explicit
                        # broad pattern, OR one with no literal filename segment
                        # left after stripping glob metachars and separators.
                        if (line in ('*', '**', '**/*', '*.*', '*/*', '**/*.*')
                                or not re.sub(r'[*?/\\.]', '', line)):
                            logger.warning(
                                '.credactorignore contains overly broad pattern "%s" '
                                '— this can suppress most or all files.', line,
                            )
                        elif any(
                            (line.endswith(ext) and line.lstrip('*').lstrip('/').startswith('*'))
                            or line == f'*{ext}'
                            for ext in SCAN_EXTENSIONS
                        ):
                            logger.warning(
                                '.credactorignore pattern "%s" may suppress many scannable files.',
                                line,
                            )
                        self._file_globs.append(line)
                    else:
                        # treat as a value literal to suppress
                        self._value_literals.add(line)
            if self._value_literals:
                # Unlike file globs (warned only when overly broad), value
                # literals had no signal at all — a contributor can hide their
                # own secret everywhere with one line. Surface that they exist.
                logger.warning(
                    '.credactorignore defines %d value-literal suppression(s); '
                    'these hide any matching value everywhere with no per-finding '
                    'signal — review them for detection-bypass.',
                    len(self._value_literals),
                )
            if self._file_line:
                # M13: file:line entries are positional only — the value is never
                # checked — so a new secret that drifts onto a suppressed line
                # after edits is silently hidden. No format change; surface the
                # drift risk so entries get re-verified.
                logger.warning(
                    '.credactorignore has %d positional file:line suppression(s); '
                    'they match by line number only and will not catch a new '
                    'secret that moves onto a suppressed line — re-check them '
                    'after large edits.',
                    sum(len(v) for v in self._file_line.values()),
                )
        except OSError as exc:
            logger.warning(
                '.credactorignore could not be fully read (%s); '
                'the allowlist may be incomplete.',
                exc,
            )

    def _rel(self, filepath: str) -> str:
        try:
            return Path(filepath).resolve().relative_to(self._root).as_posix()
        except ValueError:
            return filepath

    def is_file_suppressed(self, filepath: str) -> bool:
        """Return True if the entire file is suppressed by a glob pattern."""
        rel = self._rel(filepath)
        return any(fnmatch.fnmatch(rel, g) for g in self._file_globs)

    def is_line_suppressed(self, filepath: str, lineno: int) -> bool:
        """Return True if a specific file:line is suppressed."""
        rel = self._rel(filepath)
        return lineno in self._file_line.get(rel, set())

    def is_value_suppressed(self, value: str) -> bool:
        """Return True if the value literal is in the allowlist."""
        return value in self._value_literals

    def suppression_reason(self, filepath: str, lineno: int, value: str) -> str | None:
        """Return which suppression matched — ``'glob'`` / ``'file:line'`` /
        ``'value-literal'`` — or ``None`` (L11).

        Same precedence as ``is_suppressed`` (glob, then file:line, then value)
        so the boolean result is identical; callers use the kind to make the
        ``--verbose`` audit trail say *why* a finding was suppressed.
        """
        rel = self._rel(filepath)
        if any(fnmatch.fnmatch(rel, g) for g in self._file_globs):
            return 'glob'
        if lineno in self._file_line.get(rel, set()):
            return 'file:line'
        if value in self._value_literals:
            return 'value-literal'
        return None

    def is_suppressed(self, filepath: str, lineno: int, value: str) -> bool:
        """Combined check for any suppression."""
        return self.suppression_reason(filepath, lineno, value) is not None
