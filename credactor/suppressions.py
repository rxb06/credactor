"""
Suppression mechanisms: inline comments and .credactorignore file.

Addresses: #3 (inline suppression), #4 (allowlist file)
"""

import fnmatch
import os
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
            with open(ignore_path, encoding='utf-8', errors='replace') as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line or line.startswith('#'):
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
                        if line in ('*', '**', '**/*', '*.*'):
                            logger.warning(
                                '.credactorignore contains overly broad pattern "%s" '
                                '— this suppresses ALL files.', line,
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
        except OSError:
            pass

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

    def is_suppressed(self, filepath: str, lineno: int, value: str) -> bool:
        """Combined check for any suppression."""
        rel = self._rel(filepath)
        return (any(fnmatch.fnmatch(rel, g) for g in self._file_globs)
                or lineno in self._file_line.get(rel, set())
                or value in self._value_literals)
