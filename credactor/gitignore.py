"""
.gitignore pattern loading and matching.

Extracted from the original credential_redactor.py with no logic changes.
"""

import fnmatch
import os
from collections.abc import Sequence
from pathlib import Path

from .patterns import SKIP_DIRS


def parse_gitignore_file(gi_path: str, base_dir: Path) -> list[tuple[str, Path]]:
    """Read a single ``.gitignore`` and return its ``(pattern, base_dir)`` entries.

    Used by ``walker.walk_and_scan`` to collect patterns during the same
    ``os.walk`` pass that finds scannable files (avoids a second tree walk).
    """
    patterns: list[tuple[str, Path]] = []
    try:
        with open(gi_path, encoding='utf-8', errors='replace') as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped or stripped.startswith('#') or stripped.startswith('!'):
                    continue
                patterns.append((stripped, base_dir))
    except OSError:
        pass
    return patterns


def load_gitignore_patterns(root: str) -> list[tuple[str, Path]]:
    """Walk *root* and collect ``(pattern, base_dir)`` from every ``.gitignore``.

    Retained for callers that want gitignore patterns independently of a
    full scan.  Internal scanning (``walker.walk_and_scan``) inlines this
    logic into its main walk pass to avoid a second traversal.
    """
    patterns: list[tuple[str, Path]] = []
    root_path = Path(root).resolve()

    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if '.gitignore' in filenames:
            gi_path = os.path.join(dirpath, '.gitignore')
            patterns.extend(parse_gitignore_file(gi_path, Path(dirpath).resolve()))

    return patterns


def matches_gitignore(filepath: str, patterns: Sequence[tuple[str, str | Path]]) -> bool:
    """Return True if *filepath* is covered by any collected ``.gitignore`` pattern."""
    file_path = Path(filepath).resolve()

    for pattern, base_dir in patterns:
        base_path = base_dir if isinstance(base_dir, Path) else Path(base_dir).resolve()
        try:
            rel = file_path.relative_to(base_path)
        except ValueError:
            continue

        rel_str = rel.as_posix()
        rel_parts = rel.parts

        # Pattern ending with '/' targets directories
        if pattern.endswith('/'):
            dir_pattern = pattern.rstrip('/')
            if any(fnmatch.fnmatch(part, dir_pattern) for part in rel_parts[:-1]):
                return True
            continue

        # Pattern with '/' is anchored to the .gitignore directory
        if '/' in pattern.lstrip('/'):
            clean = pattern.lstrip('/')
            if clean.startswith('**/'):
                sub = clean[3:]
                if fnmatch.fnmatch(rel_str, sub) or fnmatch.fnmatch(rel.name, sub):
                    return True
            elif fnmatch.fnmatch(rel_str, clean):
                return True
        else:
            if fnmatch.fnmatch(rel.name, pattern):
                return True
            if any(fnmatch.fnmatch(part, pattern) for part in rel_parts[:-1]):
                return True

    return False
