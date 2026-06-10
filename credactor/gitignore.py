"""
.gitignore pattern loading and matching.

Extracted from the original single-file script with no logic changes.
"""

import fnmatch
from collections.abc import Sequence
from pathlib import Path


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
                if not stripped or stripped.startswith(('#', '!')):
                    continue
                patterns.append((stripped, base_dir))
    except OSError:
        pass
    return patterns


def matches_gitignore(filepath: str, patterns: Sequence[tuple[str, str | Path]]) -> bool:
    """Return True if *filepath* is covered by any collected ``.gitignore`` pattern."""
    file_path = Path(filepath).resolve()
    # Most repos have a single .gitignore, so every rule shares one base_dir —
    # compute the relative form once per distinct base instead of once per
    # rule (relative_to dominated per-file cost and grew linearly with rules).
    rel_cache: dict[Path, tuple[str, tuple[str, ...]] | None] = {}

    for pattern, base_dir in patterns:
        base_path = base_dir if isinstance(base_dir, Path) else Path(base_dir).resolve()
        if base_path not in rel_cache:
            try:
                rel = file_path.relative_to(base_path)
                rel_cache[base_path] = (rel.as_posix(), rel.parts)
            except ValueError:
                rel_cache[base_path] = None
        cached = rel_cache[base_path]
        if cached is None:
            continue
        rel_str, rel_parts = cached
        rel_name = rel_parts[-1] if rel_parts else ''

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
                if fnmatch.fnmatch(rel_str, sub) or fnmatch.fnmatch(rel_name, sub):
                    return True
            elif fnmatch.fnmatch(rel_str, clean):
                return True
        else:
            if fnmatch.fnmatch(rel_name, pattern):
                return True
            if any(fnmatch.fnmatch(part, pattern) for part in rel_parts[:-1]):
                return True

    return False
