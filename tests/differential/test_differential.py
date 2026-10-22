"""Ordered differential test over the whole corpus (PA-01).

For each case, the complete snapshot (findings per file in emission order with
every field, exit code, log messages, and file hashes afterwards) must equal
the committed one in ``expected/``. A change that is meant to alter behaviour
must regenerate the snapshots in the same commit and explain each changed
entry:

    python -m pytest tests/differential --update-differential

then review ``git status`` (new cases add files) and ``git diff``.

Two further checks run on every case. No fragment of a secret may reach a
snapshot, and the text, JSON and SARIF reports built from the case's findings
must not contain one either, except for the leaks listed in
``KNOWN_OUTPUT_LEAKS``, each tied to the task that fixes it.
"""

from __future__ import annotations

import difflib
import importlib.util
import os
import shutil
import sys
from pathlib import Path

import pytest

from credactor.config import Config
from credactor.scanner import scan_file

from .corpus import CASES, SECRETS, Case
from .snapshot import dumps, run_case, secret_fragments

EXPECTED = Path(__file__).parent / 'expected'
_HAS_ENCODING_EXTRA = importlib.util.find_spec('charset_normalizer') is not None

# (case id, report format) -> the task that removes the leak. When that task
# lands the entry must go: a listed leak that no longer happens fails too.
KNOWN_OUTPUT_LEAKS: dict[tuple[str, str], str] = {}


def _skip_reason(case: Case) -> str | None:
    if case.posix_only and sys.platform == 'win32':
        return 'POSIX-only fixture'
    if case.needs_git and shutil.which('git') is None:
        return 'git is not installed'
    if case.needs_encoding_extra and not _HAS_ENCODING_EXTRA:
        return 'needs the optional charset-normalizer extra'
    if case.id == 'fail-on-error-unreadable' and hasattr(os, 'getuid') and os.getuid() == 0:
        return 'root can read a mode-0 file'
    return None


def _tree_root(tmp_path: Path) -> Path:
    # Config discovery looks at the target and five parents; keep all six
    # inside tmp_path so a stray .credactor.toml above it cannot change a case.
    return tmp_path / 'a' / 'b' / 'c' / 'd' / 'e' / 'tree'


def test_case_ids_are_unique() -> None:
    ids = [c.id for c in CASES]
    assert len(ids) == len(set(ids))


def test_no_stale_snapshots() -> None:
    # A removed or renamed case must take its snapshot with it.
    known = {f'{c.id}.json' for c in CASES}
    stale = sorted(p.name for p in EXPECTED.glob('*.json') if p.name not in known)
    assert stale == []


def test_snapshots_hold_no_secrets() -> None:
    # A second line of defence for what is committed. The first is the
    # fragment check each case runs before comparing or writing its snapshot.
    dirty: dict[str, list[str]] = {}
    for path in sorted(EXPECTED.glob('*.json')):
        problems = sorted({f['type'] for f in scan_file(str(path), config=Config())})
        problems += secret_fragments(path.read_text(encoding='utf-8'), SECRETS)
        if problems:
            dirty[path.name] = problems
    assert dirty == {}


@pytest.mark.parametrize('case', CASES, ids=[c.id for c in CASES])
def test_differential(case: Case, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request) -> None:
    reason = _skip_reason(case)
    if reason:
        pytest.skip(reason)
    snapshot, rendered, known = run_case(case, _tree_root(tmp_path), monkeypatch)
    actual = dumps(snapshot)

    leaked = secret_fragments(actual, known)
    assert leaked == [], f'{case.id}: snapshot would hold secret fragments {leaked}'

    for fmt, text in sorted(rendered.items()):
        leaks = secret_fragments(text, known)
        expected_leak = KNOWN_OUTPUT_LEAKS.get((case.id, fmt))
        if expected_leak is None:
            assert leaks == [], f'{case.id}: the {fmt} report leaks secret fragments'
        else:
            assert leaks, (
                f'{case.id}: the {fmt} report no longer leaks; remove the '
                f'KNOWN_OUTPUT_LEAKS entry for {expected_leak}'
            )

    target = EXPECTED / f'{case.id}.json'
    if request.config.getoption('--update-differential'):
        EXPECTED.mkdir(exist_ok=True)
        target.write_text(actual, encoding='utf-8', newline='\n')
        return
    if not target.exists():
        pytest.fail(
            f'no snapshot for {case.id!r}; run: python -m pytest tests/differential '
            '--update-differential, then review the new file'
        )
    expected = target.read_text(encoding='utf-8')
    if actual != expected:
        diff = ''.join(
            difflib.unified_diff(
                expected.splitlines(keepends=True),
                actual.splitlines(keepends=True),
                fromfile=f'expected/{case.id}.json',
                tofile='actual',
            )
        )
        pytest.fail(
            f'behaviour changed for case {case.id!r}. If intended, rerun with '
            f'--update-differential and explain the change in the commit.\n{diff}',
            pytrace=False,
        )
