"""Run one differential case through the real CLI and build its snapshot.

The snapshot is canonical JSON: findings per file in emission order with every
field, the exit code, the log messages emitted, and a hash of every file in
the tree afterwards. Secret values never appear in it. Each known value is
replaced by a short hash token, so the committed files carry no more plaintext
than the corpus source already does.

The run is hermetic: git sees no user or system configuration and no GIT_*
variables, and the tree sits deep enough under the test's temp directory that
config discovery (the target plus five parents) never leaves it.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any

from credactor import cli, report
from credactor._log import logger

from .corpus import SECRETS, Case

_FINDING_KEYS = {
    'file',
    'line',
    'type',
    'severity',
    'full_value',
    'value_preview',
    'raw',
    'commit',
    'refuse_reason',
}

# Temp files are named randomly by mkstemp. If one is ever left behind, record
# it under a stable name so the snapshot still shows it without churning.
_TEMP_NAME_RE = re.compile(r'tmp[^/]*\.credactor\.(tmp|bak)$')
_COMMIT_RE = re.compile(r'\b[0-9a-f]{12}\b')
_MIN_TAIL = 8


def _h(value: str) -> str:
    return hashlib.sha256(value.encode('utf-8', errors='surrogateescape')).hexdigest()[:16]


def _token(value: str) -> str:
    return f'<v:{_h(value)}>'


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class _TTYInput(io.StringIO):
    """Scripted answers for interactive mode, on a stream that reports a TTY."""

    def isatty(self) -> bool:
        return True


def _write_tree(root: Path, files: dict[str, bytes]) -> None:
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _roots(root: Path) -> list[str]:
    forms = {str(root), str(root.resolve()), os.path.realpath(root)}
    return sorted(forms, key=len, reverse=True)


def _relative(path: str, roots: list[str]) -> str:
    for r in roots:
        if path == r:
            return '.'
        if path.startswith(r + os.sep) or path.startswith(r + '/'):
            return Path(path[len(r) + 1 :]).as_posix()
    return Path(path).as_posix()


def _ordered(values: set[str]) -> list[str]:
    # Longest first so a short value cannot split a longer one; ties broken by
    # the value itself so the result never depends on set iteration order.
    return sorted((v for v in values if v), key=lambda v: (-len(v), v))


def _mask(text: str, values: set[str], *, truncated_tail: bool = False) -> str:
    """Replace every known value in *text* with its hash token.

    With ``truncated_tail``, also mask a value cut off at the very end of the
    text (a multi-line block over the scanner's size cap is cut), down to
    ``_MIN_TAIL`` characters; shorter tails are left as they are. The kept
    length is recorded (``~k``) so a change in where the cut falls still shows.
    """
    ordered = _ordered(values)
    for v in ordered:
        text = text.replace(v, _token(v))
    if truncated_tail:
        for v in ordered:
            for k in range(len(v) - 1, _MIN_TAIL - 1, -1):
                if text.endswith(v[:k]):
                    text = text[: len(text) - k] + _token(v) + f'~{k}'
                    break
    return text


class _Commits:
    """Map commit hashes to c1, c2, ... in order of first appearance."""

    def __init__(self) -> None:
        self.names: dict[str, str] = {}

    def __call__(self, text: str) -> str:
        def sub(m: re.Match[str]) -> str:
            return self.names.setdefault(m.group(0), f'c{len(self.names) + 1}')

        return _COMMIT_RE.sub(sub, text)


def _tree_hashes(root: Path, *, skip_git: bool) -> dict[str, str]:
    out: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        # A real repository's .git changes on every run; a fixture .git is data.
        dirnames[:] = sorted(d for d in dirnames if not (skip_git and d == '.git'))
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            if _TEMP_NAME_RE.search(rel):
                rel = _TEMP_NAME_RE.sub('tmp*.credactor.\\1', rel)
            if full.is_symlink():
                out[rel] = 'symlink'
                continue
            try:
                out[rel] = hashlib.sha256(full.read_bytes()).hexdigest()[:16]
            except OSError:
                out[rel] = 'unreadable'
    return out


def _hermetic_git(root: Path, monkeypatch: Any) -> None:
    for name in [k for k in os.environ if k.startswith('GIT_')]:
        monkeypatch.delenv(name)
    empty = root.parent / 'empty.gitconfig'
    empty.write_bytes(b'')
    monkeypatch.setenv('GIT_CONFIG_GLOBAL', str(empty))
    monkeypatch.setenv('GIT_CONFIG_NOSYSTEM', '1')


def run_case(
    case: Case, root: Path, monkeypatch: Any
) -> tuple[dict[str, Any], dict[str, str], list[str]]:
    """Build the tree for *case* under *root*, run the CLI, and return
    ``(snapshot, rendered, known)``. ``rendered`` holds the text, JSON and SARIF
    reports built from the captured findings, and ``known`` every secret value
    in play; both are used for leak checks and are never stored."""
    root.mkdir(parents=True)
    _hermetic_git(root, monkeypatch)
    _write_tree(root, case.files)
    if case.setup is not None:
        case.setup(root)

    emitted: list[list[dict[str, Any]]] = []
    rendered: dict[str, str] = {}
    real_emit = cli._emit_report

    def spy(findings: list[Any], target: str, *args: Any, **kwargs: Any) -> None:
        emitted.append([dict(f) for f in findings])
        text = io.StringIO()
        report.print_report(findings, target, no_color=True, stream=text)
        rendered['text'] = text.getvalue()
        rendered['json'] = report.json_report(findings, target)
        rendered['sarif'] = report.sarif_report(findings, target)
        real_emit(findings, target, *args, **kwargs)

    monkeypatch.setattr(cli, '_emit_report', spy)
    monkeypatch.chdir(root)
    if case.answers:
        monkeypatch.setattr(sys, 'stdin', _TTYInput(''.join(a + '\n' for a in case.answers)))
    capture = _Capture()
    logger.addHandler(capture)
    try:
        try:
            cli.main(list(case.argv))
            exit_code: int | str | None = 0
        except SystemExit as exc:
            exit_code = exc.code if exc.code is not None else 0
        except Exception as exc:  # recorded, so a crash is part of the snapshot
            exit_code = f'exception:{type(exc).__name__}'
    finally:
        logger.removeHandler(capture)

    roots = _roots(root)
    commits = _Commits()
    findings = emitted[0] if emitted else None
    known = set(SECRETS) | {f['full_value'] for f in findings or []}

    by_file: dict[str, list[dict[str, Any]]] | None = None
    if findings is not None:
        by_file = {}
        for f in findings:
            unexpected = set(f) - _FINDING_KEYS
            assert not unexpected, f'new Finding keys not in the snapshot: {sorted(unexpected)}'
            rel = _mask(_relative(f['file'], roots), known)  # a name can hold a secret
            if f.get('commit'):
                rel = commits(rel)
            entry = {
                'line': f['line'],
                'type': _mask(f['type'], known),
                'severity': f['severity'],
                'value': _h(f['full_value']),
                'preview': _h(f['value_preview']),
                'raw': _mask(f['raw'], known, truncated_tail=True),
                'commit': commits(f['commit']) if f.get('commit') else None,
            }
            if f.get('refuse_reason'):  # recorded only when set, so older cases stay as they are
                entry['refuse_reason'] = f['refuse_reason']
            by_file.setdefault(rel, []).append(entry)

    counts: dict[tuple[str, str], int] = {}
    for record in capture.records:
        message = record.getMessage()
        for r in roots:
            message = message.replace(r, '<root>')
        if os.sep == '\\':
            message = message.replace('\\', '/')  # same snapshot on every OS
        key = (record.levelname, commits(_mask(message, known)))
        counts[key] = counts.get(key, 0) + 1
    # Sorted, not in emission order: across files the order follows the
    # filesystem's listing order until the walk is sorted (DA-7, T50).
    log = [[level, message, n] for (level, message), n in sorted(counts.items())]

    snapshot = {
        'case': case.id,
        'argv': list(case.argv),
        'note': case.note,
        'exit': exit_code,
        'reported': findings is not None,
        'findings': by_file,
        'log': log,
        'tree_after': {
            _mask(rel, known): digest
            for rel, digest in _tree_hashes(root, skip_git=case.needs_git).items()
        },
    }
    return snapshot, rendered, _ordered(known)


def dumps(snapshot: dict[str, Any]) -> str:
    return json.dumps(snapshot, indent=1, sort_keys=True, ensure_ascii=True) + '\n'


def secret_fragments(text: str, values: list[str], n: int = 10) -> list[str]:
    """Every *n*-character fragment of a known value that occurs in *text*."""
    found = {v[i : i + n] for v in values for i in range(len(v) - n + 1) if v[i : i + n] in text}
    return sorted(found)
