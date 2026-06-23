"""Tests for scripts/audit_wheel.py, the supply-chain artifact gate."""

import importlib.util
import io
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / 'scripts' / 'audit_wheel.py'
_spec = importlib.util.spec_from_file_location('audit_wheel', _SCRIPT)
assert _spec is not None and _spec.loader is not None
audit_wheel = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit_wheel)

VERSION = '1.0.0'
PKG_FILES = {
    'credactor/__init__.py': b"__version__ = '1.0.0'\n",
    'credactor/core.py': b'def run():\n    return 42\n',
}


def _git(repo: Path, *args: str) -> None:
    subprocess.run(['git', *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A committed repo with a credactor/ package; cwd is set inside it."""
    (tmp_path / 'credactor').mkdir()
    for rel, data in PKG_FILES.items():
        (tmp_path / rel).write_bytes(data)
    (tmp_path / 'pyproject.toml').write_bytes(b'[project]\nname = "credactor"\n')
    (tmp_path / 'README.md').write_bytes(b'# credactor\n')
    _git(tmp_path, 'init', '-q')
    _git(tmp_path, 'config', 'user.email', 'a@b.c')
    _git(tmp_path, 'config', 'user.name', 't')
    _git(tmp_path, 'add', '-A')
    _git(tmp_path, 'commit', '-qm', 'init')
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'dist').mkdir()
    return tmp_path


def _wheel(repo: Path, files: dict[str, bytes], *, dist_info: bool = True) -> Path:
    path = repo / 'dist' / f'credactor-{VERSION}-py3-none-any.whl'
    with zipfile.ZipFile(path, 'w') as z:
        for name, data in files.items():
            z.writestr(name, data)
        if dist_info:
            z.writestr(f'credactor-{VERSION}.dist-info/METADATA', b'Name: credactor\n')
            z.writestr(f'credactor-{VERSION}.dist-info/RECORD', b'')
    return path


def _sdist(
    repo: Path,
    files: dict[str, bytes],
    *,
    metadata: bool = True,
    pyproject: bytes = b'[project]\nname = "credactor"\n',
) -> Path:
    path = repo / 'dist' / f'credactor-{VERSION}.tar.gz'
    prefix = f'credactor-{VERSION}'
    with tarfile.open(path, 'w:gz') as t:

        def add(arc: str, data: bytes) -> None:
            info = tarfile.TarInfo(f'{prefix}/{arc}')
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))

        for name, data in files.items():
            add(name, data)
        if metadata:
            add('PKG-INFO', b'Name: credactor\n')
            add('pyproject.toml', pyproject)
            add('README.md', b'# credactor\n')
    return path


def test_passes_on_matching_artifacts(repo):
    _wheel(repo, PKG_FILES)
    _sdist(repo, PKG_FILES)
    audit_wheel.audit('dist')  # no SystemExit means it passed


def _audit_fails_with(capsys, category: str) -> None:
    """Run the audit, assert it exits non-zero AND reports the given category."""
    with pytest.raises(SystemExit):
        audit_wheel.audit('dist')
    assert category in capsys.readouterr().err


def test_fails_on_altered_wheel_content(repo, capsys):
    tampered = dict(PKG_FILES)
    tampered['credactor/core.py'] = b'def run():\n    return 666  # injected\n'
    _wheel(repo, tampered)
    _sdist(repo, PKG_FILES)
    _audit_fails_with(capsys, 'CONTENT MISMATCH')


def test_fails_on_injected_file_in_wheel(repo, capsys):
    extra = dict(PKG_FILES)
    extra['credactor/evil.py'] = b'print("pwned")\n'
    _wheel(repo, extra)
    _sdist(repo, PKG_FILES)
    # A .py under credactor/ is a package file, so the wheel flags it as not-in-repo.
    _audit_fails_with(capsys, 'NOT IN REPO')


def test_fails_on_missing_file_in_wheel(repo, capsys):
    _wheel(repo, {'credactor/__init__.py': PKG_FILES['credactor/__init__.py']})
    _sdist(repo, PKG_FILES)
    _audit_fails_with(capsys, 'MISSING FROM WHEEL')


def test_fails_on_unexpected_toplevel_in_wheel(repo, capsys):
    smuggled = dict(PKG_FILES)
    smuggled['evil.py'] = b'print("pwned")\n'
    _wheel(repo, smuggled)
    _sdist(repo, PKG_FILES)
    _audit_fails_with(capsys, 'UNEXPECTED')


def test_fails_on_altered_sdist_content(repo, capsys):
    _wheel(repo, PKG_FILES)
    tampered = dict(PKG_FILES)
    tampered['credactor/core.py'] = b'def run():\n    return 0  # injected\n'
    _sdist(repo, tampered)
    _audit_fails_with(capsys, 'CONTENT MISMATCH')


def test_fails_on_unexpected_py_in_sdist(repo, capsys):
    _wheel(repo, PKG_FILES)
    extra = dict(PKG_FILES)
    extra['hack.py'] = b'print("pwned")\n'
    _sdist(repo, extra)
    _audit_fails_with(capsys, 'UNEXPECTED')


def test_fails_on_sdist_member_escaping_the_root(repo, capsys):
    # Path traversal: a member named `credactor-X/../payload.pth` starts with the
    # archive prefix as a raw string but normalizes outside the sdist root. A
    # startswith()-only check accepted it; it must be rejected as an escape.
    _wheel(repo, PKG_FILES)
    extra = dict(PKG_FILES)
    extra['../payload.pth'] = b'import os; os.system("id")\n'
    _sdist(repo, extra)
    _audit_fails_with(capsys, 'member escapes')


def test_fails_on_tampered_tracked_nonpackage_in_sdist(repo, capsys):
    # A tracked non-package file shipped in the sdist (here pyproject.toml) must
    # match HEAD byte-for-byte, not pass on its name alone: an sdist install builds
    # from its pyproject.toml, so a tampered build config (e.g. a malicious build
    # dependency) would otherwise build unreviewed.
    _wheel(repo, PKG_FILES)
    _sdist(repo, PKG_FILES, pyproject=b'[build-system]\nrequires = ["setuptools", "evil"]\n')
    _audit_fails_with(capsys, 'CONTENT MISMATCH')


def test_passes_on_matching_tracked_nonpackage_in_sdist(repo):
    # The byte-check must not over-reach: a tracked non-package file whose bytes
    # match HEAD still passes (the fixture commits this exact pyproject.toml).
    _wheel(repo, PKG_FILES)
    _sdist(repo, PKG_FILES)  # default pyproject/README match the committed bytes
    audit_wheel.audit('dist')  # no SystemExit means it passed


def test_fails_on_untracked_so_under_credactor_in_sdist(repo, capsys):
    # AW-1: a smuggled compiled extension under credactor/ must not pass the gate.
    _wheel(repo, PKG_FILES)
    extra = dict(PKG_FILES)
    extra['credactor/payload.so'] = b'\x7fELF\x02\x01\x01\x00'
    _sdist(repo, extra)
    _audit_fails_with(capsys, 'UNEXPECTED')


def test_fails_on_untracked_nested_so_under_credactor_in_sdist(repo, capsys):
    # AW-1: the strict check must also catch members nested below credactor/.
    _wheel(repo, PKG_FILES)
    extra = dict(PKG_FILES)
    extra['credactor/sub/payload.so'] = b'\x7fELF\x02\x01\x01\x00'
    _sdist(repo, extra)
    _audit_fails_with(capsys, 'UNEXPECTED')


def test_fails_on_pyc_under_credactor_in_sdist(repo, capsys):
    # AW-1: bytecode under credactor/ is rejected just as the wheel rejects it.
    _wheel(repo, PKG_FILES)
    extra = dict(PKG_FILES)
    extra['credactor/evil.pyc'] = b'\x00\x00\x00\x00bytecode'
    _sdist(repo, extra)
    _audit_fails_with(capsys, 'UNEXPECTED')


def test_fails_on_py_under_egg_info_in_sdist(repo, capsys):
    # AW-2: a hand-authored .py nested under an *.egg-info/ path must be flagged, not
    # exempted by an unanchored substring match.
    _wheel(repo, PKG_FILES)
    extra = dict(PKG_FILES)
    extra['credactor.egg-info/evil.py'] = b'print("pwned")\n'
    _sdist(repo, extra)
    _audit_fails_with(capsys, 'UNEXPECTED')


def test_fails_on_py_under_nested_egg_info_in_sdist(repo, capsys):
    # AW-2: the substring hole was exploitable at any depth under any *.egg-info dir.
    _wheel(repo, PKG_FILES)
    extra = dict(PKG_FILES)
    extra['x.egg-info/sub/evil.py'] = b'print("pwned")\n'
    _sdist(repo, extra)
    _audit_fails_with(capsys, 'UNEXPECTED')


def test_passes_on_benign_egg_info_metadata(repo):
    # AW-2 must not over-reach: genuine egg-info bookkeeping text files still pass.
    _wheel(repo, PKG_FILES)
    extra = dict(PKG_FILES)
    extra['credactor.egg-info/SOURCES.txt'] = b'credactor/__init__.py\ncredactor/core.py\n'
    extra['credactor.egg-info/top_level.txt'] = b'credactor\n'
    extra['credactor.egg-info/dependency_links.txt'] = b'\n'
    _sdist(repo, extra)
    audit_wheel.audit('dist')  # no SystemExit means it passed


def test_fails_on_missing_sdist(repo):
    _wheel(repo, PKG_FILES)
    with pytest.raises(SystemExit):
        audit_wheel.audit('dist')


def test_fails_on_empty_dist(repo):
    with pytest.raises(SystemExit):
        audit_wheel.audit('dist')


def test_fails_on_missing_dist_dir(repo):
    with pytest.raises(SystemExit):
        audit_wheel.audit('nonexistent')
