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


def _sdist(repo: Path, files: dict[str, bytes], *, metadata: bool = True) -> Path:
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
            add('pyproject.toml', b'[project]\nname = "credactor"\n')
            add('README.md', b'# credactor\n')
    return path


def test_passes_on_matching_artifacts(repo):
    _wheel(repo, PKG_FILES)
    _sdist(repo, PKG_FILES)
    audit_wheel.audit('dist')  # no SystemExit means it passed


def test_fails_on_altered_wheel_content(repo):
    tampered = dict(PKG_FILES)
    tampered['credactor/core.py'] = b'def run():\n    return 666  # injected\n'
    _wheel(repo, tampered)
    _sdist(repo, PKG_FILES)
    with pytest.raises(SystemExit):
        audit_wheel.audit('dist')


def test_fails_on_injected_file_in_wheel(repo):
    extra = dict(PKG_FILES)
    extra['credactor/evil.py'] = b'print("pwned")\n'
    _wheel(repo, extra)
    _sdist(repo, PKG_FILES)
    with pytest.raises(SystemExit):
        audit_wheel.audit('dist')


def test_fails_on_missing_file_in_wheel(repo):
    _wheel(repo, {'credactor/__init__.py': PKG_FILES['credactor/__init__.py']})
    _sdist(repo, PKG_FILES)
    with pytest.raises(SystemExit):
        audit_wheel.audit('dist')


def test_fails_on_unexpected_toplevel_in_wheel(repo):
    smuggled = dict(PKG_FILES)
    smuggled['evil.py'] = b'print("pwned")\n'
    _wheel(repo, smuggled)
    _sdist(repo, PKG_FILES)
    with pytest.raises(SystemExit):
        audit_wheel.audit('dist')


def test_fails_on_altered_sdist_content(repo):
    _wheel(repo, PKG_FILES)
    tampered = dict(PKG_FILES)
    tampered['credactor/core.py'] = b'def run():\n    return 0  # injected\n'
    _sdist(repo, tampered)
    with pytest.raises(SystemExit):
        audit_wheel.audit('dist')


def test_fails_on_unexpected_py_in_sdist(repo):
    _wheel(repo, PKG_FILES)
    extra = dict(PKG_FILES)
    extra['hack.py'] = b'print("pwned")\n'
    _sdist(repo, extra)
    with pytest.raises(SystemExit):
        audit_wheel.audit('dist')


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
