"""Verify built artifacts (wheel and sdist) match the committed source exactly.

Run in CI on every push and again before the PyPI publish. Credactor ships a
single pure-Python package (``credactor/``) with no runtime dependencies and one
console script, so the legitimate contents of an artifact are a small, fixed,
knowable set. This gate enforces that set, failing closed on anything else:

  * fails unless ``dist/`` holds exactly one wheel and exactly one sdist (a
    vacuous pass is a failure);
  * compares every ``credactor/`` file in both artifacts, byte for byte (sha256),
    against its blob at the pinned HEAD commit, so a build that injected or
    altered code is caught (a file-name check alone would miss an in-place edit);
  * treats the wheel as a closed allowlist: every member must be a tracked
    ``credactor/`` file or one of the expected ``.dist-info`` files, and the
    ``.dist-info`` metadata that pip consumes is content-checked -- exactly one
    ``Name`` and one ``Version`` (equal to ``__version__`` at HEAD, the wheel file
    name and the sdist directory), ``Requires-Dist`` and ``Provides-Extra`` equal
    to what ``pyproject.toml`` at HEAD declares, the console entry point is
    unchanged, and a bundled licence matches HEAD -- so a build step cannot inject
    a dependency, repoint the entry point, or smuggle a ``.pth``/``.so``/module
    past the gate;
  * audits the sdist fail-closed: tracked files are byte-checked against HEAD,
    any untracked ``.py`` or ``credactor/`` member is rejected, and the only
    untracked members allowed are setuptools build metadata (``PKG-INFO``,
    ``setup.cfg``, ``*.egg-info/`` bookkeeping) -- the metadata checked as in the
    wheel, ``requires.txt`` against the same declared set, ``setup.cfg`` only as
    the exact bytes setuptools generates -- so the xz-style "fixture file in the
    tarball but not in git" class is rejected;
  * rejects duplicate archive members (a set collapses them and only one copy is
    hashed, so an evil-first/clean-last pair would otherwise pass) and any sdist
    member whose path escapes the version directory (tar-slip).

Scope limit: this proves ``artifact == HEAD``. It cannot prove ``HEAD`` itself is
trustworthy (malicious authorship), nor defend a fully compromised runner that
can patch this script or re-tamper ``dist/`` after the gate exits.
"""

import ast
import hashlib
import os
import posixpath
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from collections import Counter
from email.parser import HeaderParser
from typing import NamedTuple

try:
    from packaging.markers import Marker
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.utils import canonicalize_name
    from packaging.version import Version
except ImportError:  # pragma: no cover
    sys.exit('audit_wheel.py needs packaging: pip install --require-hashes -r requirements-ci.txt')

# Credactor's fixed identity. This gate audits Credactor's own artifacts, so the
# package name, console entry point, and top-level module are known constants.
PACKAGE = 'credactor'
EXPECTED_ENTRY_POINTS = '[console_scripts]\ncredactor = credactor.cli:main'
EXPECTED_TOP_LEVEL = PACKAGE

# The only files permitted inside the wheel's `credactor-<version>.dist-info/`
# directory. Anything else (a smuggled `.pth`, `.so`, or module) is rejected.
# Licence files under `dist-info/licenses/` are handled separately.
_WHEEL_DISTINFO_FILES = frozenset(
    {'METADATA', 'WHEEL', 'RECORD', 'entry_points.txt', 'top_level.txt'}
)

# The only setuptools bookkeeping files permitted inside the sdist's
# `credactor.egg-info/` directory.
_SDIST_EGGINFO_FILES = frozenset(
    {
        'PKG-INFO',
        'SOURCES.txt',
        'dependency_links.txt',
        'entry_points.txt',
        'requires.txt',
        'top_level.txt',
        'not-zip-safe',
        'namespace_packages.txt',
    }
)

# SR-28: the setup.cfg setuptools writes into every sdist. setuptools honours
# [options] in it at install time, so anything else is rejected. A setuptools
# pin bump that changes these bytes fails here, which is the intended outcome.
_GENERATED_SETUP_CFG = b'[egg_info]\ntag_build = \ntag_date = 0\n\n'


# A requirement in normalised form: name, extras, URL, specifier, marker.
_Key = tuple[str, tuple[str, ...], str, str, str]


class _Expected(NamedTuple):
    """What the metadata must say, derived from HEAD (SR-28)."""

    version: str
    requires: Counter[_Key]
    extras: Counter[str]


def _blob(commit: str, path: str) -> bytes:
    """Return the bytes of the file at *path* in *commit*."""
    return subprocess.check_output(['git', 'show', f'{commit}:{path}'])


def _blob_sha256(commit: str, path: str) -> str:
    """Return the sha256 of the file at *path* in *commit*."""
    return hashlib.sha256(_blob(commit, path)).hexdigest()


def _requirement_key(req: Requirement) -> _Key:
    """Return a normalised form of *req*, so equal requirements compare equal.
    Each part stays a separate field, so no two different requirements share one."""
    return (
        canonicalize_name(req.name),
        tuple(sorted(canonicalize_name(e) for e in req.extras)),
        req.url or '',
        str(req.specifier),
        str(req.marker) if req.marker is not None else '',
    )


def _show(key: _Key) -> str:
    """Render a normalised requirement for an error message."""
    name, extras, url, specifier, marker = key
    text = name + (f'[{",".join(extras)}]' if extras else '')
    text += f' @ {url}' if url else specifier
    return text + (f'; {marker}' if marker else '')


def _decode(label: str, data: bytes) -> tuple[str, list[str]]:
    """Decode metadata as pip does, strictly as UTF-8; a failure is an error."""
    try:
        return data.decode('utf-8'), []
    except UnicodeDecodeError as exc:
        return '', [f'{label}: NOT UTF-8 ({exc.reason} at byte {exc.start})']


def _has_line_break(value: str) -> bool:
    """Whether *value* holds a line break or any other line separator."""
    return value.splitlines() != ([value] if value else [])


def _gated(requirement: str, marker: str, extra: str) -> Requirement:
    """Parse *requirement*, gated on *marker* and on ``extra == "<extra>"``, joined
    the way setuptools writes them. Either may be empty."""
    clauses = []
    if marker:
        clauses.append(f'({marker})' if extra else marker)
    if extra:
        # packaging canonicalises the name in the marker (PEP 685).
        clauses.append(f'extra == "{extra}"')
    req = Requirement(requirement)
    if clauses:
        req.marker = Marker(' and '.join(clauses))
    return req


def _head_version(commit: str) -> str:
    """Return ``credactor.__version__`` at *commit*, PEP 440 normalised."""
    tree = ast.parse(_blob(commit, f'{PACKAGE}/__init__.py'))
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and [getattr(t, 'id', None) for t in node.targets] == ['__version__']
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            return str(Version(node.value.value))
    raise ValueError(f'no __version__ string in {PACKAGE}/__init__.py at {commit}')


def _expected_metadata(commit: str) -> _Expected:
    """Derive the expected version, dependencies and extras from HEAD (SR-28)."""
    project = tomllib.loads(_blob(commit, 'pyproject.toml').decode('utf-8'))['project']
    requires: Counter[_Key] = Counter(
        _requirement_key(Requirement(d)) for d in project.get('dependencies', [])
    )
    extras: Counter[str] = Counter()
    for extra, deps in project.get('optional-dependencies', {}).items():
        extras[canonicalize_name(extra)] += 1
        for dep in deps:
            req = Requirement(dep)
            marker = str(req.marker) if req.marker is not None else ''
            req.marker = None
            requires[_requirement_key(_gated(str(req), marker, extra))] += 1
    return _Expected(_head_version(commit), requires, extras)


def _head_state() -> tuple[dict[str, str], set[str], str]:
    """Return (credactor/ path -> sha256, all tracked paths, pinned commit sha).

    HEAD is resolved to a single commit sha once and used for every blob read, so
    the audit cannot straddle two refs if HEAD moves mid-run.
    """
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    listing = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', commit], text=True)
    tracked = {p for p in listing.splitlines() if p}
    pkg = {
        p: _blob_sha256(commit, p)
        for p in tracked
        if p.startswith(f'{PACKAGE}/') and not p.endswith('.pyc')
    }
    return pkg, tracked, commit


def _requirement_errors(
    label: str, found: list[Requirement | str], want: Counter[_Key]
) -> list[str]:
    """Compare *found* requirements with the expected multiset *want* (SR-28).

    A string in *found* describes an entry that is never expected.
    """
    errors: list[str] = []
    seen: Counter[_Key] = Counter()
    for req in found:
        if isinstance(req, str):
            errors.append(f'{label}: UNEXPECTED DEPENDENCY {req}')
        else:
            seen[_requirement_key(req)] += 1
    errors.extend(f'{label}: UNEXPECTED DEPENDENCY {_show(k)}' for k in sorted(seen - want))
    errors.extend(f'{label}: MISSING DEPENDENCY {_show(k)}' for k in sorted(want - seen))
    return errors


def _metadata_errors(label: str, data: bytes, expected: _Expected) -> list[str]:
    """Check Core Metadata (wheel METADATA / sdist PKG-INFO) against HEAD.

    SR-28: parsed as headers (case-insensitive names), with exactly one ``Name``
    and one ``Version``, and ``Requires-Dist`` and ``Provides-Extra`` equal to
    what pyproject.toml declares. Anything more would be installed by pip,
    anything less means the build is not what was reviewed.
    """
    text, errors = _decode(label, data)
    if errors:
        return errors
    msg = HeaderParser().parsestr(text)

    def values(field: str) -> list[str]:
        out: list[str] = []
        for value in map(str, msg.get_all(field) or []):
            # setuptools never folds these fields and pip does not unfold
            # them, so a value over several lines is rejected, not joined.
            if _has_line_break(value):
                errors.append(f'{label}: LINE BREAK IN {field} {value!r}')
            else:
                out.append(value.strip())
        return out

    names = values('Name')
    if names != [PACKAGE]:
        errors.append(f'{label}: NAME MISMATCH {names!r} (expected exactly [{PACKAGE!r}])')
    versions = values('Version')
    if versions != [expected.version]:
        errors.append(
            f'{label}: VERSION MISMATCH {versions!r} (expected exactly [{expected.version!r}])'
        )
    extras = Counter(canonicalize_name(e) for e in values('Provides-Extra'))
    if extras != expected.extras:
        errors.append(
            f'{label}: EXTRAS MISMATCH {sorted(extras.elements())} '
            f'(expected {sorted(expected.extras.elements())})'
        )
    found: list[Requirement | str] = []
    for value in values('Requires-Dist'):
        try:
            found.append(Requirement(value))
        except InvalidRequirement:
            found.append(f'{value!r} (does not parse)')
    errors.extend(_requirement_errors(label, found, expected.requires))
    return errors


def _requires_txt_errors(label: str, data: bytes, expected: _Expected) -> list[str]:
    """Check an egg-info ``requires.txt`` against the declared dependencies (SR-28).

    Requirements before the first section are unconditional; a ``[extra]``,
    ``[extra:marker]`` or ``[:marker]`` section gates the ones below it. Each is
    turned back into a ``Requires-Dist`` form and the set must match exactly.
    setuptools writes a marker only in the section header, never on the line.
    """
    text, errors = _decode(label, data)
    if errors:
        return errors
    section = ''
    found: list[Requirement | str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith('[') and stripped.endswith(']'):
            section = stripped[1:-1]
            continue
        extra, _, marker = section.partition(':')
        try:
            if Requirement(stripped).marker is not None:
                found.append(f'{stripped!r} under [{section}] (a marker on the line)')
                continue
            found.append(_gated(stripped, marker, extra))
        except InvalidRequirement:
            found.append(f'{stripped!r} under [{section}] (does not parse)')
    return _requirement_errors(label, found, expected.requires)


def _wheel_version(filename: str) -> str:
    """Return the version field of a wheel filename, or '' if not parseable.

    Wheel names are ``{name}-{version}(-{build})?-{py}-{abi}-{platform}.whl``;
    a PEP 440 version never contains '-', so the second field is the version.
    """
    stem = filename[:-4] if filename.endswith('.whl') else filename
    parts = stem.split('-')
    return parts[1] if len(parts) >= 2 else ''


def _audit_wheel_distinfo(
    name: str,
    z: zipfile.ZipFile,
    distinfo: str,
    members: set[str],
    commit: str,
    tracked: set[str],
    expected: _Expected,
) -> list[str]:
    """Content-check the wheel's `.dist-info` against an allowlist (fail-closed)."""
    errors: list[str] = []
    if f'{distinfo}METADATA' not in members:
        errors.append(f'{name}: MISSING METADATA {distinfo}METADATA')
    for member in sorted(members):
        rel = member[len(distinfo) :]
        if rel == 'METADATA':
            errors.extend(_metadata_errors(f'{name}:{rel}', z.read(member), expected))
        elif rel == 'entry_points.txt':
            if z.read(member).decode('utf-8', 'replace').strip() != EXPECTED_ENTRY_POINTS:
                errors.append(f'{name}: ENTRY POINTS ALTERED {rel}')
        elif rel == 'top_level.txt':
            if z.read(member).decode('utf-8', 'replace').strip() != EXPECTED_TOP_LEVEL:
                errors.append(f'{name}: TOP LEVEL ALTERED {rel}')
        elif rel in _WHEEL_DISTINFO_FILES:
            # WHEEL and RECORD carry no executable code; the closed member set
            # already bounds what can ship, so they are allowed without parsing.
            continue
        elif rel.startswith('licenses/'):
            licence = rel[len('licenses/') :]
            if licence not in tracked:
                errors.append(f'{name}: UNEXPECTED {member}')
            elif hashlib.sha256(z.read(member)).hexdigest() != _blob_sha256(commit, licence):
                errors.append(f'{name}: CONTENT MISMATCH {member} (does not match HEAD)')
        else:
            errors.append(f'{name}: UNEXPECTED {member}')
    return errors


def _audit_wheel(
    path: str, pkg: dict[str, str], tracked: set[str], commit: str, expected: _Expected
) -> list[str]:
    """Verify a wheel: package files match HEAD, dist-info is an allowlist."""
    errors: list[str] = []
    name = os.path.basename(path)
    if not name.startswith(f'{PACKAGE}-'):
        return [f'{name}: unexpected wheel name (does not start with {PACKAGE}-)']
    version = _wheel_version(name)
    if version != expected.version:
        errors.append(f'{name}: VERSION MISMATCH in file name (expected {expected.version!r})')
    distinfo = f'{PACKAGE}-{version}.dist-info/'

    with zipfile.ZipFile(path) as z:
        names = [i.filename for i in z.infolist() if not i.filename.endswith('/')]
        # A duplicate member name collapses in a set and `z.read()` returns only
        # the last entry, so an evil-first/clean-last pair would pass unseen.
        duplicates = sorted({n for n in names if names.count(n) > 1})
        errors.extend(f'{name}: DUPLICATE MEMBER {d}' for d in duplicates)

        members = set(names)
        pkg_files = {n for n in members if n.startswith(f'{PACKAGE}/') and not n.endswith('.pyc')}
        # Anchor to the exact `credactor-<version>.dist-info/` first segment: an
        # unanchored substring match would trust any path merely containing
        # `.dist-info/` mid-name (e.g. `...data/x.dist-info/evil`, traversal).
        distinfo_members = {n for n in members if n.startswith(distinfo)}

        # Everything that is neither a package file nor an anchored dist-info
        # member is unexpected: top-level smuggling, `.data/` payloads, zip-slip.
        errors.extend(
            f'{name}: UNEXPECTED {extra}'
            for extra in sorted(members - pkg_files - distinfo_members)
        )
        errors.extend(
            f'{name}: MISSING FROM WHEEL {missing}' for missing in sorted(set(pkg) - pkg_files)
        )
        for f in sorted(pkg_files):
            if f not in pkg:
                errors.append(f'{name}: NOT IN REPO {f}')
            elif hashlib.sha256(z.read(f)).hexdigest() != pkg[f]:
                errors.append(f'{name}: CONTENT MISMATCH {f} (does not match HEAD)')

        errors.extend(
            _audit_wheel_distinfo(name, z, distinfo, distinfo_members, commit, tracked, expected)
        )
    return errors


def _read_member(t: tarfile.TarFile, m: tarfile.TarInfo) -> bytes:
    """Return the bytes of a regular-file tar member.

    Callers filter to regular files first, so ``extractfile`` returns a stream;
    a ``None`` here means that guard was removed, so raise loudly rather than
    silently hash empty bytes (which could spoof an empty tracked file).
    """
    extracted = t.extractfile(m)
    if extracted is None:
        raise ValueError(f'cannot read tar member {m.name}')
    return extracted.read()


def _sdist_buildmeta_errors(name: str, rel: str, data: bytes, expected: _Expected) -> list[str]:
    """Classify an untracked, non-package sdist member, fail-closed.

    The only untracked members an sdist legitimately ships are setuptools build
    metadata; the dependency-bearing ones are content-checked. Everything else
    (the xz fixture class: untracked ``.sh``/``.so``/``.m4``) is rejected.
    """
    base = posixpath.basename(rel)
    if rel == 'PKG-INFO':
        return _metadata_errors(f'{name}:{rel}', data, expected)
    if rel == 'setup.cfg':
        # SR-28: setuptools reads [options] from it, so only the generated bytes pass.
        if data != _GENERATED_SETUP_CFG:
            return [f'{name}: SETUP.CFG ALTERED {rel} (differs from what setuptools generates)']
        return []
    if rel.startswith(f'{PACKAGE}.egg-info/') and base in _SDIST_EGGINFO_FILES:
        if base == 'PKG-INFO':
            return _metadata_errors(f'{name}:{rel}', data, expected)
        if base == 'entry_points.txt':
            if data.decode('utf-8', 'replace').strip() != EXPECTED_ENTRY_POINTS:
                return [f'{name}: ENTRY POINTS ALTERED {rel}']
            return []
        if base == 'requires.txt':
            return _requires_txt_errors(f'{name}:{rel}', data, expected)
        # SOURCES.txt, dependency_links.txt, top_level.txt: inert bookkeeping.
        return []
    return [f'{name}: UNEXPECTED {rel}']


def _audit_sdist(
    path: str, pkg: dict[str, str], tracked: set[str], commit: str, expected: _Expected
) -> list[str]:
    """Verify an sdist: tracked files match HEAD, untracked allowed only if metadata."""
    errors: list[str] = []
    name = os.path.basename(path)
    base = name[: -len('.tar.gz')] if name.endswith('.tar.gz') else name
    if base != f'{PACKAGE}-{expected.version}':
        errors.append(f'{name}: VERSION MISMATCH in file name (expected {expected.version!r})')
    prefix = f'{base}/'
    seen_pkg: set[str] = set()
    has_pkg_info = False

    with tarfile.open(path) as t:
        members = t.getmembers()
        file_names = [m.name for m in members if m.isfile()]
        duplicates = sorted({n for n in file_names if file_names.count(n) > 1})
        errors.extend(f'{name}: DUPLICATE MEMBER {d}' for d in duplicates)

        for m in members:
            if not (m.isfile() or m.isdir()):
                errors.append(f'{name}: non-regular member {m.name}')
                continue
            # Normalize before the containment check: a raw startswith() accepts a
            # crafted `credactor-X/../evil` member whose normalized path escapes
            # the sdist root (tar-slip). Tar names are always forward-slash, so
            # posixpath.normpath is correct on every platform.
            norm = posixpath.normpath(m.name)
            if norm != base and not norm.startswith(prefix):
                errors.append(f'{name}: member escapes {prefix}: {m.name}')
                continue
            if m.isdir():
                continue
            rel = norm[len(prefix) :]
            if rel in pkg:
                seen_pkg.add(rel)
                if hashlib.sha256(_read_member(t, m)).hexdigest() != pkg[rel]:
                    errors.append(f'{name}: CONTENT MISMATCH {rel} (does not match HEAD)')
            elif rel.startswith(f'{PACKAGE}/'):
                # Inside the package directory but not a tracked package file: a
                # smuggled .so/.pyc/data file, as strict as the wheel.
                errors.append(f'{name}: UNEXPECTED {rel}')
            elif rel.endswith('.py'):
                # A real egg-info dir ships only bookkeeping text, never a module.
                errors.append(f'{name}: UNEXPECTED {rel}')
            elif rel in tracked:
                # A tracked non-package file (pyproject.toml, README, LICENSE).
                # Byte-check it against HEAD, not just its name: an sdist install
                # builds from its pyproject.toml, so a tampered build config must
                # not ride along unreviewed.
                if hashlib.sha256(_read_member(t, m)).hexdigest() != _blob_sha256(commit, rel):
                    errors.append(f'{name}: CONTENT MISMATCH {rel} (does not match HEAD)')
            else:
                has_pkg_info = has_pkg_info or rel == 'PKG-INFO'
                errors.extend(_sdist_buildmeta_errors(name, rel, _read_member(t, m), expected))
        if not has_pkg_info:
            errors.append(f'{name}: MISSING METADATA PKG-INFO')
        errors.extend(
            f'{name}: MISSING FROM SDIST {missing}' for missing in sorted(set(pkg) - seen_pkg)
        )
    return errors


def audit(dist_dir: str = 'dist') -> None:
    """Audit the wheel and sdist in *dist_dir*; print and exit 1 on any error."""
    try:
        entries = os.listdir(dist_dir)
    except FileNotFoundError:
        entries = []
    wheels = sorted(f for f in entries if f.endswith('.whl'))
    sdists = sorted(f for f in entries if f.endswith('.tar.gz'))

    errors: list[str] = []
    if len(wheels) != 1:
        errors.append(f'expected exactly one .whl in {dist_dir}, found {len(wheels)}')
    if len(sdists) != 1:
        errors.append(f'expected exactly one .tar.gz sdist in {dist_dir}, found {len(sdists)}')

    pkg, tracked, commit = _head_state()
    if not pkg:
        errors.append('HEAD has no tracked credactor/ files to audit against')
    expected = _expected_metadata(commit)

    for f in wheels:
        errors.extend(_audit_wheel(os.path.join(dist_dir, f), pkg, tracked, commit, expected))
    for f in sdists:
        errors.extend(_audit_sdist(os.path.join(dist_dir, f), pkg, tracked, commit, expected))

    if errors:
        for e in errors:
            print(f'::error::{e}', file=sys.stderr)
        sys.exit(1)
    print(
        f'Artifact audit passed: {len(wheels)} wheel(s), {len(sdists)} sdist(s); '
        f'{len(pkg)} credactor/ files match HEAD'
    )


if __name__ == '__main__':
    audit(sys.argv[1] if len(sys.argv) > 1 else 'dist')
