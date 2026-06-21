"""Verify built artifacts (wheel and sdist) match the committed source exactly.

Run in CI on every push and again before the PyPI publish. Credactor ships a
package directory (`credactor/`), so this gate:

  * fails if `dist/` holds no wheel or no sdist (a vacuous pass is a failure);
  * checks the wheel contains exactly the `credactor/` package plus its
    `.dist-info`, and that no sdist member escapes the version directory;
  * compares every `credactor/` file in BOTH artifacts, byte for byte (sha256),
    against `git show HEAD:<path>`, so a build that injected or altered code is
    caught (a file-name check alone would miss an in-place edit);
  * confirms no tracked `credactor/` file is missing from either artifact, and
    no untracked `.py` rides along in the sdist.
"""

import hashlib
import os
import subprocess
import sys
import tarfile
import zipfile


def _head_state() -> tuple[dict[str, str], set[str]]:
    """Return (credactor/ path -> sha256 at HEAD, set of all tracked paths)."""
    listing = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', 'HEAD'], text=True)
    tracked = {p for p in listing.splitlines() if p}
    pkg = {
        p: hashlib.sha256(subprocess.check_output(['git', 'show', f'HEAD:{p}'])).hexdigest()
        for p in tracked
        if p.startswith('credactor/') and not p.endswith('.pyc')
    }
    return pkg, tracked


def _audit_wheel(path: str, pkg: dict[str, str]) -> list[str]:
    errors: list[str] = []
    name = os.path.basename(path)
    with zipfile.ZipFile(path) as z:
        members = {n for n in z.namelist() if not n.endswith('/')}
        pkg_files = {n for n in members if n.startswith('credactor/') and not n.endswith('.pyc')}
        # Metadata only (`credactor-X.dist-info/`): require the `.dist-info/` segment so a
        # smuggled top-level file sharing the `credactor-` prefix cannot ride the allowlist.
        dist_info = {n for n in members if n.startswith('credactor-') and '.dist-info/' in n}

        errors.extend(
            f'{name}: UNEXPECTED {extra}' for extra in sorted(members - pkg_files - dist_info)
        )
        errors.extend(
            f'{name}: MISSING FROM WHEEL {missing}' for missing in sorted(set(pkg) - pkg_files)
        )
        for f in sorted(pkg_files):
            if f not in pkg:
                errors.append(f'{name}: NOT IN REPO {f}')
            elif hashlib.sha256(z.read(f)).hexdigest() != pkg[f]:
                errors.append(f'{name}: CONTENT MISMATCH {f} (does not match HEAD)')
    return errors


def _audit_sdist(path: str, pkg: dict[str, str], tracked: set[str]) -> list[str]:
    errors: list[str] = []
    name = os.path.basename(path)
    base = name[: -len('.tar.gz')] if name.endswith('.tar.gz') else name
    prefix = f'{base}/'
    seen_pkg: set[str] = set()

    with tarfile.open(path) as t:
        for m in t.getmembers():
            if not (m.isfile() or m.isdir()):
                errors.append(f'{name}: non-regular member {m.name}')
                continue
            if m.name != base and not m.name.startswith(prefix):
                errors.append(f'{name}: member escapes {prefix}: {m.name}')
                continue
            if m.isdir():
                continue
            rel = m.name[len(prefix) :]
            if rel in pkg:
                seen_pkg.add(rel)
                extracted = t.extractfile(m)
                data = extracted.read() if extracted is not None else b''
                if hashlib.sha256(data).hexdigest() != pkg[rel]:
                    errors.append(f'{name}: CONTENT MISMATCH {rel} (does not match HEAD)')
            elif rel in tracked:
                # A legitimate tracked non-package file (pyproject, README, LICENSE, ...).
                continue
            elif rel.endswith('.py') and '.egg-info/' not in rel:
                errors.append(f'{name}: UNEXPECTED {rel}')
            # else: build-generated metadata (PKG-INFO, *.egg-info/, ...), allowed.
        errors.extend(
            f'{name}: MISSING FROM SDIST {missing}' for missing in sorted(set(pkg) - seen_pkg)
        )
    return errors


def audit(dist_dir: str = 'dist') -> None:
    try:
        entries = os.listdir(dist_dir)
    except FileNotFoundError:
        entries = []
    wheels = sorted(f for f in entries if f.endswith('.whl'))
    sdists = sorted(f for f in entries if f.endswith('.tar.gz'))

    errors: list[str] = []
    if not wheels:
        errors.append(f'no .whl file found in {dist_dir}')
    if not sdists:
        errors.append(f'no .tar.gz sdist found in {dist_dir}')

    pkg, tracked = _head_state()
    if not pkg:
        errors.append('HEAD has no tracked credactor/ files to audit against')

    for f in wheels:
        errors.extend(_audit_wheel(os.path.join(dist_dir, f), pkg))
    for f in sdists:
        errors.extend(_audit_sdist(os.path.join(dist_dir, f), pkg, tracked))

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
