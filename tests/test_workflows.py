"""Token and permission hygiene in the GitHub workflows (SR-29).

The workflows are read as indented text, since the test suite has no YAML
parser. The checks rely only on the two-space layout the files already use.
"""

import re
from pathlib import Path

import pytest

_DIR = Path(__file__).resolve().parent.parent / '.github' / 'workflows'
_WORKFLOWS = sorted(_DIR.glob('*.yml'))


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(' '))


def _block(lines: list[str], start: int) -> list[str]:
    """Return the lines nested under lines[start] (deeper indent, blanks kept)."""
    base = _indent(lines[start])
    out: list[str] = []
    for line in lines[start + 1 :]:
        if line.strip() and _indent(line) <= base:
            break
        out.append(line)
    return out


def _jobs(lines: list[str]) -> dict[str, list[str]]:
    """Map each job name to its lines."""
    start = lines.index('jobs:')
    jobs: dict[str, list[str]] = {}
    for i, line in enumerate(lines[start + 1 :], start + 1):
        match = re.fullmatch(r'  ([\w-]+):', line)
        if match:
            jobs[match.group(1)] = _block(lines, i)
    return jobs


def _permissions(lines: list[str], indent: int) -> dict[str, str] | None:
    """Return the permissions block at *indent* in *lines*, or None if absent.

    An inline value (``permissions: write-all``, or a flow mapping) is
    returned as ``{'*': value}``, which no check below accepts.
    """
    for i, line in enumerate(lines):
        key = ' ' * indent + 'permissions:'
        if line.startswith(key) and _indent(line) == indent:
            inline = line[len(key) :].split('#', 1)[0].strip()
            if inline:
                return {'*': inline}
            pairs = (entry.strip().split(':', 1) for entry in _block(lines, i) if entry.strip())
            return {key.strip(): value.strip() for key, value in pairs}
    return None


@pytest.mark.parametrize('workflow', _WORKFLOWS, ids=lambda p: p.name)
def test_every_checkout_drops_the_token(workflow):
    # No job pushes, so the checkout must not leave the token in .git/config.
    lines = workflow.read_text(encoding='utf-8').splitlines()
    checkouts = [i for i, line in enumerate(lines) if 'uses: actions/checkout@' in line]
    assert checkouts, f'{workflow.name}: no checkout step found'
    for i in checkouts:
        step = [entry.strip() for entry in _block(lines, i)]
        assert 'persist-credentials: false' in step, f'{workflow.name}:{i + 1}'


def test_ci_grants_only_read_at_the_top_level():
    lines = (_DIR / 'ci.yml').read_text(encoding='utf-8').splitlines()
    assert _permissions(lines, 0) == {'contents': 'read'}


def test_ci_grants_sarif_upload_to_the_self_scan_job_only():
    lines = (_DIR / 'ci.yml').read_text(encoding='utf-8').splitlines()
    jobs = _jobs(lines)
    assert 'self-scan' in jobs
    for name, body in jobs.items():
        perms = _permissions(body, 4) or {}
        if name == 'self-scan':
            assert perms == {'contents': 'read', 'actions': 'read', 'security-events': 'write'}
        else:
            assert all(value in {'read', 'none'} for value in perms.values()), (name, perms)


def test_publish_grants_only_what_trusted_publishing_needs():
    lines = (_DIR / 'publish.yml').read_text(encoding='utf-8').splitlines()
    assert _permissions(lines, 0) is None
    assert _permissions(_jobs(lines)['publish'], 4) == {
        'id-token': 'write',
        'attestations': 'write',
        'contents': 'read',
    }


@pytest.mark.parametrize('inline', ['write-all', '{ contents: write }'])
def test_an_inline_job_permission_is_caught(inline):
    # Guards the parser above: an inline value must not read as "no block".
    lines = ['jobs:', '  build:', f'    permissions: {inline}', '    runs-on: x']
    perms = _permissions(_jobs(lines)['build'], 4)
    assert perms == {'*': inline}
    assert not all(value in {'read', 'none'} for value in perms.values())


def _steps(job: list[str]) -> list[list[str]]:
    """Split a job's lines into its steps (each starts with '      - ')."""
    steps: list[list[str]] = []
    for line in job:
        if line.startswith('      - '):
            steps.append([line])
        elif steps and (not line.strip() or _indent(line) > 6):
            steps[-1].append(line)
    return steps


def _unguarded_multiline_runs(job: list[str]) -> list[str]:
    """Name each step whose run block has more than one line and no shell."""
    if not any('runs-on:' in line and ('windows' in line or '${{' in line) for line in job):
        return []  # a Linux or macOS runner already uses bash -e
    found = []
    for step in _steps(job):
        for i, line in enumerate(step):
            if line.strip() not in {'run: |', 'run: >'}:
                continue
            body = [entry for entry in _block(step, i) if entry.strip()]
            if len(body) > 1 and not any(entry.strip().startswith('shell:') for entry in step):
                found.append(step[0].strip())
    return found


@pytest.mark.parametrize('workflow', _WORKFLOWS, ids=lambda p: p.name)
def test_multiline_steps_that_may_run_on_windows_set_a_shell(workflow):
    # Under Windows' default pwsh, only the last line's exit code fails a
    # step, so an earlier failing command (pytest) passes unseen.
    lines = workflow.read_text(encoding='utf-8').splitlines()
    for name, job in _jobs(lines).items():
        assert _unguarded_multiline_runs(job) == [], name


def test_an_unguarded_windows_step_is_caught():
    # Guards the parser above.
    job = [
        '    runs-on: ${{ matrix.os }}',
        '    steps:',
        '      - name: Test',
        '        run: |',
        '          pytest',
        '          coverage report',
        '      - name: Fine',
        '        shell: bash',
        '        run: |',
        '          pytest',
        '          coverage report',
    ]
    assert _unguarded_multiline_runs(job) == ['- name: Test']
