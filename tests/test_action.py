"""The GitHub Action's scan step, run locally under bash (SR-03, SR-04).

The action-selftest CI job runs the whole action on real runners, but a step
that fails there shows only as a failed step: its exit code and the lines it
wrote to $GITHUB_OUTPUT are not visible to later steps. These tests take the
"Run Credactor" step's script out of action.yml and run it the way the runner
does (bash --noprofile --norc -eo pipefail), so a refusal can be asserted as
exit 2 with nothing written, and every run as writing exit-code once, last.

action.yml is read as indented text, since the test suite has no YAML parser.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import credactor

pytestmark = [
    pytest.mark.skipif(sys.platform == 'win32', reason='POSIX shell and symlink fixtures'),
    pytest.mark.skipif(shutil.which('bash') is None, reason='bash is not installed'),
]

_ACTION = Path(__file__).resolve().parent.parent / 'action.yml'
# The stand-in for the console script runs the package these tests imported,
# installed or not.
_PACKAGE_ROOT = str(Path(credactor.__file__).resolve().parent.parent)
_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'


def _scan_script() -> str:
    """Return the run block of the step with id 'scan', dedented."""
    lines = _ACTION.read_text(encoding='utf-8').splitlines()
    start = lines.index('      id: scan')
    run = lines.index('      run: |', start)
    body: list[str] = []
    for line in lines[run + 1 :]:
        if line.strip() and not line.startswith(' ' * 8):
            break
        body.append(line[8:])
    return '\n'.join(body) + '\n'


_SCRIPT = _scan_script()

_DEFAULT_INPUTS = {
    'TARGET': '.',
    'FORMAT': 'json',
    'OUTPUT_FILE': '',
    'FAIL_ON_ERROR': 'false',
    'SCAN_JSON': 'false',
    'SCAN_HISTORY': 'false',
    'CONFIG_PATH': '',
    'VERBOSE': 'false',
    'FROM_GITLEAKS': '',
    'FROM_TRUFFLEHOG': '',
    'FROM_BETTERLEAKS': '',
    'EXTRA_ARGS': '',
}


class _Runner:
    def __init__(self, tmp_path: Path) -> None:
        self.workspace = tmp_path / 'workspace'
        self.workspace.mkdir()
        self.temp = tmp_path / 'runner-temp'
        self.temp.mkdir()
        self.outside = tmp_path / 'outside'
        self.outside.mkdir()
        self.output = tmp_path / 'github-output'
        self.summary = tmp_path / 'step-summary'
        self.bin = tmp_path / 'bin'
        self.bin.mkdir()
        # The installed console script, as the install step leaves it on PATH.
        # Each call is logged, so a refusal can be shown to come before the scan.
        self.calls = tmp_path / 'credactor-calls'
        self.stub_credactor(
            f'echo call >> "{self.calls}"\nexec "{sys.executable}" -m credactor "$@"'
        )
        script = tmp_path / 'scan-step.sh'
        script.write_text(_SCRIPT, encoding='utf-8')
        self.script = script

    def stub_credactor(self, body: str) -> None:
        stub = self.bin / 'credactor'
        stub.write_text(f'#!/bin/sh\n{body}\n', encoding='utf-8')
        stub.chmod(0o755)

    def run(self, cwd: Path | None = None, **inputs: str) -> int:
        self.output.write_text('', encoding='utf-8')
        self.calls.unlink(missing_ok=True)
        cwd = cwd or self.workspace
        env = {
            # The logical path, as a shell that changed into it would have.
            'PWD': str(cwd),
            'PATH': os.pathsep.join(
                [str(self.bin), str(Path(sys.executable).parent), os.environ.get('PATH', '')]
            ),
            'HOME': os.environ.get('HOME', str(self.temp)),
            'PYTHONPATH': _PACKAGE_ROOT,
            'GITHUB_OUTPUT': str(self.output),
            'GITHUB_STEP_SUMMARY': str(self.summary),
            'GITHUB_WORKSPACE': str(self.workspace),
            'RUNNER_TEMP': str(self.temp),
            **_DEFAULT_INPUTS,
            **inputs,
        }
        proc = subprocess.run(
            ['bash', '--noprofile', '--norc', '-eo', 'pipefail', str(self.script)],
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.stdout = proc.stdout
        return proc.returncode

    def scanned(self) -> bool:
        return self.calls.exists()

    def assert_refused(self) -> None:
        # Exit 2 before the scan, with nothing written to $GITHUB_OUTPUT.
        assert not self.scanned()
        assert self.outputs() == []

    def outputs(self) -> list[str]:
        return self.output.read_text(encoding='utf-8').splitlines()

    def assert_exit_code_once_and_last(self, expected: str) -> None:
        lines = self.outputs()
        codes = [line for line in lines if line.startswith('exit-code=')]
        assert codes == [f'exit-code={expected}'], lines
        assert lines[-1] == f'exit-code={expected}', lines


@pytest.fixture
def runner(tmp_path: Path) -> _Runner:
    return _Runner(tmp_path)


class TestOutputs:
    def test_findings_are_reported_with_exit_code_last(self, runner: _Runner) -> None:
        (runner.workspace / 'app.py').write_text(f'api_key = "{_KEY}"\n', encoding='utf-8')
        assert runner.run() == 0
        runner.assert_exit_code_once_and_last('1')
        lines = runner.outputs()
        assert 'findings-count=1' in lines
        report = runner.workspace / 'credactor-results.json'
        assert f'report-file={os.path.realpath(report)}' in lines

    def test_clean_tree_writes_exit_code_zero_once(self, runner: _Runner) -> None:
        (runner.workspace / 'app.py').write_text('x = 1\n', encoding='utf-8')
        assert runner.run(FORMAT='sarif') == 0
        runner.assert_exit_code_once_and_last('0')
        assert 'findings-count=0' in runner.outputs()

    def test_exit_1_without_a_report_is_an_error(self, runner: _Runner) -> None:
        # A crash also exits 1; with no valid report it is not a findings result.
        runner.stub_credactor('echo boom >&2; exit 1')
        assert runner.run() == 0
        runner.assert_exit_code_once_and_last('2')

    def test_extra_args_line_breaks_become_spaces(self, runner: _Runner) -> None:
        (runner.workspace / 'app.py').write_text('x = 1\n', encoding='utf-8')
        assert runner.run(EXTRA_ARGS='--verbose\n--scan-json\n') == 0
        runner.assert_exit_code_once_and_last('0')
        assert '--verbose --scan-json' in runner.stdout


class TestLineBreaksRefused:
    @pytest.mark.parametrize(
        'name',
        [
            'FORMAT',
            'TARGET',
            'OUTPUT_FILE',
            'CONFIG_PATH',
            'FROM_GITLEAKS',
            'FROM_TRUFFLEHOG',
            'FROM_BETTERLEAKS',
        ],
    )
    @pytest.mark.parametrize('brk', ['\n', '\r'])
    def test_input_with_a_line_break_exits_2_before_any_output(
        self, runner: _Runner, name: str, brk: str
    ) -> None:
        (runner.workspace / 'app.py').write_text(f'api_key = "{_KEY}"\n', encoding='utf-8')
        value = {'FORMAT': 'json'}.get(name, 'report.json') + f'{brk}exit-code=0'
        if name != 'FORMAT':
            # The named file exists, so only the line-break check can refuse it.
            (runner.workspace / value).write_text('[]\n', encoding='utf-8')
        before = sorted(p.name for p in runner.workspace.iterdir())
        assert runner.run(**{name: value}) == 2
        runner.assert_refused()
        assert sorted(p.name for p in runner.workspace.iterdir()) == before

    def test_working_directory_resolving_to_a_line_break_exits_2(self, runner: _Runner) -> None:
        odd = runner.workspace / 'odd\nname'
        odd.mkdir()
        (odd / 'app.py').write_text('x = 1\n', encoding='utf-8')
        link = runner.workspace / 'plain'
        link.symlink_to(odd)
        assert runner.run(cwd=link) == 2
        runner.assert_refused()


class TestReportDestinationRefused:
    def test_report_name_linked_to_a_scanned_file(self, runner: _Runner) -> None:
        app = runner.workspace / 'app.py'
        app.write_text(f'api_key = "{_KEY}"\n', encoding='utf-8')
        before = app.read_bytes()
        link = runner.workspace / 'credactor-results.sarif'
        link.symlink_to('app.py')
        assert runner.run(FORMAT='sarif') == 2
        runner.assert_refused()
        assert app.read_bytes() == before
        assert link.is_symlink()

    def test_report_name_linked_to_a_file_outside(self, runner: _Runner) -> None:
        (runner.workspace / 'app.py').write_text(f'api_key = "{_KEY}"\n', encoding='utf-8')
        canary = runner.outside / 'canary.txt'
        canary.write_bytes(b'canary\n')
        link = runner.workspace / 'credactor-results.json'
        link.symlink_to(canary)
        assert runner.run() == 2
        runner.assert_refused()
        assert canary.read_bytes() == b'canary\n'
        assert link.is_symlink()

    def test_report_path_through_a_directory_link_out(self, runner: _Runner) -> None:
        (runner.workspace / 'app.py').write_text(f'api_key = "{_KEY}"\n', encoding='utf-8')
        (runner.workspace / 'escape').symlink_to(runner.outside)
        assert runner.run(OUTPUT_FILE='escape/out.json') == 2
        runner.assert_refused()
        assert list(runner.outside.iterdir()) == []

    def test_report_path_outside_the_workspace(self, runner: _Runner) -> None:
        (runner.workspace / 'app.py').write_text(f'api_key = "{_KEY}"\n', encoding='utf-8')
        assert runner.run(OUTPUT_FILE='../outside/out.json') == 2
        runner.assert_refused()
        assert list(runner.outside.iterdir()) == []

    def test_report_name_that_is_a_directory(self, runner: _Runner) -> None:
        (runner.workspace / 'app.py').write_text(f'api_key = "{_KEY}"\n', encoding='utf-8')
        (runner.workspace / 'credactor-results.json').mkdir()
        assert runner.run() == 2
        runner.assert_refused()

    def test_report_in_runner_temp_is_allowed(self, runner: _Runner) -> None:
        (runner.workspace / 'app.py').write_text(f'api_key = "{_KEY}"\n', encoding='utf-8')
        dest = runner.temp / 'reports' / 'out.json'
        assert runner.run(OUTPUT_FILE=str(dest)) == 0
        runner.assert_exit_code_once_and_last('1')
        assert f'report-file={os.path.realpath(dest)}' in runner.outputs()
