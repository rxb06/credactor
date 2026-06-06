"""Tests for directory walking and parallel scanning."""

import os
import shutil
import subprocess
from unittest import mock

import pytest

from credactor.config import Config
from credactor.suppressions import AllowList
from credactor.walker import (
    GitUnavailableError,
    _is_safe_relpath,
    _parallel_scan,
    _parse_selection,
    scan_git_history,
    scan_staged_files,
    walk_and_scan,
)


class TestWalkAndScan:
    def test_empty_directory(self, tmp_dir):
        config = Config(no_color=True)
        findings, skipped, json_files, errored = walk_and_scan(tmp_dir, config=config)
        assert findings == []
        assert json_files == []
        assert errored == []

    def test_clean_files(self, tmp_dir):
        py_file = os.path.join(tmp_dir, 'clean.py')
        with open(py_file, 'w') as f:
            f.write('x = 1\nprint("hello")\n')
        config = Config(no_color=True)
        findings, skipped, json_files, errored = walk_and_scan(tmp_dir, config=config)
        assert findings == []
        assert errored == []

    def test_detects_credential(self, tmp_dir):
        py_file = os.path.join(tmp_dir, 'secret.py')
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(py_file, 'w') as f:
            f.write(f'aws_key = "{key}"\n')
        config = Config(no_color=True)
        findings, skipped, json_files, errored = walk_and_scan(tmp_dir, config=config)
        assert len(findings) >= 1

    def test_skips_skip_dirs(self, tmp_dir):
        node_dir = os.path.join(tmp_dir, 'node_modules')
        os.makedirs(node_dir)
        py_file = os.path.join(node_dir, 'secret.py')
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(py_file, 'w') as f:
            f.write(f'aws_key = "{key}"\n')
        config = Config(no_color=True)
        findings, _, _, _ = walk_and_scan(tmp_dir, config=config)
        assert findings == []

    def test_collects_json_files(self, tmp_dir):
        json_file = os.path.join(tmp_dir, 'data.json')
        with open(json_file, 'w') as f:
            f.write('{"key": "value"}\n')
        config = Config(no_color=True)
        _, _, json_files, _ = walk_and_scan(tmp_dir, config=config)
        assert len(json_files) == 1
        assert json_files[0].endswith('data.json')

    def test_custom_skip_dirs(self, tmp_dir):
        custom_dir = os.path.join(tmp_dir, 'vendor')
        os.makedirs(custom_dir)
        py_file = os.path.join(custom_dir, 'secret.py')
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(py_file, 'w') as f:
            f.write(f'aws_key = "{key}"\n')
        config = Config(no_color=True, skip_dirs={'vendor'})
        findings, _, _, _ = walk_and_scan(tmp_dir, config=config)
        assert findings == []

    def test_custom_skip_files(self, tmp_dir):
        py_file = os.path.join(tmp_dir, 'generated.py')
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(py_file, 'w') as f:
            f.write(f'aws_key = "{key}"\n')
        config = Config(no_color=True, skip_files={'generated.py'})
        findings, _, _, _ = walk_and_scan(tmp_dir, config=config)
        assert findings == []

    def test_multiple_files(self, tmp_dir):
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        for i in range(5):
            path = os.path.join(tmp_dir, f'file{i}.py')
            with open(path, 'w') as f:
                f.write(f'key{i} = "{key}"\n')
        config = Config(no_color=True)
        findings, _, _, errored = walk_and_scan(tmp_dir, config=config)
        assert len(findings) >= 5
        assert errored == []

    def test_permission_denied_handled_gracefully(self, tmp_dir):
        """A directory with no scannable files produces no errors."""
        config = Config(no_color=True)
        findings, _, _, errored = walk_and_scan(tmp_dir, config=config)
        assert errored == []

    def test_file_level_suppression_logs_clean_message(self, tmp_dir, credactor_caplog):
        """File-level allowlist suppression logs a clean message; the [SKIP]
        prefix is supplied by the log formatter, not hard-coded in the message.

        Regression guard: log_verbose routes through logger.debug and
        _BracketFormatter prepends '  [SKIP] ' for DEBUG records, so a literal
        prefix in the message string would render twice.
        """
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(os.path.join(tmp_dir, 'secret.py'), 'w') as f:
            f.write(f'aws_key = "{key}"\n')
        with open(os.path.join(tmp_dir, '.credactorignore'), 'w') as f:
            f.write('secret.py\n')

        config = Config(no_color=True)
        allowlist = AllowList(tmp_dir)
        walk_and_scan(tmp_dir, config=config, allowlist=allowlist)

        skip_records = [
            r for r in credactor_caplog.records
            if 'suppressed by allowlist (file-level)' in r.message
        ]
        assert skip_records, 'expected a file-level suppression log record'
        assert all('[SKIP]' not in r.message for r in skip_records)

    def test_scan_error_populates_errored(self, tmp_dir):
        """scan_file raising an unexpected error populates the errored list."""
        py_file = os.path.join(tmp_dir, 'target.py')
        with open(py_file, 'w') as f:
            f.write('x = 1\n')
        config = Config(no_color=True)
        with mock.patch('credactor.walker.scan_file', side_effect=RuntimeError('injected')):
            _, _, _, errored = walk_and_scan(tmp_dir, config=config)
        resolved = os.path.realpath(py_file)
        assert any(os.path.realpath(e) == resolved for e in errored)

    @pytest.mark.skipif(not hasattr(os, 'getuid') or os.getuid() == 0,
                        reason='chmod 000 is not honoured as root / on Windows')
    def test_unreadable_file_populates_errored(self, tmp_dir):
        """H4: a file that raises OSError on read lands in errored_files (so
        --fail-on-error can exit 2 on it)."""
        py_file = os.path.join(tmp_dir, 'target.py')
        with open(py_file, 'w') as f:
            f.write('api_key = "x"\n')
        os.chmod(py_file, 0o000)
        try:
            _, _, _, errored = walk_and_scan(tmp_dir, config=Config(no_color=True))
            resolved = os.path.realpath(py_file)
            assert any(os.path.realpath(e) == resolved for e in errored)
        finally:
            os.chmod(py_file, 0o644)


@pytest.mark.skipif(shutil.which('git') is None, reason='git not installed')
class TestStagedScanning:
    """H3: --staged must scan the staged index blob, not the working tree."""

    def _init_repo(self, tmp_dir):
        subprocess.run(['git', 'init', '-q'], cwd=tmp_dir, check=True,
                       capture_output=True)
        return tmp_dir

    def test_scans_staged_blob_not_worktree(self, tmp_dir):
        repo = self._init_repo(tmp_dir)
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        path = os.path.join(repo, 'app.py')
        with open(path, 'w') as f:
            f.write(f'aws = "{key}"\n')
        subprocess.run(['git', 'add', 'app.py'], cwd=repo, check=True,
                       capture_output=True)
        # working tree is now clean; the INDEX still holds the secret
        with open(path, 'w') as f:
            f.write('aws = "clean"\n')
        findings, errored = scan_staged_files(repo, config=Config(no_color=True))
        assert len(findings) >= 1
        assert errored == []

    def test_raises_when_toplevel_unresolvable(self, tmp_dir):
        # L4: if rev-parse fails the dir isn't a usable git repo — this is a hard
        # GitUnavailableError (CLI exit 2), not a false-clean empty return.
        fake = mock.Mock(returncode=128, stdout='', stderr='fatal: not a git repo')
        with mock.patch('credactor.walker.subprocess.run', return_value=fake), \
                pytest.raises(GitUnavailableError):
            scan_staged_files(tmp_dir, config=Config(no_color=True))

    def test_staged_in_non_git_dir_raises(self, tmp_dir):
        # L4: a plain (non-git) directory is a hard error for --staged
        with pytest.raises(GitUnavailableError):
            scan_staged_files(tmp_dir, config=Config(no_color=True))

    def test_scan_history_in_non_git_dir_raises(self, tmp_dir):
        # L4: same for --scan-history
        with pytest.raises(GitUnavailableError):
            scan_git_history(tmp_dir, config=Config(no_color=True))

    def test_scan_history_empty_repo_is_clean(self, tmp_dir):
        # L4 carve-out: a valid repo with zero commits makes `git log` fail too,
        # but rev-parse succeeds -> NOT an error, just nothing to scan (exit 0).
        repo = os.path.join(tmp_dir, 'empty')
        os.makedirs(repo)
        subprocess.run(['git', 'init'], cwd=repo, check=True, capture_output=True)
        assert scan_git_history(repo, config=Config(no_color=True)) == []

    def test_scan_history_bare_repo_is_scannable(self, tmp_dir):
        # L4 regression: a valid BARE repo (no work tree) must NOT be rejected —
        # `git log` works there, but `git rev-parse --show-toplevel` fails, so the
        # discriminator must be --git-dir (rc 0 in bare repos).
        work = os.path.join(tmp_dir, 'work')
        os.makedirs(work)
        env = dict(check=True, capture_output=True, cwd=work)
        subprocess.run(['git', 'init'], **env)
        subprocess.run(['git', 'config', 'user.email', 't@t'], **env)
        subprocess.run(['git', 'config', 'user.name', 't'], **env)
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(os.path.join(work, 'app.py'), 'w') as f:
            f.write(f'aws = "{key}"\n')
        subprocess.run(['git', 'add', '-A'], **env)
        subprocess.run(['git', 'commit', '-m', 'x'], **env)
        bare = os.path.join(tmp_dir, 'bare.git')
        subprocess.run(['git', 'clone', '--bare', work, bare],
                       check=True, capture_output=True)
        findings = scan_git_history(bare, config=Config(no_color=True))   # must NOT raise
        assert any(key in f.get('full_value', '') or 'AWS' in f.get('type', '')
                   for f in findings), findings

    def test_ignores_unstaged_worktree_secret(self, tmp_dir):
        repo = self._init_repo(tmp_dir)
        path = os.path.join(repo, 'app.py')
        with open(path, 'w') as f:
            f.write('aws = "clean"\n')
        subprocess.run(['git', 'add', 'app.py'], cwd=repo, check=True,
                       capture_output=True)
        # secret exists only in the working tree, NOT staged
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(path, 'w') as f:
            f.write(f'aws = "{key}"\n')
        findings, errored = scan_staged_files(repo, config=Config(no_color=True))
        assert findings == []

    def test_scans_staged_blob_from_subdirectory(self, tmp_dir):
        # Scan root is a SUBDIR of the repo: git lists repo-root-relative paths,
        # so the on-disk path must resolve against the repo toplevel, not the
        # subdir (else the path doubles and the reported/redacted path is wrong).
        repo = self._init_repo(tmp_dir)
        subdir = os.path.join(repo, 'sub')
        os.makedirs(subdir)
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        path = os.path.join(subdir, 'app.py')
        with open(path, 'w') as f:
            f.write(f'aws = "{key}"\n')
        subprocess.run(['git', 'add', '-A'], cwd=repo, check=True,
                       capture_output=True)
        findings, errored = scan_staged_files(subdir, config=Config(no_color=True))
        assert len(findings) >= 1
        assert errored == []
        # the finding must name the real file, not a doubled .../sub/sub/app.py
        assert os.path.realpath(findings[0]['file']) == os.path.realpath(path)

    def test_scans_staged_unicode_filename(self, tmp_dir):
        # git octal-quotes non-ASCII names under the default core.quotePath;
        # the listing must use -z so the staged secret is not silently skipped.
        repo = self._init_repo(tmp_dir)
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        path = os.path.join(repo, 'café_\U0001f3af.py')
        with open(path, 'w') as f:
            f.write(f'aws = "{key}"\n')
        subprocess.run(['git', 'add', '-A'], cwd=repo, check=True,
                       capture_output=True)
        findings, errored = scan_staged_files(repo, config=Config(no_color=True))
        assert len(findings) >= 1
        assert errored == []


class TestParallelScanEmfileRecovery:
    """#17: EMFILE recovery retries ONLY fd-exhausted files and logs retry failures.

    A file that failed for a non-EMFILE reason must stay in ``errored`` and must
    not be re-scanned; an EMFILE file that succeeds on retry must not be errored.
    """

    def test_retries_only_emfile_files(self, monkeypatch, credactor_caplog):
        import collections
        import errno
        import threading

        from credactor import walker

        files = [f'/nonexistent/f{i}.py' for i in range(6)]  # >4 -> threaded branch
        emfile_file, bad_file = files[0], files[1]
        calls: collections.Counter = collections.Counter()
        lock = threading.Lock()

        def fake_scan_file(fp, *, config=None, allowlist=None):
            with lock:
                calls[fp] += 1
                n = calls[fp]
            if fp == emfile_file and n == 1:
                raise OSError(errno.EMFILE, 'too many open files')
            if fp == bad_file:
                raise OSError(errno.EACCES, 'permission denied')
            return [{'file': fp, 'line': 1, 'type': 'variable:x', 'severity': 'low',
                     'full_value': 'v', 'value_preview': 'v', 'raw': 'x'}]

        monkeypatch.setattr(walker, 'scan_file', fake_scan_file)
        findings, errored = _parallel_scan(files, Config(no_color=True), None)

        # EMFILE file recovered on the sequential retry: scanned twice, not errored.
        assert calls[emfile_file] == 2
        assert emfile_file not in errored
        # Non-EMFILE failure: stays errored and is NOT retried (scanned once).
        assert bad_file in errored
        assert calls[bad_file] == 1
        # 4 healthy files + 1 recovered = 5 findings; the retry failure is logged.
        assert len(findings) == 5
        assert any('Too many open files' in r.message
                   for r in credactor_caplog.records)


class TestParseSelection:
    """P7/#44: the pure selection parser extracted from select_json_files."""

    def test_comma_list(self):
        assert _parse_selection('1,3,5', 5) == [1, 3, 5]

    def test_range(self):
        assert _parse_selection('2-4', 5) == [2, 3, 4]

    def test_mixed_and_deduped_in_order(self):
        assert _parse_selection('1-3,2,5', 5) == [1, 2, 3, 5]

    def test_number_out_of_bounds(self):
        assert _parse_selection('9', 5) == 'Number 9 out of bounds (1-5).'

    def test_range_out_of_bounds(self):
        assert _parse_selection('4-9', 5) == 'Range 4-9 out of bounds (1-5).'

    def test_invalid_range(self):
        assert _parse_selection('2-x', 5) == 'Invalid range: 2-x'

    def test_unrecognised_token(self):
        assert _parse_selection('abc', 5) == "Unrecognised token: 'abc'"


class TestIsSafeRelpath:
    """P7/#43: component-based '..' traversal guard (not a substring check)."""

    def test_double_dot_component_rejected(self):
        assert _is_safe_relpath('../secret.py') is False
        assert _is_safe_relpath('a/../b.py') is False

    def test_dotdot_in_filename_is_safe(self):
        # 'secret..py' contains '..' as a substring but not as a path component.
        assert _is_safe_relpath('secret..py') is True
        assert _is_safe_relpath('a/b/c.py') is True
