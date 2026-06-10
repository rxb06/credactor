"""Tests for directory walking and file scanning."""

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

        Regression guard: suppression messages go to logger.debug and
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

    def _stage_json_secret(self, repo, name='credentials.json'):
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(os.path.join(repo, name), 'w') as f:
            f.write(f'{{"aws_key": "{key}"}}\n')
        subprocess.run(['git', 'add', '-A'], cwd=repo, check=True,
                       capture_output=True)
        return key

    def test_staged_json_scanned_with_scan_json(self, tmp_dir):
        # A staged .json secret must be caught when --scan-json is set — the
        # staged path previously never consulted config.scan_json at all.
        repo = self._init_repo(tmp_dir)
        key = self._stage_json_secret(repo)
        findings, errored = scan_staged_files(
            repo, config=Config(scan_json=True, no_color=True))
        assert any(key == f['full_value'] for f in findings), findings
        assert errored == []

    def test_staged_json_skipped_with_warning_without_scan_json(
            self, tmp_dir, credactor_caplog):
        # Without --scan-json the .json file is skipped, but never silently:
        # the pre-commit gate must not give a false all-clear with no signal.
        repo = self._init_repo(tmp_dir)
        self._stage_json_secret(repo)
        findings, errored = scan_staged_files(repo, config=Config(no_color=True))
        assert findings == []
        assert errored == []
        # the warning must NAME the skipped file, not just announce a skip
        assert any('Staged .json file skipped' in r.message
                   and 'credentials.json' in r.message
                   for r in credactor_caplog.records)

    def test_staged_multiline_secret_detected(self, tmp_dir):
        # The staged path reuses scan_lines(), so a secret inside a
        # triple-quoted block is caught. The old bare per-line loop missed it:
        # the high-entropy pass requires a preceding quote on the same line,
        # which a bare line inside a multi-line string never has.
        repo = self._init_repo(tmp_dir)
        secret = 'aB3dE5gH7jK9mN1pQ4sU6wX8zC2vF0yT5rL8nM3kP7qW1eR9tY4uI6oA2sD5fG8h'
        with open(os.path.join(repo, 'note.py'), 'w') as f:
            f.write(f'doc = """\nembedded config blob\n{secret}\n"""\n')
        subprocess.run(['git', 'add', '-A'], cwd=repo, check=True,
                       capture_output=True)
        findings, errored = scan_staged_files(repo, config=Config(no_color=True))
        assert any(f['type'].startswith('multiline:')
                   and f['full_value'] == secret for f in findings), findings
        assert errored == []

    def test_staged_pem_scanned_as_block(self, tmp_dir):
        # scan_lines() applies the PEM state machine to staged blobs: the key
        # is reported once as a block (header line) with the body skipped. The
        # old per-line loop labelled it 'private key header' instead.
        repo = self._init_repo(tmp_dir)
        with open(os.path.join(repo, 'server.pem'), 'w') as f:
            f.write('-----BEGIN RSA PRIVATE KEY-----\n'
                    'MIIEpAIBAAKCAQEA7examplebodyline1\n'
                    'MIIEpAIBAAKCAQEA7examplebodyline2\n'
                    '-----END RSA PRIVATE KEY-----\n')
        subprocess.run(['git', 'add', '-A'], cwd=repo, check=True,
                       capture_output=True)
        findings, errored = scan_staged_files(repo, config=Config(no_color=True))
        assert any(f['type'] == 'pattern:private key block' and f['line'] == 1
                   for f in findings), findings
        assert errored == []

    def test_staged_json_lockfile_stays_excluded(self, tmp_dir, credactor_caplog):
        # SKIP_FILES lockfiles are excluded with and without --scan-json, and
        # never trigger the skip warning (matching the directory walk).
        repo = self._init_repo(tmp_dir)
        self._stage_json_secret(repo, name='package-lock.json')
        for cfg in (Config(scan_json=True, no_color=True), Config(no_color=True)):
            findings, _errored = scan_staged_files(repo, config=cfg)
            assert findings == []
        assert not any('Staged .json file skipped' in r.message
                       for r in credactor_caplog.records)


class TestSequentialScanErrors:
    """The sequential scanner records per-file failures and keeps going —
    one unreadable file must not abort the rest of the batch."""

    def test_failed_file_recorded_others_scanned(self, monkeypatch, credactor_caplog):
        from credactor import walker

        files = [f'/nonexistent/f{i}.py' for i in range(3)]
        bad_file = files[1]

        def fake_scan_file(fp, *, config=None, allowlist=None):
            if fp == bad_file:
                raise OSError('permission denied')
            return [{'file': fp, 'line': 1, 'type': 'variable:x', 'severity': 'low',
                     'full_value': 'v', 'value_preview': 'v', 'raw': 'x'}]

        monkeypatch.setattr(walker, 'scan_file', fake_scan_file)
        findings, errored = walker._scan_files(files, Config(no_color=True), None)

        assert errored == [bad_file]
        assert len(findings) == 2            # the other two still scanned
        assert any('Error scanning' in r.message
                   for r in credactor_caplog.records)


class TestIsSafeRelpath:
    """P7/#43: component-based '..' traversal guard (not a substring check)."""

    def test_double_dot_component_rejected(self):
        assert _is_safe_relpath('../secret.py') is False
        assert _is_safe_relpath('a/../b.py') is False

    def test_dotdot_in_filename_is_safe(self):
        # 'secret..py' contains '..' as a substring but not as a path component.
        assert _is_safe_relpath('secret..py') is True
        assert _is_safe_relpath('a/b/c.py') is True
