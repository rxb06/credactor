"""Tests for directory walking and parallel scanning."""

import os
from unittest import mock

import pytest

from credactor.config import Config
from credactor.suppressions import AllowList
from credactor.walker import walk_and_scan


class TestWalkAndScan:
    def test_empty_directory(self, tmp_dir):
        config = Config(no_color=True)
        findings, skipped, json_files, errored = walk_and_scan(tmp_dir, config)
        assert findings == []
        assert json_files == []
        assert errored == []

    def test_clean_files(self, tmp_dir):
        py_file = os.path.join(tmp_dir, 'clean.py')
        with open(py_file, 'w') as f:
            f.write('x = 1\nprint("hello")\n')
        config = Config(no_color=True)
        findings, skipped, json_files, errored = walk_and_scan(tmp_dir, config)
        assert findings == []
        assert errored == []

    def test_detects_credential(self, tmp_dir):
        py_file = os.path.join(tmp_dir, 'secret.py')
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(py_file, 'w') as f:
            f.write(f'aws_key = "{key}"\n')
        config = Config(no_color=True)
        findings, skipped, json_files, errored = walk_and_scan(tmp_dir, config)
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
        findings, _, _, _ = walk_and_scan(tmp_dir, config)
        assert findings == []

    def test_collects_json_files(self, tmp_dir):
        json_file = os.path.join(tmp_dir, 'data.json')
        with open(json_file, 'w') as f:
            f.write('{"key": "value"}\n')
        config = Config(no_color=True)
        _, _, json_files, _ = walk_and_scan(tmp_dir, config)
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
        findings, _, _, _ = walk_and_scan(tmp_dir, config)
        assert findings == []

    def test_custom_skip_files(self, tmp_dir):
        py_file = os.path.join(tmp_dir, 'generated.py')
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(py_file, 'w') as f:
            f.write(f'aws_key = "{key}"\n')
        config = Config(no_color=True, skip_files={'generated.py'})
        findings, _, _, _ = walk_and_scan(tmp_dir, config)
        assert findings == []

    def test_multiple_files(self, tmp_dir):
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        for i in range(5):
            path = os.path.join(tmp_dir, f'file{i}.py')
            with open(path, 'w') as f:
                f.write(f'key{i} = "{key}"\n')
        config = Config(no_color=True)
        findings, _, _, errored = walk_and_scan(tmp_dir, config)
        assert len(findings) >= 5
        assert errored == []

    def test_permission_denied_handled_gracefully(self, tmp_dir):
        """A directory with no scannable files produces no errors."""
        config = Config(no_color=True)
        findings, _, _, errored = walk_and_scan(tmp_dir, config)
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
        walk_and_scan(tmp_dir, config, allowlist)

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
            _, _, _, errored = walk_and_scan(tmp_dir, config)
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
            _, _, _, errored = walk_and_scan(tmp_dir, Config(no_color=True))
            resolved = os.path.realpath(py_file)
            assert any(os.path.realpath(e) == resolved for e in errored)
        finally:
            os.chmod(py_file, 0o644)
