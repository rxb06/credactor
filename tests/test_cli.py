"""Tests for CLI argument parsing and main entry point."""

import json
import os

import pytest

from credactor.cli import (
    _config_from_args,
    _emit_report,
    _validate_invocation,
    _validate_replacement,
    build_parser,
    main,
)
from credactor.config import Config


class TestConfigFromArgs:
    def test_round_trip(self):
        parser = build_parser()
        args = parser.parse_args([
            '--ci', '--no-backup', '--format', 'sarif',
            '--replace-with', 'env', '--verbose', '/tmp/x',
        ])
        config = _config_from_args(args)
        assert isinstance(config, Config)
        assert config.ci_mode is True
        assert config.no_backup is True
        assert config.output_format == 'sarif'
        assert config.replace_mode == 'env'
        assert config.verbose is True
        assert config.target == '/tmp/x'


class TestValidateInvocation:
    def test_ci_plus_fix_all_exits_2(self):
        config = Config(ci_mode=True, fix_all=True)
        with pytest.raises(SystemExit) as exc:
            _validate_invocation(config)
        assert exc.value.code == 2

    def test_scan_history_plus_gitleaks_exits_2(self):
        config = Config(scan_history=True, from_gitleaks='/tmp/x.json')
        with pytest.raises(SystemExit) as exc:
            _validate_invocation(config)
        assert exc.value.code == 2

    def test_ci_mode_forces_dry_run(self):
        config = Config(ci_mode=True, dry_run=False)
        _validate_invocation(config)
        assert config.dry_run is True

    def test_dangerous_replacement_exits_2(self):
        config = Config(custom_replacement='$(rm -rf /)')
        with pytest.raises(SystemExit) as exc:
            _validate_replacement(config)   # H5: guard moved out of _validate_invocation
        assert exc.value.code == 2


class TestBuildParser:
    def test_config_path(self):
        parser = build_parser()
        args = parser.parse_args(['--config', '/path/to/config.toml'])
        assert args.config == '/path/to/config.toml'

    def test_defaults(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.ci is False
        assert args.dry_run is False
        assert args.fix_all is False
        assert args.staged is False
        assert args.scan_history is False
        assert args.no_color is False
        assert args.no_backup is False
        assert args.scan_json is False
        assert args.fail_on_error is False
        assert args.output_format == 'text'
        assert args.replace_mode == 'sentinel'
        assert args.replacement == 'REDACTED_BY_CREDACTOR'
        assert args.config is None


class TestMainExitCodes:
    def test_nonexistent_path_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            main(['/nonexistent/path/that/does/not/exist'])
        assert exc_info.value.code == 2

    def test_system_directory_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            main(['/'])
        assert exc_info.value.code == 2

    def test_clean_directory_exits_0(self, tmp_dir):
        """A directory with no credential files should exit 0."""
        clean_file = os.path.join(tmp_dir, 'clean.py')
        with open(clean_file, 'w') as f:
            f.write('x = 1\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', tmp_dir])
        assert exc_info.value.code == 0

    def test_ci_mode_with_findings_exits_1(self, make_file):
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        path = make_file('secret.py', f'aws_key = "{key}"\n')
        target = os.path.dirname(path)
        with pytest.raises(SystemExit) as exc_info:
            main(['--ci', target])
        assert exc_info.value.code == 1

    def test_dry_run_with_findings_exits_1(self, make_file):
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        path = make_file('secret.py', f'aws_key = "{key}"\n')
        target = os.path.dirname(path)
        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', target])
        assert exc_info.value.code == 1

    def test_json_output_clean(self, tmp_dir):
        clean_file = os.path.join(tmp_dir, 'clean.py')
        with open(clean_file, 'w') as f:
            f.write('x = 1\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--format', 'json', tmp_dir])
        assert exc_info.value.code == 0

    def test_sarif_output_clean(self, tmp_dir):
        clean_file = os.path.join(tmp_dir, 'clean.py')
        with open(clean_file, 'w') as f:
            f.write('x = 1\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--format', 'sarif', tmp_dir])
        assert exc_info.value.code == 0


class TestGitleaksFileTargetRejection:
    """--from-gitleaks with a file target must be rejected with exit code 2."""

    def test_file_target_exits_2(self, tmp_dir):
        repo = os.path.join(tmp_dir, 'repo')
        os.makedirs(repo)
        src_file = os.path.join(repo, 'config.py')
        with open(src_file, 'w') as f:
            f.write('x = 1\n')
        report = os.path.join(tmp_dir, 'report.json')
        with open(report, 'w') as f:
            json.dump([], f)
        with pytest.raises(SystemExit) as exc_info:
            main(['--from-gitleaks', report, src_file])
        assert exc_info.value.code == 2


class TestConfigFileIngestCLI:
    """P4.3 / P4.4: [ingest] from_gitleaks / from_trufflehog in .credactor.toml."""

    def _setup_project(self, tmp_dir: str) -> tuple[str, str]:
        """Create a project dir with one low-entropy source file (native scanner ignores it)."""
        repo = os.path.join(tmp_dir, 'repo')
        src = os.path.join(repo, 'src')
        os.makedirs(src)
        src_file = os.path.join(src, 'config.py')
        with open(src_file, 'w') as f:
            f.write('api_key = "aaaaaaaaaa"\n')
        return repo, src_file

    def test_config_file_from_gitleaks_consumed(self, tmp_dir):
        """P4.3: [ingest] from_gitleaks in .credactor.toml must produce exit 1."""
        repo, _ = self._setup_project(tmp_dir)
        finding = {
            'File': 'src/config.py',
            'StartLine': 1,
            'Secret': 'aaaaaaaaaa',
            'Match': 'api_key = "aaaaaaaaaa"',
            'RuleID': 'generic-api-key',
            'Tags': [],
            'Commit': '',
            'SymlinkFile': '',
        }
        report = os.path.join(tmp_dir, 'report.json')
        with open(report, 'w') as f:
            json.dump([finding], f)
        with open(os.path.join(repo, '.credactor.toml'), 'w') as f:
            f.write('[ingest]\n')
            f.write(f'from_gitleaks = "{report}"\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', repo])
        assert exc_info.value.code == 1

    def test_config_file_from_trufflehog_consumed(self, tmp_dir):
        """P4.4: [ingest] from_trufflehog in .credactor.toml must produce exit 1."""
        repo, _ = self._setup_project(tmp_dir)
        finding = {
            'Raw': 'aaaaaaaaaa',
            'SourceMetadata': {'Data': {'Filesystem': {'file': 'src/config.py', 'line': 1}}},
            'DetectorName': 'CustomRegex',
            'Verified': False,
        }
        report = os.path.join(tmp_dir, 'report.jsonl')
        with open(report, 'w') as f:
            f.write(json.dumps(finding) + '\n')
        with open(os.path.join(repo, '.credactor.toml'), 'w') as f:
            f.write('[ingest]\n')
            f.write(f'from_trufflehog = "{report}"\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', repo])
        assert exc_info.value.code == 1


class TestGitleaksAllowlistIntegration:
    """Allowlist suppression must apply to --from-gitleaks findings."""

    def _make_repo(self, tmp_dir: str) -> tuple[str, str]:
        """Create a minimal repo dir with one source file; return (repo, src_file)."""
        repo = os.path.join(tmp_dir, 'repo')
        src = os.path.join(repo, 'src')
        os.makedirs(src)
        src_file = os.path.join(src, 'config.py')
        with open(src_file, 'w') as f:
            f.write('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
        return repo, src_file

    def _write_report(self, tmp_dir: str, findings: list) -> str:
        path = os.path.join(tmp_dir, 'report.json')
        with open(path, 'w') as f:
            json.dump(findings, f)
        return path

    def test_gitleaks_suppressed_value_not_reported(self, tmp_dir):
        """A value suppressed in .credactorignore must not surface as a finding."""
        repo, src_file = self._make_repo(tmp_dir)
        secret = 'AKIAIOSFODNN7EXAMPLE'

        # Suppress by value literal
        with open(os.path.join(repo, '.credactorignore'), 'w') as f:
            f.write(f'{secret}\n')

        finding = {
            'File': 'src/config.py',
            'StartLine': 1,
            'Secret': secret,
            'Match': f'aws_key = "{secret}"',
            'RuleID': 'aws-access-token',
            'Tags': [],
            'Commit': '',
            'SymlinkFile': '',
        }
        report = self._write_report(tmp_dir, [finding])

        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', '--from-gitleaks', report, repo])
        # No unsuppressed findings → exit 0
        assert exc_info.value.code == 0

    def test_gitleaks_unsuppressed_value_is_reported(self, tmp_dir):
        """Without a suppression entry the finding should be reported (exit 1)."""
        repo, src_file = self._make_repo(tmp_dir)
        secret = 'AKIAIOSFODNN7EXAMPLE'

        finding = {
            'File': 'src/config.py',
            'StartLine': 1,
            'Secret': secret,
            'Match': f'aws_key = "{secret}"',
            'RuleID': 'aws-access-token',
            'Tags': [],
            'Commit': '',
            'SymlinkFile': '',
        }
        report = self._write_report(tmp_dir, [finding])

        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', '--from-gitleaks', report, repo])
        assert exc_info.value.code == 1


_NOT_ROOT = pytest.mark.skipif(
    not hasattr(os, 'getuid') or os.getuid() == 0,
    reason='chmod 000 is not honoured as root / on Windows',
)


class TestPhase1Fixes:
    """Regression tests for e2e findings H1, H4, H6."""

    # --- H1: single-file target is scanned (os.walk on a file yields nothing) ---
    def test_single_file_target_is_scanned(self, make_file):
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        path = make_file('config.py', f'aws_key = "{key}"\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', path])          # file path, not its directory
        assert exc_info.value.code == 1         # findings present

    def test_single_file_parity_with_directory(self, make_file):
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        path = make_file('config.py', f'aws_key = "{key}"\n')
        for target in (path, os.path.dirname(path)):
            with pytest.raises(SystemExit) as exc_info:
                main(['--dry-run', target])
            assert exc_info.value.code == 1

    # --- H4: --fail-on-error must surface unreadable files ---
    @_NOT_ROOT
    def test_fail_on_error_exits_2_on_unreadable_file(self, make_file):
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        path = make_file('secret.py', f'aws_key = "{key}"\n')
        os.chmod(path, 0o000)
        try:
            with pytest.raises(SystemExit) as exc_info:
                main(['--fail-on-error', '--dry-run', os.path.dirname(path)])
            assert exc_info.value.code == 2
        finally:
            os.chmod(path, 0o644)

    @_NOT_ROOT
    def test_unreadable_file_without_fail_on_error_exits_0(self, make_file):
        """Characterization: without --fail-on-error an unreadable file is a
        warning only (no SystemExit(2))."""
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        path = make_file('secret.py', f'aws_key = "{key}"\n')
        os.chmod(path, 0o000)
        try:
            with pytest.raises(SystemExit) as exc_info:
                main(['--dry-run', os.path.dirname(path)])
            assert exc_info.value.code == 0     # unread -> no findings, no error gate
        finally:
            os.chmod(path, 0o644)

    # --- H6: protected-dir guard resolves symlinked roots (macOS /etc) ---
    def test_etc_is_refused(self):
        from pathlib import Path
        if not Path('/etc').exists():
            pytest.skip('no /etc on this platform')
        with pytest.raises(SystemExit) as exc_info:
            main(['/etc'])
        assert exc_info.value.code == 2

    def test_resolved_protected_set_includes_symlink_targets(self):
        from pathlib import Path

        from credactor.cli import _PROTECTED_DIRS_RESOLVED
        if Path('/etc').resolve() != Path('/etc'):   # only where /etc is a symlink
            assert str(Path('/etc').resolve()) in _PROTECTED_DIRS_RESOLVED

    # --- H5: a dangerous replacement supplied via .credactor.toml is rejected ---
    def test_config_file_replacement_is_validated(self, tmp_dir):
        with open(os.path.join(tmp_dir, '.credactor.toml'), 'w') as f:
            f.write('replacement = "x$(whoami)"\n')
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(os.path.join(tmp_dir, 'app.py'), 'w') as f:
            f.write(f'aws = "{key}"\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', tmp_dir])
        assert exc_info.value.code == 2

    # --- M6: a newline in the replacement injects a new source line ---
    def test_newline_in_replacement_rejected(self):
        with pytest.raises(SystemExit) as exc:
            _validate_replacement(Config(custom_replacement='SAFE\nimport os'))
        assert exc.value.code == 2

    # --- H7: the empty-result message is not an absolute guarantee ---
    def test_clean_report_states_sensitivity_not_absolute(self, capsys):
        _emit_report([], '/tmp', Config(no_color=True))
        out = capsys.readouterr().out
        assert 'Safe for commits' not in out
        assert 'entropy floor' in out
