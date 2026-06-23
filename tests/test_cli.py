"""Tests for CLI argument parsing and main entry point."""

import json
import os
import sys
from pathlib import Path

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
        args = parser.parse_args(
            [
                '--ci',
                '--no-backup',
                '--format',
                'sarif',
                '--replace-with',
                'env',
                '--verbose',
                '/tmp/x',
            ]
        )
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
            _validate_replacement(config)  # H5: guard moved out of _validate_invocation
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
        # M10: default is None (not the literal) so an explicit --replacement is
        # distinguishable from "flag not passed" and can win over a config value.
        assert args.replacement is None
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

    def test_dry_run_fix_all_warns_and_modifies_nothing(self, make_file, credactor_caplog):
        # --dry-run winning IS the safe outcome, but silently ignoring
        # --fix-all was inconsistent: --staged/--scan-history warn on the
        # same combination and --ci rejects it outright.
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'  # credactor:ignore
        path = make_file('secret.py', f'aws_key = "{key}"\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', '--fix-all', '--yes', os.path.dirname(path)])
        assert exc_info.value.code == 1
        with open(path) as f:
            assert key in f.read()
        assert not os.path.exists(path + '.bak')
        assert any('--dry-run takes precedence' in r.getMessage() for r in credactor_caplog.records)

    def test_staged_dry_run_fix_all_warns_once_via_staged_only(self, credactor_caplog):
        # The staged message already covers the ignored --fix-all; the
        # generic precedence warning must not double up on top of it.
        _validate_invocation(Config(staged_only=True, dry_run=True, fix_all=True))
        msgs = [r.getMessage() for r in credactor_caplog.records]
        assert any('--staged is read-only' in m for m in msgs)
        assert not any('--dry-run takes precedence' in m for m in msgs)

    def test_no_backup_with_secure_backup_dir_warns(self, credactor_caplog):
        # --no-backup skips backup creation entirely, so --secure-backup-dir is a
        # silent no-op; the contradiction must be surfaced, not swallowed.
        _validate_invocation(Config(no_backup=True, secure_backup_dir='/tmp/safe'))
        assert any(
            '--no-backup overrides --secure-backup-dir/--secure-delete' in r.getMessage()
            for r in credactor_caplog.records
        )

    def test_no_backup_with_secure_delete_warns(self, credactor_caplog):
        _validate_invocation(Config(no_backup=True, secure_delete=True))
        assert any(
            '--no-backup overrides --secure-backup-dir/--secure-delete' in r.getMessage()
            for r in credactor_caplog.records
        )

    def test_secure_backup_dir_without_no_backup_does_not_warn(self, credactor_caplog):
        # The normal secure-backup configuration (no --no-backup) is not a
        # contradiction and must stay quiet.
        _validate_invocation(Config(secure_backup_dir='/tmp/safe', secure_delete=True))
        assert not any('--no-backup overrides' in r.getMessage() for r in credactor_caplog.records)

    def test_missing_explicit_config_exits_2(self, tmp_dir, credactor_caplog):
        # An explicit --config that doesn't exist must be fatal: silently
        # scanning at default sensitivity would drop every intended setting
        # (thresholds, extra_extensions, [ingest]) and can flip a failing
        # CI gate to a pass via a filename typo.
        with pytest.raises(SystemExit) as exc_info:
            main(['--config', os.path.join(tmp_dir, 'missing.toml'), '--dry-run', tmp_dir])
        assert exc_info.value.code == 2
        assert 'Config file not found' in credactor_caplog.text

    def test_directory_as_explicit_config_exits_2(self, tmp_dir):
        with pytest.raises(SystemExit) as exc_info:
            main(['--config', tmp_dir, '--dry-run', tmp_dir])
        assert exc_info.value.code == 2

    def test_invalid_toml_explicit_config_exits_2(self, tmp_dir, credactor_caplog):
        # An explicit --config that exists but is unparseable is the same
        # CI-gate-flip threat as a missing one: silently scanning at defaults
        # drops every intended setting. A content typo must be as loud as a
        # filename typo.
        cfg = os.path.join(tmp_dir, 'cfg.toml')
        with open(cfg, 'w') as f:
            f.write('entropy_threshold = = 4.0\n')  # syntactically invalid TOML
        with pytest.raises(SystemExit) as exc_info:
            main(['--config', cfg, '--dry-run', tmp_dir])
        assert exc_info.value.code == 2
        assert (
            'invalid TOML' in credactor_caplog.text.lower()
            or 'invalid toml' in credactor_caplog.text.lower()
        )

    def test_invalid_toml_config_does_not_silently_skip_settings(self, tmp_dir):
        # The worst case spelled out: a config whose extra_extensions makes a
        # secret in a .custom file visible. Valid -> exit 1 (found). Invalid
        # -> must be exit 2 (fatal), NOT exit 0 (silent miss at defaults).
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'  # credactor:ignore
        with open(os.path.join(tmp_dir, 'secret.custom'), 'w') as f:
            f.write(f'aws_key = "{key}"\n')
        good = os.path.join(tmp_dir, 'good.toml')
        with open(good, 'w') as f:
            f.write('extra_extensions = [".custom"]\n')
        with pytest.raises(SystemExit) as found:
            main(['--config', good, '--dry-run', tmp_dir])
        assert found.value.code == 1  # config honored -> secret found

        bad = os.path.join(tmp_dir, 'bad.toml')
        with open(bad, 'w') as f:
            f.write('extra_extensions = [".custom"\n')  # unterminated array
        with pytest.raises(SystemExit) as broken:
            main(['--config', bad, '--dry-run', tmp_dir])
        assert broken.value.code == 2  # fatal, not a silent exit 0

    def test_config_file_bad_replacement_rejected(self, tmp_dir):
        # A discovered .credactor.toml must not smuggle a dangerous replacement
        # past the CLI guard into file writes: an out-of-charset value is fatal
        # (exit 2) BEFORE any redaction, and the target file is left untouched.
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'  # credactor:ignore
        src = os.path.join(tmp_dir, 'leak.py')
        with open(src, 'w') as f:
            f.write(f'api_key = "{key}"\n')
        with open(os.path.join(tmp_dir, '.credactor.toml'), 'w') as f:
            f.write('replacement = "bad;rm -rf"\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--fix-all', '--yes', tmp_dir])
        assert exc_info.value.code == 2
        with open(src) as f:
            assert key in f.read()  # rejected before any write; secret untouched

    @pytest.mark.skipif(
        sys.platform == 'win32', reason='chmod 000 unreadable semantics are POSIX-only'
    )
    def test_unreadable_explicit_config_exits_2(self, tmp_dir):
        cfg = os.path.join(tmp_dir, 'noperm.toml')
        with open(cfg, 'w') as f:
            f.write('entropy_threshold = 4.0\n')
        os.chmod(cfg, 0o000)
        try:
            if os.access(cfg, os.R_OK):  # running as root reads it anyway
                pytest.skip('cannot make file unreadable (running as root?)')
            with pytest.raises(SystemExit) as exc_info:
                main(['--config', cfg, '--dry-run', tmp_dir])
            assert exc_info.value.code == 2
        finally:
            os.chmod(cfg, 0o644)


class TestTtyGates:
    """Interactive mode and the --fix-all confirmation require a real TTY on
    stdin — a script accidentally piping y-prefixed text must not rewrite
    files. --fix-all --yes remains the unattended path."""

    _KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'

    def test_interactive_non_tty_exits_1_untouched(self, make_file, monkeypatch, credactor_caplog):
        path = make_file('secret.py', f'aws_key = "{self._KEY}"\n')
        monkeypatch.setattr('builtins.input', lambda *a: 'y')
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
        with pytest.raises(SystemExit) as exc_info:
            main([os.path.dirname(path)])
        assert exc_info.value.code == 1
        with open(path) as f:
            assert self._KEY in f.read()
        assert not os.path.exists(path + '.bak')
        assert any('requires a TTY' in r.getMessage() for r in credactor_caplog.records)

    def test_fix_all_without_yes_non_tty_aborts(self, make_file, monkeypatch, capsys):
        path = make_file('secret.py', f'aws_key = "{self._KEY}"\n')
        monkeypatch.setattr('builtins.input', lambda *a: 'y')
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
        with pytest.raises(SystemExit) as exc_info:
            main(['--fix-all', os.path.dirname(path)])
        assert exc_info.value.code == 1
        with open(path) as f:
            assert self._KEY in f.read()
        assert 'pass --yes' in capsys.readouterr().out

    def test_interactive_with_tty_redacts(self, make_file, monkeypatch):
        # Control: a real TTY (pty wrappers included) keeps working.
        path = make_file('secret.py', f'aws_key = "{self._KEY}"\n')
        monkeypatch.setattr('builtins.input', lambda *a: 'y')
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
        with pytest.raises(SystemExit) as exc_info:
            main([os.path.dirname(path)])
        assert exc_info.value.code == 0
        with open(path) as f:
            assert self._KEY not in f.read()

    def test_fix_all_yes_non_tty_proceeds(self, make_file, monkeypatch):
        # Control: the documented unattended path is unaffected by the gate.
        path = make_file('secret.py', f'aws_key = "{self._KEY}"\n')
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: False)
        with pytest.raises(SystemExit) as exc_info:
            main(['--fix-all', '--yes', os.path.dirname(path)])
        assert exc_info.value.code == 0
        with open(path) as f:
            assert self._KEY not in f.read()


class TestNonTextFixAllStreamPurity:
    """-f json/sarif + --fix-all --yes: stdout must stay a single parseable
    document; confirmation banners and the summary belong on stderr."""

    _KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'

    def test_json_fix_all_stdout_is_pure_json(self, make_file, capsys):
        path = make_file('secret.py', f'aws_key = "{self._KEY}"\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['-f', 'json', '--fix-all', '--yes', os.path.dirname(path)])
        assert exc_info.value.code == 0
        out, err = capsys.readouterr()
        data = json.loads(out)  # was: JSON followed by human text
        assert data['count'] == 1
        assert '--fix-all will modify' in err
        assert 'Summary' in err
        with open(path) as f:
            assert self._KEY not in f.read()

    def test_sarif_fix_all_stdout_is_pure_sarif(self, make_file, capsys):
        path = make_file('secret.py', f'aws_key = "{self._KEY}"\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['-f', 'sarif', '--fix-all', '--yes', os.path.dirname(path)])
        assert exc_info.value.code == 0
        out, err = capsys.readouterr()
        data = json.loads(out)
        assert data['version'] == '2.1.0'
        assert 'Summary' in err

    def test_text_fix_all_summary_stays_on_stdout(self, make_file, capsys):
        path = make_file('secret.py', f'aws_key = "{self._KEY}"\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--fix-all', '--yes', os.path.dirname(path)])
        assert exc_info.value.code == 0
        out, _ = capsys.readouterr()
        assert '--fix-all will modify' in out
        assert 'Summary' in out


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
            # as_posix(): a Windows path's backslashes are escape sequences inside a
            # double-quoted TOML string (tomllib parse error -> config ignored).
            f.write(f'from_gitleaks = "{Path(report).as_posix()}"\n')
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
            f.write(f'from_trufflehog = "{Path(report).as_posix()}"\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', repo])
        assert exc_info.value.code == 1

    def test_config_file_ingest_with_scan_history_rejected(self, tmp_dir, credactor_caplog):
        """A config-file [ingest] table must not slip past the --scan-history
        rejection. The check runs after the config file is applied, so a
        config-sourced ingest path exits 2 just like the CLI flag does (Codex P2)."""
        repo, _ = self._setup_project(tmp_dir)
        report = os.path.join(tmp_dir, 'report.json')
        with open(report, 'w') as f:
            json.dump([], f)
        with open(os.path.join(repo, '.credactor.toml'), 'w') as f:
            f.write('[ingest]\n')
            # as_posix(): a Windows path's backslashes are escape sequences inside a
            # double-quoted TOML string (tomllib parse error -> config ignored).
            f.write(f'from_gitleaks = "{Path(report).as_posix()}"\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--scan-history', repo])
        assert exc_info.value.code == 2
        msgs = [r.getMessage() for r in credactor_caplog.records]
        assert any('--scan-history cannot be combined with' in m for m in msgs)

    def test_cli_ingest_flag_beats_config(self, tmp_dir):
        """S9: an explicit --from-gitleaks overrides a same-kind [ingest] entry
        (CLI > config, consistent with --replacement). The CLI report carries a
        finding (-> exit 1); the config report is empty (-> would be exit 0), so
        the resulting exit code proves which report was actually ingested."""
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
        cli_report = os.path.join(tmp_dir, 'cli.json')
        with open(cli_report, 'w') as f:
            json.dump([finding], f)
        cfg_report = os.path.join(tmp_dir, 'cfg.json')
        with open(cfg_report, 'w') as f:
            json.dump([], f)  # empty: if config won, the run would exit 0
        with open(os.path.join(repo, '.credactor.toml'), 'w') as f:
            f.write('[ingest]\n')
            f.write(f'from_gitleaks = "{Path(cfg_report).as_posix()}"\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', '--from-gitleaks', cli_report, repo])
        assert exc_info.value.code == 1  # CLI report's finding -> exit 1

    def test_empty_from_gitleaks_is_fatal(self, tmp_dir):
        """S9 edge: an explicit --from-gitleaks "" (e.g. an unset shell var) is a
        user error, not a silent no-op. It must fail closed (exit 2), mirroring
        --replacement "" — never silently disable ingest (incl. a config source)."""
        repo, _ = self._setup_project(tmp_dir)
        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', '--from-gitleaks', '', repo])
        assert exc_info.value.code == 2

    def test_empty_from_trufflehog_is_fatal(self, tmp_dir):
        repo, _ = self._setup_project(tmp_dir)
        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', '--from-trufflehog', '', repo])
        assert exc_info.value.code == 2

    def test_empty_cli_from_flag_does_not_clobber_config_ingest(self, tmp_dir):
        """S9 edge, false-clean guard: --from-gitleaks "" alongside a config
        [ingest] source that yields a finding must NOT silently drop to exit 0;
        it fails closed (exit 2) rather than flipping a CI gate green."""
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
        cfg_report = os.path.join(tmp_dir, 'cfg.json')
        with open(cfg_report, 'w') as f:
            json.dump([finding], f)
        with open(os.path.join(repo, '.credactor.toml'), 'w') as f:
            f.write('[ingest]\n')
            f.write(f'from_gitleaks = "{Path(cfg_report).as_posix()}"\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', '--from-gitleaks', '', repo])
        assert exc_info.value.code == 2


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
            main(['--dry-run', path])  # file path, not its directory
        assert exc_info.value.code == 1  # findings present

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
            assert exc_info.value.code == 0  # unread -> no findings, no error gate
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

        # Require /etc to EXIST as well as resolve differently: on Windows
        # '/etc' also resolves to something else (C:\etc), which would run the
        # macOS-symlink assertion against a path that was never protected.
        if Path('/etc').exists() and Path('/etc').resolve() != Path('/etc'):
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

    # --- M5: the replacement guard is an allowlist (markup/quote chars rejected) ---
    def test_markup_replacement_rejected(self):
        # <>"'/ passed the old shell-only denylist and could inject into XML/HTML
        with pytest.raises(SystemExit) as exc:
            _validate_replacement(Config(custom_replacement='"></secret><x>'))
        assert exc.value.code == 2

    def test_benign_replacement_accepted(self):
        # alphanumeric + underscore + hyphen passes (no exit)
        _validate_replacement(Config(custom_replacement='MY-REDACTION_1'))

    def test_empty_replacement_rejected(self):
        # S5: '' must be rejected — the allowlist regex uses + not *; otherwise
        # --replacement '' excises the secret with no marker.
        with pytest.raises(SystemExit) as exc:
            _validate_replacement(Config(replace_mode='custom', custom_replacement=''))
        assert exc.value.code == 2

    def test_trailing_newline_replacement_rejected(self):
        # fullmatch (not search) is required: the regex `$` matches before a
        # trailing newline, so a search-based guard would let this inject a line
        with pytest.raises(SystemExit) as exc:
            _validate_replacement(Config(custom_replacement='REDACTED\n'))
        assert exc.value.code == 2

    # --- H7: the empty-result message is not an absolute guarantee ---
    def test_clean_report_states_sensitivity_not_absolute(self, capsys):
        _emit_report([], '/tmp', Config(no_color=True))
        out = capsys.readouterr().out
        assert 'Safe for commits' not in out
        assert 'entropy floor' in out


class TestStagedReadOnly:
    """M7: --staged is read-only — it forces dry-run so a staged scan never
    rewrites the working tree, even when --fix-all is also passed."""

    def test_staged_forces_dry_run(self):
        config = Config(staged_only=True, dry_run=False)
        _validate_invocation(config)
        assert config.dry_run is True

    def test_staged_fix_all_warns_and_forces_dry_run(self, credactor_caplog):
        config = Config(staged_only=True, fix_all=True, dry_run=False)
        _validate_invocation(config)
        assert config.dry_run is True
        assert any('--staged is read-only' in r.message for r in credactor_caplog.records)


class TestScanHistoryReadOnly:
    """--scan-history is read-only — history findings carry synthetic
    'file (commit abc123)' paths no write pass can open, so dry-run is forced
    and a redaction pass (which could only fail per finding) is never offered."""

    def test_scan_history_forces_dry_run(self):
        config = Config(scan_history=True, dry_run=False)
        _validate_invocation(config)
        assert config.dry_run is True

    def test_scan_history_fix_all_warns_and_forces_dry_run(self, credactor_caplog):
        config = Config(scan_history=True, fix_all=True, dry_run=False)
        _validate_invocation(config)
        assert config.dry_run is True
        assert any('--scan-history is read-only' in r.message for r in credactor_caplog.records)


class TestReplacementEnvModeWarning:
    """--replacement is never consulted in env mode (which generates
    language-aware references) — passing both must warn, not silently ignore."""

    def test_replacement_with_env_mode_warns(self, tmp_dir, credactor_caplog):
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(os.path.join(tmp_dir, 'app.py'), 'w') as f:
            f.write(f'aws = "{key}"\n')
        with pytest.raises(SystemExit):
            main(['--dry-run', '--replace-with', 'env', '--replacement', 'CUSTOM', tmp_dir])
        assert any('--replacement has no effect' in r.message for r in credactor_caplog.records)

    def test_no_warning_without_env_mode(self, tmp_dir, credactor_caplog):
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(os.path.join(tmp_dir, 'app.py'), 'w') as f:
            f.write(f'aws = "{key}"\n')
        with pytest.raises(SystemExit):
            main(['--dry-run', '--replacement', 'CUSTOM', tmp_dir])
        assert not any('--replacement has no effect' in r.message for r in credactor_caplog.records)


class TestReplacementPrecedence:
    """M10: an explicit --replacement overrides a config-file 'replacement'
    (precedence CLI > config > default)."""

    def test_config_from_args_resolves_none_to_default(self):
        args = build_parser().parse_args([])
        assert _config_from_args(args).custom_replacement == 'REDACTED_BY_CREDACTOR'

    def test_config_from_args_defers_explicit_to_main_inner(self):
        # P2/#46: _config_from_args no longer bakes in --replacement; it leaves
        # the Config default in place and the override is applied in _main_inner
        # (so precedence is CLI > config-file > default). The end-to-end CLI
        # override is covered by test_cli_replacement_overrides_config below.
        args = build_parser().parse_args(['--replacement', 'FROM_CLI'])
        assert _config_from_args(args).custom_replacement == 'REDACTED_BY_CREDACTOR'
        assert args.replacement == 'FROM_CLI'  # value still captured for _main_inner

    def _make_repo(self, tmp_dir):
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        src = os.path.join(tmp_dir, 'app.py')
        with open(src, 'w') as f:
            f.write(f'api_key = "{key}"\n')
        return src, key

    def test_cli_replacement_overrides_config(self, tmp_dir, monkeypatch):
        src, key = self._make_repo(tmp_dir)
        with open(os.path.join(tmp_dir, '.credactor.toml'), 'w') as f:
            f.write('replacement = "FROM_CONFIG"\n')
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
        monkeypatch.setattr('builtins.input', lambda *a: 'y')
        with pytest.raises(SystemExit):
            main(['--fix-all', '--replace-with', 'custom', '--replacement', 'FROM_CLI', tmp_dir])
        with open(src) as f:
            out = f.read()
        assert 'FROM_CLI' in out and 'FROM_CONFIG' not in out and key not in out

    def test_config_replacement_applies_without_cli_flag(self, tmp_dir, monkeypatch):
        src, key = self._make_repo(tmp_dir)
        with open(os.path.join(tmp_dir, '.credactor.toml'), 'w') as f:
            f.write('replacement = "FROM_CONFIG"\n')
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
        monkeypatch.setattr('builtins.input', lambda *a: 'y')
        with pytest.raises(SystemExit):
            main(['--fix-all', '--replace-with', 'custom', tmp_dir])
        with open(src) as f:
            assert 'FROM_CONFIG' in f.read()


class TestFixAllYes:
    """L3: --fix-all needs a TTY or --yes; --yes proceeds non-interactively, while
    a non-TTY stdin without --yes aborts (no destructive surprise in a pipe)."""

    def _repo(self, tmp_dir):
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        src = os.path.join(tmp_dir, 'app.py')
        with open(src, 'w') as f:
            f.write(f'api_key = "{key}"\n')
        return src, key

    def test_fix_all_without_yes_aborts_on_eof_at_tty(self, tmp_dir, monkeypatch):
        # isatty=True so this pins the EOF (Ctrl-D at the prompt) handler —
        # the non-TTY pipe case is owned by TestTtyGates and would otherwise
        # gate first, leaving this branch uncovered.
        src, key = self._repo(tmp_dir)
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)

        def _raise_eof(*_a):
            raise EOFError()

        monkeypatch.setattr('builtins.input', _raise_eof)
        with pytest.raises(SystemExit) as exc:
            main(['--fix-all', tmp_dir])
        assert exc.value.code == 1
        with open(src) as f:
            assert key in f.read()  # file left untouched

    def test_fix_all_yes_proceeds_without_prompt(self, tmp_dir, monkeypatch):
        src, key = self._repo(tmp_dir)

        def _no_prompt(*_a):
            raise AssertionError('--yes must not prompt')

        monkeypatch.setattr('builtins.input', _no_prompt)
        with pytest.raises(SystemExit) as exc:
            main(['--fix-all', '--yes', tmp_dir])
        assert exc.value.code == 0
        with open(src) as f:
            assert key not in f.read()  # redacted


class TestGitUnavailableExit:
    """L4: --staged/--scan-history in a non-git directory is a hard exit 2, not a
    false-clean exit 0."""

    def test_staged_non_git_dir_exits_2(self, tmp_dir):
        with pytest.raises(SystemExit) as exc:
            main(['--staged', tmp_dir])
        assert exc.value.code == 2

    def test_scan_history_non_git_dir_exits_2(self, tmp_dir):
        with pytest.raises(SystemExit) as exc:
            main(['--scan-history', tmp_dir])
        assert exc.value.code == 2


class TestIngestErrorMessages:
    """P2/#1: the collapsed _ingest_one helper must render tool/flag names exactly."""

    def _report(self, tmp_dir):
        report = os.path.join(tmp_dir, 'report.json')
        with open(report, 'w') as f:
            json.dump([], f)
        return report

    def _file_target(self, tmp_dir):
        repo = os.path.join(tmp_dir, 'repo')
        os.makedirs(repo)
        target = os.path.join(repo, 'a.py')
        with open(target, 'w') as f:
            f.write('x = 1\n')
        return target

    def test_gitleaks_file_not_found_message(self, tmp_dir, credactor_caplog):
        missing = os.path.join(tmp_dir, 'nope.json')
        with pytest.raises(SystemExit) as exc:
            main(['--from-gitleaks', missing, tmp_dir])
        assert exc.value.code == 2
        assert any('Gitleaks file not found' in r.getMessage() for r in credactor_caplog.records)

    def test_trufflehog_file_not_found_message(self, tmp_dir, credactor_caplog):
        missing = os.path.join(tmp_dir, 'nope.json')
        with pytest.raises(SystemExit) as exc:
            main(['--from-trufflehog', missing, tmp_dir])
        assert exc.value.code == 2
        assert any('TruffleHog file not found' in r.getMessage() for r in credactor_caplog.records)

    def test_gitleaks_directory_target_message(self, tmp_dir, credactor_caplog):
        report = self._report(tmp_dir)
        with pytest.raises(SystemExit):
            main(['--from-gitleaks', report, self._file_target(tmp_dir)])
        msgs = [r.getMessage() for r in credactor_caplog.records]
        assert any(
            '--from-gitleaks requires a directory target' in m and 'Gitleaks report' in m
            for m in msgs
        )

    def test_trufflehog_directory_target_message(self, tmp_dir, credactor_caplog):
        report = self._report(tmp_dir)
        with pytest.raises(SystemExit):
            main(['--from-trufflehog', report, self._file_target(tmp_dir)])
        msgs = [r.getMessage() for r in credactor_caplog.records]
        assert any(
            '--from-trufflehog requires a directory target' in m and 'TruffleHog report' in m
            for m in msgs
        )


class TestNoColorEnv:
    """P1 quick win: honor the NO_COLOR convention (no-color.org)."""

    def test_no_color_env_disables_color(self, monkeypatch):
        monkeypatch.setenv('NO_COLOR', '1')
        assert _config_from_args(build_parser().parse_args([])).no_color is True

    def test_empty_no_color_does_not_disable(self, monkeypatch):
        monkeypatch.setenv('NO_COLOR', '')  # convention: empty value = not set
        assert _config_from_args(build_parser().parse_args([])).no_color is False

    def test_absent_no_color_keeps_default(self, monkeypatch):
        monkeypatch.delenv('NO_COLOR', raising=False)
        assert _config_from_args(build_parser().parse_args([])).no_color is False


class TestJsonSkippedNotice:
    """P1/#1B: a default scan must not imply 'clean' when .json files were held
    back (they are only scanned under --scan-json)."""

    def test_notice_when_json_present_and_not_scanned(self, tmp_dir, capsys):
        with open(os.path.join(tmp_dir, 'data.json'), 'w') as f:
            f.write('{"k": "v"}\n')
        with pytest.raises(SystemExit):
            main(['--dry-run', tmp_dir])
        err = capsys.readouterr().err
        assert '.json file(s) present but not scanned' in err


class TestExitCodeEdgeBranches:
    """Three small exit paths that had no coverage: a non-text format WITH
    findings exits 1; Ctrl-C anywhere in main exits 130; declining the
    --fix-all confirmation aborts with exit 1 and touches nothing."""

    def _make_secret(self, tmp_dir):
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        path = os.path.join(tmp_dir, 'app.py')
        with open(path, 'w') as f:
            f.write(f'aws = "{key}"\n')
        return path, key

    def test_json_format_with_findings_exits_1(self, tmp_dir, capsys):
        self._make_secret(tmp_dir)
        with pytest.raises(SystemExit) as exc:
            main(['--format', 'json', tmp_dir])
        assert exc.value.code == 1
        assert '"count": 1' in capsys.readouterr().out

    def test_keyboard_interrupt_exits_130(self, monkeypatch, capsys):
        def boom(argv=None):
            raise KeyboardInterrupt

        monkeypatch.setattr('credactor.cli._main_inner', boom)
        with pytest.raises(SystemExit) as exc:
            main([])
        assert exc.value.code == 130
        assert 'Interrupted' in capsys.readouterr().err

    def test_fix_all_decline_aborts_exit_1(self, tmp_dir, monkeypatch, capsys):
        # isatty=True so the answer branch is what's covered here — without
        # it the TTY gate aborts first and 'n' is never read.
        path, key = self._make_secret(tmp_dir)
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
        monkeypatch.setattr('builtins.input', lambda *a: 'n')
        with pytest.raises(SystemExit) as exc:
            main(['--fix-all', tmp_dir])
        assert exc.value.code == 1
        assert 'Aborted' in capsys.readouterr().out
        with open(path) as f:
            assert key in f.read()  # nothing was redacted


class TestScanJsonEndToEnd:
    """S33: --scan-json detection end-to-end — a secret whose only home is a
    .json file flips the exit code only when the flag is passed (the flag's
    actual scanning branch was previously untested; only the skip notice was)."""

    def _make_json_secret(self, tmp_dir):
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(os.path.join(tmp_dir, 'cfg.json'), 'w') as f:
            f.write(f'{{"aws_key": "{key}"}}\n')

    def test_json_secret_found_with_flag(self, tmp_dir):
        self._make_json_secret(tmp_dir)
        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', '--scan-json', tmp_dir])
        assert exc.value.code == 1

    def test_json_secret_missed_without_flag(self, tmp_dir):
        self._make_json_secret(tmp_dir)
        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', tmp_dir])
        assert exc.value.code == 0

    def test_interactive_mode_scans_json_without_picker(self, tmp_dir, monkeypatch, capsys):
        # --scan-json is the explicit opt-in: interactive mode scans all
        # collected .json like every other mode. The former numbered
        # file-picker prompt is gone — the only prompt is Replace?.
        self._make_json_secret(tmp_dir)
        monkeypatch.setattr(sys.stdin, 'isatty', lambda: True)
        monkeypatch.setattr('builtins.input', lambda *a: 'n')
        with pytest.raises(SystemExit) as exc:
            main(['--scan-json', tmp_dir])
        assert exc.value.code == 1  # found, then skipped at the prompt
        out = capsys.readouterr().out
        assert 'Selection' not in out  # no picker prompt
        assert 'INTERACTIVE REDACTION' in out  # went straight to review


class TestCredactorignoreFileTarget:
    """MV-2: .credactorignore loads only for a directory scan (its root is the
    scanned dir). A single-file target never applies one, so warn when an ignore
    file sits beside the target instead of suppressing nothing silently."""

    _KEY = 'AKIA4HJR6WPT3XLQ8NVB'

    def test_file_target_warns_credactorignore_inert(self, make_file, tmp_dir, credactor_caplog):
        # The glob would suppress this file on a DIR scan (-> 0), but is inert
        # for the file target (finding stays -> exit 1). The miss must not be
        # silent: a default-visible WARN names it.
        path = make_file('app.py', f'aws_key = "{self._KEY}"\n')
        Path(tmp_dir, '.credactorignore').write_text('app.py\n', encoding='utf-8')

        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', path])

        assert exc.value.code == 1  # NOT suppressed — proves the inertness
        assert any(
            'single-file target' in r.getMessage() and r.levelname == 'WARNING'
            for r in credactor_caplog.records
        )

    def test_file_target_no_warn_without_ignore_file(self, make_file, credactor_caplog):
        # No .credactorignore present -> no spurious warning on a normal scan.
        path = make_file('app.py', f'aws_key = "{self._KEY}"\n')

        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', path])

        assert exc.value.code == 1
        assert not any('single-file target' in r.getMessage() for r in credactor_caplog.records)

    def test_dir_target_applies_credactorignore_and_no_warn(
        self, make_file, tmp_dir, credactor_caplog
    ):
        # The directory scan still loads and applies .credactorignore (-> 0) and
        # does NOT emit the single-file-target warning.
        make_file('app.py', f'aws_key = "{self._KEY}"\n')
        Path(tmp_dir, '.credactorignore').write_text('app.py\n', encoding='utf-8')

        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', tmp_dir])

        assert exc.value.code == 0  # suppressed by the glob
        assert not any('single-file target' in r.getMessage() for r in credactor_caplog.records)
