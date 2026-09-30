"""Tests for CLI argument parsing and main entry point."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest import mock

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

    def test_suppressed_pem_header_does_not_hide_a_key_after_it(self, make_file):
        # SR-08: an ignored header used to hide every following line.
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        path = make_file(
            'k.py', f'-----BEGIN RSA PRIVATE KEY-----  # credactor:ignore\napi_key = "{key}"\n'
        )
        with pytest.raises(SystemExit) as exc_info:
            main(['--ci', os.path.dirname(path)])
        assert exc_info.value.code == 1

    @pytest.mark.parametrize(
        'error',
        [
            RuntimeError('boom\n::error::x'),
            OSError('boom\n::error::x'),
            ValueError('boom\n::error::x'),
            UnicodeDecodeError('utf-8', b'boom\n::error::x', 0, 1, 'boom'),
        ],
        ids=['runtime', 'os', 'value', 'decode'],
    )
    def test_unexpected_exception_exits_2_not_1(self, monkeypatch, capsys, error):
        # T15a: exit 1 means "findings found", so a crash must not use it.
        from credactor import cli

        def boom(argv):
            raise error

        monkeypatch.setattr(cli, '_main_inner', boom)
        with pytest.raises(SystemExit) as exc_info:
            main(['--ci', '.'])
        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert 'Traceback' in err
        assert f'{type(error).__name__}: ' in err
        assert not [ln for ln in err.split('\n') if ln.lstrip().startswith('::')]

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

    def test_directory_as_explicit_config_exits_2(self, tmp_dir, credactor_caplog):
        with pytest.raises(SystemExit) as exc_info:
            main(['--config', tmp_dir, '--dry-run', tmp_dir])
        assert exc_info.value.code == 2
        # K-1 parity with report paths: the directory exists, so 'not found'
        # would send the user chasing a phantom typo.
        assert 'Config path is not a regular file' in credactor_caplog.text

    @pytest.mark.skipif(os.name != 'posix', reason='symlinks are unreliable off POSIX')
    def test_dangling_symlink_explicit_config_exits_2(self, tmp_dir, credactor_caplog):
        link = os.path.join(tmp_dir, 'cfg.toml')
        os.symlink(os.path.join(tmp_dir, 'gone.toml'), link)
        with pytest.raises(SystemExit) as exc_info:
            main(['--config', link, '--dry-run', tmp_dir])
        assert exc_info.value.code == 2
        assert 'broken symlink' in credactor_caplog.text

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


class TestIngestIntoGit:
    """SR-16: an ingested finding under .git is reported but never rewritten."""

    TOKEN = 'ghp_' + 'Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78'

    def _project(self, tmp_path, rel='.git/config'):
        repo = tmp_path / 'repo'
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f'url = https://x:{self.TOKEN}@github.com/o/r.git\n', encoding='utf-8')
        return repo, target

    def _report(self, tmp_path, rel):
        report = tmp_path / 'gl.json'
        record = {
            'File': rel,
            'StartLine': 1,
            'Secret': self.TOKEN,
            'Match': self.TOKEN,
            'RuleID': 'github-pat',
            'Tags': [],
            'Commit': '',
            'SymlinkFile': '',
        }
        report.write_text(json.dumps([record]), encoding='utf-8')
        return report

    def _run(self, *argv):
        with pytest.raises(SystemExit) as exc_info:
            main(list(argv))
        return exc_info.value.code

    @pytest.mark.parametrize('rel', ['.git/config', '.git/hooks/pre-commit', 'sub/.git/config'])
    def test_fix_all_leaves_git_untouched_and_exits_1(self, tmp_path, rel, capsys):
        repo, target = self._project(tmp_path, rel)
        before = target.read_bytes()
        report = self._report(tmp_path, rel)
        code = self._run('--fix-all', '--yes', '--from-gitleaks', str(report), str(repo))
        assert code == 1
        assert target.read_bytes() == before
        assert not list(target.parent.glob('*.bak'))
        err = capsys.readouterr().err
        assert '.git' in err and 'not rewritten' in err

    def test_ci_still_reports_it(self, tmp_path, capsys):
        repo, _ = self._project(tmp_path)
        report = self._report(tmp_path, '.git/config')
        assert self._run('--ci', '-f', 'json', '--from-gitleaks', str(report), str(repo)) == 1
        data = json.loads(capsys.readouterr().out)
        assert data['count'] == 1

    def test_case_variant_on_a_case_insensitive_filesystem(self, tmp_path):
        repo, target = self._project(tmp_path)
        if not (repo / '.GIT' / 'config').exists():
            pytest.skip('case-sensitive filesystem')
        before = target.read_bytes()
        report = self._report(tmp_path, '.GIT/config')
        assert self._run('--fix-all', '--yes', '--from-gitleaks', str(report), str(repo)) == 1
        assert target.read_bytes() == before

    @pytest.mark.skipif(sys.platform == 'win32', reason='symlinks')
    def test_symlink_into_git(self, tmp_path):
        repo, target = self._project(tmp_path)
        (repo / 'alias.py').symlink_to(target)
        before = target.read_bytes()
        report = self._report(tmp_path, 'alias.py')
        assert self._run('--fix-all', '--yes', '--from-gitleaks', str(report), str(repo)) == 1
        assert target.read_bytes() == before

    @pytest.mark.skipif(sys.platform == 'win32', reason='symlinks')
    def test_git_that_is_a_symlink_to_another_directory(self, tmp_path):
        # The resolved path has no .git component; the path the report gave does.
        repo = tmp_path / 'repo'
        (repo / 'realgit').mkdir(parents=True)
        target = repo / 'realgit' / 'config'
        target.write_text(f'url = https://x:{self.TOKEN}@github.com/o/r.git\n', encoding='utf-8')
        (repo / '.git').symlink_to(repo / 'realgit')
        before = target.read_bytes()
        report = self._report(tmp_path, '.git/config')
        assert self._run('--fix-all', '--yes', '--from-gitleaks', str(report), str(repo)) == 1
        assert target.read_bytes() == before

    def test_git_file_of_a_worktree(self, tmp_path):
        repo = tmp_path / 'repo'
        repo.mkdir()
        (repo / '.git').write_text(f'gitdir: /tmp/{self.TOKEN}\n', encoding='utf-8')
        before = (repo / '.git').read_bytes()
        report = self._report(tmp_path, '.git')
        assert self._run('--fix-all', '--yes', '--from-gitleaks', str(report), str(repo)) == 1
        assert (repo / '.git').read_bytes() == before

    def test_config_file_ingest_is_named_before_writing(self, tmp_path, capsys):
        repo = tmp_path / 'repo'
        (repo / 'src').mkdir(parents=True)
        (repo / 'src' / 'a.py').write_text(f'k = "{self.TOKEN}"\n', encoding='utf-8')
        report = self._report(tmp_path, 'src/a.py')
        (repo / '.credactor.toml').write_text(
            f'[ingest]\nfrom_gitleaks = "{report.as_posix()}"\n', encoding='utf-8'
        )
        self._run('--fix-all', '--yes', '--config', str(repo / '.credactor.toml'), str(repo))
        assert f'Applying the Gitleaks report {report}' in capsys.readouterr().err


class TestIngestedValuesAtTheSink:
    """SR-15: an ingested value is only replaced where it stands as a whole
    token, and an implausible one is never written."""

    def _run_fix(self, tmp_path, secret, line_text):
        repo = tmp_path / 'repo'
        (repo / 'src').mkdir(parents=True)
        target = repo / 'src' / 'app.py'
        target.write_text(line_text + '\n', encoding='utf-8')
        report = tmp_path / 'gl.json'
        record = {
            'File': 'src/app.py',
            'StartLine': 1,
            'Secret': secret,
            'Match': line_text,
            'RuleID': 'generic-api-key',
            'Tags': [],
            'Commit': '',
            'SymlinkFile': '',
        }
        report.write_text(json.dumps([record]), encoding='utf-8')
        before = target.read_bytes()
        codes = []
        for argv in (['--ci'], ['--fix-all', '--yes', '--no-backup']):
            with pytest.raises(SystemExit) as exc_info:
                main([*argv, '--from-gitleaks', str(report), str(repo)])
            codes.append(exc_info.value.code)
        return codes, before, target.read_bytes()

    @pytest.mark.parametrize('secret', ['a', 'api', 'password'])
    def test_implausible_secret_leaves_the_file_alone(self, tmp_path, secret):
        codes, before, after = self._run_fix(tmp_path, secret, 'api_key = load_password()')
        assert codes == [1, 1]
        assert after == before

    def test_value_only_inside_a_longer_word_is_not_replaced(self, tmp_path, capsys):
        codes, before, after = self._run_fix(tmp_path, 'pass', 'password_hint = compass()')
        assert codes == [1, 1]
        assert after == before
        assert 'only inside a longer word' in capsys.readouterr().err

    def test_realistic_secret_still_redacts(self, tmp_path):
        codes, _, after = self._run_fix(tmp_path, 'Hx7Kq2Lm9Pz4Wr5', 'k = "Hx7Kq2Lm9Pz4Wr5"')
        assert codes == [1, 0]
        assert b'Hx7Kq2Lm9Pz4Wr5' not in after

    def test_whole_token_is_replaced_not_the_first_occurrence(self, tmp_path):
        from credactor.config import Config
        from credactor.redactor import batch_replace_in_file

        path = tmp_path / 'app.py'
        path.write_text('passport = "pass"\n', encoding='utf-8')
        finding = {
            'file': str(path),
            'line': 1,
            'type': 'external:gitleaks:generic-api-key',
            'severity': 'medium',
            'full_value': 'pass',
            'value_preview': 'pass',
            'raw': 'passport = "pass"',
        }
        assert batch_replace_in_file(str(path), [finding], Config(no_backup=True)) == (1, 0)
        assert path.read_text(encoding='utf-8').startswith('passport = "')
        assert '"pass"' not in path.read_text(encoding='utf-8')

    def test_env_mode_fallback_replaces_the_whole_token(self, tmp_path):
        # Not a quoted literal of its own, so env mode falls back to the sentinel.
        from credactor.config import Config
        from credactor.redactor import batch_replace_in_file

        path = tmp_path / 'app.py'
        path.write_text('note = "passport pass"\n', encoding='utf-8')
        finding = {
            'file': str(path),
            'line': 1,
            'type': 'external:gitleaks:generic-api-key',
            'severity': 'medium',
            'full_value': 'pass',
            'value_preview': 'pass',
            'raw': 'note = "passport pass"',
        }
        config = Config(no_backup=True, replace_mode='env')
        assert batch_replace_in_file(str(path), [finding], config) == (1, 0)
        assert path.read_text(encoding='utf-8') == 'note = "passport REDACTED_BY_CREDACTOR"\n'

    def test_password_in_a_connection_string_still_redacts(self, tmp_path):
        # ':' and '@' are token boundaries. Called on the sink directly: the
        # native scanner reports the whole URL, which would redact it first.
        from credactor.config import Config
        from credactor.redactor import batch_replace_in_file

        path = tmp_path / 'app.py'
        path.write_text(
            'DSN = "postgres://app:Hx7Kq2Lm9Pz4Wr5@db.example.com/app"\n', encoding='utf-8'
        )
        finding = {
            'file': str(path),
            'line': 1,
            'type': 'external:gitleaks:generic-api-key',
            'severity': 'medium',
            'full_value': 'Hx7Kq2Lm9Pz4Wr5',
            'value_preview': 'Hx7Kq2Lm9Pz4Wr5',
            'raw': path.read_text(encoding='utf-8').rstrip(),
        }
        assert batch_replace_in_file(str(path), [finding], Config(no_backup=True)) == (1, 0)
        after = path.read_text(encoding='utf-8')
        assert 'Hx7Kq2Lm9Pz4Wr5' not in after
        assert 'postgres://app:' in after and '@db.example.com/app' in after


class TestIngestedKeyHeaders:
    """SR-17: a report whose secret is a private key's BEGIN line is refused,
    whatever the rule is called, so the key is never left headerless."""

    _KEY = (
        '-----BEGIN ENCRYPTED PRIVATE KEY-----\n'
        'MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF0qFCzXY1CVHwPGVJP2XBpX3XY1p\n'
        '-----END ENCRYPTED PRIVATE KEY-----\n'
    )

    def _run(self, tmp_path, flag, report_text):
        repo = tmp_path / 'repo'
        repo.mkdir()
        target = repo / 'README.md'
        target.write_text(self._KEY, encoding='utf-8')
        report = tmp_path / 'report.json'
        report.write_text(report_text, encoding='utf-8')
        before = target.read_bytes()
        with pytest.raises(SystemExit) as exc_info:
            main(['--fix-all', '--yes', '--no-backup', flag, str(report), str(repo)])
        return exc_info.value.code, before, target.read_bytes()

    def test_gitleaks_header_only_secret_refused(self, tmp_path):
        record = {
            'File': 'README.md',
            'StartLine': 1,
            'Secret': '-----BEGIN ENCRYPTED PRIVATE KEY-----',
            'Match': '-----BEGIN ENCRYPTED PRIVATE KEY-----',
            'RuleID': 'private-key',
            'Tags': [],
            'Commit': '',
            'SymlinkFile': '',
        }
        code, before, after = self._run(tmp_path, '--from-gitleaks', json.dumps([record]))
        assert code == 1
        assert after == before

    def test_trufflehog_header_only_secret_refused(self, tmp_path):
        record = {
            'Raw': '-----BEGIN ENCRYPTED PRIVATE KEY-----',
            'SourceMetadata': {'Data': {'Filesystem': {'file': 'README.md', 'line': 1}}},
            'DetectorName': 'PrivateKey',
            'Verified': False,
        }
        code, before, after = self._run(tmp_path, '--from-trufflehog', json.dumps(record) + '\n')
        assert code == 1
        assert after == before


class TestMalformedReportFieldsCLI:
    """SR-19: a malformed report field neither crashes the run nor hides the
    finding."""

    def _run(self, tmp_path, capsys, **fields):
        repo = tmp_path / 'repo'
        repo.mkdir()
        (repo / 'app.py').write_text('k = "Hx7Kq2Lm9Pz4Wr5"\n', encoding='utf-8')
        record = {
            'File': 'app.py',
            'StartLine': 1,
            'Secret': 'Hx7Kq2Lm9Pz4Wr5',
            'Match': 'k = "Hx7Kq2Lm9Pz4Wr5"',
            'RuleID': 'generic-api-key',
            'Tags': [],
            'Commit': '',
            'SymlinkFile': '',
            **fields,
        }
        report = tmp_path / 'gl.json'
        report.write_text(json.dumps([record]), encoding='utf-8')
        with pytest.raises(SystemExit) as exc_info:
            main(['--ci', '-f', 'json', '--from-gitleaks', str(report), str(repo)])
        out, err = capsys.readouterr()
        assert 'Traceback' not in err
        return exc_info.value.code, out, err

    @pytest.mark.parametrize('rule_id', [[1], {'a': 1}, 7, None])
    def test_bad_rule_id_keeps_the_finding(self, tmp_path, capsys, rule_id):
        code, out, _ = self._run(tmp_path, capsys, RuleID=rule_id, Tags={'x': 1})
        assert code == 1
        types = {f['type'] for f in json.loads(out)['findings']}
        assert 'external:gitleaks:unknown' in types

    def test_secret_with_a_lone_surrogate_is_invalid(self, tmp_path, capsys):
        code, _, err = self._run(tmp_path, capsys, Secret='Hx7Kq2Lm9Pz4Wr5' + chr(0xD800))
        # No finding is left, so the run exits 0, and the warning says why.
        assert code == 0
        assert '1 Gitleaks record(s) skipped as invalid' in err


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


@pytest.mark.skipif(shutil.which('git') is None, reason='git not installed')
class TestStagedReadFailures:
    """SR-14: the pre-commit gate cannot call a commit clean when it could
    not read it."""

    def _repo(self, tmp_path):
        run = dict(cwd=tmp_path, check=True, capture_output=True)
        subprocess.run(['git', 'init', '-q'], **run)
        subprocess.run(['git', 'config', 'user.email', 't@t'], **run)
        subprocess.run(['git', 'config', 'user.name', 't'], **run)
        (tmp_path / 'app.py').write_text('x = 1\n', encoding='utf-8')
        subprocess.run(['git', 'add', 'app.py'], **run)
        return tmp_path

    def test_corrupt_index_exits_2(self, tmp_path):
        repo = self._repo(tmp_path)
        subprocess.run(['git', 'commit', '-qm', 'x'], cwd=repo, check=True, capture_output=True)
        index = repo / '.git' / 'index'
        index.write_bytes(b'DIRC\0\0\0\2\0\0\0\5garbage')
        with pytest.raises(SystemExit) as exc_info:
            main(['--staged', '--ci', str(repo)])
        assert exc_info.value.code == 2
        assert index.read_bytes() == b'DIRC\0\0\0\2\0\0\0\5garbage'  # left alone

    def test_unreadable_staged_blob_exits_2_without_fail_on_error(self, tmp_path, capsys):
        repo = self._repo(tmp_path)
        real_run = subprocess.run

        def run(args, **kwargs):
            if args[:2] == ['git', 'show']:
                return subprocess.CompletedProcess(args, 128, b'', b'fatal: bad object')
            return real_run(args, **kwargs)

        with (
            mock.patch('credactor.walker.subprocess.run', side_effect=run),
            pytest.raises(SystemExit) as exc_info,
        ):
            main(['--staged', '--ci', str(repo)])
        assert exc_info.value.code == 2
        assert 'staged file(s) could not be read' in capsys.readouterr().err


@pytest.mark.skipif(shutil.which('git') is None, reason='git not installed')
class TestStagedEntries:
    """What --staged reads from the index."""

    _KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'

    def _git(self, repo, *args):
        return subprocess.run(
            ['git', '-c', 'user.email=t@t', '-c', 'user.name=t', *args],
            cwd=repo,
            check=True,
            capture_output=True,
        )

    def _repo(self, path):
        path.mkdir(parents=True, exist_ok=True)
        self._git(path, 'init', '-q')
        (path / 'x.py').write_text('x = 1\n', encoding='utf-8')
        self._git(path, 'add', 'x.py')
        self._git(path, 'commit', '-qm', 'x')
        return path

    def _staged(self, repo):
        with pytest.raises(SystemExit) as exc_info:
            main(['--staged', '--ci', str(repo)])
        return exc_info.value.code

    def test_submodule_with_a_scanned_name_is_skipped(self, tmp_path):
        # A gitlink is a commit id with no blob in the superproject, so
        # showing it can fail ('bad object'); it must not be read at all, or
        # the hook would fail every commit that adds or bumps the submodule.
        sub = self._repo(tmp_path / 'sub')
        repo = self._repo(tmp_path / 'main')
        self._git(
            repo, '-c', 'protocol.file.allow=always', 'submodule', 'add', str(sub), 'lib/three.js'
        )
        real_run = subprocess.run

        def run(args, **kwargs):
            if args[:2] == ['git', 'show'] and args[2].endswith('lib/three.js'):
                return subprocess.CompletedProcess(args, 128, b'', b'fatal: bad object')
            return real_run(args, **kwargs)

        with mock.patch('credactor.walker.subprocess.run', side_effect=run):
            assert self._staged(repo) == 0

    @pytest.mark.skipif(sys.platform == 'win32', reason='file names with a colon')
    def test_path_that_looks_like_a_stage_number(self, tmp_path):
        # 'git show :0:x.py' would be stage 0 of x.py, not the file '0:x.py'.
        repo = self._repo(tmp_path / 'main')
        (repo / '0:x.py').write_text(f'k = "{self._KEY}"\n', encoding='utf-8')
        self._git(repo, 'add', '0:x.py')
        assert self._staged(repo) == 1

    @pytest.mark.skipif(sys.platform == 'win32', reason='symlinks')
    def test_symlink_replaced_by_a_file_is_scanned(self, tmp_path):
        repo = self._repo(tmp_path / 'main')
        (repo / 'cfg.py').symlink_to('x.py')
        self._git(repo, 'add', 'cfg.py')
        self._git(repo, 'commit', '-qm', 'link')
        (repo / 'cfg.py').unlink()
        (repo / 'cfg.py').write_text(f'k = "{self._KEY}"\n', encoding='utf-8')
        self._git(repo, 'add', 'cfg.py')
        assert self._staged(repo) == 1


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


class TestReportPathErrorAccuracy:
    """K-1 completion: a dangling-symlink report path exists in the directory
    listing, so 'file not found' (plus the CWD hint) is the phantom-typo chase
    the accuracy fix was written to end."""

    @pytest.mark.skipif(os.name != 'posix', reason='symlinks are unreliable off POSIX')
    def test_dangling_symlink_report_path_exits_2_named(self, tmp_dir, credactor_caplog):
        link = os.path.join(tmp_dir, 'gl.json')
        os.symlink(os.path.join(tmp_dir, 'gone.json'), link)
        with pytest.raises(SystemExit) as exc_info:
            main(['--from-gitleaks', link, '--dry-run', tmp_dir])
        assert exc_info.value.code == 2
        assert 'broken symlink' in credactor_caplog.text
        assert 'file not found' not in credactor_caplog.text


class TestIngestConfigEmptyPathExitsTwo:
    """The config spelling of an empty ingest path is as fatal as the flag
    spelling — previously it silently disabled ingestion and could exit 0."""

    def test_empty_ingest_path_in_config_exits_2(self, tmp_dir, credactor_caplog):
        cfg = os.path.join(tmp_dir, 'cred.toml')
        with open(cfg, 'w', encoding='utf-8') as f:
            f.write('[ingest]\nfrom_gitleaks = ""\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--config', cfg, '--ci', tmp_dir])
        assert exc_info.value.code == 2
        assert 'ingest.from_gitleaks is empty' in credactor_caplog.text


class TestStagedHistoryModeGuards:
    """Conflicting or unsupported mode/target pairings must fail loudly with
    exit 2 — not silently drop a scan or traceback with exit 1."""

    def test_staged_plus_scan_history_exits_2(self):
        # Dispatch would run --staged and never reach the history scan: a repo
        # whose only secret lives in history would gate green.
        with pytest.raises(SystemExit) as exc:
            _validate_invocation(Config(staged_only=True, scan_history=True))
        assert exc.value.code == 2

    def test_staged_or_history_with_file_target_exits_2(self, make_file):
        path = make_file('lone.py', 'x = 1\n')
        for cfg in (
            Config(staged_only=True, target=path),
            Config(scan_history=True, target=path),
        ):
            with pytest.raises(SystemExit) as exc:
                _validate_invocation(cfg)
            assert exc.value.code == 2


class TestNonRegularTarget:
    """A FIFO/device named directly as the target used to fall into the
    directory branch, walk nothing, and report a clean [OK] exit 0 — a silent
    no-op on an explicitly named target."""

    @pytest.mark.skipif(os.name != 'posix', reason='mkfifo is POSIX-only')
    def test_fifo_target_exits_2(self, tmp_dir, credactor_caplog):
        fifo = os.path.join(tmp_dir, 'pipe.txt')
        os.mkfifo(fifo)
        with pytest.raises(SystemExit) as exc_info:
            main(['--dry-run', fifo])
        assert exc_info.value.code == 2
        assert 'not a regular file or directory' in credactor_caplog.text


# ---------------------------------------------------------------------------
# Betterleaks ingestion (--from-betterleaks) — CLI surface
# ---------------------------------------------------------------------------
# Every value below is low-entropy filler ('aaaaaaaaaa' and friends): the native
# scanner ignores it, so any finding in the output can only have come from the
# ingested report. No credential literal is written to disc by these tests.


def _bl_finding(**kwargs) -> dict:
    """Return a minimal valid Betterleaks finding object, overridden by kwargs.

    Keys are the Go field names verbatim, exactly as the real 1.8.1 binary
    writes them (no struct tags), including the deprecated-but-populated
    File/SymlinkFile/Commit mirrors.
    """
    base = {
        'RuleID': 'generic-api-key',
        'Description': 'Generic API Key',
        'StartLine': 1,
        'EndLine': 1,
        'StartColumn': 1,
        'EndColumn': 22,
        'Match': 'api_key = "aaaaaaaaaa"',
        'Secret': 'aaaaaaaaaa',
        'Attributes': {'path': 'src/config.py', 'resource': 'fs.content'},
        'Tags': [],
        'Fingerprint': 'src/config.py:generic-api-key:1',
        'File': 'src/config.py',
        'SymlinkFile': '',
        'Commit': '',
        'Entropy': 2.5,
        'Author': '',
        'Email': '',
        'Date': '',
        'Message': '',
    }
    base.update(kwargs)
    return base


def _write_bl_report(tmp_dir: str, payload, name: str = 'bl.json') -> str:
    """Write a Betterleaks JSON report; ``payload=None`` writes literal ``null``,
    which is what Betterleaks emits for a zero-finding scan."""
    path = os.path.join(tmp_dir, name)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f)
    return path


def _make_bl_repo(tmp_dir: str, name: str = 'repo') -> str:
    """Create a repo dir holding src/config.py with a filler value the native
    scanner does not flag, so exit codes attribute cleanly to ingestion."""
    repo = os.path.join(tmp_dir, name)
    os.makedirs(os.path.join(repo, 'src'))
    _bl_write_source(repo, 'src/config.py', 'aaaaaaaaaa')
    return repo


def _bl_write_source(repo: str, rel: str, value: str) -> str:
    """Write ``api_key = "<value>"`` at <repo>/<rel> and return the path."""
    path = os.path.join(repo, *rel.split('/'))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f'api_key = "{value}"\n')
    return path


def _bl_types(capsys) -> list[str]:
    """Return the 'type' of every finding in a --format json run's stdout."""
    return [f['type'] for f in json.loads(capsys.readouterr().out)['findings']]


class TestBetterleaksParserSurface:
    """--from-betterleaks must exist on the parser as a third, independent ingest
    source, default to None, and reach Config unchanged.

    Prevents: a flag that parses but is never carried into Config — the report
    would be silently ignored and an ingesting gate would read clean. The
    None default is what distinguishes 'flag not passed' from an explicit
    empty value, so CLI-beats-config precedence depends on it.
    """

    def test_default_is_none(self):
        assert build_parser().parse_args([]).from_betterleaks is None

    def test_dest_captures_the_value(self):
        args = build_parser().parse_args(['--from-betterleaks', '/tmp/bl.json'])
        assert args.from_betterleaks == '/tmp/bl.json'

    def test_config_from_args_maps_the_flag(self):
        args = build_parser().parse_args(['--from-betterleaks', '/tmp/bl.json', '/tmp/x'])
        config = _config_from_args(args)
        assert config.from_betterleaks == '/tmp/bl.json'
        # C1: the third source must not disturb the two that already work.
        assert config.from_gitleaks is None
        assert config.from_trufflehog is None


class TestBetterleaksEmptyFlagIsFatal:
    """--from-betterleaks "" is a user error (exit 2), never a silent disable.

    Prevents: an unset shell var collapsing the flag to "" and quietly turning
    an ingesting run into a native-only one. Worse, it must not clobber a
    .credactor.toml [ingest] source into a false-clean exit 0. Same contract as
    --from-gitleaks "" and --replacement "".
    """

    def test_empty_value_exits_2(self, tmp_dir):
        repo = _make_bl_repo(tmp_dir)
        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', '--from-betterleaks', '', repo])
        assert exc.value.code == 2

    def test_empty_value_does_not_clobber_config_source(self, tmp_dir, credactor_caplog):
        repo = _make_bl_repo(tmp_dir)
        cfg_report = _write_bl_report(tmp_dir, [_bl_finding()], name='cfg.json')
        with open(os.path.join(repo, '.credactor.toml'), 'w', encoding='utf-8') as f:
            f.write('[ingest]\n')
            # as_posix(): a Windows path's backslashes are escape sequences
            # inside a double-quoted TOML string (parse error -> config ignored).
            f.write(f'from_betterleaks = "{Path(cfg_report).as_posix()}"\n')
        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', '--from-betterleaks', '', repo])
        assert exc.value.code == 2  # fails closed, not a silent drop to 0
        assert '--from-betterleaks requires a non-empty report path' in credactor_caplog.text


class TestBetterleaksScanHistoryRejection:
    """--scan-history plus --from-betterleaks exits 2, and the message names the
    flag the user actually passed.

    Prevents: history mode (committed content) silently swallowing an ingest
    source that references on-disc files, and a rejection message that lists
    only the two older flags so the user cannot tell which one is at fault.
    """

    def test_validate_invocation_rejects_the_pair(self):
        config = Config(scan_history=True, from_betterleaks='/tmp/bl.json')
        with pytest.raises(SystemExit) as exc:
            _validate_invocation(config)
        assert exc.value.code == 2

    def test_cli_message_names_the_flag(self, tmp_dir, credactor_caplog):
        repo = _make_bl_repo(tmp_dir)
        report = _write_bl_report(tmp_dir, [])
        with pytest.raises(SystemExit) as exc:
            main(['--scan-history', '--from-betterleaks', report, repo])
        assert exc.value.code == 2
        msgs = [r.getMessage() for r in credactor_caplog.records]
        assert any(
            '--scan-history cannot be combined with' in m and '--from-betterleaks' in m
            for m in msgs
        )


class TestBetterleaksFileTargetRejection:
    """--from-betterleaks against a file target exits 2 with a message naming the
    flag and the scanner.

    Prevents: report paths (relative to a repo root) being joined onto a single
    file, which resolves nothing and would report a clean run.
    """

    def test_file_target_exits_2(self, tmp_dir, credactor_caplog):
        repo = _make_bl_repo(tmp_dir)
        report = _write_bl_report(tmp_dir, [])
        with pytest.raises(SystemExit) as exc:
            main(['--from-betterleaks', report, os.path.join(repo, 'src', 'config.py')])
        assert exc.value.code == 2
        msgs = [r.getMessage() for r in credactor_caplog.records]
        assert any(
            '--from-betterleaks requires a directory target' in m and 'Betterleaks report' in m
            for m in msgs
        )


class TestBetterleaksReportPathErrors:
    """A report path that is missing, not a regular file, or unreadable exits 2
    with a message that distinguishes the three cases and names Betterleaks.

    Prevents: the phantom-typo chase — 'file not found' for a path plainly
    visible in a directory listing — and prevents an unreadable report
    tracebacking (exit 1, which a gate reads as 'findings') instead of the
    contracted fatal exit 2.
    """

    def test_missing_report_exits_2(self, tmp_dir, credactor_caplog):
        repo = _make_bl_repo(tmp_dir)
        missing = os.path.join(tmp_dir, 'nope.json')  # absolute: no CWD hint
        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', '--from-betterleaks', missing, repo])
        assert exc.value.code == 2
        assert any('Betterleaks file not found' in r.getMessage() for r in credactor_caplog.records)

    def test_directory_report_path_exits_2(self, tmp_dir, credactor_caplog):
        repo = _make_bl_repo(tmp_dir)
        as_dir = os.path.join(tmp_dir, 'report.json')
        os.makedirs(as_dir)
        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', '--from-betterleaks', as_dir, repo])
        assert exc.value.code == 2
        assert 'Betterleaks report path is not a regular file' in credactor_caplog.text
        assert 'Betterleaks file not found' not in credactor_caplog.text

    @_NOT_ROOT
    def test_unreadable_report_exits_2(self, tmp_dir, credactor_caplog):
        repo = _make_bl_repo(tmp_dir)
        report = _write_bl_report(tmp_dir, [_bl_finding()])
        os.chmod(report, 0o000)
        try:
            with pytest.raises(SystemExit) as exc:
                main(['--dry-run', '--from-betterleaks', report, repo])
        finally:
            os.chmod(report, 0o600)
        assert exc.value.code == 2
        assert 'Cannot open Betterleaks file' in credactor_caplog.text


class TestBetterleaksNullReportIsClean:
    """D0, the must-fix: a Betterleaks report that is literal `null` (what the
    binary writes for a zero-finding scan) over an otherwise-clean tree exits 0.

    Prevents: the worst CI failure mode there is — a CLEAN upstream scan turning
    the build red. Without the null coercion the non-list guard fires and the
    run exits 2 with 'must be a JSON array at top level (got NoneType)', so
    every clean run of the gate fails with a malformed-report message.
    """

    def test_null_report_clean_tree_exits_0(self, tmp_dir, credactor_caplog):
        repo = _make_bl_repo(tmp_dir)
        report = _write_bl_report(tmp_dir, None)
        with open(report, encoding='utf-8') as f:
            assert f.read().strip() == 'null'  # the exact bytes betterleaks writes
        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', '--from-betterleaks', report, repo])
        assert exc.value.code == 0
        assert 'must be a JSON array at top level' not in credactor_caplog.text

    def test_null_report_still_exits_1_on_a_native_finding(self, tmp_dir):
        """A null report is empty, not a mute: the native scan still gates."""
        repo = _make_bl_repo(tmp_dir)
        # credactor:ignore
        _bl_write_source(repo, 'src/aws.py', 'AKIA' + 'IOSFODNN7EXAMPLE')
        report = _write_bl_report(tmp_dir, None)
        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', '--from-betterleaks', report, repo])
        assert exc.value.code == 1


class TestBetterleaksCliBeatsConfigFile:
    """An explicit --from-betterleaks overrides a same-kind [ingest]
    from_betterleaks entry in .credactor.toml (CLI > config > default).

    Prevents: a stale config-file report silently winning over the one the user
    named on the command line. The CLI report carries a finding (exit 1) while
    the config report is a clean `null` (exit 0), so the exit code alone proves
    which report was actually ingested.
    """

    def test_cli_report_wins(self, tmp_dir):
        repo = _make_bl_repo(tmp_dir)
        cli_report = _write_bl_report(tmp_dir, [_bl_finding()], name='cli.json')
        cfg_report = _write_bl_report(tmp_dir, None, name='cfg.json')
        with open(os.path.join(repo, '.credactor.toml'), 'w', encoding='utf-8') as f:
            f.write('[ingest]\n')
            # as_posix(): a Windows path's backslashes are escape sequences
            # inside a double-quoted TOML string (parse error -> config ignored).
            f.write(f'from_betterleaks = "{Path(cfg_report).as_posix()}"\n')
        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', '--from-betterleaks', cli_report, repo])
        assert exc.value.code == 1  # the CLI report's finding

    def test_config_file_source_is_consumed_when_no_flag(self, tmp_dir):
        """The config spelling works on its own — the flag is not the only path in."""
        repo = _make_bl_repo(tmp_dir)
        cfg_report = _write_bl_report(tmp_dir, [_bl_finding()], name='cfg.json')
        with open(os.path.join(repo, '.credactor.toml'), 'w', encoding='utf-8') as f:
            f.write('[ingest]\n')
            f.write(f'from_betterleaks = "{Path(cfg_report).as_posix()}"\n')
        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', repo])
        assert exc.value.code == 1


class TestBetterleaksEndToEnd:
    """A valid Betterleaks report over a real tree produces findings attributed
    to Betterleaks and exits 1.

    Prevents: D1 regressing to the Gitleaks type string. Provenance is not
    cosmetic — the last colon segment drives --replace-with env variable names,
    and a mislabelled finding tells the user the wrong scanner found it.
    """

    def test_finding_type_is_external_betterleaks(self, tmp_dir, capsys):
        repo = _make_bl_repo(tmp_dir)
        report = _write_bl_report(tmp_dir, [_bl_finding()])
        with pytest.raises(SystemExit) as exc:
            main(['--format', 'json', '--dry-run', '--from-betterleaks', report, repo])
        assert exc.value.code == 1
        types = _bl_types(capsys)
        assert types == ['external:betterleaks:generic-api-key']
        assert all(t.startswith('external:betterleaks:') for t in types)

    def test_attributes_path_only_report_is_ingested(self, tmp_dir, capsys):
        """Attributes['path'] alone is enough — the deprecated File mirror may go."""
        repo = _make_bl_repo(tmp_dir)
        finding = _bl_finding(File='', SymlinkFile='')
        report = _write_bl_report(tmp_dir, [finding])
        with pytest.raises(SystemExit) as exc:
            main(['--format', 'json', '--dry-run', '--from-betterleaks', report, repo])
        assert exc.value.code == 1
        assert _bl_types(capsys) == ['external:betterleaks:generic-api-key']


class TestRedactedReportWritesNoBytes:
    """A report made with the scanner's own ``--redact`` flag must abort the run
    (exit 2) with the tree untouched.

    Prevents the whole-file corruption it used to cause. ``--redact`` writes the
    literal ``REDACTED`` into ``Secret``, the redactor applies ``full_value`` as
    a substring replacement and then sweeps the file for further copies, and
    every line holding that word was rewritten, including Credactor's own
    ``REDACTED_BY_CREDACTOR`` sentinel, which is what a re-scan of an
    already-redacted tree reports. The run then claimed ``1 replaced | 0 failed``
    and exited 0, so nothing in the gate signalled the damage, and under
    --no-backup the originals were gone.
    """

    def test_fix_all_aborts_and_leaves_the_tree_byte_identical(self, tmp_dir):
        repo = _make_bl_repo(tmp_dir)
        source = _bl_write_source(repo, 'src/config.py', 'REDACTED_BY_CREDACTOR')
        before = Path(source).read_bytes()
        report = _write_bl_report(
            tmp_dir,
            [_bl_finding(Secret='REDACTED', Match='api_key = "REDACTED"')],
        )
        with pytest.raises(SystemExit) as exc:
            main(['--from-betterleaks', report, '--fix-all', '--yes', '--no-backup', repo])
        assert exc.value.code == 2
        assert Path(source).read_bytes() == before
        assert not list(Path(repo).rglob('*.bak'))


class TestBetterleaksCombinedWithOtherSources:
    """All three ingest sources may be named in one invocation; each contributes
    its own findings under its own type string.

    Prevents: a third source turning the two-source condition into an
    either/or — one flag winning and the others' reports being dropped without
    a word, which is a silent partial gate.
    """

    def test_three_sources_in_one_run(self, tmp_dir, capsys):
        repo = _make_bl_repo(tmp_dir)
        _bl_write_source(repo, 'src/other.py', 'bbbbbbbbbb')
        _bl_write_source(repo, 'src/third.py', 'cccccccccc')

        gl_report = os.path.join(tmp_dir, 'gl.json')
        with open(gl_report, 'w', encoding='utf-8') as f:
            json.dump(
                [
                    {
                        'File': 'src/config.py',
                        'StartLine': 1,
                        'Secret': 'aaaaaaaaaa',
                        'Match': 'api_key = "aaaaaaaaaa"',
                        'RuleID': 'generic-api-key',
                        'Tags': [],
                        'Commit': '',
                        'SymlinkFile': '',
                    }
                ],
                f,
            )

        th_report = os.path.join(tmp_dir, 'th.jsonl')
        with open(th_report, 'w', encoding='utf-8') as f:
            f.write(
                json.dumps(
                    {
                        'DetectorName': 'CustomRegex',
                        'Raw': 'bbbbbbbbbb',
                        'Verified': False,
                        'SourceMetadata': {
                            'Data': {'Filesystem': {'file': 'src/other.py', 'line': 1}}
                        },
                    }
                )
                + '\n'
            )

        bl_report = _write_bl_report(
            tmp_dir,
            [
                _bl_finding(
                    Secret='cccccccccc',
                    Match='api_key = "cccccccccc"',
                    File='src/third.py',
                    Attributes={'path': 'src/third.py', 'resource': 'fs.content'},
                )
            ],
        )

        with pytest.raises(SystemExit) as exc:
            main(
                [
                    '--format',
                    'json',
                    '--dry-run',
                    '--from-gitleaks',
                    gl_report,
                    '--from-trufflehog',
                    th_report,
                    '--from-betterleaks',
                    bl_report,
                    repo,
                ]
            )
        assert exc.value.code == 1
        types = _bl_types(capsys)
        assert 'external:gitleaks:generic-api-key' in types
        assert 'external:trufflehog:CustomRegex' in types
        assert 'external:betterleaks:generic-api-key' in types


class TestBetterleaksDispatchOrder:
    """The documented dedup priority Credactor > Gitleaks > TruffleHog >
    Betterleaks is produced ONLY by the append order of the three ``if`` blocks
    in ``cli._ingest_external``; nothing in ingest.py asserts it.

    Prevents: reordering those blocks, which would silently change a documented,
    user-visible ``type`` string on every cross-scanner duplicate while the rest
    of the suite stayed green. The severity merge is order-independent, so the
    type string is the only observable, which is exactly why it needs pinning.
    """

    def test_trufflehog_identity_beats_betterleaks_on_a_duplicate(self, tmp_dir, capsys):
        repo = _make_bl_repo(tmp_dir)
        secret = 'z' * 24
        _bl_write_source(repo, 'src/dup.py', secret)

        th_report = os.path.join(tmp_dir, 'th.ndjson')
        with open(th_report, 'w', encoding='utf-8') as f:
            f.write(
                json.dumps(
                    {
                        'Raw': secret,
                        'DetectorName': 'AWS',
                        'SourceMetadata': {
                            'Data': {'Filesystem': {'file': 'src/dup.py', 'line': 1}}
                        },
                    }
                )
                + '\n'
            )
        bl_report = _write_bl_report(
            tmp_dir,
            [
                _bl_finding(
                    Secret=secret,
                    Attributes={'path': 'src/dup.py', 'resource': 'fs.content'},
                    File='src/dup.py',
                    Fingerprint='src/dup.py:generic-api-key:1',
                )
            ],
        )

        with pytest.raises(SystemExit) as exc:
            main(
                [
                    repo,
                    '--ci',
                    '--format',
                    'json',
                    '--from-trufflehog',
                    th_report,
                    '--from-betterleaks',
                    bl_report,
                ]
            )
        assert exc.value.code == 1
        types = _bl_types(capsys)
        # One surviving finding for the shared file:line:value, and TruffleHog
        # keeps the identity because it is dispatched first.
        dup = [t for t in types if t.endswith(':AWS') or 'betterleaks' in t]
        assert dup == ['external:trufflehog:AWS'], types


class TestBetterleaksLeavesGitleaksAlone:
    """C1 regression guard: --from-gitleaks behaves exactly as it did before,
    whether or not --from-betterleaks is also passed.

    Prevents: the third source being wired in by widening the Gitleaks path.
    A Gitleaks report must still yield external:gitleaks: types, and adding an
    empty Betterleaks report alongside must change neither the reported
    findings nor the exit code.
    """

    def _gitleaks_report(self, tmp_dir: str) -> str:
        report = os.path.join(tmp_dir, 'gl.json')
        with open(report, 'w', encoding='utf-8') as f:
            json.dump(
                [
                    {
                        'File': 'src/config.py',
                        'StartLine': 1,
                        'Secret': 'aaaaaaaaaa',
                        'Match': 'api_key = "aaaaaaaaaa"',
                        'RuleID': 'generic-api-key',
                        'Tags': [],
                        'Commit': '',
                        'SymlinkFile': '',
                    }
                ],
                f,
            )
        return report

    def test_gitleaks_output_unchanged_by_a_betterleaks_flag(self, tmp_dir, capsys):
        repo = _make_bl_repo(tmp_dir)
        gl_report = self._gitleaks_report(tmp_dir)
        bl_report = _write_bl_report(tmp_dir, None)  # clean: contributes nothing

        with pytest.raises(SystemExit) as exc:
            main(['--format', 'json', '--dry-run', '--from-gitleaks', gl_report, repo])
        alone_code, alone_out = exc.value.code, capsys.readouterr().out

        with pytest.raises(SystemExit) as exc:
            main(
                [
                    '--format',
                    'json',
                    '--dry-run',
                    '--from-gitleaks',
                    gl_report,
                    '--from-betterleaks',
                    bl_report,
                    repo,
                ]
            )
        both_code, both_out = exc.value.code, capsys.readouterr().out

        assert alone_code == both_code == 1
        assert json.loads(alone_out) == json.loads(both_out)
        assert json.loads(both_out)['findings'][0]['type'] == 'external:gitleaks:generic-api-key'

    def test_gitleaks_type_survives_a_populated_betterleaks_report(self, tmp_dir, capsys):
        repo = _make_bl_repo(tmp_dir)
        _bl_write_source(repo, 'src/third.py', 'cccccccccc')
        gl_report = self._gitleaks_report(tmp_dir)
        bl_report = _write_bl_report(
            tmp_dir,
            [
                _bl_finding(
                    Secret='cccccccccc',
                    Match='api_key = "cccccccccc"',
                    File='src/third.py',
                    Attributes={'path': 'src/third.py', 'resource': 'fs.content'},
                )
            ],
        )
        with pytest.raises(SystemExit) as exc:
            main(
                [
                    '--format',
                    'json',
                    '--dry-run',
                    '--from-gitleaks',
                    gl_report,
                    '--from-betterleaks',
                    bl_report,
                    repo,
                ]
            )
        assert exc.value.code == 1
        types = _bl_types(capsys)
        assert 'external:gitleaks:generic-api-key' in types
        assert 'external:betterleaks:generic-api-key' in types
