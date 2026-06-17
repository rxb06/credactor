"""Tests for the redaction/replacement logic."""

import os
import sys

import pytest

from credactor.config import Config
from credactor.redactor import (
    _derive_env_var_name,
    batch_replace_in_file,
    fix_all,
    interactive_review,
)

# Construct test credentials via concatenation so the tool doesn't self-redact
_AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'
_PASSWORD = 'xK9#mL2' + '$vQ7@nR5'


def _mk_finding(path, value, ftype='variable:api_key', line=1):
    return {'file': path, 'line': line, 'type': ftype, 'severity': 'high',
            'full_value': value, 'value_preview': '', 'raw': ''}


class TestSecureDelete:
    """P3: --secure-delete must leave no plaintext .bak behind (was untested)."""

    def test_secure_delete_removes_backup(self, make_file):
        config = Config(no_backup=False, secure_delete=True)
        path = make_file('secret.py', f'api_key = "{_AWS_KEY}"\n')
        replaced, failed = batch_replace_in_file(path, [_mk_finding(path, _AWS_KEY)], config)
        assert replaced == 1
        assert not os.path.exists(path + '.bak')      # backup securely deleted
        with open(path) as f:
            assert _AWS_KEY not in f.read()            # original redacted

    def test_backup_kept_without_secure_delete(self, make_file):
        config = Config(no_backup=False, secure_delete=False)
        path = make_file('secret.py', f'api_key = "{_AWS_KEY}"\n')
        batch_replace_in_file(path, [_mk_finding(path, _AWS_KEY)], config)
        assert os.path.exists(path + '.bak')           # contrast: .bak lingers


class TestBackup:
    def test_backup_created(self, make_file):
        config = Config(no_backup=False)
        path = make_file('secret.py', f'api_key = "{_AWS_KEY}"\n')
        finding = {
            'file': path,
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': _AWS_KEY,
            'value_preview': _AWS_KEY,
            'raw': f'api_key = "{_AWS_KEY}"',
        }
        batch_replace_in_file(path, [finding], config)
        assert os.path.exists(path + '.bak')
        with open(path + '.bak') as f:
            assert _AWS_KEY in f.read()

    def test_no_backup_flag(self, make_file):
        config = Config(no_backup=True)
        path = make_file('secret2.py', f'api_key = "{_AWS_KEY}"\n')
        finding = {
            'file': path,
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': _AWS_KEY,
            'value_preview': _AWS_KEY,
            'raw': f'api_key = "{_AWS_KEY}"',
        }
        batch_replace_in_file(path, [finding], config)
        assert not os.path.exists(path + '.bak')


class TestBatchReplace:
    def test_multiple_findings_same_file(self, make_file):
        config = Config(no_backup=True)
        content = f'api_key = "{_AWS_KEY}"\npassword = "{_PASSWORD}"\n'
        path = make_file('multi.py', content)
        findings = [
            {'file': path, 'line': 1, 'type': 'variable:api_key', 'severity': 'high',
             'full_value': _AWS_KEY, 'value_preview': '', 'raw': ''},
            {'file': path, 'line': 2, 'type': 'variable:password', 'severity': 'high',
             'full_value': _PASSWORD, 'value_preview': '', 'raw': ''},
        ]
        replaced, failed = batch_replace_in_file(path, findings, config)
        assert replaced == 2
        assert failed == 0
        with open(path) as f:
            text = f.read()
        assert _AWS_KEY not in text
        assert _PASSWORD not in text
        assert 'REDACTED_BY_CREDACTOR' in text

    def test_sentinel_replacement(self, make_file):
        config = Config(no_backup=True, replace_mode='sentinel',
                        custom_replacement='REDACTED_BY_CREDACTOR')
        path = make_file('sent.py', 'api_key = "mysecretkey123456"\n')
        finding = {'file': path, 'line': 1, 'type': 'variable:api_key',
                   'severity': 'high', 'full_value': 'mysecretkey123456',
                   'value_preview': '', 'raw': ''}
        batch_replace_in_file(path, [finding], config)
        with open(path) as f:
            assert 'REDACTED_BY_CREDACTOR' in f.read()

    @pytest.mark.skipif(sys.platform == 'win32',
                        reason='Windows does not support Unix-style permission bits')
    def test_preserves_file_permissions(self, make_file):
        config = Config(no_backup=True)
        path = make_file('perms.py', 'api_key = "mysecretkey123456"\n')
        os.chmod(path, 0o644)
        finding = {'file': path, 'line': 1, 'type': 'variable:api_key',
                   'severity': 'high', 'full_value': 'mysecretkey123456',
                   'value_preview': '', 'raw': ''}
        batch_replace_in_file(path, [finding], config)
        stat = os.stat(path)
        assert stat.st_mode & 0o777 == 0o644


class TestEnvVarReplacement:
    """H2: env-mode replacement must emit syntactically valid code — the env
    reference replaces the quoted literal, never nests inside the source quotes.

    Assertions check the FULL line (the prior substring checks passed on the
    broken nested-quote output, which is why the bug shipped).
    """

    _SECRET = 'mysecretkey123456'

    def _redact_env(self, make_file, name, content, value=None,
                    ftype='variable:api_key'):
        config = Config(no_backup=True, replace_mode='env')
        path = make_file(name, content)
        finding = _mk_finding(path, value or self._SECRET, ftype)
        batch_replace_in_file(path, [finding], config)
        with open(path) as f:
            return f.read()

    def test_python_env_ref(self, make_file):
        out = self._redact_env(make_file, 'envtest.py',
                               'api_key = "mysecretkey123456"\n')
        assert out == 'api_key = os.environ["API_KEY"]\n'
        compile(out, 'envtest.py', 'exec')   # H2: must be valid Python

    def test_python_env_ref_single_quote_source(self, make_file):
        # a single-quoted source must also have its quotes consumed, else the
        # env ref becomes a string literal instead of a lookup
        out = self._redact_env(make_file, 'sq.py',
                               "api_key = 'mysecretkey123456'\n")
        assert out == 'api_key = os.environ["API_KEY"]\n'
        compile(out, 'sq.py', 'exec')

    def test_js_env_ref(self, make_file):
        out = self._redact_env(make_file, 'envtest.js',
                               'const api_key = "mysecretkey123456";\n')
        assert out == 'const api_key = process.env["API_KEY"];\n'

    def test_ruby_env_ref(self, make_file):
        out = self._redact_env(make_file, 'app.rb',
                               'api_key = "mysecretkey123456"\n')
        assert out == "api_key = ENV['API_KEY']\n"

    def test_go_env_ref(self, make_file):
        out = self._redact_env(make_file, 'app.go',
                               'var api_key = "mysecretkey123456"\n')
        assert out == 'var api_key = os.Getenv("API_KEY")\n'

    def test_java_env_ref(self, make_file):
        out = self._redact_env(make_file, 'App.java',
                               'String api_key = "mysecretkey123456";\n')
        assert out == 'String api_key = System.getenv("API_KEY");\n'

    def test_php_env_ref(self, make_file):
        out = self._redact_env(make_file, 'app.php',
                               '$api_key = "mysecretkey123456";\n')
        assert out == "$api_key = getenv('API_KEY');\n"

    def test_embedded_secret_uses_sentinel(self, make_file):
        # a secret inside a LARGER quoted literal (Bearer header / URL) cannot
        # host a bare env ref without nesting quotes, so the sentinel is used
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        out = self._redact_env(make_file, 'embed.py', f'auth = "Bearer {key}"\n',
                               value=key, ftype='pattern:AWS access key')
        assert out == 'auth = "Bearer REDACTED_BY_CREDACTOR"\n'
        assert key not in out
        compile(out, 'embed.py', 'exec')

    def test_nested_quote_embedded_uses_sentinel(self, make_file):
        # a pattern secret SINGLE-quoted inside a DOUBLE-quoted string: inlining a
        # "-bearing env ref (os.environ["X"]) would break the outer string, so the
        # sentinel is used instead — output must stay valid and secret-free
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        out = self._redact_env(make_file, 'nested.py', f'auth = "Bearer \'{key}\'"\n',
                               value=key, ftype='pattern:AWS access key')
        assert out == 'auth = "Bearer \'REDACTED_BY_CREDACTOR\'"\n'
        assert key not in out
        compile(out, 'nested.py', 'exec')

    # --- guard cases: behaviour that must NOT change ---
    def test_shell_env_ref_stays_quoted(self, make_file):
        out = self._redact_env(make_file, 'app.sh',
                               'API_KEY="mysecretkey123456"\n',
                               ftype='variable:API_KEY')
        assert out == 'API_KEY="${API_KEY}"\n'

    def test_yaml_unquoted_env_ref(self, make_file):
        out = self._redact_env(make_file, 'app.yaml',
                               'api_key: mysecretkey123456\n')
        assert out == 'api_key: ${API_KEY}\n'

    def test_sentinel_mode_keeps_quotes(self, make_file):
        config = Config(no_backup=True, replace_mode='sentinel',
                        custom_replacement='REDACTED_BY_CREDACTOR')
        path = make_file('sent2.py', 'api_key = "mysecretkey123456"\n')
        batch_replace_in_file(path, [_mk_finding(path, 'mysecretkey123456')], config)
        with open(path) as f:
            out = f.read()
        assert out == 'api_key = "REDACTED_BY_CREDACTOR"\n'
        compile(out, 'sent2.py', 'exec')


class TestNoLeakOnRepeatedValue:
    """H10: when the same secret value appears more than once on a line but
    scans to a single finding, no copy may survive the redaction."""

    _SECRET = 'r4nd0mSecretVal9876'

    def test_repeated_value_fully_removed(self, make_file):
        # one finding (only api_key is a credential var), but the value is also
        # in a second, non-credential variable on the same line
        config = Config(no_backup=True, replace_mode='sentinel')
        path = make_file('dup.py', f'api_key = "{self._SECRET}"; note = "{self._SECRET}"\n')
        batch_replace_in_file(path, [_mk_finding(path, self._SECRET)], config)
        with open(path) as f:
            out = f.read()
        assert self._SECRET not in out
        compile(out, 'dup.py', 'exec')

    def test_env_mode_primary_keeps_ref_stray_sentinelled(self, make_file):
        config = Config(no_backup=True, replace_mode='env')
        path = make_file('dupe.py', f'api_key = "{self._SECRET}"; note = "{self._SECRET}"\n')
        batch_replace_in_file(path, [_mk_finding(path, self._SECRET)], config)
        with open(path) as f:
            out = f.read()
        assert self._SECRET not in out
        assert 'os.environ["API_KEY"]' in out   # primary kept the env ref
        compile(out, 'dupe.py', 'exec')

    def test_duplicate_value_on_other_lines_swept(self, make_file):
        # The detector-dedup case (benchmark): a secret reported once but present
        # verbatim on lines NO finding cited. The single finding must clear every
        # copy in this file in one pass, not just its own line.
        config = Config(no_backup=True, replace_mode='sentinel')
        path = make_file(
            'dups.env',
            f'TOKEN={self._SECRET}\n'      # the reported finding (line 1)
            f'COPY_A={self._SECRET}\n'     # un-reported duplicate (line 2)
            f'COPY_B={self._SECRET}\n')    # un-reported duplicate (line 3)
        # only one finding, on line 1
        batch_replace_in_file(path, [_mk_finding(path, self._SECRET, line=1)], config)
        with open(path) as f:
            out = f.read()
        assert self._SECRET not in out               # no copy survives
        assert out.count('REDACTED_BY_CREDACTOR') == 3

    def test_sweep_stays_within_the_redacted_file(self, make_file):
        # The sweep is bounded to the file being rewritten; a verbatim copy of
        # the same secret in a DIFFERENT, un-scanned file is left alone.
        config = Config(no_backup=True, replace_mode='sentinel')
        target = make_file('a.py', f'api_key = "{self._SECRET}"\n')
        other = make_file('b.py', f'api_key = "{self._SECRET}"\n')
        batch_replace_in_file(target, [_mk_finding(target, self._SECRET)], config)
        with open(target) as f:
            assert self._SECRET not in f.read()
        with open(other) as f:
            assert self._SECRET in f.read()          # untouched — different file

    def test_sweep_skips_substring_of_larger_token(self, make_file):
        # the secret value is also a substring of an adjacent numeric literal —
        # the sweep must redact the credential but NOT corrupt the other token
        config = Config(no_backup=True, replace_mode='sentinel')
        path = make_file('emb.py', 'db_password = "12345678"; timeout = 123456789\n')
        batch_replace_in_file(
            path, [_mk_finding(path, '12345678', 'variable:db_password')], config)
        with open(path) as f:
            out = f.read()
        assert '"12345678"' not in out          # the credential literal is gone
        assert 'timeout = 123456789' in out      # the adjacent number is untouched
        compile(out, 'emb.py', 'exec')

    def test_sweep_redacts_value_in_nonword_bounded_token(self, make_file):
        # Documented boundary of the word-anchor protection: a copy of the
        # exact secret inside a LARGER token bounded by a non-word char
        # (-, ., @, =, /) IS swept. That is over-redaction, not under: it fails
        # safe (the .bak keeps the original; the result over-redacts, never
        # leaks). Pinned so the boundary cannot shift silently. Contrast
        # test_sweep_skips_substring_of_larger_token, where a \w-adjacent
        # substring (123456789) stays protected.
        config = Config(no_backup=True, replace_mode='sentinel')
        path = make_file(
            'tok.py',
            f'api_key = "{self._SECRET}"\n'        # line 1: the reported finding
            f'name = "{self._SECRET}-extended"\n'  # line 2: hyphen-bounded copy
            f'backup = "{self._SECRET}.bak"\n')    # line 3: dot-bounded copy
        batch_replace_in_file(path, [_mk_finding(path, self._SECRET, line=1)], config)
        with open(path) as f:
            out = f.read()
        assert self._SECRET not in out                  # every literal copy is gone
        assert 'REDACTED_BY_CREDACTOR-extended' in out  # larger token's prefix swept
        assert 'REDACTED_BY_CREDACTOR.bak' in out
        compile(out, 'tok.py', 'exec')

    def test_distinct_values_both_replaced(self, make_file):
        # the sweep must not interfere with the normal two-findings case
        s1, s2 = 'aaa1bbb2ccc3ddd4', 'zzz9yyy8xxx7www6'
        config = Config(no_backup=True, replace_mode='sentinel')
        path = make_file('two.py', f'api_key = "{s1}"; token = "{s2}"\n')
        batch_replace_in_file(
            path,
            [_mk_finding(path, s1), _mk_finding(path, s2, 'variable:token')],
            config,
        )
        with open(path) as f:
            out = f.read()
        assert s1 not in out and s2 not in out


class TestDeriveEnvVarName:
    def test_variable_type(self):
        assert _derive_env_var_name({'type': 'variable:api_key'}) == 'API_KEY'

    def test_dotted_variable(self):
        assert _derive_env_var_name({'type': 'variable:self.api_key'}) == 'API_KEY'

    def test_pattern_type(self):
        assert _derive_env_var_name({'type': 'pattern:AWS access key'}) == 'AWS_ACCESS_KEY'

    def test_sec30_sanitizes_xml_injection(self):
        """SEC-30: Adversarial xml_key with JS syntax must be stripped."""
        result = _derive_env_var_name(
            {'type': 'xml-attr:password]);require("child_process").exec("pwned")//'}
        )
        # Only alphanumeric + underscore should survive
        assert result.isidentifier()
        assert ']' not in result
        assert ')' not in result
        assert ';' not in result
        assert '(' not in result
        assert '"' not in result

    def test_sec30_sanitizes_shell_injection(self):
        """SEC-30: Adversarial xml_key with shell metacharacters must be stripped."""
        result = _derive_env_var_name(
            {'type': 'xml-attr:password};rm -rf /;${x'}
        )
        assert result.isidentifier()
        assert ';' not in result
        assert ' ' not in result
        assert '{' not in result

    def test_sec30_empty_after_sanitize_returns_credential(self):
        """SEC-30: If sanitization strips everything, return fallback."""
        result = _derive_env_var_name({'type': 'xml-attr:]);()'})
        assert result == 'CREDENTIAL'

    def test_derive_env_var_external_gitleaks(self):
        """external:gitleaks:aws-access-token -> AWS_ACCESS_TOKEN"""
        result = _derive_env_var_name({'type': 'external:gitleaks:aws-access-token'})
        assert result == 'AWS_ACCESS_TOKEN'

    def test_derive_env_var_external_trufflehog(self):
        """external:trufflehog:AWS -> AWS"""
        assert _derive_env_var_name({'type': 'external:trufflehog:AWS'}) == 'AWS'

    def test_derive_env_var_external_sanitised(self):
        """Non-identifier chars stripped from external label."""
        result = _derive_env_var_name({'type': 'external:gitleaks:foo.bar@baz'})
        assert result.isidentifier()
        assert '.' not in result
        assert '@' not in result


class TestSecureBackupDirSymlink:
    """M11: refuse a --secure-backup-dir reached through a symlink — leaf OR
    ancestor — so a symlinked parent can't redirect the plaintext backup outside
    the intended directory."""

    def _finding(self, path):
        return {'file': path, 'line': 1, 'type': 'variable:api_key',
                'severity': 'high', 'full_value': _AWS_KEY,
                'value_preview': '', 'raw': ''}

    def test_plain_backup_dir_works(self, make_file, tmp_dir):
        backup = os.path.join(tmp_dir, 'backups')
        config = Config(secure_backup_dir=backup)
        path = make_file('s.py', f'api_key = "{_AWS_KEY}"\n')
        replaced, _ = batch_replace_in_file(path, [self._finding(path)], config)
        assert replaced == 1
        assert os.listdir(backup)            # backup landed where requested

    @pytest.mark.skipif(sys.platform == 'win32', reason='symlinks need admin on Windows')
    def test_leaf_symlink_refused(self, make_file, tmp_dir):
        real = os.path.join(tmp_dir, 'real')
        os.makedirs(real)
        link = os.path.join(tmp_dir, 'backups')
        os.symlink(real, link)
        config = Config(secure_backup_dir=link)
        path = make_file('s.py', f'api_key = "{_AWS_KEY}"\n')
        replaced, _ = batch_replace_in_file(path, [self._finding(path)], config)
        assert replaced == 0                 # backup refused -> redaction skipped
        with open(path) as f:
            assert _AWS_KEY in f.read()       # file untouched
        assert not os.listdir(real)           # nothing escaped into the target

    @pytest.mark.skipif(sys.platform == 'win32', reason='symlinks need admin on Windows')
    def test_parent_symlink_refused(self, make_file, tmp_dir):
        # symlinked PARENT with a real leaf dir — the case the old leaf-only
        # os.path.islink() guard missed
        realdest = os.path.join(tmp_dir, 'realdest')
        os.makedirs(realdest)
        symparent = os.path.join(tmp_dir, 'symparent')
        os.symlink(realdest, symparent)
        config = Config(secure_backup_dir=os.path.join(symparent, 'backups'))
        path = make_file('s.py', f'api_key = "{_AWS_KEY}"\n')
        replaced, _ = batch_replace_in_file(path, [self._finding(path)], config)
        assert replaced == 0
        with open(path) as f:
            assert _AWS_KEY in f.read()
        escaped = os.path.join(realdest, 'backups')
        assert not (os.path.isdir(escaped) and os.listdir(escaped))


class TestSecureBackupDirUnwritable:
    """L10: an unwritable --secure-backup-dir fails closed — no in-repo .bak is
    left behind and the file is not redacted (matches the symlink branch)."""

    @pytest.mark.skipif(
        sys.platform == 'win32' or (hasattr(os, 'getuid') and os.getuid() == 0),
        reason='chmod-based unwritability is unreliable on Windows / as root')
    def test_unwritable_backup_dir_fails_closed(self, make_file, tmp_dir):
        ro_parent = os.path.join(tmp_dir, 'ro')
        os.makedirs(ro_parent)
        os.chmod(ro_parent, 0o500)   # read+execute, no write -> mkdir fails
        try:
            config = Config(secure_backup_dir=os.path.join(ro_parent, 'backups'))
            path = make_file('s.py', f'api_key = "{_AWS_KEY}"\n')
            finding = {'file': path, 'line': 1, 'type': 'variable:api_key',
                       'severity': 'high', 'full_value': _AWS_KEY,
                       'value_preview': '', 'raw': ''}
            replaced, _ = batch_replace_in_file(path, [finding], config)
            assert replaced == 0                       # fail-closed: skipped
            assert not os.path.exists(path + '.bak')   # no in-repo bak left
            with open(path) as f:
                assert _AWS_KEY in f.read()            # file unchanged
        finally:
            os.chmod(ro_parent, 0o700)


class TestEnvRefForLanguage:
    """SEC-30: Verify bracket notation for JS and quoting for other languages."""

    def test_js_bracket_notation(self):
        from credactor.redactor import _env_ref_for_language
        assert _env_ref_for_language('API_KEY', '.js') == 'process.env["API_KEY"]'

    def test_ts_bracket_notation(self):
        from credactor.redactor import _env_ref_for_language
        assert _env_ref_for_language('API_KEY', '.ts') == 'process.env["API_KEY"]'

    def test_python_quoted(self):
        from credactor.redactor import _env_ref_for_language
        assert _env_ref_for_language('API_KEY', '.py') == 'os.environ["API_KEY"]'

    def test_go_quoted(self):
        from credactor.redactor import _env_ref_for_language
        assert _env_ref_for_language('API_KEY', '.go') == 'os.Getenv("API_KEY")'


class TestSweepRespectsAdjudication:
    """The value-global sweep clears UNREPORTED copies only. A finding the
    user explicitly skipped — or one whose own replacement failed — owns its
    line, and the sweep must not override that adjudication; the summary
    then matches the file state."""

    def test_interactive_skip_preserves_skipped_copies(
            self, make_file, monkeypatch, capsys):
        content = (f'a = "{_AWS_KEY}"\n'
                   f'b = "{_AWS_KEY}"\n'
                   f'c = "{_AWS_KEY}"\n')
        path = make_file('m.py', content)
        findings = [_mk_finding(path, _AWS_KEY, line=i) for i in (1, 2, 3)]
        answers = iter(['y', 'n', 'n'])
        monkeypatch.setattr('builtins.input', lambda *a: next(answers))
        unresolved = interactive_review(findings, os.path.dirname(path),
                                        Config(no_backup=True))
        assert unresolved == 2
        with open(path) as fh:
            text = fh.read()
        assert text.count(_AWS_KEY) == 2          # the skipped copies live on
        assert 'REDACTED_BY_CREDACTOR' in text.splitlines()[0]
        assert '1 replaced  |  2 skipped  |  3 total' in capsys.readouterr().out

    def test_fix_all_still_sweeps_unreported_copies(
            self, make_file, credactor_caplog):
        # The ingest-dedup case the sweep exists for: one reported finding,
        # copies on lines no finding cites — all cleared, and said so.
        content = (f'a = "{_AWS_KEY}"\n'
                   f'# backup copy: {_AWS_KEY}\n'
                   f'c = "{_AWS_KEY}"\n')
        path = make_file('d.py', content)
        fix_all([_mk_finding(path, _AWS_KEY, line=1)], os.path.dirname(path),
                Config(no_backup=True))
        with open(path) as fh:
            assert _AWS_KEY not in fh.read()
        notes = [r for r in credactor_caplog.records
                 if 'value-global sweep' in r.getMessage()]
        assert len(notes) == 1
        assert '2 additional' in notes[0].getMessage()

    def test_no_sweep_note_when_nothing_unreported(
            self, make_file, credactor_caplog):
        path = make_file('e.py', f'a = "{_AWS_KEY}"\n')
        fix_all([_mk_finding(path, _AWS_KEY, line=1)], os.path.dirname(path),
                Config(no_backup=True))
        assert not [r for r in credactor_caplog.records
                    if 'value-global sweep' in r.getMessage()]

    def test_all_approved_cross_value_copy_swept(self, make_file, monkeypatch):
        # Value A approved on line 1; line 2 holds finding B (different
        # value, also approved) PLUS a bare copy of A. Once B is resolved its
        # line is no longer owned by a pending adjudication — the approved
        # A-copy must not silently survive the session (exit 0, no warn).
        content = (f'password = "{_AWS_KEY}"\n'
                   f'token = "{_PASSWORD}"  # legacy {_AWS_KEY}\n')
        path = make_file('cross.py', content)
        findings = [
            _mk_finding(path, _AWS_KEY, 'variable:password', line=1),
            _mk_finding(path, _PASSWORD, 'variable:token', line=2),
        ]
        answers = iter(['y', 'y'])
        monkeypatch.setattr('builtins.input', lambda *a: next(answers))
        unresolved = interactive_review(findings, os.path.dirname(path),
                                        Config(no_backup=True))
        assert unresolved == 0
        with open(path) as fh:
            text = fh.read()
        assert _AWS_KEY not in text
        assert _PASSWORD not in text

    def test_skipped_line_preserves_other_values_copies(self, make_file, monkeypatch):
        # Contract pin: adjudication owns the LINE. Skipping finding B
        # preserves B's line wholesale — including a bare copy of approved
        # value A sitting on it. The .bak/manual document this boundary.
        content = (f'password = "{_AWS_KEY}"\n'
                   f'token = "{_PASSWORD}"  # legacy {_AWS_KEY}\n')
        path = make_file('skipline.py', content)
        findings = [
            _mk_finding(path, _AWS_KEY, 'variable:password', line=1),
            _mk_finding(path, _PASSWORD, 'variable:token', line=2),
        ]
        answers = iter(['y', 'n'])
        monkeypatch.setattr('builtins.input', lambda *a: next(answers))
        interactive_review(findings, os.path.dirname(path),
                           Config(no_backup=True))
        with open(path) as fh:
            lines = fh.read().splitlines()
        assert _AWS_KEY not in lines[0]
        assert _PASSWORD in lines[1] and _AWS_KEY in lines[1]

    def test_same_line_same_value_single_prompt(self, make_file, monkeypatch, capsys):
        # Two findings, one line, one value: line-granularity adjudication
        # cannot represent them separately — they are deduplicated into one
        # prompt, and a 'y' clears both occurrences / an 'n' keeps both.
        content = f'password = "{_AWS_KEY}"; token = "{_AWS_KEY}"\n'
        path = make_file('twin.py', content)
        findings = [
            _mk_finding(path, _AWS_KEY, 'variable:password', line=1),
            _mk_finding(path, _AWS_KEY, 'variable:token', line=1),
        ]
        answers = iter(['y'])
        monkeypatch.setattr('builtins.input', lambda *a: next(answers))
        unresolved = interactive_review(findings, os.path.dirname(path),
                                        Config(no_backup=True))
        assert unresolved == 0
        out = capsys.readouterr().out
        assert '1 replaced  |  0 skipped  |  1 total' in out
        with open(path) as fh:
            assert _AWS_KEY not in fh.read()

    def test_same_line_same_value_single_n_keeps_both(
            self, make_file, monkeypatch, capsys):
        # The other branch of the dedupe contract: one 'n' keeps every
        # occurrence on the line.
        content = f'password = "{_AWS_KEY}"; token = "{_AWS_KEY}"\n'
        path = make_file('twin_n.py', content)
        findings = [
            _mk_finding(path, _AWS_KEY, 'variable:password', line=1),
            _mk_finding(path, _AWS_KEY, 'variable:token', line=1),
        ]
        answers = iter(['n'])
        monkeypatch.setattr('builtins.input', lambda *a: next(answers))
        unresolved = interactive_review(findings, os.path.dirname(path),
                                        Config(no_backup=True))
        assert unresolved == 1
        assert '0 replaced  |  1 skipped  |  1 total' in capsys.readouterr().out
        with open(path) as fh:
            assert fh.read().count(_AWS_KEY) == 2

    def test_interrupt_preserves_pending_lines_in_final_sweep(
            self, make_file, monkeypatch):
        # Ctrl-C with finding B pending: B's line (holding a copy of approved
        # value A) stays preserved — pending adjudication owns it.
        content = (f'password = "{_AWS_KEY}"\n'
                   f'token = "{_PASSWORD}"  # legacy {_AWS_KEY}\n')
        path = make_file('intr.py', content)
        findings = [
            _mk_finding(path, _AWS_KEY, 'variable:password', line=1),
            _mk_finding(path, _PASSWORD, 'variable:token', line=2),
        ]
        answers = iter(['y', KeyboardInterrupt])

        def fake_input(*a):
            v = next(answers)
            if v is KeyboardInterrupt:
                raise KeyboardInterrupt
            return v

        monkeypatch.setattr('builtins.input', fake_input)
        interactive_review(findings, os.path.dirname(path),
                           Config(no_backup=True))
        with open(path) as fh:
            lines = fh.read().splitlines()
        assert _AWS_KEY not in lines[0]
        assert _AWS_KEY in lines[1]               # pending line untouched

    def test_fix_all_cross_value_copy_swept(self, make_file):
        # The batch path has no such hole (one call, full knowledge) — pin it.
        content = (f'password = "{_AWS_KEY}"\n'
                   f'token = "{_PASSWORD}"  # legacy {_AWS_KEY}\n')
        path = make_file('batchcross.py', content)
        findings = [
            _mk_finding(path, _AWS_KEY, 'variable:password', line=1),
            _mk_finding(path, _PASSWORD, 'variable:token', line=2),
        ]
        fix_all(findings, os.path.dirname(path), Config(no_backup=True))
        with open(path) as fh:
            text = fh.read()
        assert _AWS_KEY not in text and _PASSWORD not in text

    def test_failed_finding_line_not_swept(self, make_file):
        # Line 2's own finding fails (value drifted since scan); the line
        # also carries a copy of line 1's value. A drifted line is reported
        # 'failed' — silently rewriting it anyway would mask the failure.
        content = (f'a = "{_AWS_KEY}"\n'
                   f'b = "{_AWS_KEY}"  # drifted\n')
        path = make_file('f.py', content)
        findings = [_mk_finding(path, _AWS_KEY, line=1),
                    _mk_finding(path, 'VALUE_NOT_ON_THIS_LINE', line=2)]
        replaced, failed = batch_replace_in_file(path, findings,
                                                 Config(no_backup=True))
        assert (replaced, failed) == (1, 1)
        with open(path) as fh:
            lines = fh.read().splitlines()
        assert _AWS_KEY not in lines[0]
        assert _AWS_KEY in lines[1]               # its own adjudication failed


class TestUnreadableFileFailsAlone:
    """A read failure (incl. UnicodeDecodeError from a truncated multibyte
    encoding) must fail THAT file only — an ingested finding pointing at a
    corrupt UTF-16 file previously aborted the whole redaction run."""

    def test_truncated_utf16_counts_failed_not_crash(self, tmp_dir, monkeypatch):
        monkeypatch.setattr('credactor.utils.charset_normalizer', None)
        monkeypatch.setattr('credactor.utils.chardet', None)
        path = os.path.join(tmp_dir, 'trunc.py')
        with open(path, 'wb') as f:
            f.write(f'aws_key = "{_AWS_KEY}"\n'.encode('utf-16-le')[:-1])
        replaced, failed = batch_replace_in_file(
            path, [_mk_finding(path, _AWS_KEY)], Config(no_backup=True))
        assert (replaced, failed) == (0, 1)


class TestSummaryBackupFooter:
    """The plaintext-.bak SECURITY footer must reflect the backup mode: under
    --no-backup no .bak ever exists, and --secure-delete wipes it — telling
    users to go delete nonexistent files is misleading."""

    def test_no_backup_suppresses_footer(self, make_file, capsys):
        path = make_file('a.py', f'api_key = "{_AWS_KEY}"\n')
        fix_all([_mk_finding(path, _AWS_KEY)], os.path.dirname(path),
                Config(no_backup=True))
        out = capsys.readouterr().out
        assert '1 replaced' in out
        assert 'SECURITY: .bak' not in out
        assert 'rotate / revoke' in out  # rotation advice is mode-independent

    def test_secure_delete_suppresses_footer(self, make_file, capsys):
        path = make_file('b.py', f'api_key = "{_AWS_KEY}"\n')
        fix_all([_mk_finding(path, _AWS_KEY)], os.path.dirname(path),
                Config(no_backup=False, secure_delete=True))
        out = capsys.readouterr().out
        assert 'SECURITY: .bak' not in out
        assert not os.path.exists(path + '.bak')

    def test_default_keeps_footer(self, make_file, capsys):
        path = make_file('c.py', f'api_key = "{_AWS_KEY}"\n')
        fix_all([_mk_finding(path, _AWS_KEY)], os.path.dirname(path),
                Config(no_backup=False))
        out = capsys.readouterr().out
        assert 'SECURITY: .bak' in out

    def test_secure_backup_dir_keeps_footer(self, make_file, tmp_dir, capsys):
        # Plaintext backups still exist (moved into DIR) — suppressing the
        # footer there would be fail-open messaging.
        path = make_file('d.py', f'api_key = "{_AWS_KEY}"\n')
        backup = os.path.join(tmp_dir, 'backups')
        fix_all([_mk_finding(path, _AWS_KEY)], os.path.dirname(path),
                Config(no_backup=False, secure_backup_dir=backup))
        out = capsys.readouterr().out
        assert 'SECURITY: .bak' in out

    def test_interrupt_under_secure_delete_does_not_claim_baks_exist(
            self, make_file, monkeypatch, capsys):
        # The Ctrl-C path said '.bak backups exist for modified files.' even
        # under --secure-delete, which wipes each .bak right after its
        # replacement — pointing an interrupted user at a recovery artifact
        # that is not there.
        p1 = make_file('a.py', f'api_key = "{_AWS_KEY}"\n')
        p2 = make_file('b.py', f'api_key = "{_AWS_KEY}"\n')
        answers = iter(['y', KeyboardInterrupt])

        def fake_input(*a):
            v = next(answers)
            if v is KeyboardInterrupt:
                raise KeyboardInterrupt
            return v

        monkeypatch.setattr('builtins.input', fake_input)
        interactive_review(
            [_mk_finding(p1, _AWS_KEY), _mk_finding(p2, _AWS_KEY)],
            os.path.dirname(p1), Config(no_backup=False, secure_delete=True))
        out = capsys.readouterr().out
        assert 'Interrupted' in out
        assert '.bak backups exist' not in out
        assert not os.path.exists(p1 + '.bak')


class TestFixAllSummary:
    """#8: fix_all must report write/lookup FAILURES as 'failed', not 'skipped'."""

    def test_failures_reported_as_failed_not_skipped(self, make_file, capsys):
        # full_value is absent from the line, so batch_replace counts it failed.
        path = make_file('a.py', f'api_key = "{_AWS_KEY}"\n')
        bogus = _mk_finding(path, 'VALUE_NOT_ON_THIS_LINE')
        unresolved = fix_all([bogus], os.path.dirname(path), Config(no_backup=True))
        out = capsys.readouterr().out
        assert unresolved == 1
        assert '1 failed' in out
        assert 'skipped' not in out


class TestInteractiveReview:
    """S32: the default no-flags mode — per-finding y/N prompts driving real
    file rewrites — was previously the tool's only completely untested core
    path."""

    def _cfg(self):
        return Config(no_backup=True, no_color=True)

    def test_yes_replaces_and_returns_zero_unresolved(
            self, make_file, monkeypatch):
        path = make_file('app.py', f'api_key = "{_AWS_KEY}"\n')
        monkeypatch.setattr('builtins.input', lambda *a: 'y')
        unresolved = interactive_review(
            [_mk_finding(path, _AWS_KEY)], os.path.dirname(path), self._cfg())
        assert unresolved == 0
        with open(path) as f:
            content = f.read()
        assert _AWS_KEY not in content
        assert 'REDACTED_BY_CREDACTOR' in content

    def test_no_and_enter_skip_file_untouched(self, make_file, monkeypatch):
        path = make_file('app.py', f'api_key = "{_AWS_KEY}"\n'
                                   f'db_password = "{_PASSWORD}"\n')
        with open(path, 'rb') as f:
            before = f.read()
        answers = iter(['n', ''])           # explicit no, then bare Enter
        monkeypatch.setattr('builtins.input', lambda *a: next(answers))
        findings = [_mk_finding(path, _AWS_KEY),
                    _mk_finding(path, _PASSWORD, line=2)]
        unresolved = interactive_review(findings, os.path.dirname(path), self._cfg())
        assert unresolved == 2
        with open(path, 'rb') as f:
            assert f.read() == before        # byte-identical: nothing written

    def test_interrupt_stops_cleanly_and_reports(
            self, make_file, monkeypatch, capsys):
        # A skip BEFORE the interrupt pins the accounting: unresolved must be
        # total - replaced (the 'n' answer stays unresolved, not dropped).
        p1 = make_file('a.py', f'api_key = "{_AWS_KEY}"\n')
        p2 = make_file('b.py', f'api_key = "{_AWS_KEY}"\n')
        p3 = make_file('c.py', f'api_key = "{_AWS_KEY}"\n')
        answers = iter(['n', 'y', KeyboardInterrupt])

        def fake_input(*a):
            v = next(answers)
            if v is KeyboardInterrupt:
                raise KeyboardInterrupt
            return v

        monkeypatch.setattr('builtins.input', fake_input)
        unresolved = interactive_review(
            [_mk_finding(p1, _AWS_KEY), _mk_finding(p2, _AWS_KEY),
             _mk_finding(p3, _AWS_KEY)],
            os.path.dirname(p1), self._cfg())
        assert unresolved == 2               # 3 total - 1 replaced
        with open(p1) as f:
            assert _AWS_KEY in f.read()      # 'n': skipped, untouched
        with open(p2) as f:
            assert _AWS_KEY not in f.read()  # 'y': applied before ^C
        with open(p3) as f:
            assert _AWS_KEY in f.read()      # interrupted finding untouched
        out = capsys.readouterr().out
        assert 'Interrupted' in out
        assert 'replacement(s) already applied' in out

    def test_invalid_answer_reprompts(self, make_file, monkeypatch, capsys):
        path = make_file('app.py', f'api_key = "{_AWS_KEY}"\n')
        answers = iter(['x', 'y'])
        monkeypatch.setattr('builtins.input', lambda *a: next(answers))
        unresolved = interactive_review(
            [_mk_finding(path, _AWS_KEY)], os.path.dirname(path), self._cfg())
        assert unresolved == 0
        assert "Please enter 'y' or 'n'." in capsys.readouterr().out

    def test_failed_replacement_counts_as_unresolved(
            self, make_file, monkeypatch, capsys):
        # full_value not on the line -> replace_single fails -> stays unresolved.
        path = make_file('app.py', f'api_key = "{_AWS_KEY}"\n')
        stale = _mk_finding(path, 'VALUE_NOT_ON_THIS_LINE')
        monkeypatch.setattr('builtins.input', lambda *a: 'y')
        unresolved = interactive_review(
            [stale], os.path.dirname(path), self._cfg())
        assert unresolved == 1
        assert 'Replacement failed' in capsys.readouterr().out
