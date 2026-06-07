"""Tests for the redaction/replacement logic."""

import os
import sys

import pytest

from credactor.config import Config
from credactor.redactor import _derive_env_var_name, batch_replace_in_file, fix_all

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
