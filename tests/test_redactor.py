"""Tests for the redaction/replacement logic."""

import errno
import hashlib
import os
import shutil
import stat
import sys
import tempfile

import pytest

from credactor.config import Config
from credactor.redactor import (
    _derive_env_var_name,
    _final_file_sweep,
    batch_replace_in_file,
    fix_all,
    interactive_review,
)
from credactor.utils import preview

# Construct test credentials via concatenation so the tool doesn't self-redact
_AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'
_PASSWORD = 'xK9#mL2' + '$vQ7@nR5'


def _mk_finding(path, value, ftype='variable:api_key', line=1):
    return {
        'file': path,
        'line': line,
        'type': ftype,
        'severity': 'high',
        'full_value': value,
        'value_preview': '',
        'raw': '',
    }


class TestSecureDelete:
    """P3: --secure-delete must leave no plaintext .bak behind (was untested)."""

    def test_secure_delete_removes_backup(self, make_file):
        config = Config(no_backup=False, secure_delete=True)
        path = make_file('secret.py', f'api_key = "{_AWS_KEY}"\n')
        replaced, failed = batch_replace_in_file(path, [_mk_finding(path, _AWS_KEY)], config)
        assert replaced == 1
        assert not os.path.exists(path + '.bak')  # backup securely deleted
        with open(path) as f:
            assert _AWS_KEY not in f.read()  # original redacted

    def test_backup_kept_without_secure_delete(self, make_file):
        config = Config(no_backup=False, secure_delete=False)
        path = make_file('secret.py', f'api_key = "{_AWS_KEY}"\n')
        batch_replace_in_file(path, [_mk_finding(path, _AWS_KEY)], config)
        assert os.path.exists(path + '.bak')  # contrast: .bak lingers


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
            {
                'file': path,
                'line': 1,
                'type': 'variable:api_key',
                'severity': 'high',
                'full_value': _AWS_KEY,
                'value_preview': '',
                'raw': '',
            },
            {
                'file': path,
                'line': 2,
                'type': 'variable:password',
                'severity': 'high',
                'full_value': _PASSWORD,
                'value_preview': '',
                'raw': '',
            },
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
        config = Config(
            no_backup=True, replace_mode='sentinel', custom_replacement='REDACTED_BY_CREDACTOR'
        )
        path = make_file('sent.py', 'api_key = "mysecretkey123456"\n')
        finding = {
            'file': path,
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': 'mysecretkey123456',
            'value_preview': '',
            'raw': '',
        }
        batch_replace_in_file(path, [finding], config)
        with open(path) as f:
            assert 'REDACTED_BY_CREDACTOR' in f.read()

    @pytest.mark.skipif(
        sys.platform == 'win32', reason='Windows does not support Unix-style permission bits'
    )
    def test_preserves_file_permissions(self, make_file):
        config = Config(no_backup=True)
        path = make_file('perms.py', 'api_key = "mysecretkey123456"\n')
        os.chmod(path, 0o644)
        finding = {
            'file': path,
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': 'mysecretkey123456',
            'value_preview': '',
            'raw': '',
        }
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

    def _redact_env(self, make_file, name, content, value=None, ftype='variable:api_key'):
        config = Config(no_backup=True, replace_mode='env')
        path = make_file(name, content)
        finding = _mk_finding(path, value or self._SECRET, ftype)
        batch_replace_in_file(path, [finding], config)
        with open(path) as f:
            return f.read()

    def test_python_env_ref(self, make_file):
        out = self._redact_env(make_file, 'envtest.py', 'api_key = "mysecretkey123456"\n')
        assert out == 'api_key = os.environ["API_KEY"]\n'
        compile(out, 'envtest.py', 'exec')  # H2: must be valid Python

    def test_python_env_ref_single_quote_source(self, make_file):
        # a single-quoted source must also have its quotes consumed, else the
        # env ref becomes a string literal instead of a lookup
        out = self._redact_env(make_file, 'sq.py', "api_key = 'mysecretkey123456'\n")
        assert out == 'api_key = os.environ["API_KEY"]\n'
        compile(out, 'sq.py', 'exec')

    def test_js_env_ref(self, make_file):
        out = self._redact_env(make_file, 'envtest.js', 'const api_key = "mysecretkey123456";\n')
        assert out == 'const api_key = process.env["API_KEY"];\n'

    def test_ruby_env_ref(self, make_file):
        out = self._redact_env(make_file, 'app.rb', 'api_key = "mysecretkey123456"\n')
        assert out == "api_key = ENV['API_KEY']\n"

    def test_go_env_ref(self, make_file):
        out = self._redact_env(make_file, 'app.go', 'var api_key = "mysecretkey123456"\n')
        assert out == 'var api_key = os.Getenv("API_KEY")\n'

    def test_java_env_ref(self, make_file):
        out = self._redact_env(make_file, 'App.java', 'String api_key = "mysecretkey123456";\n')
        assert out == 'String api_key = System.getenv("API_KEY");\n'

    def test_php_env_ref(self, make_file):
        out = self._redact_env(make_file, 'app.php', '$api_key = "mysecretkey123456";\n')
        assert out == "$api_key = getenv('API_KEY');\n"

    def test_embedded_secret_uses_sentinel(self, make_file):
        # a secret inside a LARGER quoted literal (Bearer header / URL) cannot
        # host a bare env ref without nesting quotes, so the sentinel is used
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        out = self._redact_env(
            make_file,
            'embed.py',
            f'auth = "Bearer {key}"\n',
            value=key,
            ftype='pattern:AWS access key',
        )
        assert out == 'auth = "Bearer REDACTED_BY_CREDACTOR"\n'
        assert key not in out
        compile(out, 'embed.py', 'exec')

    def test_nested_quote_embedded_uses_sentinel(self, make_file):
        # a pattern secret SINGLE-quoted inside a DOUBLE-quoted string: inlining a
        # "-bearing env ref (os.environ["X"]) would break the outer string, so the
        # sentinel is used instead — output must stay valid and secret-free
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        out = self._redact_env(
            make_file,
            'nested.py',
            f'auth = "Bearer \'{key}\'"\n',
            value=key,
            ftype='pattern:AWS access key',
        )
        assert out == 'auth = "Bearer \'REDACTED_BY_CREDACTOR\'"\n'
        assert key not in out
        compile(out, 'nested.py', 'exec')

    # --- guard cases: behaviour that must NOT change ---
    def test_shell_env_ref_stays_quoted(self, make_file):
        out = self._redact_env(
            make_file, 'app.sh', 'API_KEY="mysecretkey123456"\n', ftype='variable:API_KEY'
        )
        assert out == 'API_KEY="${API_KEY}"\n'

    def test_yaml_unquoted_env_ref(self, make_file):
        out = self._redact_env(make_file, 'app.yaml', 'api_key: mysecretkey123456\n')
        assert out == 'api_key: ${API_KEY}\n'

    def test_sentinel_mode_keeps_quotes(self, make_file):
        config = Config(
            no_backup=True, replace_mode='sentinel', custom_replacement='REDACTED_BY_CREDACTOR'
        )
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
        assert 'os.environ["API_KEY"]' in out  # primary kept the env ref
        compile(out, 'dupe.py', 'exec')

    def test_duplicate_value_on_other_lines_swept(self, make_file):
        # The detector-dedup case (benchmark): a secret reported once but present
        # verbatim on lines NO finding cited. The single finding must clear every
        # copy in this file in one pass, not just its own line.
        config = Config(no_backup=True, replace_mode='sentinel')
        path = make_file(
            'dups.env',
            f'TOKEN={self._SECRET}\n'  # the reported finding (line 1)
            f'COPY_A={self._SECRET}\n'  # un-reported duplicate (line 2)
            f'COPY_B={self._SECRET}\n',
        )  # un-reported duplicate (line 3)
        # only one finding, on line 1
        batch_replace_in_file(path, [_mk_finding(path, self._SECRET, line=1)], config)
        with open(path) as f:
            out = f.read()
        assert self._SECRET not in out  # no copy survives
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
            assert self._SECRET in f.read()  # untouched — different file

    def test_sweep_skips_substring_of_larger_token(self, make_file):
        # the secret value is also a substring of an adjacent numeric literal —
        # the sweep must redact the credential but NOT corrupt the other token
        config = Config(no_backup=True, replace_mode='sentinel')
        path = make_file('emb.py', 'db_password = "12345678"; timeout = 123456789\n')
        batch_replace_in_file(path, [_mk_finding(path, '12345678', 'variable:db_password')], config)
        with open(path) as f:
            out = f.read()
        assert '"12345678"' not in out  # the credential literal is gone
        assert 'timeout = 123456789' in out  # the adjacent number is untouched
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
            f'api_key = "{self._SECRET}"\n'  # line 1: the reported finding
            f'name = "{self._SECRET}-extended"\n'  # line 2: hyphen-bounded copy
            f'backup = "{self._SECRET}.bak"\n',
        )  # line 3: dot-bounded copy
        batch_replace_in_file(path, [_mk_finding(path, self._SECRET, line=1)], config)
        with open(path) as f:
            out = f.read()
        assert self._SECRET not in out  # every literal copy is gone
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

    # T15b: the name comes from text the scanned file or a report supplied, so
    # it can spell the secret; written into the file it would leave a copy.
    @pytest.mark.parametrize(
        ('ftype', 'value'),
        [
            ('external:gitleaks:Zq7wPx2mTr9vLk3nQ8sB', 'Zq7wPx2mTr9vLk3nQ8sB'),
            ('external:gitleaks:rule-zq7wpx2mtr', 'Zq7wPx2mTr9vLk3nQ8sB'),
            ('variable:token_Hx7Kq2Lm9Pz4', 'Hx7Kq2Lm9Pz4'),
            ('xml-attr:ab-cd-ef-gh', 'AB_CD_EF_GH_99'),
        ],
        ids=['equal', 'prefix-other-case', 'variable', 'separators'],
    )
    def test_name_that_holds_the_secret_falls_back(self, ftype, value):
        assert _derive_env_var_name({'type': ftype, 'full_value': value}) == 'CREDENTIAL'

    def test_name_sharing_seven_characters_is_kept(self):
        finding = {
            'type': 'external:gitleaks:aws-access-token',
            'full_value': 'x' + 'WSACCES' + 'y' * 9,
        }
        assert _derive_env_var_name(finding) == 'AWS_ACCESS_TOKEN'

    @pytest.mark.parametrize(
        ('ftype', 'value', 'name'),
        [
            (
                'external:trufflehog:Postgres',
                'postgresql://app:S3cr3tPassw0rdXyz@db.example.com:5432/app',
                'POSTGRES',
            ),
            (
                'variable:postgres_url',
                'postgresql://app:S3cr3tPassw0rdXyz@db.example.com/app',
                'POSTGRES_URL',
            ),
            (
                'variable:mongodb_uri',
                'mongodb://user:Hx7Kq2Lm9Pz4Wr5@mongodb.internal/db',
                'MONGODB_URI',
            ),
            (
                'external:gitleaks:private-key',
                '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJ\n'
                '-----END RSA PRIVATE KEY-----',
                'PRIVATE_KEY',
            ),
        ],
        ids=['postgres', 'postgres-url', 'mongodb-uri', 'private-key'],
    )
    def test_scheme_host_and_armor_are_not_the_secret(self, ftype, value, name):
        assert _derive_env_var_name({'type': ftype, 'full_value': value}) == name

    def test_password_in_a_url_still_counts(self):
        finding = {
            'type': 'variable:S3cr3tPassw0rdXyz',
            'full_value': 'postgres://a:S3cr3tPassw0rdXyz@h/d',
        }
        assert _derive_env_var_name(finding) == 'CREDENTIAL'

    def test_provider_prefix_in_the_label_is_kept(self):
        finding = {'type': 'pattern:Stripe live key', 'full_value': 'sk_live_' + 'Ab12Cd34Ef56Gh78'}
        assert _derive_env_var_name(finding) == 'STRIPE_LIVE_KEY'

    def test_env_mode_leaves_no_copy_of_the_secret(self, make_file):
        value = 'Zq7wPx2mTr9vLk3nQ8sB'
        path = make_file('handle.py', f'handle = lookup("{value}")\n')
        finding = _mk_finding(path, value, f'external:gitleaks:{value}')
        config = Config(no_backup=True, replace_mode='env')
        fix_all([finding], os.path.dirname(path), config)
        with open(path, encoding='utf-8') as f:
            out = f.read()
        assert value.upper() not in out.upper()
        assert 'CREDENTIAL' in out

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
        result = _derive_env_var_name({'type': 'xml-attr:password};rm -rf /;${x'})
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
        return {
            'file': path,
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': _AWS_KEY,
            'value_preview': '',
            'raw': '',
        }

    def test_plain_backup_dir_works(self, make_file, tmp_dir):
        backup = os.path.join(tmp_dir, 'backups')
        config = Config(secure_backup_dir=backup)
        path = make_file('s.py', f'api_key = "{_AWS_KEY}"\n')
        replaced, _ = batch_replace_in_file(path, [self._finding(path)], config)
        assert replaced == 1
        assert os.listdir(backup)  # backup landed where requested

    @pytest.mark.skipif(sys.platform == 'win32', reason='symlinks need admin on Windows')
    def test_leaf_symlink_refused(self, make_file, tmp_dir):
        real = os.path.join(tmp_dir, 'real')
        os.makedirs(real)
        link = os.path.join(tmp_dir, 'backups')
        os.symlink(real, link)
        config = Config(secure_backup_dir=link)
        path = make_file('s.py', f'api_key = "{_AWS_KEY}"\n')
        replaced, _ = batch_replace_in_file(path, [self._finding(path)], config)
        assert replaced == 0  # backup refused -> redaction skipped
        with open(path) as f:
            assert _AWS_KEY in f.read()  # file untouched
        assert not os.listdir(real)  # nothing escaped into the target

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
        reason='chmod-based unwritability is unreliable on Windows / as root',
    )
    def test_unwritable_backup_dir_fails_closed(self, make_file, tmp_dir):
        ro_parent = os.path.join(tmp_dir, 'ro')
        os.makedirs(ro_parent)
        os.chmod(ro_parent, 0o500)  # read+execute, no write -> mkdir fails
        try:
            config = Config(secure_backup_dir=os.path.join(ro_parent, 'backups'))
            path = make_file('s.py', f'api_key = "{_AWS_KEY}"\n')
            finding = {
                'file': path,
                'line': 1,
                'type': 'variable:api_key',
                'severity': 'high',
                'full_value': _AWS_KEY,
                'value_preview': '',
                'raw': '',
            }
            replaced, _ = batch_replace_in_file(path, [finding], config)
            assert replaced == 0  # fail-closed: skipped
            assert not os.path.exists(path + '.bak')  # no in-repo bak left
            with open(path) as f:
                assert _AWS_KEY in f.read()  # file unchanged
        finally:
            os.chmod(ro_parent, 0o700)


class TestInteractiveBackupOncePerFile:
    """B2: interactive redaction of several findings in ONE file must back the
    file up once per session — on the first approval — so the single .bak holds
    the true original (every secret), not the already-redacted state after the
    first approval (which would lose all-but-the-last original)."""

    def test_two_approvals_bak_restores_all_originals(self, make_file, monkeypatch):
        secret_a = 'AKIA' + 'IOSFODNN7AAAAAAA'
        secret_b = 'AKIA' + 'IOSFODNN7BBBBBBB'
        path = make_file('t.py', f'a = "{secret_a}"\nb = "{secret_b}"\n')
        findings = [_mk_finding(path, secret_a, line=1), _mk_finding(path, secret_b, line=2)]
        monkeypatch.setattr('builtins.input', lambda *a: 'y')
        interactive_review(findings, os.path.dirname(path), Config(no_backup=False))

        with open(path) as fh:  # file fully redacted
            redacted = fh.read()
        assert secret_a not in redacted
        assert secret_b not in redacted

        bak = path + '.bak'
        assert os.path.exists(bak)
        with open(bak) as fh:  # the .bak restores BOTH originals, not just the last
            restored = fh.read()
        assert secret_a in restored
        assert secret_b in restored

    def test_two_approvals_secure_backup_dir_restores_all_originals(
        self, make_file, tmp_dir, monkeypatch
    ):
        backup = os.path.join(tmp_dir, 'securebak')
        secret_a = 'AKIA' + 'IOSFODNN7AAAAAAA'
        secret_b = 'AKIA' + 'IOSFODNN7BBBBBBB'
        path = make_file('proj/t.py', f'a = "{secret_a}"\nb = "{secret_b}"\n')
        findings = [_mk_finding(path, secret_a, line=1), _mk_finding(path, secret_b, line=2)]
        monkeypatch.setattr('builtins.input', lambda *a: 'y')
        interactive_review(findings, os.path.dirname(path), Config(secure_backup_dir=backup))

        baks = os.listdir(backup)
        assert len(baks) == 1  # one backup for the one file (not clobbered per approval)
        with open(os.path.join(backup, baks[0])) as fh:
            restored = fh.read()
        assert secret_a in restored
        assert secret_b in restored


class TestSecureBackupDirCollision:
    """R1: two scanned files that share a basename in different directories must
    map to DISTINCT backups in one --secure-backup-dir, so the second redaction
    cannot silently clobber the first file's only recovery copy."""

    def _finding(self, path):
        return _mk_finding(path, _AWS_KEY)

    def test_same_basename_distinct_subdirs_both_recoverable(self, make_file, tmp_dir):
        backup = os.path.join(tmp_dir, 'securebak')
        config = Config(secure_backup_dir=backup, replace_mode='sentinel')

        # Two same-basename sources in different subdirs, each with its own secret.
        secret_a = 'AKIA' + 'IOSFODNN7AAAAAAA'
        secret_b = 'AKIA' + 'IOSFODNN7BBBBBBB'
        path_a = make_file('a/config.py', f'api_key = "{secret_a}"\n')
        path_b = make_file('b/config.py', f'api_key = "{secret_b}"\n')

        ra, _ = batch_replace_in_file(path_a, [_mk_finding(path_a, secret_a)], config)
        rb, _ = batch_replace_in_file(path_b, [_mk_finding(path_b, secret_b)], config)
        assert ra == 1
        assert rb == 1

        # Both backups must coexist in the secure dir (no basename collision).
        baks = os.listdir(backup)
        assert len(baks) == 2

        # Nothing landed beside either original.
        assert not os.path.exists(path_a + '.bak')
        assert not os.path.exists(path_b + '.bak')

        # Each original must be recoverable from its OWN distinct backup — neither
        # secret was clobbered by the other.
        recovered = []
        for name in baks:
            with open(os.path.join(backup, name)) as f:
                recovered.append(f.read())
        joined = '\n'.join(recovered)
        assert secret_a in joined
        assert secret_b in joined

    def test_backup_name_stable_across_runs(self, make_file, tmp_dir):
        # Re-running on the same source maps to the same backup name (the source
        # owns its backup), so a re-run overwrites its own copy, not a sibling's.
        backup = os.path.join(tmp_dir, 'securebak')
        config = Config(secure_backup_dir=backup, replace_mode='sentinel')
        path = make_file('pkg/config.py', f'api_key = "{_AWS_KEY}"\n')

        batch_replace_in_file(path, [self._finding(path)], config)
        first = sorted(os.listdir(backup))

        # Restore the secret and redact again — same source, same backup name.
        with open(path, 'w') as f:
            f.write(f'api_key = "{_AWS_KEY}"\n')
        batch_replace_in_file(path, [self._finding(path)], config)
        second = sorted(os.listdir(backup))

        assert first == second
        assert len(second) == 1


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

    def test_interactive_skip_preserves_skipped_copies(self, make_file, monkeypatch, capsys):
        content = f'a = "{_AWS_KEY}"\nb = "{_AWS_KEY}"\nc = "{_AWS_KEY}"\n'
        path = make_file('m.py', content)
        findings = [_mk_finding(path, _AWS_KEY, line=i) for i in (1, 2, 3)]
        answers = iter(['y', 'n', 'n'])
        monkeypatch.setattr('builtins.input', lambda *a: next(answers))
        unresolved = interactive_review(findings, os.path.dirname(path), Config(no_backup=True))
        assert unresolved == 2
        with open(path) as fh:
            text = fh.read()
        assert text.count(_AWS_KEY) == 2  # the skipped copies live on
        assert 'REDACTED_BY_CREDACTOR' in text.splitlines()[0]
        assert '1 replaced  |  2 skipped  |  3 total' in capsys.readouterr().out

    def test_fix_all_still_sweeps_unreported_copies(self, make_file, credactor_caplog):
        # The ingest-dedup case the sweep exists for: one reported finding,
        # copies on lines no finding cites — all cleared, and said so.
        content = f'a = "{_AWS_KEY}"\n# backup copy: {_AWS_KEY}\nc = "{_AWS_KEY}"\n'
        path = make_file('d.py', content)
        fix_all(
            [_mk_finding(path, _AWS_KEY, line=1)], os.path.dirname(path), Config(no_backup=True)
        )
        with open(path) as fh:
            assert _AWS_KEY not in fh.read()
        notes = [r for r in credactor_caplog.records if 'value-global sweep' in r.getMessage()]
        assert len(notes) == 1
        assert '2 additional' in notes[0].getMessage()

    def test_no_sweep_note_when_nothing_unreported(self, make_file, credactor_caplog):
        path = make_file('e.py', f'a = "{_AWS_KEY}"\n')
        fix_all(
            [_mk_finding(path, _AWS_KEY, line=1)], os.path.dirname(path), Config(no_backup=True)
        )
        assert not [r for r in credactor_caplog.records if 'value-global sweep' in r.getMessage()]

    def test_all_approved_cross_value_copy_swept(self, make_file, monkeypatch):
        # Value A approved on line 1; line 2 holds finding B (different
        # value, also approved) PLUS a bare copy of A. Once B is resolved its
        # line is no longer owned by a pending adjudication — the approved
        # A-copy must not silently survive the session (exit 0, no warn).
        content = f'password = "{_AWS_KEY}"\ntoken = "{_PASSWORD}"  # legacy {_AWS_KEY}\n'
        path = make_file('cross.py', content)
        findings = [
            _mk_finding(path, _AWS_KEY, 'variable:password', line=1),
            _mk_finding(path, _PASSWORD, 'variable:token', line=2),
        ]
        answers = iter(['y', 'y'])
        monkeypatch.setattr('builtins.input', lambda *a: next(answers))
        unresolved = interactive_review(findings, os.path.dirname(path), Config(no_backup=True))
        assert unresolved == 0
        with open(path) as fh:
            text = fh.read()
        assert _AWS_KEY not in text
        assert _PASSWORD not in text

    def test_skipped_line_preserves_other_values_copies(self, make_file, monkeypatch):
        # Contract pin: adjudication owns the LINE. Skipping finding B
        # preserves B's line wholesale — including a bare copy of approved
        # value A sitting on it. The .bak/manual document this boundary.
        content = f'password = "{_AWS_KEY}"\ntoken = "{_PASSWORD}"  # legacy {_AWS_KEY}\n'
        path = make_file('skipline.py', content)
        findings = [
            _mk_finding(path, _AWS_KEY, 'variable:password', line=1),
            _mk_finding(path, _PASSWORD, 'variable:token', line=2),
        ]
        answers = iter(['y', 'n'])
        monkeypatch.setattr('builtins.input', lambda *a: next(answers))
        interactive_review(findings, os.path.dirname(path), Config(no_backup=True))
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
        unresolved = interactive_review(findings, os.path.dirname(path), Config(no_backup=True))
        assert unresolved == 0
        out = capsys.readouterr().out
        assert '1 replaced  |  0 skipped  |  1 total' in out
        with open(path) as fh:
            assert _AWS_KEY not in fh.read()

    def test_same_line_same_value_single_n_keeps_both(self, make_file, monkeypatch, capsys):
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
        unresolved = interactive_review(findings, os.path.dirname(path), Config(no_backup=True))
        assert unresolved == 1
        assert '0 replaced  |  1 skipped  |  1 total' in capsys.readouterr().out
        with open(path) as fh:
            assert fh.read().count(_AWS_KEY) == 2

    def test_interrupt_preserves_pending_lines_in_final_sweep(self, make_file, monkeypatch):
        # Ctrl-C with finding B pending: B's line (holding a copy of approved
        # value A) stays preserved — pending adjudication owns it.
        content = f'password = "{_AWS_KEY}"\ntoken = "{_PASSWORD}"  # legacy {_AWS_KEY}\n'
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
        interactive_review(findings, os.path.dirname(path), Config(no_backup=True))
        with open(path) as fh:
            lines = fh.read().splitlines()
        assert _AWS_KEY not in lines[0]
        assert _AWS_KEY in lines[1]  # pending line untouched

    def test_fix_all_cross_value_copy_swept(self, make_file):
        # The batch path has no such hole (one call, full knowledge) — pin it.
        content = f'password = "{_AWS_KEY}"\ntoken = "{_PASSWORD}"  # legacy {_AWS_KEY}\n'
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
        content = f'a = "{_AWS_KEY}"\nb = "{_AWS_KEY}"  # drifted\n'
        path = make_file('f.py', content)
        findings = [
            _mk_finding(path, _AWS_KEY, line=1),
            _mk_finding(path, 'VALUE_NOT_ON_THIS_LINE', line=2),
        ]
        replaced, failed = batch_replace_in_file(path, findings, Config(no_backup=True))
        assert (replaced, failed) == (1, 1)
        with open(path) as fh:
            lines = fh.read().splitlines()
        assert _AWS_KEY not in lines[0]
        assert _AWS_KEY in lines[1]  # its own adjudication failed


class TestUnreadableFileFailsAlone:
    """A read failure (incl. UnicodeDecodeError from a truncated multibyte
    encoding) must fail THAT file only — an ingested finding pointing at a
    corrupt UTF-16 file previously aborted the whole redaction run."""

    def test_truncated_utf16_counts_failed_not_crash(self, tmp_dir, monkeypatch):
        monkeypatch.setattr('credactor.utils.charset_normalizer', None)
        path = os.path.join(tmp_dir, 'trunc.py')
        with open(path, 'wb') as f:
            f.write(f'aws_key = "{_AWS_KEY}"\n'.encode('utf-16-le')[:-1])
        replaced, failed = batch_replace_in_file(
            path, [_mk_finding(path, _AWS_KEY)], Config(no_backup=True)
        )
        assert (replaced, failed) == (0, 1)


class TestSummaryBackupFooter:
    """The plaintext-.bak SECURITY footer must reflect the backup mode: under
    --no-backup no .bak ever exists, and --secure-delete wipes it — telling
    users to go delete nonexistent files is misleading."""

    def test_no_backup_suppresses_footer(self, make_file, capsys):
        path = make_file('a.py', f'api_key = "{_AWS_KEY}"\n')
        fix_all([_mk_finding(path, _AWS_KEY)], os.path.dirname(path), Config(no_backup=True))
        out = capsys.readouterr().out
        assert '1 replaced' in out
        assert 'SECURITY: .bak' not in out
        assert 'rotate / revoke' in out  # rotation advice is mode-independent

    def test_secure_delete_suppresses_footer(self, make_file, capsys):
        path = make_file('b.py', f'api_key = "{_AWS_KEY}"\n')
        fix_all(
            [_mk_finding(path, _AWS_KEY)],
            os.path.dirname(path),
            Config(no_backup=False, secure_delete=True),
        )
        out = capsys.readouterr().out
        assert 'SECURITY: .bak' not in out
        assert not os.path.exists(path + '.bak')

    def test_default_keeps_footer(self, make_file, capsys):
        path = make_file('c.py', f'api_key = "{_AWS_KEY}"\n')
        fix_all([_mk_finding(path, _AWS_KEY)], os.path.dirname(path), Config(no_backup=False))
        out = capsys.readouterr().out
        assert 'SECURITY: .bak' in out

    def test_secure_backup_dir_keeps_footer(self, make_file, tmp_dir, capsys):
        # Plaintext backups still exist (moved into DIR) — suppressing the
        # footer there would be fail-open messaging.
        path = make_file('d.py', f'api_key = "{_AWS_KEY}"\n')
        backup = os.path.join(tmp_dir, 'backups')
        fix_all(
            [_mk_finding(path, _AWS_KEY)],
            os.path.dirname(path),
            Config(no_backup=False, secure_backup_dir=backup),
        )
        out = capsys.readouterr().out
        assert 'SECURITY: .bak' in out

    def test_interrupt_under_secure_delete_does_not_claim_baks_exist(
        self, make_file, monkeypatch, capsys
    ):
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
            os.path.dirname(p1),
            Config(no_backup=False, secure_delete=True),
        )
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

    def test_yes_replaces_and_returns_zero_unresolved(self, make_file, monkeypatch):
        path = make_file('app.py', f'api_key = "{_AWS_KEY}"\n')
        monkeypatch.setattr('builtins.input', lambda *a: 'y')
        unresolved = interactive_review(
            [_mk_finding(path, _AWS_KEY)], os.path.dirname(path), self._cfg()
        )
        assert unresolved == 0
        with open(path) as f:
            content = f.read()
        assert _AWS_KEY not in content
        assert 'REDACTED_BY_CREDACTOR' in content

    def test_no_and_enter_skip_file_untouched(self, make_file, monkeypatch):
        path = make_file('app.py', f'api_key = "{_AWS_KEY}"\ndb_password = "{_PASSWORD}"\n')
        with open(path, 'rb') as f:
            before = f.read()
        answers = iter(['n', ''])  # explicit no, then bare Enter
        monkeypatch.setattr('builtins.input', lambda *a: next(answers))
        findings = [_mk_finding(path, _AWS_KEY), _mk_finding(path, _PASSWORD, line=2)]
        unresolved = interactive_review(findings, os.path.dirname(path), self._cfg())
        assert unresolved == 2
        with open(path, 'rb') as f:
            assert f.read() == before  # byte-identical: nothing written

    def test_interrupt_stops_cleanly_and_reports(self, make_file, monkeypatch, capsys):
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
            [_mk_finding(p1, _AWS_KEY), _mk_finding(p2, _AWS_KEY), _mk_finding(p3, _AWS_KEY)],
            os.path.dirname(p1),
            self._cfg(),
        )
        assert unresolved == 2  # 3 total - 1 replaced
        with open(p1) as f:
            assert _AWS_KEY in f.read()  # 'n': skipped, untouched
        with open(p2) as f:
            assert _AWS_KEY not in f.read()  # 'y': applied before ^C
        with open(p3) as f:
            assert _AWS_KEY in f.read()  # interrupted finding untouched
        out = capsys.readouterr().out
        assert 'Interrupted' in out
        assert 'replacement(s) already applied' in out

    def test_invalid_answer_reprompts(self, make_file, monkeypatch, capsys):
        path = make_file('app.py', f'api_key = "{_AWS_KEY}"\n')
        answers = iter(['x', 'y'])
        monkeypatch.setattr('builtins.input', lambda *a: next(answers))
        unresolved = interactive_review(
            [_mk_finding(path, _AWS_KEY)], os.path.dirname(path), self._cfg()
        )
        assert unresolved == 0
        assert "Please enter 'y' or 'n'." in capsys.readouterr().out

    def test_failed_replacement_counts_as_unresolved(self, make_file, monkeypatch, capsys):
        # full_value not on the line -> replace_single fails -> stays unresolved.
        path = make_file('app.py', f'api_key = "{_AWS_KEY}"\n')
        stale = _mk_finding(path, 'VALUE_NOT_ON_THIS_LINE')
        monkeypatch.setattr('builtins.input', lambda *a: 'y')
        unresolved = interactive_review([stale], os.path.dirname(path), self._cfg())
        assert unresolved == 1
        assert 'Replacement failed' in capsys.readouterr().out


class TestWritePathSafety:
    """Phase-1 hardening (deep-review S1/S2/S14/S15): symlinked targets refused,
    atomic-write and backup failures fail closed, and --secure-backup-dir never
    writes a plaintext .bak inside the repo."""

    def _finding(self, path, line=1):
        return {
            'file': path,
            'line': line,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': _AWS_KEY,
            'value_preview': '',
            'raw': '',
        }

    @pytest.mark.skipif(sys.platform == 'win32', reason='symlinks need admin on Windows')
    def test_symlinked_file_skipped_not_clobbered(self, make_file, credactor_caplog):
        # S1: os.replace would rewrite the LINK, not its target — leaving the
        # live secret in the target file while reporting success. Must refuse.
        real = make_file('real.py', f'api_key = "{_AWS_KEY}"\n')
        link = os.path.join(os.path.dirname(real), 'link.py')
        os.symlink(real, link)
        config = Config(no_backup=True, replace_mode='sentinel')
        replaced, failed = batch_replace_in_file(link, [self._finding(link)], config)
        assert (replaced, failed) == (0, 1)  # refused -> unresolved, exit 1
        assert os.path.islink(link)  # link not clobbered
        with open(real) as f:
            assert _AWS_KEY in f.read()  # target keeps the secret
        assert any('symlink' in r.getMessage().lower() for r in credactor_caplog.records)

    def test_write_atomic_failure_leaves_original_intact(self, make_file, monkeypatch):
        # S14: a mid-write OSError must leave the original byte-identical, the
        # .bak intact, and no .credactor.tmp orphaned.
        def boom(*a, **k):
            raise OSError('disk full')

        path = make_file('w.py', f'api_key = "{_AWS_KEY}"\n')
        with open(path) as f:
            before = f.read()
        monkeypatch.setattr('os.fdopen', boom)
        config = Config(no_backup=False, replace_mode='sentinel')
        replaced, _ = batch_replace_in_file(path, [self._finding(path)], config)
        assert replaced == 0
        with open(path) as f:
            assert f.read() == before  # original intact
        assert os.path.exists(path + '.bak')  # backup kept
        d = os.path.dirname(path)
        assert not [f for f in os.listdir(d) if f.endswith('.credactor.tmp')]

    def test_backup_creation_failure_skips_file(self, make_file, monkeypatch, credactor_caplog):
        # S15: if the backup cannot be created, the file is not touched.
        def boom(*a, **k):
            raise OSError('no space')

        path = make_file('b.py', f'api_key = "{_AWS_KEY}"\n')
        monkeypatch.setattr('tempfile.mkstemp', boom)
        config = Config(no_backup=False, replace_mode='sentinel')
        replaced, _ = batch_replace_in_file(path, [self._finding(path)], config)
        assert replaced == 0
        with open(path) as f:
            assert _AWS_KEY in f.read()  # untouched
        assert any('backup' in r.getMessage().lower() for r in credactor_caplog.records)

    def test_secure_backup_dir_never_writes_in_repo(self, make_file, tmp_dir):
        # S2: the plaintext .bak must be created in the secure dir, never beside
        # the original (the crash-window leak the flag exists to prevent).
        backup = os.path.join(tmp_dir, 'outside')
        config = Config(secure_backup_dir=backup, replace_mode='sentinel')
        path = make_file('src.py', f'api_key = "{_AWS_KEY}"\n')
        replaced, _ = batch_replace_in_file(path, [self._finding(path)], config)
        assert replaced == 1
        assert not os.path.exists(path + '.bak')  # nothing beside the file
        assert os.listdir(backup)  # backup is in the secure dir

    def test_invalid_replacement_rejected_at_sink(self, make_file):
        # S6: a library caller building a Config directly (bypassing the CLI
        # guard) must not get an unvalidated replacement written into a file.
        path = make_file('s.py', f'api_key = "{_AWS_KEY}"\n')
        config = Config(replace_mode='custom', custom_replacement='bad;rm -rf')
        with pytest.raises(ValueError):
            batch_replace_in_file(path, [self._finding(path)], config)
        with open(path) as f:
            assert _AWS_KEY in f.read()  # untouched — raised pre-write


class TestFixAllStaleReportWarning:
    """K-5 attribution: the stale-report pointer counts failures in files
    containing ingested findings — failures confined to purely-native files
    must not blame a report that applied cleanly (the advice 'regenerate the
    report and re-run' would be actively wrong there)."""

    def test_native_only_failure_does_not_blame_report(self, make_file, credactor_caplog):
        native_path = make_file('native.py', f'api_key = "{_AWS_KEY}"\n')
        ext_path = make_file('ext.py', f'token = "{_PASSWORD}"\n')
        failing_native = _mk_finding(native_path, 'VALUE_NOT_ON_THIS_LINE')
        ok_external = _mk_finding(ext_path, _PASSWORD, ftype='external:gitleaks:generic')
        unresolved = fix_all(
            [failing_native, ok_external], os.path.dirname(native_path), Config(no_backup=True)
        )
        assert unresolved == 1
        assert not any('stale' in r.getMessage() for r in credactor_caplog.records)

    def test_failure_in_file_with_ingested_finding_warns(self, make_file, credactor_caplog):
        ext_path = make_file('ext.py', 'nothing_secret_here = 1\n')
        failing_external = _mk_finding(
            ext_path, 'VALUE_NOT_ON_THIS_LINE', ftype='external:trufflehog:AWS'
        )
        unresolved = fix_all([failing_external], os.path.dirname(ext_path), Config(no_backup=True))
        assert unresolved == 1
        assert any(
            'in file(s) with ingested findings' in r.getMessage() and 'stale' in r.getMessage()
            for r in credactor_caplog.records
        )


class TestPrivateKeyBlockRefusal:
    """A PEM finding's value is only its BEGIN header line: a line-based
    replacement would rewrite the header, leave the key material in place, and
    make the next scan report the file clean — a certified-clean file still
    holding a complete private key. Fail closed instead."""

    _PEM = (
        '-----BEGIN RSA PRIVATE KEY-----\n'
        'MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF0qFCzXY1CVHwPGVJP2XBpX3XY1p\n'
        'q8K1Gm2LPeZ4XhZi0hL6WD1Wq6Zx8mYQr0P7ncy3ZJ0Zj1P0YQ7c2S0Vt1p2b3cX\n'
        '-----END RSA PRIVATE KEY-----\n'
    )

    def _pem_finding(self, path):
        return {
            'file': path,
            'line': 1,
            'type': 'pattern:private key block',
            'severity': 'critical',
            'full_value': '-----BEGIN RSA PRIVATE KEY-----',
            'value_preview': '',
            'raw': '-----BEGIN RSA PRIVATE KEY-----',
        }

    def test_pem_block_refused_file_untouched(self, make_file, credactor_caplog):
        path = make_file('key.pem', self._PEM)
        with open(path, 'rb') as f:
            before = f.read()
        replaced, failed = batch_replace_in_file(
            path, [self._pem_finding(path)], Config(no_backup=True)
        )
        assert (replaced, failed) == (0, 1)
        with open(path, 'rb') as f:
            assert f.read() == before  # byte-identical: header NOT rewritten
        assert any(
            'refusing to redact a multi-line private key block' in r.getMessage()
            for r in credactor_caplog.records
        )

    def test_mixed_file_redacts_rest_and_counts_refusal(self, make_file):
        path = make_file('mixed.py', f'api_key = "{_AWS_KEY}"\n{self._PEM}')
        pem = self._pem_finding(path)
        pem['line'] = 2
        replaced, failed = batch_replace_in_file(
            path, [_mk_finding(path, _AWS_KEY), pem], Config(no_backup=True)
        )
        assert (replaced, failed) == (1, 1)
        with open(path) as f:
            content = f.read()
        assert _AWS_KEY not in content
        assert 'BEGIN RSA PRIVATE KEY' in content  # block intact, not half-eaten

    def test_fix_all_exits_unresolved_not_false_success(self, make_file):
        path = make_file('key.pem', self._PEM)
        unresolved = fix_all(
            [self._pem_finding(path)], os.path.dirname(path), Config(no_backup=True)
        )
        assert unresolved == 1


class TestGuardPins:
    """SR-01 and PA-02: each test pins one write-path guard that could once be
    deleted, or quietly weakened, with the whole suite still green (found by
    guard mutation). A test here must fail when its guard is broken, not merely
    run through it."""

    @pytest.mark.skipif(sys.platform == 'win32', reason='fcntl is POSIX only')
    def test_advisory_lock_held_across_read_and_write(self, make_file, monkeypatch):
        # SEC-15: the rewrite takes a non-blocking exclusive flock on the very
        # file it rewrites, and still holds it while reading and while writing.
        # A probe on a second descriptor must find the file locked at both
        # points. This spies on the read by its newline='' open, so a change to
        # how the file is read must update the spy, not drop the check.
        import fcntl

        import credactor.redactor as redactor

        path = make_file('lock.py', f'api_key = "{_AWS_KEY}"\n')
        target_ino = os.stat(path).st_ino
        real_flock = fcntl.flock
        real_open = open
        real_write = redactor._write_atomic
        calls = []
        held = {}

        def recorder(fd, op):
            calls.append((os.fstat(fd).st_ino, op))
            return real_flock(fd, op)

        def locked_elsewhere():
            with real_open(path, 'rb') as probe:
                try:
                    real_flock(probe.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return True
                real_flock(probe.fileno(), fcntl.LOCK_UN)
                return False

        def spy_open(file, *args, **kwargs):
            if file == path and kwargs.get('newline') == '' and 'encoding' in kwargs:
                held['read'] = locked_elsewhere()
            return real_open(file, *args, **kwargs)

        def spy_write(filepath, lines, encoding):
            held['write'] = locked_elsewhere()
            return real_write(filepath, lines, encoding)

        monkeypatch.setattr(fcntl, 'flock', recorder)
        monkeypatch.setattr(redactor, 'open', spy_open, raising=False)
        monkeypatch.setattr(redactor, '_write_atomic', spy_write)
        replaced, failed = batch_replace_in_file(
            path, [_mk_finding(path, _AWS_KEY)], Config(no_backup=True)
        )
        assert (replaced, failed) == (1, 0)
        assert calls == [(target_ino, fcntl.LOCK_EX | fcntl.LOCK_NB)]
        assert held == {'read': True, 'write': True}

    @pytest.mark.skipif(sys.platform == 'win32', reason='fcntl is POSIX only')
    def test_lock_contention_proceeds_and_is_logged(self, make_file, monkeypatch, credactor_caplog):
        # SEC-15 is best effort: a held lock does not block the rewrite, but the
        # failure to lock is recorded so it shows under --verbose.
        import fcntl

        def busy(fd, op):
            raise BlockingIOError(errno.EAGAIN, 'Resource temporarily unavailable')

        monkeypatch.setattr(fcntl, 'flock', busy)
        path = make_file('busy.py', f'api_key = "{_AWS_KEY}"\n')
        replaced, failed = batch_replace_in_file(
            path, [_mk_finding(path, _AWS_KEY)], Config(no_backup=True)
        )
        assert (replaced, failed) == (1, 0)
        assert any('proceeding unlocked' in r.getMessage() for r in credactor_caplog.records)

    @pytest.mark.skipif(sys.platform == 'win32', reason='symlinks need admin on Windows')
    def test_final_sweep_refuses_symlink(self, tmp_path, credactor_caplog):
        # The end-of-session sweep publishes with os.replace, which would swap
        # the link node for a regular file. It must refuse and leave the link.
        outside = tmp_path / 'outside'
        outside.mkdir()
        target = outside / 'real.py'
        original = f'token = "{_AWS_KEY}"\n'
        target.write_text(original)
        repo = tmp_path / 'repo'
        repo.mkdir()
        link = repo / 'link.py'
        link.symlink_to(target)
        _final_file_sweep(
            str(link), [_mk_finding(str(link), _AWS_KEY)], set(), Config(no_backup=True)
        )
        assert link.is_symlink()  # the link node was not replaced
        assert target.read_text() == original
        assert any(
            'refusing to sweep symlink' in r.getMessage().lower() for r in credactor_caplog.records
        )

    @pytest.mark.skipif(
        sys.platform == 'win32', reason='Windows does not support Unix-style permission bits'
    )
    @pytest.mark.parametrize('mode', [0o640, 0o4750])
    def test_final_sweep_restores_exact_mode(self, make_file, monkeypatch, mode):
        # The final sweep publishes through mkstemp, which creates files 0600,
        # so it must put the file's own mode back exactly. 0o640 is neither
        # mkstemp's 0600 nor the umask default 0644, so restoring "a sensible
        # default" fails; 0o4750 covers the special bits on this path too.
        content = f'password = "{_AWS_KEY}"\ntoken = "{_PASSWORD}"  # legacy {_AWS_KEY}\n'
        path = make_file('mode.py', content)
        try:
            os.chmod(path, mode)
        except OSError:
            pytest.skip('platform refused the mode')
        if stat.S_IMODE(os.stat(path).st_mode) != mode:
            pytest.skip('filesystem dropped part of the mode')
        findings = [
            _mk_finding(path, _AWS_KEY, 'variable:password', line=1),
            _mk_finding(path, _PASSWORD, 'variable:token', line=2),
        ]
        answers = iter(['y', 'y'])
        monkeypatch.setattr('builtins.input', lambda *a: next(answers))
        unresolved = interactive_review(findings, os.path.dirname(path), Config(no_backup=True))
        assert unresolved == 0
        with open(path) as fh:
            # The legacy copy on line 2 is only cleared by the final sweep, so
            # this proves the sweep actually rewrote the file.
            assert _AWS_KEY not in fh.read()
        assert stat.S_IMODE(os.stat(path).st_mode) == mode

    @pytest.mark.skipif(
        sys.platform == 'win32', reason='Windows does not support Unix-style permission bits'
    )
    @pytest.mark.parametrize('mode', [0o4755, 0o2755, 0o1755])
    def test_special_mode_bits_preserved(self, make_file, mode):
        # SEC-22: the rewrite restores the full mode (& 0o7777), not only rwx.
        # One special bit per case, so a platform that refuses one bit (macOS
        # clears setgid when the directory's group is not the user's, and
        # refuses sticky on regular files) skips only that case.
        path = make_file('suid.py', f'api_key = "{_AWS_KEY}"\n')
        try:
            os.chmod(path, mode)
        except OSError:
            pytest.skip('platform refused the bit')
        if stat.S_IMODE(os.stat(path).st_mode) != mode:
            pytest.skip('filesystem dropped the bit')
        replaced, _ = batch_replace_in_file(
            path, [_mk_finding(path, _AWS_KEY)], Config(no_backup=True)
        )
        assert replaced == 1
        assert stat.S_IMODE(os.stat(path).st_mode) == mode

    def _bak_fixture(self, tmp_path):
        repo = tmp_path / 'repo'
        repo.mkdir()
        src = repo / 'a.py'
        original = f'api_key = "{_AWS_KEY}"\n'
        src.write_text(original)
        return src, original

    @pytest.mark.skipif(sys.platform == 'win32', reason='symlinks need admin on Windows')
    def test_planted_bak_symlink_not_followed(self, tmp_path):
        # SEC-09: the backup goes to a fresh temp file that is renamed over
        # <file>.bak, so a pre-planted .bak symlink is replaced, never written
        # through to its target.
        canary = tmp_path / 'canary.txt'
        canary.write_bytes(b'CANARY-DO-NOT-TOUCH\n')
        src, original = self._bak_fixture(tmp_path)
        bak = src.with_name('a.py.bak')
        bak.symlink_to(canary)
        replaced, _ = batch_replace_in_file(str(src), [_mk_finding(str(src), _AWS_KEY)], Config())
        assert replaced == 1
        assert canary.read_bytes() == b'CANARY-DO-NOT-TOUCH\n'
        assert not bak.is_symlink()
        assert bak.read_text() == original

    @pytest.mark.skipif(sys.platform == 'win32', reason='symlinks need admin on Windows')
    def test_bak_symlink_planted_during_backup_not_followed(self, tmp_path, monkeypatch):
        # SEC-09 exists to close a check-then-copy race: the symlink may appear
        # after any check and just before the copy. Plant it at that moment.
        # A return to islink() plus copy2() onto the .bak fails here.
        canary = tmp_path / 'canary.txt'
        canary.write_bytes(b'CANARY-DO-NOT-TOUCH\n')
        src, original = self._bak_fixture(tmp_path)
        bak = src.with_name('a.py.bak')
        real_copy2 = shutil.copy2

        def racing_copy2(source, dest, *args, **kwargs):
            if not os.path.lexists(bak):
                os.symlink(canary, bak)
            return real_copy2(source, dest, *args, **kwargs)

        monkeypatch.setattr(shutil, 'copy2', racing_copy2)
        replaced, _ = batch_replace_in_file(str(src), [_mk_finding(str(src), _AWS_KEY)], Config())
        assert replaced == 1
        assert canary.read_bytes() == b'CANARY-DO-NOT-TOUCH\n'
        assert not bak.is_symlink()
        assert bak.read_text() == original

    @pytest.mark.skipif(sys.platform == 'win32', reason='symlinks need admin on Windows')
    def test_bak_symlink_to_directory_not_followed(self, tmp_path):
        # A .bak symlink to a directory must be replaced as a node. shutil.move
        # would instead drop the plaintext backup inside the outside directory.
        outside = tmp_path / 'outside'
        outside.mkdir()
        src, original = self._bak_fixture(tmp_path)
        bak = src.with_name('a.py.bak')
        bak.symlink_to(outside, target_is_directory=True)
        replaced, _ = batch_replace_in_file(str(src), [_mk_finding(str(src), _AWS_KEY)], Config())
        assert replaced == 1
        assert os.listdir(outside) == []
        assert not bak.is_symlink()
        assert bak.read_text() == original

    @pytest.mark.skipif(sys.platform == 'win32', reason='symlinks need admin on Windows')
    @pytest.mark.parametrize('target_kind', ['file', 'directory'])
    def test_secure_dir_planted_dest_symlink_not_followed(self, tmp_path, target_kind):
        # SEC-09 in the --secure-backup-dir branch. The destination name is
        # predictable (basename plus a hash of the absolute path), and the
        # manual's own example puts the directory under /tmp, so a symlink can
        # be planted there in advance. It must be replaced, never followed.
        src, original = self._bak_fixture(tmp_path)
        backup = tmp_path / 'securebak'
        backup.mkdir()
        digest = hashlib.sha256(os.path.abspath(str(src)).encode('utf-8')).hexdigest()[:12]
        dest = backup / f'a.py.{digest}.bak'
        if target_kind == 'file':
            target = tmp_path / 'canary.txt'
            target.write_bytes(b'CANARY-DO-NOT-TOUCH\n')
            dest.symlink_to(target)
        else:
            target = tmp_path / 'outside'
            target.mkdir()
            dest.symlink_to(target, target_is_directory=True)
        replaced, _ = batch_replace_in_file(
            str(src), [_mk_finding(str(src), _AWS_KEY)], Config(secure_backup_dir=str(backup))
        )
        assert replaced == 1
        if target_kind == 'file':
            assert target.read_bytes() == b'CANARY-DO-NOT-TOUCH\n'
        else:
            assert os.listdir(target) == []
        assert not dest.is_symlink()
        assert dest.read_text() == original

    def test_backup_failure_aborts_before_any_write(self, make_file, monkeypatch, credactor_caplog):
        # S15, narrowed: only the backup step fails. The mkstemp-wide test in
        # TestWritePathSafety also breaks the later write, so it cannot tell
        # whether the abort itself ran.
        path = make_file('abort.py', f'api_key = "{_AWS_KEY}"\n')
        with open(path, 'rb') as fh:
            before = fh.read()
        monkeypatch.setattr('credactor.redactor._create_backup', lambda *a, **k: None)
        replaced, failed = batch_replace_in_file(
            path, [_mk_finding(path, _AWS_KEY)], Config(no_backup=False)
        )
        assert (replaced, failed) == (0, 1)
        with open(path, 'rb') as fh:
            assert fh.read() == before
        assert any('backup failed' in r.getMessage().lower() for r in credactor_caplog.records)

    def test_real_backup_failure_aborts_before_any_write(self, make_file):
        # A real backup failure with no monkeypatching, and one that leaves the
        # write path working: <file>.bak is a non-empty directory, so publishing
        # the backup fails while the rewrite itself would succeed. The backup
        # step must report the failure and the file must be left alone.
        path = make_file('abort2.py', f'api_key = "{_AWS_KEY}"\n')
        with open(path, 'rb') as fh:
            before = fh.read()
        os.mkdir(path + '.bak')
        with open(os.path.join(path + '.bak', 'keep'), 'w') as fh:
            fh.write('x')
        replaced, failed = batch_replace_in_file(path, [_mk_finding(path, _AWS_KEY)], Config())
        assert (replaced, failed) == (0, 1)
        with open(path, 'rb') as fh:
            assert fh.read() == before
        leftovers = [f for f in os.listdir(os.path.dirname(path)) if f.endswith('.credactor.bak')]
        assert leftovers == []

    def test_interactive_backup_failure_not_skipped_later(self, make_file, monkeypatch):
        # Interactive mode backs a file up once, on the first approval that
        # succeeds. If that first backup fails, a later approval to the same
        # file must try the backup again, not rewrite with no backup at all.
        path = make_file('two.py', f'api_key = "{_AWS_KEY}"\npassword = "{_PASSWORD}"\n')
        with open(path, 'rb') as fh:
            before = fh.read()
        findings = [
            _mk_finding(path, _AWS_KEY, line=1),
            _mk_finding(path, _PASSWORD, 'variable:password', line=2),
        ]
        monkeypatch.setattr('builtins.input', lambda *a: 'y')
        monkeypatch.setattr('credactor.redactor._create_backup', lambda *a, **k: None)
        unresolved = interactive_review(findings, os.path.dirname(path), Config(no_backup=False))
        assert unresolved == 2
        with open(path, 'rb') as fh:
            assert fh.read() == before

    @pytest.mark.parametrize('publisher', ['batch', 'final_sweep'])
    def test_publication_is_an_atomic_rename(self, make_file, monkeypatch, publisher):
        # PA-02: both write paths publish by renaming a complete temp file, made
        # in the target's own directory, over the target. At that moment the
        # target still holds its original bytes and the temp file the whole new
        # content, so a run that dies at any point leaves the old file or the
        # new one, never a partial mix. (That is process death, not power loss:
        # nothing is fsynced.) A copy-based or in-place publish never makes this
        # rename.
        path = make_file('pub.py', f'api_key = "{_AWS_KEY}"\n')
        with open(path, 'rb') as fh:
            original = fh.read()
        real_replace = os.replace
        seen = []

        def spy(src, dst, *args, **kwargs):
            if os.path.abspath(dst) == os.path.abspath(path):
                with open(dst, 'rb') as fh:
                    target_now = fh.read()
                with open(src, 'rb') as fh:
                    temp_now = fh.read()
                seen.append((os.path.dirname(os.path.abspath(src)), target_now, temp_now))
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, 'replace', spy)
        finding = _mk_finding(path, _AWS_KEY)
        if publisher == 'batch':
            replaced, failed = batch_replace_in_file(path, [finding], Config(no_backup=True))
            assert (replaced, failed) == (1, 0)
        else:
            _final_file_sweep(path, [finding], set(), Config(no_backup=True))
        with open(path, 'rb') as fh:
            final = fh.read()
        assert _AWS_KEY.encode() not in final
        assert len(seen) == 1
        temp_dir, target_at_publish, temp_at_publish = seen[0]
        assert temp_dir == os.path.dirname(os.path.abspath(path))  # same filesystem
        assert target_at_publish == original
        assert temp_at_publish == final

    def test_failed_publication_leaves_original_intact(self, make_file, monkeypatch):
        # PA-02: if the final rename fails, the original stays byte-identical,
        # the temp file is cleaned up, and the finding counts as unresolved.
        path = make_file('pubfail.py', f'api_key = "{_AWS_KEY}"\n')
        with open(path, 'rb') as fh:
            original = fh.read()
        real_replace = os.replace

        def failing(src, dst, *args, **kwargs):
            if os.path.abspath(dst) == os.path.abspath(path):
                raise OSError('simulated publish failure')
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, 'replace', failing)
        replaced, failed = batch_replace_in_file(
            path, [_mk_finding(path, _AWS_KEY)], Config(no_backup=True)
        )
        assert (replaced, failed) == (0, 1)
        with open(path, 'rb') as fh:
            assert fh.read() == original
        leftovers = [f for f in os.listdir(os.path.dirname(path)) if f.endswith('.credactor.tmp')]
        assert leftovers == []

    def test_temp_creation_failure_does_not_write_in_place(self, make_file, monkeypatch):
        # PA-02: when the temp file cannot be created (for example a writable
        # file in a read-only directory), the rewrite must fail closed rather
        # than fall back to rewriting the target in place. With no_backup, the
        # publish step is the only caller of mkstemp, so this injection is
        # precise.
        path = make_file('notemp.py', f'api_key = "{_AWS_KEY}"\n')
        with open(path, 'rb') as fh:
            original = fh.read()

        def no_temp(*args, **kwargs):
            raise OSError(errno.EACCES, 'simulated read-only directory')

        monkeypatch.setattr(tempfile, 'mkstemp', no_temp)
        replaced, failed = batch_replace_in_file(
            path, [_mk_finding(path, _AWS_KEY)], Config(no_backup=True)
        )
        assert (replaced, failed) == (0, 1)
        with open(path, 'rb') as fh:
            assert fh.read() == original

    def test_interactive_prompt_masks_every_value(self, make_file, monkeypatch, capsys):
        # PA-02: every prompt shows only the masked value, never the secret, on
        # either stream. The findings carry realistic raw and value_preview
        # fields (both hold the plaintext), and the fake input echoes its prompt
        # the way the real input() does, so a leak through any of them fails.
        text = f'api_key = "{_AWS_KEY}"\npassword = "{_PASSWORD}"\n'
        path = make_file('prompt.py', text)
        findings = []
        for line, (value, ftype) in enumerate(
            [(_AWS_KEY, 'variable:api_key'), (_PASSWORD, 'variable:password')], start=1
        ):
            f = _mk_finding(path, value, ftype, line=line)
            f['raw'] = text.splitlines()[line - 1]
            f['value_preview'] = preview(value)
            findings.append(f)

        def fake_input(prompt=''):
            print(prompt, end='')
            return 'n'

        monkeypatch.setattr('builtins.input', fake_input)
        interactive_review(findings, os.path.dirname(path), Config(no_backup=True))
        captured = capsys.readouterr()
        for value in (_AWS_KEY, _PASSWORD):
            assert value not in captured.out + captured.err
            assert f'  Value    : {value[:4]}[REDACTED]\n' in captured.out

    def test_interactive_prompt_masks_a_secret_in_the_type(self, make_file, monkeypatch, capsys):
        # PA-04: an ingested type carries a report-controlled label, which can
        # hold a secret, this finding's or another one's.
        path = make_file('labels.py', f'api_key = "{_AWS_KEY}"\npassword = "{_PASSWORD}"\n')
        findings = [
            _mk_finding(path, _AWS_KEY, f'external:gitleaks:{_PASSWORD}', line=1),
            _mk_finding(path, _PASSWORD, f'external:gitleaks:rule-{_AWS_KEY}', line=2),
        ]
        monkeypatch.setattr('builtins.input', lambda *a: 'n')
        interactive_review(findings, os.path.dirname(path), Config(no_backup=True))
        out = capsys.readouterr().out
        for value in (_AWS_KEY, _PASSWORD):
            assert value not in out
        assert f'  Type     : external:gitleaks:{_PASSWORD[:4]}[REDACTED]\n' in out
        assert f'  Type     : external:gitleaks:rule-{_AWS_KEY[:4]}[REDACTED]\n' in out

    @pytest.mark.skipif(sys.platform == 'win32', reason='Windows file names cannot hold these')
    def test_interactive_prompt_sanitizes_paths(self, tmp_path, monkeypatch, capsys):
        # SR-06: the prompt prints the path; a name can carry a line break and
        # a CI workflow command.
        path = tmp_path / 'x\n::error::y ##[warning]z.py'
        path.write_text(f'api_key = "{_AWS_KEY}"\n', encoding='utf-8')
        monkeypatch.setattr('builtins.input', lambda *a: 'n')
        interactive_review(
            [_mk_finding(str(path), _AWS_KEY)], str(tmp_path), Config(no_backup=True)
        )
        out = capsys.readouterr().out
        assert '  [1/1]  x?::error::y #?[warning]z.py  --  line 1\n' in out
        assert not [ln for ln in out.split('\n') if ln.lstrip().startswith('::') or '##[' in ln]

    def test_interactive_prompt_masks_a_secret_in_the_path(self, tmp_path, monkeypatch, capsys):
        # SR-07: a secret in a file or directory name is masked in the prompt.
        path = tmp_path / _AWS_KEY / 'app.py'
        path.parent.mkdir()
        path.write_text(f'password = "{_PASSWORD}"\n', encoding='utf-8')
        findings = [
            _mk_finding(str(path), _PASSWORD, 'variable:password'),
            _mk_finding(str(tmp_path / 'other.py'), _AWS_KEY),
        ]
        monkeypatch.setattr('builtins.input', lambda *a: 'n')
        interactive_review(findings, str(tmp_path), Config(no_backup=True))
        out = capsys.readouterr().out
        assert _AWS_KEY not in out
        assert f'  [1/2]  {os.path.join("AKIA[REDACTED]", "app.py")}  --  line 1\n' in out

    @pytest.mark.skipif(sys.platform == 'win32', reason='Windows file names cannot hold ESC')
    def test_interactive_prompt_masks_a_value_split_by_an_escape(
        self, tmp_path, monkeypatch, capsys
    ):
        # The escape is removed for display, which joins the two halves.
        path = tmp_path / (_AWS_KEY[:8] + '\x1b[0m' + _AWS_KEY[8:] + '.py')
        path.write_text(f'password = "{_PASSWORD}"\n', encoding='utf-8')
        findings = [
            _mk_finding(str(path), _PASSWORD, 'variable:password'),
            _mk_finding(str(tmp_path / 'other.py'), _AWS_KEY),
        ]
        monkeypatch.setattr('builtins.input', lambda *a: 'n')
        interactive_review(findings, str(tmp_path), Config(no_backup=True))
        assert _AWS_KEY not in capsys.readouterr().out

    def test_nothing_under_git_is_rewritten_even_unmarked(self, tmp_path):
        # SR-16, for library callers that pass a finding in without the ingest
        # step's mark.
        path = tmp_path / '.git' / 'config'
        path.parent.mkdir()
        path.write_text(f'k = "{_AWS_KEY}"\n', encoding='utf-8')
        before = path.read_bytes()
        finding = _mk_finding(str(path), _AWS_KEY)
        assert fix_all([finding], str(tmp_path), Config(no_backup=True)) == 1
        assert path.read_bytes() == before
        replaced, failed = batch_replace_in_file(str(path), [finding], Config(no_backup=True))
        assert (replaced, failed) == (0, 1)
        assert path.read_bytes() == before

    def test_refused_finding_is_not_written_by_fix_all(self, make_file):
        path = make_file('b.py', f'k = "{_AWS_KEY}"\n')
        finding = _mk_finding(path, _AWS_KEY)
        finding['refuse_reason'] = 'the path is inside .git'
        assert fix_all([finding], os.path.dirname(path), Config(no_backup=True)) == 1
        with open(path, encoding='utf-8') as f:
            assert _AWS_KEY in f.read()

    def test_refused_finding_is_shown_but_not_prompted(self, make_file, monkeypatch, capsys):
        path = make_file('a.py', f'k = "{_AWS_KEY}"\n')
        finding = _mk_finding(path, _AWS_KEY)
        finding['refuse_reason'] = 'the path is inside .git'
        monkeypatch.setattr('builtins.input', lambda *a: pytest.fail('prompted'))
        assert interactive_review([finding], os.path.dirname(path), Config(no_backup=True)) == 1
        assert '-- Not rewritten: the path is inside .git.' in capsys.readouterr().out
        with open(path, encoding='utf-8') as f:
            assert _AWS_KEY in f.read()

    def test_interactive_prompt_strips_terminal_escapes(self, make_file, monkeypatch, capsys):
        # The prompt sanitizes what it prints. The visible prefix of a masked
        # value is four characters, which is enough for a complete escape
        # sequence such as ESC[2J (clear screen), and the type can carry
        # report-controlled text.
        value = '\x1b[2J' + 'Zq8vN3pL6tR1'
        path = make_file('esc.xml', f'<add key="Password" value="{value}" />\n')
        finding = _mk_finding(path, value, 'xml-attr:\x1b[31mPassword')
        monkeypatch.setattr('builtins.input', lambda *a: 'n')
        interactive_review([finding], os.path.dirname(path), Config(no_backup=True))
        assert '\x1b' not in capsys.readouterr().out
