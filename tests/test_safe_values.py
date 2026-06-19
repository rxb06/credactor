"""Tests for safe-value detection."""

import pytest

from credactor.scanner import _is_safe_value


class TestSafeValues:
    @pytest.mark.parametrize(
        'val',
        [
            'your_api_key',
            'placeholder',
            'changeme',
            'xxxxx',
            'REDACTED_BY_CREDACTOR',
            'none',
            'null',
            'true',
            'false',
        ],
    )
    def test_known_placeholders(self, val):
        assert _is_safe_value(val)

    def test_placeholder_case_insensitive(self):
        assert _is_safe_value('PLACEHOLDER')
        assert _is_safe_value('Changeme')
        assert _is_safe_value('NULL')

    @pytest.mark.parametrize(
        'val',
        [
            '$API_KEY',
            '${SECRET}',
        ],
    )
    def test_env_var_references(self, val):
        assert _is_safe_value(val)

    def test_template_refs_safe(self):
        """${VAR} and {%...%} are template refs — safe."""
        assert _is_safe_value('${MY_SECRET}')
        assert _is_safe_value('{%- env "SECRET" %}')

    def test_bare_curly_not_safe(self):
        """CVE-03 fix: bare {value} must NOT be auto-safe."""
        assert not _is_safe_value('{real_credential_here_12345}')

    @pytest.mark.parametrize(
        'val',
        [
            'get_secret()',
            'Variable.get("key")',
            'config.get("password")',
        ],
    )
    def test_function_calls(self, val):
        assert _is_safe_value(val)

    def test_parens_in_value_not_safe(self):
        """CVE-01 fix: credential containing ( should NOT be marked safe."""
        assert not _is_safe_value('my_p@ss(word)123')
        assert not _is_safe_value('sk_live_abc(def)ghijk')

    @pytest.mark.parametrize(
        'val',
        [
            './relative/path/to/key',
            '~/config/secrets.yaml',
            'C:\\Users\\key.pem',
        ],
    )
    def test_file_paths(self, val):
        assert _is_safe_value(val)

    def test_slash_prefix_not_auto_safe(self):
        """HIGH-01 fix: bare / prefix should NOT auto-mark safe."""
        assert not _is_safe_value('/tmp/AKIAIOSFODNN7EXAMPLE')

    def test_real_path_with_high_slash_density(self):
        """Genuine paths with many slashes are still safe."""
        assert _is_safe_value('./a/b/c/d/e/f/g/config.yaml')

    @pytest.mark.parametrize(
        'val',
        [
            'https://api.example.com/v1/endpoint',
            'http://localhost:8080/api',
            'ftp://files.example.com/data',
        ],
    )
    def test_urls_without_creds(self, val):
        assert _is_safe_value(val)

    def test_url_with_embedded_creds_not_safe(self):
        # Connection strings with user:pass@host should NOT be safe
        conn = 'postgresql://admin:secret' + '@host/db'
        assert not _is_safe_value(conn)

    def test_real_credentials_not_safe(self):
        # credactor:ignore
        pwd = 'xK9#mL2' + '$vQ7@nR5'
        assert not _is_safe_value(pwd)
        # credactor:ignore
        key = 'sk_live_abcdefghij' + 'klmnopqrstuvwx'
        assert not _is_safe_value(key)

    def test_sentinel_is_safe(self):
        # The redaction sentinel must be safe so we don't re-flag already-redacted files
        assert _is_safe_value('REDACTED_BY_CREDACTOR')

    def test_extra_safe_values(self):
        assert _is_safe_value('custom_safe_val', extra_safe={'custom_safe_val'})
        assert not _is_safe_value('not_custom', extra_safe={'custom_safe_val'})
