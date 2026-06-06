"""Unit tests for regex patterns in credactor.patterns."""

import pytest

from credactor.patterns import (
    _AWS_RE,
    _CONN_STRING_RE,
    _GCP_RE,
    _GITHUB_RE,
    _GITLAB_RE,
    _NPM_RE,
    _PEM_KEY_RE,
    _PYPI_RE,
    _SLACK_RE,
    _STRIPE_LIVE_RE,
    ASSIGNMENT_RE,
    CRED_VAR_PATTERNS,
    DYNAMIC_LOOKUP_RE,
    SUPPRESS_RE,
    xml_attr_finditer,
)


# ---------------------------------------------------------------------------
# Provider-specific token patterns (#19)
# ---------------------------------------------------------------------------
class TestProviderPatterns:
    def test_aws_key(self):
        assert _AWS_RE.search('AKIA' + 'IOSFODNN7EXAMPLE')

    def test_gcp_key(self):
        assert _GCP_RE.search('AIzaSyA12345678' + '90abcdefghijklmnopqrstuv')

    def test_stripe_live(self):
        assert _STRIPE_LIVE_RE.search('sk_live_abcdefghij' + 'klmnopqrstuvwx')

    def test_slack_token(self):
        assert _SLACK_RE.search('xoxb-12345678' + '90-abcdefghij')

    def test_github_pat(self):
        assert _GITHUB_RE.search('ghp_ABCDEFGHIJ' + 'KLMNOPqrstuvwxyz123456')

    def test_github_pat_v2(self):
        assert _GITHUB_RE.search('github_pat_ABCDEFGHIJ' + 'KLMNOPqrst')

    def test_gitlab_pat(self):
        assert _GITLAB_RE.search('glpat-xxxxxxxxxx' + 'xxxxxxxxxx')

    def test_npm_token(self):
        assert _NPM_RE.search('npm_abcdefghijklmnop' + 'qrstuvwxyz0123456789')

    def test_pypi_token(self):
        assert _PYPI_RE.search('pypi-abcdefghij' + 'klmnop')

    def test_pem_header(self):
        assert _PEM_KEY_RE.search('-----BEGIN RSA PRIVATE KEY-----')
        assert _PEM_KEY_RE.search('-----BEGIN PRIVATE KEY-----')
        assert _PEM_KEY_RE.search('-----BEGIN EC PRIVATE KEY-----')

    def test_no_false_positive_aws(self):
        assert not _AWS_RE.search('AKIANOTLONG')  # too short

    def test_no_false_positive_gcp(self):
        assert not _GCP_RE.search('AIzaShort')  # too short


# ---------------------------------------------------------------------------
# Connection strings (#17)
# ---------------------------------------------------------------------------
class TestConnectionStrings:
    def test_postgres(self):
        conn = 'postgresql://admin:s3cretP' + '@ss@db.host.com:5432/mydb'
        assert _CONN_STRING_RE.search(conn)

    def test_mongodb(self):
        conn = 'mongodb+srv://user:p4ssw0rd' + '@cluster.mongodb.net/db'
        assert _CONN_STRING_RE.search(conn)

    def test_redis(self):
        conn = 'redis://default:mypassword' + '@redis.host.io:6379'
        assert _CONN_STRING_RE.search(conn)

    def test_no_match_without_creds(self):
        assert not _CONN_STRING_RE.search('https://example.com/path')


# ---------------------------------------------------------------------------
# Assignment regex (#13 fix)
# ---------------------------------------------------------------------------
class TestAssignmentRegex:
    def test_quoted_value(self):
        m = ASSIGNMENT_RE.search('api_key = "sk-abc123xyz"')
        assert m
        assert m.group('val_q') == 'sk-abc123xyz'

    def test_single_quoted(self):
        m = ASSIGNMENT_RE.search("api_key = 'sk-abc123xyz'")
        assert m
        assert m.group('val_q') == 'sk-abc123xyz'

    def test_unquoted_stops_at_comment(self):
        m = ASSIGNMENT_RE.search('api_key = sk-abc123xyz  # my key')
        assert m
        val = m.group('val_u')
        assert val == 'sk-abc123xyz'

    def test_unquoted_does_not_include_quotes(self):
        m = ASSIGNMENT_RE.search('key = value"extra"')
        assert m
        val = m.group('val_u')
        assert '"' not in (val or '')

    def test_dict_colon(self):
        m = ASSIGNMENT_RE.search('"api_key": "sk-abc123xyz"')
        assert m
        assert m.group('val_q') == 'sk-abc123xyz'


# ---------------------------------------------------------------------------
# XML attribute (#21)
# ---------------------------------------------------------------------------
class TestXmlAttr:
    def test_xml_password_key_first(self):
        line = '<add key="Password" value="s3cretP@ssw0rd123!!" />'
        results = list(xml_attr_finditer(line))
        assert len(results) >= 1
        key, val, span = results[0]
        assert key == 'Password'
        assert val == 's3cretP@ssw0rd123!!'
        assert line[span[0]:span[1]] == val

    def test_xml_value_first(self):
        line = '<add value="s3cretP@ssw0rd123!!" key="Password" />'
        results = list(xml_attr_finditer(line))
        assert len(results) >= 1
        key, val, span = results[0]
        assert key == 'Password'
        assert val == 's3cretP@ssw0rd123!!'
        # L2: the span must locate the value within the line for dedup
        assert line[span[0]:span[1]] == val

    def test_xml_name_variant(self):
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        line = f'<setting name="api_key" value="{key}" />'
        results = list(xml_attr_finditer(line))
        assert len(results) >= 1
        assert results[0][0] == 'api_key'


class TestValuePattern:
    def test_named_fields_and_positional_unpacking(self):
        from credactor.patterns import VALUE_PATTERNS, ValuePattern
        vp = VALUE_PATTERNS[0]
        assert isinstance(vp, ValuePattern)
        assert vp.severity == 'critical'
        # The scanner unpacks positionally — that must keep working.
        pattern, label, min_ent, severity = vp
        assert (pattern, label, min_ent, severity) == (
            vp.pattern, vp.label, vp.min_entropy, vp.severity)


# ---------------------------------------------------------------------------
# Variable name patterns
# ---------------------------------------------------------------------------
class TestCredVarPatterns:
    @pytest.mark.parametrize('name', [
        'api_key', 'API_KEY', 'apikey', 'api-key',
        'password', 'PASSWD', 'db_password',
        'access_token', 'auth_token', 'bearer_token',
        'client_secret', 'secret_key', 'private_key',
        'webhook_secret', 'bot_token',
        'database_url', 'db_conn_string',
    ])
    def test_matches(self, name):
        assert CRED_VAR_PATTERNS.search(name)

    @pytest.mark.parametrize('name', [
        'username', 'email', 'name', 'description',
        'is_active', 'count', 'filepath',
    ])
    def test_no_match(self, name):
        assert not CRED_VAR_PATTERNS.search(name)


# ---------------------------------------------------------------------------
# Dynamic lookup patterns (#20)
# ---------------------------------------------------------------------------
class TestDynamicLookup:
    @pytest.mark.parametrize('line', [
        'os.getenv("API_KEY")',
        'os.environ["API_KEY"]',
        'os.environ.get("API_KEY")',
        'Variable.get("my_key")',
        'config.get("key")',
        'keyring.get_password("service", "user")',
        'vault:secret/data/myapp#key',
        'ENC[AES256_GCM,data:abc123]',
        'hvac.Client(url="https://vault")',
    ])
    def test_matches(self, line):
        assert DYNAMIC_LOOKUP_RE.search(line)

    @pytest.mark.parametrize('line', [
        'api_key = "hardcoded_secret_value"',
        'secret = "AKIAIOSFODNN7EXAMPLE"',
        'password = "p4$$w0rd!"',
        'just_a_string',
    ])
    def test_no_match(self, line):
        assert not DYNAMIC_LOOKUP_RE.search(line)


# ---------------------------------------------------------------------------
# Inline suppression (#3)
# ---------------------------------------------------------------------------
class TestSuppressPattern:
    def test_basic(self):
        assert SUPPRESS_RE.search('api_key = "secret"  # credactor:ignore')

    def test_case_insensitive(self):
        assert SUPPRESS_RE.search('key = "val"  # Credactor: Ignore')

    def test_no_match(self):
        assert not SUPPRESS_RE.search('api_key = "secret"  # this is fine')
