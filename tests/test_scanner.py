"""Tests for the core scanning logic.

All test credential values are synthetic/example-only and appear in public
documentation.  They MUST NOT be redacted — add this directory to
.credactorignore to prevent self-redaction.
"""

import pytest

from credactor.scanner import scan_file, scan_line, should_scan_file


# ---------------------------------------------------------------------------
# True positives — these MUST be detected
# ---------------------------------------------------------------------------
class TestTruePositives:
    def test_aws_key_in_assignment(self, config):
        # credactor:ignore
        findings = scan_line(1, 'aws_key = "AKIA' + 'IOSFODNN7EXAMPLE"', 'test.py', config=config)
        assert len(findings) >= 1
        assert any('AWS' in f['type'] or 'variable' in f['type'] for f in findings)

    def test_scan_line_finding_shape(self, config):
        """Every Finding must carry the full canonical key set."""
        # credactor:ignore
        findings = scan_line(1, 'aws_key = "AKIA' + 'IOSFODNN7EXAMPLE"',
                             'test.py', config=config)
        required = {'file', 'line', 'type', 'severity',
                    'full_value', 'value_preview', 'raw'}
        for f in findings:
            missing = required - set(f.keys())
            assert not missing, f'Finding missing keys: {missing}'

    def test_jwt_token(self, config):
        # credactor:ignore
        jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
               '.eyJzdWIiOiIxMjM0NTY3ODkwIn0'
               '.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U')
        findings = scan_line(1, f'token = "{jwt}"', 'test.py', config=config)
        assert len(findings) >= 1
        assert any('JWT token' in f['type'] for f in findings)

    def test_high_entropy_password(self, config):
        # credactor:ignore
        pwd = 'xK9#mL2' + '$vQ7@nR5pZ3'
        findings = scan_line(1, f'password = "{pwd}"', 'test.py', config=config)
        assert len(findings) >= 1
        assert any('variable:' in f['type'] for f in findings)

    def test_github_pat(self, config):
        # credactor:ignore
        tok = 'ghp_ABCDEFGHIJ' + 'KLMNOPqrstuvwxyz123456'
        findings = scan_line(1, f'token = "{tok}"', 'test.py', config=config)
        assert len(findings) >= 1
        assert any('GitHub token' in f['type'] for f in findings)

    def test_stripe_live_key(self, config):
        # credactor:ignore
        key = 'sk_live_abcdefghij' + 'klmnopqrstuvwx'
        findings = scan_line(1, f'key = "{key}"', 'test.py', config=config)
        assert len(findings) >= 1
        assert any('Stripe live key' in f['type'] for f in findings)

    def test_connection_string(self, config):
        # credactor:ignore
        conn = 'postgresql://admin:s3cretP' + '@ss@db.host.com:5432/mydb'
        findings = scan_line(1, f'db_url = "{conn}"', 'test.py', config=config)
        assert len(findings) >= 1
        assert any('connection string' in f['type'] for f in findings)

    def test_slack_token(self, config):
        # credactor:ignore
        tok = 'xoxb-12345678' + '90-abcdefghij'
        findings = scan_line(1, f'bot = "{tok}"', 'test.py', config=config)
        assert len(findings) >= 1
        assert any('Slack token' in f['type'] for f in findings)

    def test_severity_is_present(self, config):
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        findings = scan_line(1, f'key = "{key}"', 'test.py', config=config)
        assert all('severity' in f for f in findings)
        assert any('AWS access key' in f['type'] for f in findings)

    def test_gcp_api_key(self, config):
        # credactor:ignore
        key = 'AIzaSyA12345678' + '90abcdefghijklmnopqrstuv'
        findings = scan_line(1, f'gcp_key = "{key}"', 'test.py', config=config)
        assert len(findings) >= 1
        assert any('GCP API key' in f['type'] for f in findings)

    def test_gitlab_pat(self, config):
        # credactor:ignore
        tok = 'glpat-a1B2c3D4e5' + 'F6g7H8i9J0k1L2m3N4o5'
        findings = scan_line(1, f'token = "{tok}"', 'test.py', config=config)
        assert len(findings) >= 1
        assert any('GitLab token' in f['type'] for f in findings)

    def test_npm_token(self, config):
        # credactor:ignore
        tok = 'npm_abcdefghijklmnop' + 'qrstuvwxyz0123456789'
        findings = scan_line(1, f'token = "{tok}"', 'test.py', config=config)
        assert len(findings) >= 1
        assert any('npm token' in f['type'] for f in findings)


# ---------------------------------------------------------------------------
# True negatives — these MUST NOT be flagged
# ---------------------------------------------------------------------------
class TestTrueNegatives:
    def test_placeholder_value(self, config):
        findings = scan_line(1, 'api_key = "your_api_key"', 'test.py', config=config)
        assert len(findings) == 0

    def test_env_var_reference(self, config):
        findings = scan_line(1, 'api_key = os.getenv("API_KEY")', 'test.py', config=config)
        assert len(findings) == 0

    def test_function_call(self, config):
        findings = scan_line(1, 'password = get_password()', 'test.py', config=config)
        assert len(findings) == 0

    def test_file_path(self, config):
        findings = scan_line(1, 'key_path = "/home/user/.ssh/id_rsa"', 'test.py', config=config)
        assert len(findings) == 0

    def test_url_without_creds(self, config):
        findings = scan_line(
            1, 'api_url = "https://api.example.com/v1/key"', 'test.py', config=config,
        )
        assert len(findings) == 0

    def test_inline_suppression(self, config):
        # credactor:ignore
        pwd = 'xK9#mL2' + '$vQ7@nR5'
        findings = scan_line(
            1, f'api_key = "{pwd}"  # credactor:ignore',
            'test.py', config=config,
        )
        assert len(findings) == 0

    def test_vault_reference(self, config):
        findings = scan_line(1, 'secret = "vault:secret/data/myapp#key"', 'test.py', config=config)
        assert len(findings) == 0

    def test_def_line_skipped(self, config):
        findings = scan_line(
            1, 'def get_password(self, password="default_value"):',
            'test.py', config=config,
        )
        assert len(findings) == 0

    def test_short_value_skipped(self, config):
        findings = scan_line(1, 'password = "short"', 'test.py', config=config)
        assert len(findings) == 0

    def test_comment_line_no_value_patterns(self, config):
        findings = scan_line(1, '# api_key = "not_real"', 'test.py', config=config)
        assert len(findings) == 0

    def test_sentinel_not_reflagged(self, config):
        findings = scan_line(1, 'api_key = "REDACTED_BY_CREDACTOR"', 'test.py', config=config)
        assert len(findings) == 0

    def test_sops_encrypted(self, config):
        findings = scan_line(
            1, 'secret = "ENC[AES256_GCM,data:abc123xyz]"', 'test.py', config=config,
        )
        assert len(findings) == 0


class TestPasswordFamilyFloor:
    """H7: password-family variables get a lower entropy floor (3.0) so memorable
    weak passwords are caught, without lowering the floor for other variables."""

    def test_weak_password_in_password_var_detected(self, config):
        # entropy('Summer2024!') == 3.096: below 3.5, above the 3.0 password floor
        findings = scan_line(1, 'password = "Summer2024!"', 'test.py', config=config)
        assert len(findings) == 1
        assert findings[0]['type'] == 'variable:password'

    def test_carveout_is_scoped_to_password_family(self, config):
        # api_key matches CRED_VAR_PATTERNS but is NOT password-family, so it
        # keeps the 3.5 floor and the same weak value stays below threshold
        findings = scan_line(1, 'api_key = "Summer2024!"', 'test.py', config=config)
        assert len(findings) == 0

    def test_low_entropy_password_value_still_filtered(self, config):
        # below even the 3.0 password floor -> still filtered (precision guard)
        findings = scan_line(1, 'password = "aaaaaaaaaa"', 'test.py', config=config)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------
class TestScanFile:
    def test_pem_block_detected(self, make_file, config):
        content = (
            '-----BEGIN RSA PRIVATE KEY-----\n'
            'MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB\n'
            '-----END RSA PRIVATE KEY-----\n'
        )
        path = make_file('test_key.py', content)
        findings = scan_file(path, config=config)
        assert len(findings) >= 1
        assert any('private key' in f['type'].lower() for f in findings)

    def test_pem_block_suppressed_skips_contents(self, make_file, config):
        content = (
            '-----BEGIN RSA PRIVATE KEY-----  # credactor:ignore\n'
            'MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB\n'
            '-----END RSA PRIVATE KEY-----\n'
        )
        path = make_file('test_key_suppressed.py', content)
        findings = scan_file(path, config=config)
        assert len(findings) == 0

    def test_clean_file_no_findings(self, make_file, config):
        content = (
            'import os\n'
            'api_key = os.getenv("API_KEY")\n'
            'print("hello world")\n'
        )
        path = make_file('clean.py', content)
        findings = scan_file(path, config=config)
        assert len(findings) == 0

    def test_bom_file(self, make_file, config):
        """UTF-8 BOM should not break detection on line 1."""
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        content = f'\ufeffapi_key = "{key}"\n'
        path = make_file('bom.py', content)
        findings = scan_file(path, config=config)
        assert len(findings) >= 1

    def test_unclosed_pem_does_not_suppress_rest(
        self, make_file, config,
    ):
        """CVE-02: unclosed PEM block must not suppress subsequent lines."""
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        # PEM header with no END marker, followed by >500 filler lines,
        # then a real credential that MUST be detected.
        lines = ['-----BEGIN RSA PRIVATE KEY-----\n']
        lines += ['filler line\n'] * 505
        lines.append(f'api_key = "{key}"\n')
        content = ''.join(lines)
        path = make_file('unclosed_pem.py', content)
        findings = scan_file(path, config=config)
        # Should find the PEM header AND the AWS key after recovery
        types = [f['type'] for f in findings]
        assert any('private key' in t for t in types)
        assert any('AWS' in t or 'variable' in t for t in types)


# ---------------------------------------------------------------------------
# should_scan_file (#15)
# ---------------------------------------------------------------------------
class TestShouldScanFile:
    @pytest.mark.parametrize('name', [
        'app.py', 'config.js', 'main.ts', 'run.sh',
        '.env', '.env.local', '.env.production', '.env.staging',
        'settings.yaml', 'config.toml',
        'App.java', 'main.go', 'config.rb', 'main.php',
        'app.cs', 'main.kt', 'infra.tf',
    ])
    def test_scannable(self, name):
        assert should_scan_file(name)

    @pytest.mark.parametrize('name', [
        'image.png', 'data.csv', 'binary.exe', 'archive.zip',
        'readme.md', 'document.pdf',
    ])
    def test_not_scannable(self, name):
        assert not should_scan_file(name)

    def test_env_dash_variant(self):
        """MED-04: .env-local should still be scannable."""
        assert should_scan_file('.env-local')

    def test_env_prefix_not_overbroad(self):
        """MED-04: .environment or .envrc should NOT match."""
        assert not should_scan_file('.environment')
        assert not should_scan_file('.envrc')
