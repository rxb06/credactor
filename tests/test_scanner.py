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


class TestSecretFamilyVars:
    """H11: secret-family variable names are recognized by CRED_VAR_PATTERNS."""

    _SECRET = 'r4nd0mSecretVal9876'

    def test_bare_secret_var_detected(self, config):
        findings = scan_line(1, f'secret = "{self._SECRET}"', 'test.py', config=config)
        assert len(findings) == 1
        assert findings[0]['type'] == 'variable:secret'

    def test_api_secret_var_detected(self, config):
        findings = scan_line(1, f'api_secret = "{self._SECRET}"', 'test.py', config=config)
        assert len(findings) == 1

    def test_auth_secret_var_detected(self, config):
        findings = scan_line(1, f'auth_secret = "{self._SECRET}"', 'test.py', config=config)
        assert len(findings) == 1

    def test_compound_secret_vars_detected(self, config):
        # common *_secret names must match (the bare `\bsecret\b` alone never
        # matched after an underscore)
        for var in ('jwt_secret', 'my_secret', 'user_secret'):
            findings = scan_line(1, f'{var} = "{self._SECRET}"', 'test.py', config=config)
            assert len(findings) == 1, var

    def test_vault_reference_not_flagged(self, config):
        # adding bare `secret` must not flag a Vault reference (a dynamic lookup)
        findings = scan_line(1, 'secret = "vault:secret/data/app"', 'test.py', config=config)
        assert len(findings) == 0

    def test_secretary_and_secrets_not_matched(self, config):
        # the secret-family pattern must not match `secretary` or `secrets`
        for var in ('secretary', 'secrets'):
            findings = scan_line(1, f'{var} = "{self._SECRET}"', 'test.py', config=config)
            assert len(findings) == 0, var


class TestRecallCoverage:
    """M1/M2/M4: scan standalone key files, .config files, and Go := assignments."""

    _KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'

    def test_key_and_config_files_scanned(self):
        for name in ('server.pem', 'cert.key', 'public.crt', 'web.config',
                     'app.config', 'id_rsa', 'id_ed25519'):
            assert should_scan_file(name), name

    def test_public_key_and_unrelated_files_not_scanned(self):
        assert not should_scan_file('id_rsa.pub')
        assert not should_scan_file('notes.txt')

    def test_extensionless_private_key_file_detected(self, make_file, config):
        content = ('-----BEGIN RSA PRIVATE KEY-----\n'
                   'MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB\n'
                   '-----END RSA PRIVATE KEY-----\n')
        path = make_file('id_rsa', content)
        findings = scan_file(path, config=config)
        assert any('private key' in f['type'].lower() for f in findings)

    def test_web_config_xml_attribute_detected(self, make_file, config):
        # high-entropy generic value (>= 3.5) so this isolates the .config
        # extension gap from the entropy floor
        path = make_file('web.config',
                         '<add key="Password" value="Xy9KmL2vQ7nR5tW8pA3bC6dE" />\n')
        findings = scan_file(path, config=config)
        assert any('xml-attr' in f['type'] for f in findings)

    def test_go_short_var_declaration_detected(self, config):
        findings = scan_line(1, f'apiKey := "{self._KEY}"', 'main.go', config=config)
        assert len(findings) == 1
        assert findings[0]['full_value'] == self._KEY

    def test_comparison_operators_not_matched(self, config):
        for line in ('a == b', 'x != y', 'cond <= 5', 'count := len(items)'):
            assert scan_line(1, line, 'main.go', config=config) == [], line


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


class TestCommentProviderScan:
    """M3: deterministic provider prefixes (critical severity) are scanned on
    comment lines — a commented-out live key is a common leak shape — while the
    heuristic/structural patterns stay code-only to avoid prose false-positives."""

    _AWS = 'AKIA' + 'IOSFODNN7EXAMPLE'

    def test_bare_provider_token_in_hash_comment_detected(self, config):
        findings = scan_line(1, f'# {self._AWS}', 'test.py', config=config)
        assert len(findings) == 1
        assert findings[0]['severity'] == 'critical'
        assert findings[0]['full_value'] == self._AWS

    def test_bare_provider_token_in_slash_comment_detected(self, config):
        tok = 'ghp_ABCDEFGHIJ' + 'KLMNOPqrstuvwxyz123456'
        findings = scan_line(1, f'// {tok}', 'app.js', config=config)
        assert len(findings) == 1
        assert any('GitHub token' in f['type'] for f in findings)

    def test_commented_assignment_still_detected(self, config):
        # `# api_key = "AKIA..."` was already caught (pass 3); still one finding
        findings = scan_line(1, f'# api_key = "{self._AWS}"', 'test.py', config=config)
        assert len(findings) == 1

    def test_structural_pattern_in_comment_stays_code_only(self, config):
        # a bare JWT is detected in code (structural, high) but NOT inside a
        # comment — M3 runs only critical provider prefixes on comment lines
        jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
               '.eyJzdWIiOiIxMjM0NTY3ODkwIn0'
               '.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U')
        assert len(scan_line(1, jwt, 'a.py', config=config)) == 1
        assert len(scan_line(1, f'# {jwt}', 'a.py', config=config)) == 0


class TestCompactJwt:
    """L1: a compact JWT (all 3 segments <=40 chars) must not be dropped as
    dotted-property access, while real dotted access stays safe."""

    _COMPACT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.aZ9bY8cX7dW6eV5f'

    def test_compact_jwt_detected(self, config):
        findings = scan_line(1, f'token = "{self._COMPACT}"', 'a.py', config=config)
        assert any('JWT token' in f['type'] for f in findings), findings

    def test_dotted_access_still_safe(self, config):
        for v in ('self.config.password', 'context.config.apiKey'):
            assert scan_line(1, f'x = {v}', 'a.py', config=config) == [], v

    def test_realistic_long_jwt_still_detected(self, config):
        jwt = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
               '.eyJzdWIiOiIxMjM0NTY3ODkwIn0'
               '.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U')
        findings = scan_line(1, f'token = "{jwt}"', 'a.py', config=config)
        assert any('JWT token' in f['type'] for f in findings)


class TestMultipleSecretsPerLine:
    """L2: distinct secrets on one line are all reported; one secret matched by
    several patterns/passes is still reported exactly once."""

    _AWS = 'AKIA' + 'IOSFODNN7EXAMPLE'

    def test_two_distinct_secrets_both_reported(self, config):
        conn = 'postgres://u:pw' + '@h.example.com/db'
        line = f'url = "{conn}"; key = "{self._AWS}"'
        findings = scan_line(1, line, 'a.py', config=config)
        types = ' '.join(f['type'] for f in findings)
        assert len(findings) == 2, findings
        assert 'AWS access key' in types and 'connection string' in types

    def test_single_hex_not_double_reported(self, config):
        # a 64-char hex matches BOTH the hex and base64 patterns -> ONE finding
        h = '0123456789abcdef' * 4   # 64 chars, entropy 4.0 (clears both floors)
        findings = scan_line(1, f'token = "{h}"', 'a.py', config=config)
        assert len(findings) == 1, findings

    def test_aws_and_password_cross_pass(self, config):
        line = f'key = "{self._AWS}"; password = "Summer2024!"'
        findings = scan_line(1, line, 'a.py', config=config)
        types = ' '.join(f['type'] for f in findings)
        assert len(findings) == 2, findings
        assert 'AWS access key' in types and 'variable:password' in types

    def test_single_secret_cross_pass_collapses(self, config):
        # `api_key = "AKIA..."` matches BOTH pass-1 (AWS pattern) and pass-3
        # (api_key assignment) on the same span -> ONE finding (critical AWS wins)
        findings = scan_line(1, f'api_key = "{self._AWS}"', 'a.py', config=config)
        assert len(findings) == 1, findings
        assert 'AWS access key' in findings[0]['type']

    def test_dedup_keeps_higher_severity_discovered_later(self):
        # the dedup priority branch: a higher-severity candidate with a LATER
        # discovery index must still win over an overlapping lower-severity one
        from credactor.scanner import _dedup_findings
        low = (0, 10, {'type': 'low', 'severity': 'low', 'file': 'f', 'line': 1,
                       'full_value': 'x', 'value_preview': 'x', 'raw': ''})
        crit = (0, 10, {'type': 'crit', 'severity': 'critical', 'file': 'f', 'line': 1,
                        'full_value': 'x', 'value_preview': 'x', 'raw': ''})
        result = _dedup_findings([low, crit])
        assert len(result) == 1
        assert result[0]['severity'] == 'critical'


class TestProviderEntropyFloor:
    """L12: deterministic provider tokens are detected regardless of entropy."""

    _AWS = 'AKIA' + 'IOSFODNN7EXAMPLE'

    def test_low_entropy_aws_token_detected(self, config):
        tok = 'AKIA' + 'A' * 16   # format-valid, near-zero entropy
        findings = scan_line(1, f'key = "{tok}"', 'a.py', config=config)
        assert any('AWS access key' in f['type'] for f in findings), findings

    def test_low_entropy_github_token_detected(self, config):
        tok = 'ghp_' + 'a' * 36
        findings = scan_line(1, f'tok = "{tok}"', 'a.py', config=config)
        assert any('GitHub token' in f['type'] for f in findings), findings

    def test_realistic_aws_still_detected(self, config):
        findings = scan_line(1, f'key = "{self._AWS}"', 'a.py', config=config)
        assert any('AWS access key' in f['type'] for f in findings)

    @pytest.mark.parametrize('tok', [
        'AKIA' + 'A' * 16,            # AWS
        'ghp_' + 'a' * 36,            # GitHub
        'glpat-' + 'a' * 20,          # GitLab
        'AIza' + 'A' * 35,            # GCP
        'npm_' + 'a' * 36,            # npm
        'xoxb-' + '1' * 20,           # Slack
        'sk_live_' + '0' * 24,        # Stripe live
        'pypi-' + 'a' * 16,           # PyPI
    ])
    def test_low_entropy_provider_tokens_detected(self, config, tok):
        # all 8 deterministic provider rows must fire at 0.0 entropy
        findings = scan_line(1, f'k = "{tok}"', 'a.py', config=config)
        assert findings, tok


class TestEvaluateCandidate:
    """P6/#10: the shared gate's `floor > 0` short-circuit is load-bearing —
    provider keys (min_ent=0.0) must never acquire an entropy gate."""

    def test_zero_floor_keeps_low_entropy_value(self):
        from credactor.scanner import _evaluate_candidate
        val = 'AKIA' + 'A' * 16  # format-valid, near-zero entropy
        assert _evaluate_candidate(
            val, min_len=8, floor=0.0, filepath='f.py', lineno=1,
            allowlist=None) == val

    def test_positive_floor_drops_low_entropy_value(self):
        from credactor.scanner import _evaluate_candidate
        assert _evaluate_candidate(
            'a' * 16, min_len=8, floor=3.5, filepath='f.py', lineno=1,
            allowlist=None) is None

    def test_short_value_dropped_unless_allow_short(self):
        from credactor.scanner import _evaluate_candidate
        assert _evaluate_candidate(
            'abcd', min_len=8, floor=0.0, filepath='f.py', lineno=1,
            allowlist=None) is None
        assert _evaluate_candidate(
            'abcd', min_len=8, floor=0.0, filepath='f.py', lineno=1,
            allowlist=None, allow_short=True) == 'abcd'


class TestDynamicLookupAuditTrail:
    """SEC-27: a dynamic-lookup line suppresses the assignment pass — that
    suppression must show on the --verbose audit trail (auditability, not
    detection: the hardcoded default is still not scanned)."""

    def test_dynamic_lookup_emits_skip_log(self, credactor_caplog):
        # password = config.get("db_pass", "summer2024") — only the assignment
        # pass would catch the weak default, and it is (correctly) suppressed.
        scan_line(1, 'password = config.get("db_pass", "summer2024")', 'f.py')
        assert any('runtime/dynamic lookup' in r.message
                   for r in credactor_caplog.records)
