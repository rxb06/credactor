"""Tests for report output formatting."""

import io
import json
from pathlib import Path

from credactor.report import (
    json_report,
    print_gitignore_skipped,
    print_report,
    sarif_report,
)
from credactor.utils import mask_secret

# Construct test credential via concatenation to prevent self-redaction
_AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'


class TestMaskSecret:
    def test_long_value(self):
        assert mask_secret(_AWS_KEY) == 'AKIA[REDACTED]'

    def test_short_value(self):
        assert mask_secret('abc') == '[REDACTED]'

    def test_custom_visible(self):
        assert mask_secret(_AWS_KEY, visible=6) == 'AKIAIO[REDACTED]'


class TestTextReport:
    def test_no_findings_prints_nothing(self):
        # The 'clean scan' message has exactly one owner: cli._emit_report
        # (which returns early on empty findings in text mode and is tested in
        # test_cli). print_report's own empty-branch copy had drifted from it
        # and was removed — empty input prints nothing at all, so neither a
        # duplicate clean message nor a misleading 0-finding report frame can
        # come back.
        buf = io.StringIO()
        print_report([], '/tmp', no_color=True, stream=buf)
        assert buf.getvalue() == ''

    def test_secrets_masked_in_output(self):
        findings = [{
            'file': '/tmp/test.py',
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': _AWS_KEY,
            'value_preview': _AWS_KEY,
            'raw': f'api_key = "{_AWS_KEY}"',
        }]
        buf = io.StringIO()
        print_report(findings, '/tmp', no_color=True, stream=buf)
        output = buf.getvalue()
        # The full credential should NOT appear in output
        assert _AWS_KEY not in output
        # But the masked version should
        assert 'AKIA[REDACTED]' in output

    def test_no_leak_when_value_not_verbatim_in_raw(self):
        # An ingested finding whose stored value is NOT a verbatim substring of
        # the raw line (e.g. TruffleHog URL-decoded value vs the encoded source)
        # must not leak the on-disk secret: the substring mask no-ops, so the
        # report must fail closed and show only the masked value, never raw.
        on_disk = 'Sup3rS3cr3tP%40ss'
        findings = [{
            'file': '/tmp/config.py', 'line': 7,
            'type': 'external:trufflehog:URI', 'severity': 'high',
            'full_value': 'postgresql://admin:Sup3rS3cr3tP@ss@db:5432/x',  # decoded
            'value_preview': '',
            'raw': f'db_url = "postgresql://admin:{on_disk}@db:5432/x"',   # encoded
        }]
        buf = io.StringIO()
        print_report(findings, '/tmp', no_color=True, stream=buf)
        output = buf.getvalue()
        assert on_disk not in output           # no unmasked secret
        assert '[REDACTED]' in output          # masked value shown instead


class TestJsonReport:
    def test_valid_json(self):
        findings = [{
            'file': '/tmp/test.py',
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': _AWS_KEY,
            'value_preview': _AWS_KEY,
            'raw': f'api_key = "{_AWS_KEY}"',
        }]
        result = json.loads(json_report(findings, '/tmp'))
        assert result['count'] == 1
        assert result['findings'][0]['severity'] == 'high'
        # Secret should be masked
        assert _AWS_KEY not in result['findings'][0]['value']

    def test_empty(self):
        result = json.loads(json_report([], '/tmp'))
        assert result['count'] == 0
        assert result['findings'] == []


def test_critical_and_high_have_distinct_colors():
    # P1 quick win: CRITICAL and HIGH must not both render the same red.
    from credactor.report import _SEVERITY_COLOR
    assert _SEVERITY_COLOR['critical'] != _SEVERITY_COLOR['high']


class TestSarifReport:
    def test_valid_sarif(self):
        findings = [{
            'file': '/tmp/test.py',
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'critical',
            'full_value': _AWS_KEY,
            'value_preview': _AWS_KEY,
            'raw': f'api_key = "{_AWS_KEY}"',
        }]
        result = json.loads(sarif_report(findings, '/tmp'))
        assert result['version'] == '2.1.0'
        assert len(result['runs']) == 1
        assert len(result['runs'][0]['results']) == 1
        assert result['runs'][0]['results'][0]['level'] == 'error'
        # Secret should be masked
        msg = result['runs'][0]['results'][0]['message']['text']
        assert _AWS_KEY not in msg

    def test_sarif_region_fields(self):
        """SARIF output should include endLine and column information."""
        raw_line = f'api_key = "{_AWS_KEY}"'
        findings = [{
            'file': '/tmp/test.py',
            'line': 5,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': _AWS_KEY,
            'value_preview': _AWS_KEY,
            'raw': raw_line,
        }]
        result = json.loads(sarif_report(findings, '/tmp'))
        region = result['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']
        assert region['startLine'] == 5
        assert region['endLine'] == 5
        assert region['startColumn'] >= 1
        assert 'endColumn' in region

    def test_sarif_omits_columns_when_value_absent(self):
        # P8/#31: when full_value isn't on the raw line, omit column info rather
        # than point at a wrong column.
        findings = [{
            'file': '/tmp/test.py',
            'line': 3,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': _AWS_KEY,
            'value_preview': _AWS_KEY,
            'raw': 'api_key = os.environ["KEY"]',  # value not present in raw
        }]
        result = json.loads(sarif_report(findings, '/tmp'))
        region = result['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']
        assert region['startLine'] == 3
        assert 'startColumn' not in region
        assert 'endColumn' not in region


class TestPrintGitignoreSkipped:
    def test_writes_to_configurable_stream(self, tmp_path):
        # P8/#60: a configurable stream like print_report. Real paths under
        # tmp_path so relativize() works identically on every platform — the
        # old hardcoded '/tmp/...' passed on Windows only via the
        # outside-root fallback printing the original string by coincidence.
        buf = io.StringIO()
        skipped = str(tmp_path / 'a' / 'secret.json')
        print_gitignore_skipped([skipped], str(tmp_path),
                                no_color=True, stream=buf)
        out = buf.getvalue()
        assert 'not scanned' in out
        assert str(Path('a') / 'secret.json') in out

    def test_empty_is_noop(self):
        buf = io.StringIO()
        print_gitignore_skipped([], '/tmp', stream=buf)
        assert buf.getvalue() == ''

    def test_sarif_rule_fields(self):
        """SARIF rules should include fullDescription and help."""
        findings = [{
            'file': '/tmp/test.py',
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': _AWS_KEY,
            'value_preview': _AWS_KEY,
            'raw': f'api_key = "{_AWS_KEY}"',
        }]
        result = json.loads(sarif_report(findings, '/tmp'))
        rules = result['runs'][0]['tool']['driver']['rules']
        assert len(rules) >= 1
        rule = rules[0]
        assert 'fullDescription' in rule
        assert 'help' in rule
        assert 'text' in rule['fullDescription']
        assert 'text' in rule['help']

    def test_sarif_driver_info(self):
        """SARIF driver should include informationUri."""
        findings = [{
            'file': '/tmp/test.py',
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': _AWS_KEY,
            'value_preview': _AWS_KEY,
            'raw': f'api_key = "{_AWS_KEY}"',
        }]
        result = json.loads(sarif_report(findings, '/tmp'))
        driver = result['runs'][0]['tool']['driver']
        assert 'informationUri' in driver
        assert 'Credactor' in driver['name']

    def test_sarif_rule_index(self):
        """SARIF results should include ruleIndex."""
        findings = [{
            'file': '/tmp/test.py',
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': _AWS_KEY,
            'value_preview': _AWS_KEY,
            'raw': f'api_key = "{_AWS_KEY}"',
        }]
        result = json.loads(sarif_report(findings, '/tmp'))
        assert 'ruleIndex' in result['runs'][0]['results'][0]
