"""Tests for report output formatting."""

import io
import json
import random
import re
from pathlib import Path

from credactor.report import (
    json_report,
    print_gitignore_skipped,
    print_report,
    sarif_report,
)
from credactor.utils import KnownSecrets, mask_secret

# Construct test credential via concatenation to prevent self-redaction
_AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE'
_GH_TOKEN = 'ghp_' + 'x9Kq2Lm8Rt4Wv6Yb1Nc3Pd5Fg7Hj0Sa2Ue4Io'


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
        findings = [
            {
                'file': '/tmp/test.py',
                'line': 1,
                'type': 'variable:api_key',
                'severity': 'high',
                'full_value': _AWS_KEY,
                'value_preview': _AWS_KEY,
                'raw': f'api_key = "{_AWS_KEY}"',
            }
        ]
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
        findings = [
            {
                'file': '/tmp/config.py',
                'line': 7,
                'type': 'external:trufflehog:URI',
                'severity': 'high',
                'full_value': 'postgresql://admin:Sup3rS3cr3tP@ss@db:5432/x',  # decoded
                'value_preview': '',
                'raw': f'db_url = "postgresql://admin:{on_disk}@db:5432/x"',  # encoded
            }
        ]
        buf = io.StringIO()
        print_report(findings, '/tmp', no_color=True, stream=buf)
        output = buf.getvalue()
        assert on_disk not in output  # no unmasked secret
        assert '[REDACTED]' in output  # masked value shown instead


def _finding(value, raw, *, line=1, ftype='pattern:AWS access key', path='/tmp/multi.py'):
    return {
        'file': path,
        'line': line,
        'type': ftype,
        'severity': 'critical',
        'full_value': value,
        'value_preview': value,
        'raw': raw,
    }


def _text(findings):
    buf = io.StringIO()
    print_report(findings, '/tmp', no_color=True, stream=buf)
    return buf.getvalue()


class TestKnownSecrets:
    def test_masks_every_occurrence(self):
        assert KnownSecrets([_AWS_KEY]).redact(f'{_AWS_KEY} and {_AWS_KEY}') == (
            'AKIA[REDACTED] and AKIA[REDACTED]'
        )

    def test_longest_value_first(self):
        # A value that is a prefix of another must not split the longer one.
        longer = _AWS_KEY + 'EXTRA99'
        out = KnownSecrets([_AWS_KEY, longer]).redact(f'{longer} {_AWS_KEY}')
        assert out == 'AKIA[REDACTED] AKIA[REDACTED]'

    def test_single_pass(self):
        # The mask's own visible prefix is never masked again.
        assert KnownSecrets([_AWS_KEY, 'AKIA']).redact(f'x {_AWS_KEY} y') == 'x AKIA[REDACTED] y'

    def test_short_values_ignored(self):
        # Values under four characters would mask ordinary text.
        assert KnownSecrets(['a', 'abc']).redact('a b abc') == 'a b abc'

    def test_limit_cuts_after_masking(self):
        # A value straddling the cut is masked, never shown in part.
        text = 'x' * 110 + _AWS_KEY
        assert KnownSecrets([_AWS_KEY]).redact(text, limit=120) == 'x' * 110 + 'AKIA[REDAC'

    def test_limit_reads_past_masked_values(self):
        # Masking shortens long values, so the displayed text can come from
        # beyond the first *limit* characters of the input.
        first = 'A' * 200
        text = f'{first} {_GH_TOKEN}'
        out = KnownSecrets([first, _GH_TOKEN]).redact(text, limit=120)
        assert out == 'AAAA[REDACTED] ghp_[REDACTED]'

    def test_matches_a_regex_reference(self):
        # Same result as a longest-first regex alternation, and the same as
        # slicing the full result when a limit is given.
        rng = random.Random(5)
        alphabet = 'ab_AB12'
        for _ in range(300):
            values = [
                ''.join(rng.choice(alphabet) for _ in range(rng.randint(1, 9)))
                for _ in range(rng.randint(0, 6))
            ]
            text = ''.join(rng.choice(alphabet + ' ') for _ in range(rng.randint(0, 60)))
            long_enough = sorted({v for v in values if len(v) >= 4}, key=lambda v: (-len(v), v))
            expected = text
            if long_enough:
                pattern = re.compile('|'.join(map(re.escape, long_enough)))
                expected = pattern.sub(lambda m: mask_secret(m.group(0)), text)
            assert KnownSecrets(values).redact(text) == expected
            cut = rng.randint(0, 80)
            assert KnownSecrets(values).redact(text, limit=cut) == expected[:cut]


class TestTextReportMasksEveryValue:
    """SR-05: the text report masks every known secret in a displayed line,
    not only the first occurrence of the finding's own value."""

    def test_same_value_twice_on_one_line(self):
        raw = f'a = "{_AWS_KEY}"; b = "{_AWS_KEY}"'
        out = _text([_finding(_AWS_KEY, raw)])
        assert _AWS_KEY not in out
        assert out.count('AKIA[REDACTED]') == 2

    def test_two_secrets_on_one_line(self):
        raw = f'a = "{_AWS_KEY}"; b = "{_GH_TOKEN}"'
        findings = [
            _finding(_AWS_KEY, raw),
            _finding(_GH_TOKEN, raw, ftype='pattern:GitHub token'),
        ]
        out = _text(findings)
        assert _AWS_KEY not in out
        assert _GH_TOKEN not in out

    def test_value_that_prefixes_another(self):
        longer = _GH_TOKEN + 'Zz9'
        raw = f'a = "{_GH_TOKEN}"; b = "{longer}"; c = "{_AWS_KEY}"'
        findings = [
            _finding(_GH_TOKEN, raw, ftype='pattern:GitHub token'),
            _finding(longer, raw, ftype='pattern:GitHub token'),
            _finding(_AWS_KEY, raw),
        ]
        out = _text(findings)
        for value in (_GH_TOKEN, longer, _AWS_KEY):
            assert value not in out
        assert 'Zz9' not in out  # the longer value's tail is not left behind

    def test_value_known_from_another_file(self):
        # A secret found in one file is masked wherever it is displayed.
        findings = [
            _finding(_AWS_KEY, f'key = "{_AWS_KEY}"', path='/tmp/a.py'),
            _finding(_GH_TOKEN, f'token = "{_GH_TOKEN}"  # old {_AWS_KEY}', path='/tmp/b.py'),
        ]
        out = _text(findings)
        assert _AWS_KEY not in out
        assert _GH_TOKEN not in out

    def test_escape_inside_a_value_is_masked_as_displayed(self):
        # The terminal sanitizer removes escape sequences, which would join a
        # split copy of the value back together after masking.
        raw = f'a = "{_AWS_KEY[:8]}\x1b[0m{_AWS_KEY[8:]}"; b = "{_AWS_KEY}"'
        out = _text([_finding(_AWS_KEY, raw)])
        assert _AWS_KEY not in out
        assert out.count('AKIA[REDACTED]') == 2

    def test_value_at_the_display_cut_is_masked_before_cutting(self):
        raw = 'x' * 110 + _AWS_KEY
        out = _text([_finding(_AWS_KEY, raw)])
        assert _AWS_KEY[:6] not in out
        assert 'x' * 110 + 'AKIA[REDAC\n' in out

    def test_value_too_short_to_mask_in_line(self):
        # Fails closed: the masked value alone, not the raw line.
        out = _text([_finding('abc', 'x = "abc"; y = "abc"')])
        assert 'abc' not in out
        assert '           [REDACTED]\n' in out

    def test_multiline_raw_with_the_value_twice(self):
        raw = f'\\n  token: {_GH_TOKEN}\\n  again: {_GH_TOKEN}\\n'
        out = _text([_finding(_GH_TOKEN, raw, ftype='multiline:GitHub token')])
        assert _GH_TOKEN not in out


class TestTypeMasking:
    """PA-04: an ingested type holds a report's label, so every format masks
    the report's known values in it."""

    def _findings(self):
        return [
            _finding(_AWS_KEY, f'key = "{_AWS_KEY}"', ftype=f'external:gitleaks:{_GH_TOKEN}'),
            _finding(_GH_TOKEN, f'token = "{_GH_TOKEN}"', line=2, ftype='pattern:GitHub token'),
        ]

    def test_text(self):
        out = _text(self._findings())
        assert _GH_TOKEN not in out
        assert '[external:gitleaks:ghp_[REDACTED]]' in out

    def test_json(self):
        data = json.loads(json_report(self._findings(), '/tmp'))
        assert data['findings'][0]['type'] == 'external:gitleaks:ghp_[REDACTED]'
        assert _GH_TOKEN not in json.dumps(data)

    def test_sarif(self):
        out = sarif_report(self._findings(), '/tmp')
        assert _GH_TOKEN not in out
        run = json.loads(out)['runs'][0]
        assert run['results'][0]['ruleId'] == 'external-gitleaks-ghp_[REDACTED]'


class TestSecretInFileName:
    """SR-07: a secret in a path is masked in every format, and the text and
    SARIF reports say the file name holds a secret."""

    @staticmethod
    def _findings(root, rel, value=_AWS_KEY):
        return [_finding(value, f'aws_key = "{value}"', path=str(root / rel))]

    @staticmethod
    def _text_at(findings, root):
        buf = io.StringIO()
        print_report(findings, str(root), no_color=True, stream=buf)
        return buf.getvalue()

    def test_text(self, tmp_path):
        out = self._text_at(self._findings(tmp_path, f'{_AWS_KEY}.py'), tmp_path)
        assert _AWS_KEY not in out
        assert '  FILE: AKIA[REDACTED].py\n' in out
        assert 'the file name holds a secret' in out

    def test_json(self, tmp_path):
        out = json_report(self._findings(tmp_path, f'{_AWS_KEY}.py'), str(tmp_path))
        assert _AWS_KEY not in out
        assert json.loads(out)['findings'][0]['file'] == 'AKIA[REDACTED].py'

    def test_sarif(self, tmp_path):
        rel = Path('keys', _AWS_KEY, 'app.py')
        out = sarif_report(self._findings(tmp_path, rel), str(tmp_path))
        assert _AWS_KEY not in out
        (result,) = json.loads(out)['runs'][0]['results']
        uri = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
        assert uri == str(Path('keys', 'AKIA[REDACTED]', 'app.py'))
        assert result['message']['text'].endswith(
            '(AKIA[REDACTED]). The file name holds a secret, so rename the file as well.'
        )

    def test_another_findings_secret_in_the_name(self, tmp_path):
        findings = [
            _finding(_AWS_KEY, f'aws_key = "{_AWS_KEY}"', path=str(tmp_path / 'a.py')),
            _finding(_GH_TOKEN, f't = "{_GH_TOKEN}"', path=str(tmp_path / f'{_AWS_KEY}.txt')),
        ]
        outputs = (
            self._text_at(findings, tmp_path),
            json_report(findings, str(tmp_path)),
            sarif_report(findings, str(tmp_path)),
        )
        for out in outputs:
            assert _AWS_KEY not in out

    def test_clean_names_have_no_note(self, tmp_path):
        findings = self._findings(tmp_path, 'config.py')
        assert 'file name' not in self._text_at(findings, tmp_path)
        sarif = json.loads(sarif_report(findings, str(tmp_path)))
        assert sarif['runs'][0]['results'][0]['message']['text'].endswith('(AKIA[REDACTED])')


class TestJsonReport:
    def test_valid_json(self):
        findings = [
            {
                'file': '/tmp/test.py',
                'line': 1,
                'type': 'variable:api_key',
                'severity': 'high',
                'full_value': _AWS_KEY,
                'value_preview': _AWS_KEY,
                'raw': f'api_key = "{_AWS_KEY}"',
            }
        ]
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
        findings = [
            {
                'file': '/tmp/test.py',
                'line': 1,
                'type': 'variable:api_key',
                'severity': 'critical',
                'full_value': _AWS_KEY,
                'value_preview': _AWS_KEY,
                'raw': f'api_key = "{_AWS_KEY}"',
            }
        ]
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
        findings = [
            {
                'file': '/tmp/test.py',
                'line': 5,
                'type': 'variable:api_key',
                'severity': 'high',
                'full_value': _AWS_KEY,
                'value_preview': _AWS_KEY,
                'raw': raw_line,
            }
        ]
        result = json.loads(sarif_report(findings, '/tmp'))
        region = result['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']
        assert region['startLine'] == 5
        assert region['endLine'] == 5
        assert region['startColumn'] >= 1
        assert 'endColumn' in region

    def test_sarif_omits_columns_when_value_absent(self):
        # P8/#31: when full_value isn't on the raw line, omit column info rather
        # than point at a wrong column.
        findings = [
            {
                'file': '/tmp/test.py',
                'line': 3,
                'type': 'variable:api_key',
                'severity': 'high',
                'full_value': _AWS_KEY,
                'value_preview': _AWS_KEY,
                'raw': 'api_key = os.environ["KEY"]',  # value not present in raw
            }
        ]
        result = json.loads(sarif_report(findings, '/tmp'))
        region = result['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']
        assert region['startLine'] == 3
        assert 'startColumn' not in region
        assert 'endColumn' not in region

    def test_sarif_declares_codepoint_columns(self):
        """S13: columns are computed with str.find/len (codepoints), but SARIF
        2.1.0 defaults to utf16CodeUnits when columnKind is absent — GitHub then
        mis-highlights astral-plane chars. Declare unicodeCodePoints so the
        existing columns are interpreted correctly."""
        findings = [
            {
                'file': '/tmp/test.py',
                'line': 1,
                'type': 'variable:api_key',
                'severity': 'high',
                'full_value': _AWS_KEY,
                'value_preview': _AWS_KEY,
                'raw': f'api_key = "{_AWS_KEY}"',
            }
        ]
        result = json.loads(sarif_report(findings, '/tmp'))
        assert result['runs'][0]['columnKind'] == 'unicodeCodePoints'

    def test_sarif_columns_are_codepoint_offsets(self):
        """Guard for the declaration above: a non-BMP char before the secret is
        1 codepoint (2 UTF-16 units), so startColumn is the codepoint offset —
        consistent with the declared unicodeCodePoints, not UTF-16 units."""
        raw_line = f'x = "\U0001f511" ; api_key = "{_AWS_KEY}"'
        findings = [
            {
                'file': '/tmp/test.py',
                'line': 1,
                'type': 'variable:api_key',
                'severity': 'high',
                'full_value': _AWS_KEY,
                'value_preview': _AWS_KEY,
                'raw': raw_line,
            }
        ]
        result = json.loads(sarif_report(findings, '/tmp'))
        region = result['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']
        assert region['startColumn'] == raw_line.find(_AWS_KEY) + 1


class TestPrintGitignoreSkipped:
    def test_writes_to_configurable_stream(self, tmp_path):
        # P8/#60: a configurable stream like print_report. Real paths under
        # tmp_path so relativize() works identically on every platform — the
        # old hardcoded '/tmp/...' passed on Windows only via the
        # outside-root fallback printing the original string by coincidence.
        buf = io.StringIO()
        skipped = str(tmp_path / 'a' / 'secret.json')
        print_gitignore_skipped([skipped], str(tmp_path), no_color=True, stream=buf)
        out = buf.getvalue()
        assert 'not scanned' in out
        assert str(Path('a') / 'secret.json') in out

    def test_empty_is_noop(self):
        buf = io.StringIO()
        print_gitignore_skipped([], '/tmp', stream=buf)
        assert buf.getvalue() == ''

    def test_sarif_rule_fields(self):
        """SARIF rules should include fullDescription and help."""
        findings = [
            {
                'file': '/tmp/test.py',
                'line': 1,
                'type': 'variable:api_key',
                'severity': 'high',
                'full_value': _AWS_KEY,
                'value_preview': _AWS_KEY,
                'raw': f'api_key = "{_AWS_KEY}"',
            }
        ]
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
        findings = [
            {
                'file': '/tmp/test.py',
                'line': 1,
                'type': 'variable:api_key',
                'severity': 'high',
                'full_value': _AWS_KEY,
                'value_preview': _AWS_KEY,
                'raw': f'api_key = "{_AWS_KEY}"',
            }
        ]
        result = json.loads(sarif_report(findings, '/tmp'))
        driver = result['runs'][0]['tool']['driver']
        assert 'informationUri' in driver
        assert 'Credactor' in driver['name']

    def test_sarif_rule_index(self):
        """SARIF results should include ruleIndex."""
        findings = [
            {
                'file': '/tmp/test.py',
                'line': 1,
                'type': 'variable:api_key',
                'severity': 'high',
                'full_value': _AWS_KEY,
                'value_preview': _AWS_KEY,
                'raw': f'api_key = "{_AWS_KEY}"',
            }
        ]
        result = json.loads(sarif_report(findings, '/tmp'))
        assert 'ruleIndex' in result['runs'][0]['results'][0]
