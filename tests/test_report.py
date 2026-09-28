"""Tests for report output formatting."""

import io
import json
import random
import string
import time
from pathlib import Path

import pytest

from credactor.cli import main
from credactor.config import Config
from credactor.report import (
    json_report,
    print_gitignore_skipped,
    print_report,
    sarif_report,
)
from credactor.scanner import scan_file
from credactor.utils import KnownSecrets, OutputMasker, mask_secret

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


def _reference_redact(text, values):
    """Mask every occurrence span of every value of 4+ characters, merging
    spans that overlap, the slow and obvious way."""
    spans = []
    for v in {v for v in values if len(v) >= 4}:
        start = text.find(v)
        while start >= 0:
            spans.append((start, start + len(v)))
            start = text.find(v, start + 1)
    merged: list[list[int]] = []
    for s, e in sorted(spans):
        if merged and s < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    out, pos = [], 0
    for s, e in merged:
        out += [text[pos:s], mask_secret(text[s:e])]
        pos = e
    return ''.join(out) + text[pos:]


class _ReadProbe(str):
    """A str that records how far, and how much, indexing read from it."""

    max_read = 0
    chars_read = 0

    def __getitem__(self, key):
        part = str.__getitem__(self, key)
        stop = key.stop if isinstance(key, slice) else key + 1
        if stop is not None:
            self.max_read = max(self.max_read, min(stop, len(self)))
        self.chars_read += len(part)
        return part


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

    def test_matches_a_reference(self):
        # Same result as masking every occurrence span of every value, with
        # overlapping spans merged, and the same as slicing the full result
        # when a limit is given.
        rng = random.Random(5)
        for alphabet in ('ab', 'ab_AB12'):  # two letters make overlaps common
            for _ in range(600):
                self._check_reference(rng, alphabet)

    @staticmethod
    def _check_reference(rng, alphabet):
        values = [
            ''.join(rng.choice(alphabet) for _ in range(rng.randint(1, 9)))
            for _ in range(rng.randint(0, 6))
        ]
        text = ''.join(rng.choice(alphabet + ' ') for _ in range(rng.randint(0, 60)))
        expected = _reference_redact(text, values)
        assert KnownSecrets(values).redact(text) == expected, (text, values)
        cut = rng.randint(0, 80)
        assert KnownSecrets(values).redact(text, limit=cut) == expected[:cut]

    def test_overlapping_values_are_masked_as_one(self):
        # Neither value's tail may show when one starts inside the other.
        token = 'ghp_' + 'Zy98Xw76Vu54Ts32Rq10Po98Nm76Lk54Ji32'
        known = KnownSecrets([token, 'Bearer ghp_Zy98'])
        assert known.redact(f'auth = "Bearer {token}"') == 'auth = "Bear[REDACTED]"'
        known = KnownSecrets([_AWS_KEY + 'ghp_', _GH_TOKEN])
        assert known.redact(f'creds {_AWS_KEY}{_GH_TOKEN} end') == 'creds AKIA[REDACTED] end'

    def test_touching_values_are_masked_separately(self):
        assert KnownSecrets(['aaaa1111', 'bbbb2222']).redact('aaaa1111bbbb2222') == (
            'aaaa[REDACTED]bbbb[REDACTED]'
        )

    def test_longest_of_many_lengths_sharing_a_prefix(self):
        values = ['Zq9X' + 'b' * k for k in range(1, 300)]
        known = KnownSecrets(values)
        assert known.redact('Zq9X' + 'b' * 150 + 'c') == 'Zq9X[REDACTED]c'
        assert known.redact('Zq9Xc') == 'Zq9Xc'

    def test_many_lengths_sharing_a_prefix_do_bounded_work(self):
        # Trying every length at a candidate position read about a
        # length-squared number of characters; the work stays linear.
        values = ['Zq9X' + 'b' * k for k in range(1, 3001)]
        text = _ReadProbe('Zq9Xbbbbb' + 'c' * 3000)
        assert KnownSecrets(values).redact(text) == 'Zq9X[REDACTED]' + 'c' * 3000
        assert text.chars_read < 50_000

    def test_values_that_differ_only_at_the_end_stay_fast(self):
        # Each binary search used to land on the next-shorter value, so one
        # position cost a Python loop per value.
        # Timed at the one position that matters: scanning the rest of the
        # text is a plain loop, slow under coverage and not what this pins.
        values = ['Zq9X' + 'b' * k + 'a' for k in range(1, 4001)]
        known = KnownSecrets(values)
        trap = 'Zq9X' + 'b' * 4001
        assert known.redact(trap + ' x') == trap + ' x'
        start = time.perf_counter()
        for _ in range(20):
            assert known._match_at(trap, 0) == 0
        assert time.perf_counter() - start < 1

    def test_longest_match_matches_a_brute_force(self):
        # Values that are prefixes of one another, or differ only at the end.
        rng = random.Random(1)
        for _ in range(3000):
            values = {
                'abab' + ''.join(rng.choice('ab') for _ in range(rng.randint(0, 8)))
                for _ in range(rng.randint(1, 12))
            }
            text = 'abab' + ''.join(rng.choice('ab') for _ in range(rng.randint(0, 12)))
            expected = max((len(v) for v in values if text.startswith(v)), default=0)
            assert KnownSecrets(values)._match_at(text, 0) == expected, (text, values)

    @pytest.mark.parametrize('shape', ['pairs', 'chain'])
    def test_prefix_families_stay_fast(self, shape):
        # Pairs P+b^j+'a' and P+b^j+'aa' defeat searching again for the
        # common prefix; a chain P+b^k for every k defeats walking the
        # known-prefix links alone.
        if shape == 'pairs':
            values = [f'Zq9X{"b" * j}{t}' for j in range(1, 4001) for t in ('a', 'aa')]
            trap, expected = 'Zq9X' + 'b' * 4010, 0
        else:
            values = ['Zq9X' + 'b' * k for k in range(1, 4001)]
            trap, expected = 'Zq9X' + 'b' * 5 + 'c', 9
        known = KnownSecrets(values)
        start = time.perf_counter()
        for _ in range(200):
            assert known._match_at(trap, 0) == expected
        assert time.perf_counter() - start < 1

    def test_nested_values_pick_the_longest_prefix(self):
        values = ['Zq9X' + 'b' * k for k in range(1, 50)] + ['Zq9X' + 'b' * 10 + 'a']
        known = KnownSecrets(values)
        assert known.redact('Zq9X' + 'b' * 20 + 'c') == 'Zq9X[REDACTED]c'
        assert known.redact('Zq9X' + 'b' * 10 + 'ac') == 'Zq9X[REDACTED]c'
        assert known.redact('Zq9X' + 'b' * 10 + 'c') == 'Zq9X[REDACTED]c'

    def test_limit_stops_reading(self):
        text = _ReadProbe('x' * 10_000 + _AWS_KEY)
        KnownSecrets([_AWS_KEY]).redact(text, limit=120)
        assert text.max_read < 200


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
    SARIF reports say the path holds a secret."""

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
        assert 'the path holds a secret' in out

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
            '(AKIA[REDACTED]). The path holds a secret, so rename the file or directory as well.'
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
        assert 'holds a secret' not in self._text_at(findings, tmp_path)
        sarif = json.loads(sarif_report(findings, str(tmp_path)))
        assert sarif['runs'][0]['results'][0]['message']['text'].endswith('(AKIA[REDACTED])')


class TestMultilineRawIsWhole:
    """A multi-line finding's raw holds the whole block, so the report can
    mask a value that sits past the first 120 characters before cutting."""

    TOKEN = 'ghp_' + 'Mn34Op56Qr78St90Uv12Wx34Yz56Ab78Cd90'

    def _scan(self, tmp_path):
        path = tmp_path / 'cfg.js'
        path.write_text(
            'const cfg = `\n'
            f'primary: {self.TOKEN}\n'
            'note: rotate this one every ninety\n'
            f'backup: {self.TOKEN}\n'
            '`;\n',
            encoding='utf-8',
        )
        return scan_file(str(path), config=Config())

    def test_no_part_of_a_value_past_the_cut_shows(self, tmp_path):
        # The second copy starts before character 120 of the escaped block
        # and ends after it.
        findings = self._scan(tmp_path)
        buf = io.StringIO()
        print_report(findings, str(tmp_path), no_color=True, stream=buf)
        out = buf.getvalue()
        leaked = {self.TOKEN[i : i + 8] for i in range(4, len(self.TOKEN) - 7)} & {
            out[j : j + 8] for j in range(len(out) - 7)
        }
        assert leaked == set()
        (block,) = [f for f in findings if f['type'].startswith('multiline:')]
        assert block['raw'].count(self.TOKEN) == 2

    def test_sarif_omits_columns_for_a_block(self, tmp_path):
        findings = [f for f in self._scan(tmp_path) if f['type'].startswith('multiline:')]
        run = json.loads(sarif_report(findings, str(tmp_path)))['runs'][0]
        region = run['results'][0]['locations'][0]['physicalLocation']['region']
        assert 'startColumn' not in region


def _fragments(value, out, n=8):
    """Parts of *value* past its visible prefix that show in *out*."""
    return {value[i : i + n] for i in range(4, len(value) - n + 1)} & {
        out[j : j + n] for j in range(len(out) - n + 1)
    }


class TestMaskingAroundEscapes:
    """An escape sequence can end right where a secret starts (and take its
    first character when removed), or split a secret that its removal then
    joins. Masking runs on the raw text and again on the displayed text."""

    def test_escape_that_takes_a_first_character_in_a_line(self):
        raw = f'a = "\x1b[{_AWS_KEY}" b = "{_GH_TOKEN}"'
        findings = [_finding(_AWS_KEY, raw), _finding(_GH_TOKEN, raw, line=2)]
        assert _fragments(_AWS_KEY, _text(findings)) == set()

    def test_escape_that_takes_a_first_character_in_a_name(self, tmp_path):
        findings = [
            _finding(_AWS_KEY, f'k = "{_AWS_KEY}"', path=str(tmp_path / f'x\x1b[{_AWS_KEY}.py'))
        ]
        buf = io.StringIO()
        print_report(findings, str(tmp_path), no_color=True, stream=buf)
        out = buf.getvalue()
        assert _fragments(_AWS_KEY, out) == set()
        assert 'Note:' in out

    def test_value_split_by_an_escape_in_a_name(self, tmp_path):
        split = _AWS_KEY[:8] + '\x1b[0m' + _AWS_KEY[8:]
        findings = [
            _finding(_AWS_KEY, f'k = "{_AWS_KEY}"', path=str(tmp_path / 'a.py')),
            _finding(_GH_TOKEN, f't = "{_GH_TOKEN}"', path=str(tmp_path / f'{split}.py')),
        ]
        buf = io.StringIO()
        print_report(findings, str(tmp_path), no_color=True, stream=buf)
        assert _AWS_KEY not in buf.getvalue()


class TestMaskingAroundEscapesHarder:
    """Shapes that defeated masking the raw text and the displayed text in
    two separate passes."""

    OTHER = 'ghp_' + 'Qq11Ww22Ee33Rr44Tt55Yy66Uu77Ii88Oo99'

    def test_known_value_inside_a_value_an_escape_splits(self):
        outer = 'ghp_Ab12' + _AWS_KEY + 'Zz99Yy88Xx77'
        raw = f'note = "ghp_Ab12\x1b[1~{_AWS_KEY}Zz99Yy88Xx77"  other = "{self.OTHER}"'
        findings = [
            _finding(outer, f'token = "{outer}"'),
            _finding(_AWS_KEY, f'aws = "{_AWS_KEY}"', line=2),
            _finding(self.OTHER, raw, line=3),
        ]
        out = _text(findings)
        assert _fragments(outer, out) == set()

    def test_value_holding_an_escape_where_it_stands_whole(self):
        # Its escape is kept, so it shows character by character.
        value = 'Zq8v\x1b[31mN3pL6tR1x9'
        out = _text([_finding(value, f'k = "{value}"'), _finding(_AWS_KEY, f'x "{value}"', line=2)])
        assert 'N3pL6tR1x9' not in out

    def test_value_holding_an_escape_shown_without_it(self):
        # A copy of what the value displays as is masked too.
        value = 'Zq8v\x1b[31mN3pL6tR1x9'
        findings = [
            _finding(value, f'k = "{value}"'),
            _finding(_AWS_KEY, f'a = "{_AWS_KEY}" shown = "Zq8vN3pL6tR1x9"', line=2),
        ]
        assert 'N3pL6tR1x9' not in _text(findings)

    def test_escape_inside_one_value_splitting_another(self):
        # The password holds the escape that splits the token.
        token = 'ghp_' + 'Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78'
        password = 'b12\x1b[mCd34Ef5'
        raw = f'note ghp_Ab12\x1b[mCd34Ef56Gh78Ij90Kl12Mn34Op56Qr78 aws = "{_AWS_KEY}"'
        findings = [
            _finding(token, f'token = "{token}"'),
            _finding(_AWS_KEY, raw, line=2),
            _finding(password, f'password = "{password}"', line=3),
        ]
        assert _fragments(token, _text(findings)) == set()

    def test_fuzz_no_value_shows_in_any_form(self):
        # Lines built from values, values split by escape sequences, stray
        # escapes and filler: no value shows, in raw or displayed form, and no
        # ESC reaches the output.
        rng = random.Random(7)
        alnum = string.ascii_letters + string.digits
        escapes = ['\x1b[m', '\x1b[31m', '\x1b[', '\x1b]0;t\x07', '\x1b[?25l', '\x1b']
        for _ in range(400):
            values = [
                ''.join(rng.choice(alnum) for _ in range(rng.randint(8, 14))) for _ in range(3)
            ]
            pieces = []
            for _ in range(rng.randint(1, 8)):
                kind = rng.randrange(4)
                v = rng.choice(values)
                if kind == 0:
                    pieces.append(v)
                elif kind == 1:
                    cut = rng.randint(1, len(v) - 1)
                    pieces.append(v[:cut] + rng.choice(escapes[:2] + escapes[3:5]) + v[cut:])
                elif kind == 2:
                    pieces.append(rng.choice(escapes))
                else:
                    pieces.append(
                        ''.join(rng.choice(alnum + ' ') for _ in range(rng.randint(0, 6)))
                    )
            line = ''.join(pieces)
            masker = OutputMasker(values)
            out = masker.show_line(line)
            assert '\x1b' not in out
            for v in values:
                assert v not in out, (line, values, out)

    def test_split_value_far_into_a_long_line(self):
        token = 'ghp_' + 'Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78'
        osc = '\x1b]' + 'x' * 4040 + '\x07'
        raw = f'\\n{_AWS_KEY}\\n{osc}{token[:8]}\x1b[m{token[8:]}\\n'
        findings = [
            _finding(_AWS_KEY, raw, ftype='multiline:AWS access key'),
            _finding(token, f'token = "{token}"', line=5),
        ]
        assert _fragments(token, _text(findings)) == set()


class TestLineCutBeforeTheReport:
    """The scanner keeps at most 4,096 characters of a line. A known value
    cut off at the end of that must not show in part once masking or escape
    removal brings the end of the line into view."""

    def test_tail_that_starts_a_known_value_is_masked(self):
        known = KnownSecrets([_AWS_KEY])
        assert known.redact('x = "' + _AWS_KEY[:15], mask_tail=True) == 'x = "AKIA[REDACTED]'
        assert known.redact('x = "' + _AWS_KEY[:15]) == 'x = "' + _AWS_KEY[:15]
        assert known.redact('x = AKIZ', mask_tail=True) == 'x = AKIZ'

    def test_cut_inside_a_trailing_escape(self):
        # The cut left an unterminated escape right after the start of a value.
        raw = f'x = "{_GH_TOKEN}" ' + _AWS_KEY[:19] + '\x1b['
        findings = [_finding(_GH_TOKEN, raw), _finding(_AWS_KEY, f'k = "{_AWS_KEY}"', line=2)]
        assert _fragments(_AWS_KEY, _text(findings)) == set()

    def test_value_cut_at_the_end_of_a_long_line(self, tmp_path):
        line = f'x = "{_GH_TOKEN}" ' + '\x1b[m' * 1400
        line = (line + ' ' * 4096)[: 4096 - 15] + _AWS_KEY + '"'
        (tmp_path / 'a.py').write_text(line + '\n', encoding='utf-8')
        (tmp_path / 'b.py').write_text(f'k = "{_AWS_KEY}"\n', encoding='utf-8')
        findings = scan_file(str(tmp_path / 'a.py'), config=Config())
        findings += scan_file(str(tmp_path / 'b.py'), config=Config())
        buf = io.StringIO()
        print_report(findings, str(tmp_path), no_color=True, stream=buf)
        assert _fragments(_AWS_KEY, buf.getvalue()) == set()


class TestDistinctiveValuesOnlyInNames:
    """Paths and types are masked only with values that look like secrets,
    not words: a found password such as 'production' must not mask an
    unrelated directory, break its SARIF link, or change a rule id."""

    def _findings(self, root):
        return [
            _finding(
                'production',
                'db_password = "production"',
                path=str(root / 'settings.py'),
                ftype='variable:db_password',
            ),
            _finding(
                _GH_TOKEN,
                f't = "{_GH_TOKEN}"',
                path=str(root / 'config/production/app.py'),
                ftype='pattern:GitHub token',
            ),
            _finding(
                'token',
                'x = token',
                path=str(root / 'b.py'),
                ftype='external:gitleaks:github-token',
            ),
            _finding('20260928', 'pin = "20260928"', path=str(root / 'logs/20260928/app.py')),
            _finding('ab12cd', 'k = "ab12cd"', path=str(root / 'src/ab12cd/x.py')),
            _finding('Production', 'pw = "Production"', path=str(root / 'Production/a.py')),
            _finding('STAGINGENV', 'pw = "STAGINGENV"', path=str(root / 'STAGINGENV/b.py')),
        ]

    def test_text(self, tmp_path):
        buf = io.StringIO()
        print_report(self._findings(tmp_path), str(tmp_path), no_color=True, stream=buf)
        out = buf.getvalue()
        assert f'  FILE: {Path("config/production/app.py")}\n' in out
        assert 'Note:' not in out
        assert f'  FILE: {Path("logs/20260928/app.py")}\n' in out  # no letter
        assert f'  FILE: {Path("src/ab12cd/x.py")}\n' in out  # under 8 characters
        assert f'  FILE: {Path("Production/a.py")}\n' in out  # a capitalised word
        assert f'  FILE: {Path("STAGINGENV/b.py")}\n' in out  # one case, letters only
        assert '[pattern:GitHub token]' in out
        assert '[external:gitleaks:github-token]' in out
        assert 'db_password = "prod[REDACTED]"' in out  # lines still use every value

    def test_json_and_sarif(self, tmp_path):
        findings = self._findings(tmp_path)
        data = json.loads(json_report(findings, str(tmp_path)))['findings']
        assert data[1]['file'] == str(Path('config/production/app.py'))
        assert [f['type'] for f in data] == [f['type'] for f in findings]
        run = json.loads(sarif_report(findings, str(tmp_path)))['runs'][0]
        uri = run['results'][1]['locations'][0]['physicalLocation']['artifactLocation']['uri']
        assert uri == str(Path('config/production/app.py'))
        assert run['results'][1]['ruleId'] == 'pattern-GitHub token'
        assert 'holds a secret' not in run['results'][1]['message']['text']

    def test_mixed_case_letters_mask_names(self, tmp_path):
        # A passphrase of letters only is not a plain word.
        value = 'CorrectHorseBatteryStaple'
        findings = [
            _finding(
                value,
                f'note {value} here',
                path=str(tmp_path / f'{value}.txt'),
                ftype=f'external:gitleaks:{value}',
            )
        ]
        data = json.loads(json_report(findings, str(tmp_path)))['findings'][0]
        assert data['file'] == 'Corr[REDACTED].txt'
        assert data['type'] == 'external:gitleaks:Corr[REDACTED]'

    def test_value_split_by_an_escape_in_a_name_after_its_tab(self, tmp_path):
        # The name shows the value's display form (tab as a space) only once
        # the escape that splits it is removed.
        value = 'Zq7w\tPx2mTr9vLk3nQ8sB'
        path = tmp_path / 'Zq7w\tPx2m\x1b[0mTr9vLk3nQ8sB.py'
        findings = [
            _finding(value, f'k = "{value}"', path=str(tmp_path / 'a.py')),
            _finding(_AWS_KEY, f'k = "{_AWS_KEY}"', path=str(path)),
        ]
        buf = io.StringIO()
        print_report(findings, str(tmp_path), no_color=True, stream=buf)
        assert _fragments('Zq7w Px2mTr9vLk3nQ8sB', buf.getvalue()) == set()

    def test_distinctive_values_still_mask_names(self, tmp_path):
        findings = [
            _finding(
                'Hx7Kq2Lm9Pz4',
                'k = "Hx7Kq2Lm9Pz4"',
                path=str(tmp_path / 'Hx7Kq2Lm9Pz4.txt'),
                ftype='external:gitleaks:Hx7Kq2Lm9Pz4',
            )
        ]
        data = json.loads(json_report(findings, str(tmp_path)))['findings'][0]
        assert data['file'] == 'Hx7K[REDACTED].txt'
        assert data['type'] == 'external:gitleaks:Hx7K[REDACTED]'


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

    def test_masks_known_values_in_names(self, tmp_path):
        # SR-07: a skipped file can be a copy of a file whose name holds a
        # secret, such as a .bak beside it.
        buf = io.StringIO()
        skipped = str(tmp_path / f'{_GH_TOKEN}.py.bak')
        print_gitignore_skipped(
            [skipped], str(tmp_path), no_color=True, stream=buf, values=[_GH_TOKEN]
        )
        out = buf.getvalue()
        assert _GH_TOKEN not in out
        assert '    ghp_[REDACTED].py.bak\n' in out

    def test_cli_masks_the_skip_list_with_the_final_findings(self, tmp_path, capsys):
        (tmp_path / '.gitignore').write_text('*.bak\n', encoding='utf-8')
        for name in (f'{_GH_TOKEN}.py', f'{_GH_TOKEN}.py.bak'):
            (tmp_path / name).write_text(f'token = "{_GH_TOKEN}"\n', encoding='utf-8')
        with pytest.raises(SystemExit):
            main(['--ci', '--no-color', str(tmp_path)])
        out = capsys.readouterr().out
        assert 'not scanned -- covered by .gitignore' in out
        assert _GH_TOKEN not in out

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
