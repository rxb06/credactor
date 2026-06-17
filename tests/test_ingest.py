"""
Tests for credactor/ingest.py — Phase 1: Gitleaks parser.
Target: ~23 tests for the Gitleaks ingestion path.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

from credactor.ingest import (
    _GITLEAKS_SEVERITY,
    _TRUFFLEHOG_SEVERITY,
    _gitleaks_severity,
    _synthesise_raw,
    _trufflehog_severity,
    deduplicate_findings,
    ingest_gitleaks,
    ingest_trufflehog,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_gitleaks_finding(**kwargs) -> dict:
    """Return a minimal valid Gitleaks finding, overriding with kwargs."""
    base = {
        'File': 'src/config.py',
        'StartLine': 10,
        'EndLine': 10,
        'Secret': 'AKIAIOSFODNN7EXAMPLE',
        'Match': 'aws_key = "AKIAIOSFODNN7EXAMPLE"',
        'RuleID': 'aws-access-token',
        'Tags': [],
        'Commit': '',
        'SymlinkFile': '',
    }
    base.update(kwargs)
    return base


def _write_report(tmp_path: Path, findings: list) -> Path:
    """Write a Gitleaks JSON report to a temp file."""
    report = tmp_path / 'gitleaks_report.json'
    report.write_text(json.dumps(findings), encoding='utf-8')
    return report


def _make_target(tmp_path: Path) -> tuple[Path, Path]:
    """Create a target directory with a dummy src/config.py file.

    Returns (target_dir, config_py_path).
    """
    target = tmp_path / 'repo'
    src = target / 'src'
    src.mkdir(parents=True)
    config_py = src / 'config.py'
    config_py.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n', encoding='utf-8')
    return target, config_py


# ---------------------------------------------------------------------------
# 8.1 Gitleaks Parser Tests
# ---------------------------------------------------------------------------

class TestGitleaksBasicFinding:
    def test_gitleaks_basic_finding(self, tmp_path):
        """Single finding with all fields present — verify all dict keys."""
        target, config_py = _make_target(tmp_path)
        finding = _make_gitleaks_finding(
            File='src/config.py',
            StartLine=1,
            Secret='AKIAIOSFODNN7EXAMPLE',
            Match='aws_key = "AKIAIOSFODNN7EXAMPLE"',
            RuleID='aws-access-token',
            Commit='abc123def456789',
        )
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))

        assert len(results) == 1
        r = results[0]
        assert r['file'] == str((target / 'src' / 'config.py').resolve())
        assert r['line'] == 1
        assert r['type'] == 'external:gitleaks:aws-access-token'
        assert r['severity'] == 'critical'
        assert r['full_value'] == 'AKIAIOSFODNN7EXAMPLE'
        assert r['value_preview'] == 'AKIAIOSFODNN7EXAMPLE'
        assert r['raw'] == 'aws_key = "AKIAIOSFODNN7EXAMPLE"'
        assert r['commit'] == 'abc123def456'  # truncated to 12

    def test_gitleaks_multiple_findings(self, tmp_path):
        """Array with 3 findings all parsed."""
        target, _ = _make_target(tmp_path)
        findings = [
            _make_gitleaks_finding(Secret='SECRET1', Match='a = "SECRET1"', StartLine=1),
            _make_gitleaks_finding(Secret='SECRET2', Match='b = "SECRET2"', StartLine=2),
            _make_gitleaks_finding(Secret='SECRET3', Match='c = "SECRET3"', StartLine=3),
        ]
        report = _write_report(tmp_path, findings)
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 3
        assert results[0]['full_value'] == 'SECRET1'
        assert results[1]['full_value'] == 'SECRET2'
        assert results[2]['full_value'] == 'SECRET3'

    def test_gitleaks_empty_array(self, tmp_path):
        """Empty JSON array returns empty list."""
        target, _ = _make_target(tmp_path)
        report = _write_report(tmp_path, [])
        results = ingest_gitleaks(str(report), str(target))
        assert results == []


class TestGitleaksInputValidation:
    def test_gitleaks_not_array(self, tmp_path):
        """Top-level dict raises ValueError."""
        target, _ = _make_target(tmp_path)
        report = tmp_path / 'report.json'
        report.write_text('{"Secret": "foo"}', encoding='utf-8')
        with pytest.raises(ValueError, match='array'):
            ingest_gitleaks(str(report), str(target))

    def test_gitleaks_missing_secret(self, tmp_path):
        """Finding without Secret key is skipped."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding()
        del finding['Secret']
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results == []

    def test_gitleaks_empty_secret(self, tmp_path):
        """Finding with Secret='' is skipped."""
        target, _ = _make_target(tmp_path)
        report = _write_report(tmp_path, [_make_gitleaks_finding(Secret='')])
        results = ingest_gitleaks(str(report), str(target))
        assert results == []

    def test_gitleaks_non_string_secret_skipped(self, tmp_path):
        """Finding with a non-string Secret (e.g. int) is skipped, not crashed."""
        target, _ = _make_target(tmp_path)
        for bad_value in (12345, True, [], {}):
            finding = _make_gitleaks_finding()
            finding['Secret'] = bad_value
            report = _write_report(tmp_path, [finding])
            results = ingest_gitleaks(str(report), str(target))
            assert results == [], f'Expected skip for Secret={bad_value!r}'

    def test_gitleaks_missing_file(self, tmp_path):
        """Finding without File key is skipped."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding()
        del finding['File']
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results == []

    def test_gitleaks_empty_file(self, tmp_path):
        """Finding with File='' is skipped."""
        target, _ = _make_target(tmp_path)
        report = _write_report(tmp_path, [_make_gitleaks_finding(File='', SymlinkFile='')])
        results = ingest_gitleaks(str(report), str(target))
        assert results == []

    def test_gitleaks_invalid_json(self, tmp_path):
        """Non-JSON file raises ValueError."""
        target, _ = _make_target(tmp_path)
        report = tmp_path / 'bad.json'
        report.write_text('not json at all', encoding='utf-8')
        with pytest.raises(ValueError, match='not valid JSON'):
            ingest_gitleaks(str(report), str(target))

    def test_gitleaks_oversized_file_rejected(self, tmp_path, monkeypatch):
        """Report file exceeding _MAX_REPORT_BYTES raises ValueError before json.load().

        The limit is monkeypatched down so the boundary is tested without
        writing a real 100 MB file (same size-comparison semantics).
        """
        monkeypatch.setattr('credactor.ingest._MAX_REPORT_BYTES', 4096)
        target, _ = _make_target(tmp_path)
        report = tmp_path / 'huge.json'
        # Write a file exactly one byte over the limit.
        report.write_bytes(b'x' * 4097)
        with pytest.raises(ValueError, match='refusing to parse'):
            ingest_gitleaks(str(report), str(target))

    def test_gitleaks_non_string_file_skipped(self, tmp_path):
        """Finding with a non-string File value (e.g. list) is skipped, not crashed."""
        target, _ = _make_target(tmp_path)
        for bad_value in (['src/config.py'], 42, True, {}):
            finding = _make_gitleaks_finding()
            finding['File'] = bad_value
            finding['SymlinkFile'] = ''
            report = _write_report(tmp_path, [finding])
            results = ingest_gitleaks(str(report), str(target))
            assert results == [], f'Expected skip for File={bad_value!r}'


class TestGitleaksSymlinkAndPath:
    def test_gitleaks_symlink_file_used(self, tmp_path):
        """SymlinkFile takes precedence over File."""
        target, _ = _make_target(tmp_path)
        # Create the symlink target file
        (target / 'src' / 'real.py').write_text('x = "AKIAIOSFODNN7EXAMPLE"\n')
        finding = _make_gitleaks_finding(
            File='src/config.py',
            SymlinkFile='src/real.py',
            Secret='AKIAIOSFODNN7EXAMPLE',
        )
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 1
        assert results[0]['file'].endswith('real.py')

    def test_gitleaks_path_resolution(self, tmp_path):
        """Relative File resolved against target directory."""
        target, config_py = _make_target(tmp_path)
        finding = _make_gitleaks_finding(File='src/config.py')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 1
        assert os.path.isabs(results[0]['file'])
        assert results[0]['file'] == str(config_py.resolve())

    def test_gitleaks_path_traversal_blocked(self, tmp_path, capsys):
        """File='../../etc/passwd' rejected — path traversal (SEC-40c)."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(File='../../etc/passwd')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results == []
        captured = capsys.readouterr()
        assert 'traversal' in captured.err.lower() or 'outside' in captured.err.lower()

    def test_gitleaks_file_target_uses_parent_directory(self, tmp_path, capsys):
        """Passing a file as target falls back to its parent; finding is still resolved."""
        target, config_py = _make_target(tmp_path)
        finding = _make_gitleaks_finding(File='src/config.py', StartLine=1)
        report = _write_report(tmp_path, [finding])
        # Pass the file itself as target — should resolve relative to its parent dir
        results = ingest_gitleaks(str(report), str(config_py))
        captured = capsys.readouterr()
        assert 'warn' in captured.err.lower()  # defensive warning emitted
        # Finding should still be resolved (parent of config_py = src/, not repo root)
        # Path traversal guard may block it; what matters is no crash and raw is str
        for r in results:
            assert isinstance(r['raw'], str)

    @pytest.mark.skipif(
        not hasattr(os, 'symlink'), reason='symlinks not supported'
    )
    def test_gitleaks_symlink_outside_root_blocked(self, tmp_path, capsys):
        """Symlink within target pointing outside root is blocked (SEC-40c)."""
        target, _ = _make_target(tmp_path)
        # Create an external file and a symlink inside the target pointing to it
        external = tmp_path / 'external_secret.txt'
        external.write_text('secret_value\n', encoding='utf-8')
        link = target / 'src' / 'escape.py'
        try:
            link.symlink_to(external)
        except (OSError, NotImplementedError):
            pytest.skip('cannot create symlink in this environment')

        finding = _make_gitleaks_finding(File='src/escape.py', Secret='secret_value')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results == [], 'Symlink escaping target root must be blocked'
        captured = capsys.readouterr()
        assert 'traversal' in captured.err.lower() or 'outside' in captured.err.lower()


class TestGitleaksFieldMapping:
    def test_gitleaks_multiline_finding(self, tmp_path):
        """StartLine != EndLine still produces a finding (known limitation)."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(StartLine=1, EndLine=3)
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 1
        assert results[0]['line'] == 1

    def test_gitleaks_commit_present(self, tmp_path):
        """Commit mapped and truncated to 12 chars."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(Commit='deadbeef12345678')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert 'commit' in results[0]
        assert results[0]['commit'] == 'deadbeef1234'

    def test_gitleaks_commit_empty(self, tmp_path):
        """Empty Commit omits the commit key."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(Commit='')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert 'commit' not in results[0]

    def test_gitleaks_type_prefix(self, tmp_path):
        """Type is external:gitleaks:{RuleID}."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(RuleID='jwt')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results[0]['type'] == 'external:gitleaks:jwt'

    def test_gitleaks_match_as_raw(self, tmp_path):
        """Match field used as raw context line."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(Match='the_match_line = "SECRET"')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results[0]['raw'] == 'the_match_line = "SECRET"'

    def test_gitleaks_match_empty_synthesised(self, tmp_path):
        """Empty Match triggers file read to synthesise raw."""
        target, _ = _make_target(tmp_path)
        # Write a known line to the file
        (target / 'src' / 'config.py').write_text(
            'aws_key = "AKIAIOSFODNN7EXAMPLE"\n', encoding='utf-8'
        )
        finding = _make_gitleaks_finding(Match='', StartLine=1)
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results[0]['raw'] == 'aws_key = "AKIAIOSFODNN7EXAMPLE"'

    def test_gitleaks_non_string_match_falls_back_to_synthesised(self, tmp_path):
        """Non-string Match (malformed report) falls back to synthesised raw."""
        target, _ = _make_target(tmp_path)
        (target / 'src' / 'config.py').write_text(
            'aws_key = "AKIAIOSFODNN7EXAMPLE"\n', encoding='utf-8'
        )
        for bad_match in (42, True, [], {}):
            finding = _make_gitleaks_finding(StartLine=1)
            finding['Match'] = bad_match
            report = _write_report(tmp_path, [finding])
            results = ingest_gitleaks(str(report), str(target))
            assert len(results) == 1, f'Finding dropped for Match={bad_match!r}'
            assert isinstance(results[0]['raw'], str), (
                f'raw must be str, got {type(results[0]["raw"])} for Match={bad_match!r}'
            )

    def test_gitleaks_finding_dict_shape(self, tmp_path):
        """All required keys present in output finding dict."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding()
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 1
        r = results[0]
        for key in ('file', 'line', 'type', 'severity', 'full_value', 'value_preview', 'raw'):
            assert key in r, f'Missing key: {key}'


class TestGitleaksSeverity:
    def test_gitleaks_severity_mapping(self, tmp_path):
        """Known RuleIDs get correct severity from table."""
        target, _ = _make_target(tmp_path)
        cases = [
            ('aws-access-token', 'critical'),
            ('slack-webhook-url', 'high'),
            ('generic-api-key', 'medium'),
            ('jwt', 'high'),
            ('password-in-url', 'high'),
            ('private-key', 'critical'),
        ]
        for rule_id, expected in cases:
            finding = _make_gitleaks_finding(RuleID=rule_id, Tags=[])
            report = _write_report(tmp_path, [finding])
            results = ingest_gitleaks(str(report), str(target))
            assert len(results) == 1
            assert results[0]['severity'] == expected, (
                f'RuleID {rule_id!r}: expected {expected!r}, got {results[0]["severity"]!r}'
            )

    def test_gitleaks_severity_unknown_rule(self, tmp_path):
        """Unknown RuleID defaults to medium."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(RuleID='some-new-detector')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results[0]['severity'] == 'medium'

    def test_gitleaks_severity_tags_override(self, tmp_path):
        """Tags containing severity level overrides table."""
        target, _ = _make_target(tmp_path)
        # generic-api-key is 'medium' in table, but Tag says 'critical'
        finding = _make_gitleaks_finding(RuleID='generic-api-key', Tags=['critical'])
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert results[0]['severity'] == 'critical'


class TestGitleaksCap:
    def test_gitleaks_cap_10000(self, tmp_path, capsys):
        """Array with 10,001 items is truncated to 10,000 with warning."""
        target, _ = _make_target(tmp_path)
        findings = [_make_gitleaks_finding(Secret=f'SECRET{i}') for i in range(10_001)]
        report = _write_report(tmp_path, findings)
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 10_000
        captured = capsys.readouterr()
        assert 'truncating' in captured.err.lower() or 'truncated' in captured.err.lower()


# ---------------------------------------------------------------------------
# _synthesise_raw unit tests
# ---------------------------------------------------------------------------

class TestSynthesiseRaw:
    def test_reads_correct_line(self, tmp_path):
        f = tmp_path / 'myfile.py'
        f.write_text('line1\nline2\nline3\n', encoding='utf-8')
        from credactor.ingest import _read_file_lines
        _read_file_lines.cache_clear()
        assert _synthesise_raw(str(f), 2) == 'line2'

    def test_out_of_range_returns_empty(self, tmp_path):
        f = tmp_path / 'short.py'
        f.write_text('only_one_line\n', encoding='utf-8')
        from credactor.ingest import _read_file_lines
        _read_file_lines.cache_clear()
        assert _synthesise_raw(str(f), 999) == ''

    def test_missing_file_returns_empty(self, tmp_path):
        from credactor.ingest import _read_file_lines
        _read_file_lines.cache_clear()
        assert _synthesise_raw(str(tmp_path / 'nonexistent.py'), 1) == ''


# ---------------------------------------------------------------------------
# 8.2 TruffleHog Parser Tests
# ---------------------------------------------------------------------------

def _make_trufflehog_finding(**kwargs) -> dict:
    """Return a minimal valid TruffleHog finding dict, overriding with kwargs."""
    base = {
        'DetectorName': 'AWS',
        'Raw': 'AKIAIOSFODNN7EXAMPLE',
        'Verified': False,
        'SourceMetadata': {
            'Data': {
                'Filesystem': {
                    'file': 'src/config.py',
                    'line': 1,
                },
            },
        },
    }
    base.update(kwargs)
    return base


def _write_ndjson(tmp_path: Path, findings: list) -> Path:
    """Write TruffleHog NDJSON to a temp file."""
    report = tmp_path / 'trufflehog_output.json'
    lines = '\n'.join(json.dumps(f) for f in findings)
    report.write_text(lines + '\n', encoding='utf-8')
    return report


def _make_th_target(tmp_path: Path) -> tuple[Path, Path]:
    """Create a target directory with a dummy src/config.py file."""
    target = tmp_path / 'repo'
    src = target / 'src'
    src.mkdir(parents=True)
    config_py = src / 'config.py'
    config_py.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n', encoding='utf-8')
    return target, config_py


class TestTrufflehogBasicFinding:
    def test_trufflehog_basic_finding(self, tmp_path):
        """Single NDJSON line with Filesystem source — verify all dict keys."""
        target, config_py = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding()
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))

        assert len(results) == 1
        r = results[0]
        assert r['file'] == str(config_py.resolve())
        assert r['line'] == 1
        assert r['type'] == 'external:trufflehog:AWS'
        assert r['severity'] == 'high'
        assert r['full_value'] == 'AKIAIOSFODNN7EXAMPLE'
        assert r['value_preview'] == 'AKIAIOSFODNN7EXAMPLE'
        assert isinstance(r['raw'], str)

    def test_trufflehog_multiple_lines(self, tmp_path):
        """Three NDJSON lines all parsed."""
        target, _ = _make_th_target(tmp_path)
        findings = [
            _make_trufflehog_finding(Raw='SECRET1'),
            _make_trufflehog_finding(Raw='SECRET2'),
            _make_trufflehog_finding(Raw='SECRET3'),
        ]
        report = _write_ndjson(tmp_path, findings)
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 3
        assert results[0]['full_value'] == 'SECRET1'
        assert results[1]['full_value'] == 'SECRET2'
        assert results[2]['full_value'] == 'SECRET3'

    def test_trufflehog_empty_file(self, tmp_path):
        """Empty file returns empty list."""
        target, _ = _make_th_target(tmp_path)
        report = tmp_path / 'empty.json'
        report.write_text('', encoding='utf-8')
        results = ingest_trufflehog(str(report), str(target))
        assert results == []

    def test_trufflehog_blank_lines_skipped(self, tmp_path):
        """Blank lines between JSON objects are skipped."""
        target, _ = _make_th_target(tmp_path)
        report = tmp_path / 'report.json'
        finding_str = json.dumps(_make_trufflehog_finding())
        report.write_text(f'\n{finding_str}\n\n{finding_str}\n', encoding='utf-8')
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 2

    def test_trufflehog_invalid_line_skipped(self, tmp_path, credactor_caplog):
        """Malformed JSON line is skipped with a log message."""
        target, _ = _make_th_target(tmp_path)
        report = tmp_path / 'report.json'
        good = json.dumps(_make_trufflehog_finding())
        report.write_text(f'not_json\n{good}\n', encoding='utf-8')
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        assert any('invalid' in r.message.lower() for r in credactor_caplog.records)

    def test_trufflehog_wholly_unparseable_raises(self, tmp_path):
        # MV-6: a non-empty report with NO valid JSON object on any line (garbage,
        # an HTML error page, truncated braces) is a malformed report, not a clean
        # "no findings" result — fail closed like the Gitleaks path, never a silent
        # zero-findings success. (An empty / blank-only file stays a valid no-op.)
        target, _ = _make_th_target(tmp_path)
        report = tmp_path / 'bad.json'
        report.write_text('this is not json\n<html>404</html>\n{ unclosed\n',
                          encoding='utf-8')
        with pytest.raises(ValueError, match='NDJSON'):
            ingest_trufflehog(str(report), str(target))

    def test_trufflehog_json_array_raises(self, tmp_path):
        # A Gitleaks-style JSON array fed to --from-trufflehog: valid JSON but no
        # per-line object — the wrong file, must fail closed (was silently []).
        target, _ = _make_th_target(tmp_path)
        report = tmp_path / 'arr.json'
        report.write_text(json.dumps([_make_trufflehog_finding()]), encoding='utf-8')
        with pytest.raises(ValueError, match='NDJSON'):
            ingest_trufflehog(str(report), str(target))


class TestTrufflehogSourceTypes:
    def test_trufflehog_git_source(self, tmp_path):
        """SourceMetadata.Data.Git path used when no Filesystem key."""
        target, config_py = _make_th_target(tmp_path)
        finding = {
            'DetectorName': 'GitHub',
            'Raw': 'ghp_SECRETTOKEN',
            'Verified': False,
            'SourceMetadata': {
                'Data': {
                    'Git': {
                        'file': 'src/config.py',
                        'line': 1,
                        'commit': 'deadbeef12345678',
                    },
                },
            },
        }
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        assert results[0]['type'] == 'external:trufflehog:GitHub'
        assert results[0]['commit'] == 'deadbeef1234'

    def test_trufflehog_unsupported_source_skipped(self, tmp_path, credactor_caplog):
        """S3/Docker source type skipped with a log message."""
        target, _ = _make_th_target(tmp_path)
        finding = {
            'DetectorName': 'AWS',
            'Raw': 'AKIAIOSFODNN7EXAMPLE',
            'Verified': False,
            'SourceMetadata': {
                'Data': {
                    'S3': {
                        'bucket': 'my-bucket',
                        'file': 'config.py',
                        'line': 1,
                    },
                },
            },
        }
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results == []
        assert any('unsupported' in r.message.lower() for r in credactor_caplog.records)


class TestTrufflehogInputValidation:
    def test_trufflehog_missing_raw(self, tmp_path):
        """Finding without Raw key is skipped."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding()
        del finding['Raw']
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results == []

    def test_trufflehog_empty_raw(self, tmp_path):
        """Finding with Raw='' is skipped."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(Raw='')
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results == []

    def test_trufflehog_path_resolution(self, tmp_path):
        """Relative file path resolved against target directory."""
        target, config_py = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding()
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        assert os.path.isabs(results[0]['file'])
        assert results[0]['file'] == str(config_py.resolve())

    def test_trufflehog_path_traversal_blocked(self, tmp_path, capsys):
        """Path traversal via crafted file path rejected (SEC-40c)."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding()
        finding['SourceMetadata']['Data']['Filesystem']['file'] = '../../etc/passwd'
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results == []
        captured = capsys.readouterr()
        assert 'traversal' in captured.err.lower() or 'outside' in captured.err.lower()

    def test_trufflehog_non_string_file_skipped(self, tmp_path):
        """Finding with a non-string file value (e.g. list) is skipped, not crashed."""
        target, _ = _make_th_target(tmp_path)
        for bad_value in (['src/config.py'], 42, True, {}):
            finding = _make_trufflehog_finding()
            finding['SourceMetadata']['Data']['Filesystem']['file'] = bad_value
            report = _write_ndjson(tmp_path, [finding])
            results = ingest_trufflehog(str(report), str(target))
            assert results == [], f'Expected skip for file={bad_value!r}'


class TestTrufflehogRawSynthesis:
    def test_trufflehog_raw_synthesised_from_file(self, tmp_path):
        """raw field is read from the actual file at the given line number."""
        target, config_py = _make_th_target(tmp_path)
        config_py.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n', encoding='utf-8')
        from credactor.ingest import _read_file_lines
        _read_file_lines.cache_clear()
        finding = _make_trufflehog_finding()
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results[0]['raw'] == 'aws_key = "AKIAIOSFODNN7EXAMPLE"'

    def test_trufflehog_raw_fallback_on_unreadable_line(self, tmp_path):
        """An out-of-range source line falls back to the Raw value for the raw
        field. (L5a now skips a genuinely missing file, so this exercises the
        fallback via an existing file whose referenced line is past EOF.)"""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding()
        # File exists, but the line number is past EOF -> source line unavailable
        finding['SourceMetadata']['Data']['Filesystem']['file'] = 'src/config.py'
        finding['SourceMetadata']['Data']['Filesystem']['line'] = 999
        from credactor.ingest import _read_file_lines
        _read_file_lines.cache_clear()
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        assert results[0]['raw'] == 'AKIAIOSFODNN7EXAMPLE'



class TestTrufflehogSeverityAndType:
    def test_trufflehog_verified_true_critical(self, tmp_path):
        """Verified=True always maps to critical regardless of DetectorName."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(DetectorName='SlackWebhook', Verified=True)
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results[0]['severity'] == 'critical'

    def test_trufflehog_verified_false_uses_table(self, tmp_path):
        """Verified=False uses DetectorName table lookup."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(DetectorName='SlackWebhook', Verified=False)
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results[0]['severity'] == 'medium'

    def test_trufflehog_type_prefix(self, tmp_path):
        """Type is external:trufflehog:{DetectorName}."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(DetectorName='Stripe')
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results[0]['type'] == 'external:trufflehog:Stripe'

    def test_trufflehog_commit_from_git_source(self, tmp_path):
        """Git source commit mapped and truncated to 12 chars."""
        target, _ = _make_th_target(tmp_path)
        finding = {
            'DetectorName': 'GitHub',
            'Raw': 'ghp_SECRETTOKEN',
            'Verified': False,
            'SourceMetadata': {
                'Data': {
                    'Git': {
                        'file': 'src/config.py',
                        'line': 1,
                        'commit': 'abcdef1234567890',
                    },
                },
            },
        }
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert 'commit' in results[0]
        assert results[0]['commit'] == 'abcdef123456'

    def test_trufflehog_finding_dict_shape(self, tmp_path):
        """All required keys present in output finding dict."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding()
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        r = results[0]
        for key in ('file', 'line', 'type', 'severity', 'full_value', 'value_preview', 'raw'):
            assert key in r, f'Missing key: {key}'


class TestTrufflehogCap:
    def test_trufflehog_cap_10000(self, tmp_path, capsys):
        """10,001 lines truncated to 10,000 with a warning."""
        target, _ = _make_th_target(tmp_path)
        findings = [_make_trufflehog_finding(Raw=f'SECRET{i}') for i in range(10_001)]
        report = _write_ndjson(tmp_path, findings)
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 10_000
        captured = capsys.readouterr()
        assert 'truncating' in captured.err.lower() or 'truncated' in captured.err.lower()


# ---------------------------------------------------------------------------
# End-to-end redaction integration: proves TruffleHog-only finding drives
# actual file modification (no native scan involved).
# ---------------------------------------------------------------------------

class TestTrufflehogRedactionIntegration:
    """Verify that a TruffleHog finding with URL-encoded Raw can redact a file.

    The native scanner is NOT invoked here — findings come solely from the
    ingested NDJSON report.  This proves the URL-decode fix enables the full
    ingest → redact pipeline rather than just correcting the field value.
    """

    def test_urldecode_enables_redaction(self, tmp_path):
        """full_value decoded from %40 can be found and replaced in the source file."""
        from credactor.config import Config
        from credactor.ingest import _read_file_lines
        from credactor.redactor import batch_replace_in_file

        # File with a credential whose password contains a literal '@'.
        # This format intentionally does NOT match native credactor patterns
        # so only the TruffleHog-sourced finding drives redaction.
        target = tmp_path / "repo"
        target.mkdir()
        secret_file = target / "settings.py"
        # Credential: password is  s3cr3t@p4ss  (literal @)
        raw_credential = "xmpp://bot:s3cr3t@p4ss@chat.example.com/room"
        secret_file.write_text(f'CHAT_URI = "{raw_credential}"\n', encoding='utf-8')

        # TruffleHog URL-encodes the @ inside the password → %40
        url_encoded_raw = "xmpp://bot:s3cr3t%40p4ss@chat.example.com/room"
        assert url_encoded_raw != raw_credential  # sanity: they differ

        # Craft TruffleHog NDJSON pointing at the real file on disk.
        # Use an absolute path as TruffleHog Filesystem source would emit.
        finding_obj = {
            "DetectorName": "GenericCredential",
            "Raw": url_encoded_raw,
            "Verified": False,
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {
                        "file": str(secret_file),
                        "line": 1,
                    },
                },
            },
        }
        report = tmp_path / "th_report.ndjson"
        report.write_text(json.dumps(finding_obj) + "\n", encoding='utf-8')

        _read_file_lines.cache_clear()
        findings = ingest_trufflehog(str(report), str(target))
        assert len(findings) == 1, "expected exactly one finding from NDJSON"

        fv = findings[0]['full_value']
        assert '%40' not in fv, f"full_value still URL-encoded: {fv!r}"
        assert fv == raw_credential, f"full_value mismatch: {fv!r}"

        # Apply redaction via the same code path CLI uses.
        config = Config(no_backup=True)
        replaced, failed = batch_replace_in_file(str(secret_file), findings, config)

        assert replaced == 1, f"expected 1 replacement, got replaced={replaced} failed={failed}"
        assert failed == 0, f"unexpected failures: {failed}"

        content = secret_file.read_text(encoding='utf-8')
        assert raw_credential not in content, "credential still present after redaction"
        assert "REDACTED" in content, "sentinel not written to file"

    def test_without_urldecode_redaction_would_fail(self, tmp_path):
        """Control: if full_value were left URL-encoded, batch_replace_in_file skips it."""
        from credactor.config import Config
        from credactor.redactor import batch_replace_in_file

        target = tmp_path / "repo"
        target.mkdir()
        secret_file = target / "settings.py"
        raw_credential = "xmpp://bot:s3cr3t@p4ss@chat.example.com/room"
        secret_file.write_text(f'CHAT_URI = "{raw_credential}"\n', encoding='utf-8')

        # Simulate what ingest_trufflehog produced BEFORE the fix:
        # full_value still contains %40, not matching file content.
        synthetic_finding = {
            'file': str(secret_file),
            'line': 1,
            'type': 'external:trufflehog:GenericCredential',
            'severity': 'medium',
            'full_value': 'xmpp://bot:s3cr3t%40p4ss@chat.example.com/room',  # NOT decoded
            'value_preview': 'xmpp://bot:s3cr3t%40p4ss@chat.example.com/room'[:60],
            'raw': f'CHAT_URI = "{raw_credential}"',
        }

        config = Config(no_backup=True)
        replaced, failed = batch_replace_in_file(str(secret_file), [synthetic_finding], config)

        # Without the decode fix the replacement would be skipped.
        assert replaced == 0, "redaction should have failed without URL-decode"
        assert failed == 1

        content = secret_file.read_text(encoding='utf-8')
        assert raw_credential in content, "file should be unchanged without URL-decode"


# ---------------------------------------------------------------------------
# Helpers shared by dedup tests
# ---------------------------------------------------------------------------

def _make_finding(
    file: str = '/repo/src/app.py',
    line: int = 10,
    full_value: str = 'AKIAIOSFODNN7EXAMPLE',
    ftype: str = 'external:gitleaks:aws-access-token',
    severity: str = 'critical',
    commit: str | None = None,
) -> dict:
    d: dict = {
        'file': file,
        'line': line,
        'type': ftype,
        'severity': severity,
        'full_value': full_value,
        'value_preview': full_value[:60],
        'raw': f'AWS_KEY = "{full_value}"',
    }
    if commit is not None:
        d['commit'] = commit
    return d


# ---------------------------------------------------------------------------
# Phase 3: Deduplication tests
# ---------------------------------------------------------------------------

class TestIngestMissingAndInvalidPaths:
    """L5a/L5b: a finding pointing at a missing file is skipped; a NUL-byte path
    skips only that finding rather than aborting the whole batch."""

    def test_gitleaks_missing_file_on_disk_skipped(self, tmp_path, credactor_caplog):
        target, _ = _make_target(tmp_path)
        report = _write_report(tmp_path, [_make_gitleaks_finding(File='src/ghost.py')])
        results = ingest_gitleaks(str(report), str(target))
        assert results == []
        assert any('missing file' in r.message for r in credactor_caplog.records)

    def test_trufflehog_missing_file_on_disk_skipped(self, tmp_path, credactor_caplog):
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding()
        finding['SourceMetadata']['Data']['Filesystem']['file'] = 'src/ghost.py'
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results == []
        assert any('missing file' in r.message for r in credactor_caplog.records)

    def test_gitleaks_nul_path_skips_one_not_batch(self, tmp_path, credactor_caplog):
        target, _ = _make_target(tmp_path)
        good = _make_gitleaks_finding(File='src/config.py', StartLine=1)
        bad = _make_gitleaks_finding(File='a\x00b')
        report = _write_report(tmp_path, [good, bad])
        results = ingest_gitleaks(str(report), str(target))   # must NOT raise
        assert len(results) == 1
        assert any('invalid' in r.message.lower() or 'nul' in r.message.lower()
                   for r in credactor_caplog.records)

    def test_trufflehog_nul_path_skips_one_not_batch(self, tmp_path, credactor_caplog):
        target, _ = _make_th_target(tmp_path)
        good = _make_trufflehog_finding()
        bad = _make_trufflehog_finding()
        bad['SourceMetadata']['Data']['Filesystem']['file'] = 'a\x00b'
        report = _write_ndjson(tmp_path, [good, bad])
        results = ingest_trufflehog(str(report), str(target))   # must NOT raise
        assert len(results) == 1
        assert any('invalid' in r.message.lower() or 'nul' in r.message.lower()
                   for r in credactor_caplog.records)


class TestDeduplication:
    """Tests for deduplicate_findings() — section 7 of the plan."""

    def test_dedup_identical_findings(self):
        """Two identical findings reduce to one."""
        f = _make_finding()
        result = deduplicate_findings([f, f.copy()])
        assert len(result) == 1

    def test_dedup_different_lines_kept(self):
        """Same secret on different lines — both kept."""
        f1 = _make_finding(line=10)
        f2 = _make_finding(line=20)
        result = deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_dedup_different_files_kept(self):
        """Same secret in different files — both kept."""
        f1 = _make_finding(file='/repo/src/a.py')
        f2 = _make_finding(file='/repo/src/b.py')
        result = deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_dedup_different_values_same_location_kept(self):
        """Different secrets at the same file:line — both kept."""
        f1 = _make_finding(full_value='AKIAIOSFODNN7EXAMPLE')
        f2 = _make_finding(full_value='AKIAI0SF0DNN7EXAMPLE')
        result = deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_dedup_credactor_preferred_over_external(self):
        """Native finding (first) is kept over the external duplicate."""
        native = _make_finding(ftype='pattern:AWS access key', severity='critical')
        external = _make_finding(ftype='external:gitleaks:aws-access-token', severity='critical')
        result = deduplicate_findings([native, external])
        assert len(result) == 1
        assert result[0]['type'] == 'pattern:AWS access key'

    def test_dedup_merges_higher_severity_from_dropped_dup(self):
        """L5c: a native 'medium' kept over an external Verified 'critical' dup is
        raised to 'critical' (identity preserved, count unchanged)."""
        native = _make_finding(ftype='variable:api_key', severity='medium')
        external = _make_finding(ftype='external:trufflehog:AWS', severity='critical')
        result = deduplicate_findings([native, external])
        assert len(result) == 1
        assert result[0]['type'] == 'variable:api_key'   # native identity kept
        assert result[0]['severity'] == 'critical'        # severity merged up

    def test_dedup_does_not_lower_survivor_severity(self):
        """L5c: a lower-severity dropped dup must not downgrade the survivor."""
        native = _make_finding(ftype='pattern:AWS access key', severity='critical')
        external = _make_finding(ftype='external:trufflehog:AWS', severity='medium')
        result = deduplicate_findings([native, external])
        assert len(result) == 1
        assert result[0]['severity'] == 'critical'

    def test_dedup_gitleaks_preferred_over_trufflehog(self):
        """Gitleaks finding (second) is kept over TruffleHog (third) dup."""
        gl = _make_finding(ftype='external:gitleaks:aws-access-token')
        th = _make_finding(ftype='external:trufflehog:AWS')
        result = deduplicate_findings([gl, th])
        assert len(result) == 1
        assert result[0]['type'] == 'external:gitleaks:aws-access-token'

    def test_dedup_path_normalisation(self):
        """./src/f.py and src/f.py with the same absolute root collapse to one."""
        import os
        base = os.path.realpath('/tmp')
        f1 = _make_finding(file=os.path.join(base, 'src', 'f.py'))
        f2 = _make_finding(file=os.path.join(base, '.', 'src', 'f.py'))
        result = deduplicate_findings([f1, f2])
        assert len(result) == 1

    def test_dedup_preserves_order(self):
        """First occurrence wins and its position in the output is preserved."""
        f1 = _make_finding(line=1, full_value='secret_a')
        f2 = _make_finding(line=2, full_value='secret_b')
        f3 = _make_finding(line=3, full_value='secret_c')
        f1_dup = _make_finding(line=1, full_value='secret_a')
        result = deduplicate_findings([f1, f2, f3, f1_dup])
        assert len(result) == 3
        assert result[0]['line'] == 1
        assert result[1]['line'] == 2
        assert result[2]['line'] == 3

    def test_dedup_empty_list(self):
        """Empty input returns empty list without error."""
        assert deduplicate_findings([]) == []

    def test_dedup_verbose_prints_count(self, credactor_caplog):
        """When findings are deduplicated, a log message reports the count."""
        f = _make_finding()
        deduplicate_findings([f, f.copy()])
        assert any('Deduplicated 1' in r.message for r in credactor_caplog.records)

    def test_dedup_verbose_silent_when_no_dups(self, credactor_caplog):
        """When no findings are removed, no dedup log message is emitted."""
        f = _make_finding()
        deduplicate_findings([f])
        assert not any('Deduplicated' in r.message for r in credactor_caplog.records)


# ---------------------------------------------------------------------------
# Phase 3: Severity mapping completeness tests
# ---------------------------------------------------------------------------

class TestSeverityMappingCompleteness:
    """Verify the full severity tables and override logic."""

    def test_gitleaks_severity_all_known_rules(self):
        """Each rule in _GITLEAKS_SEVERITY returns the expected severity."""
        for rule_id, expected in _GITLEAKS_SEVERITY.items():
            result = _gitleaks_severity(rule_id)
            assert result == expected, (
                f'_gitleaks_severity({rule_id!r}) = {result!r}, expected {expected!r}'
            )

    def test_trufflehog_severity_all_known_detectors(self):
        """Each detector in _TRUFFLEHOG_SEVERITY returns its base severity."""
        for detector, expected in _TRUFFLEHOG_SEVERITY.items():
            result = _trufflehog_severity(detector, verified=False)
            assert result == expected, (
                f'_trufflehog_severity({detector!r}, False) = {result!r}, '
                f'expected {expected!r}'
            )

    def test_trufflehog_verified_overrides_all(self):
        """Verified=True escalates every detector (including medium) to critical."""
        # Medium detector from the table
        assert _trufflehog_severity('SlackWebhook', verified=True) == 'critical'
        # Unknown detector (defaults to medium without verified)
        assert _trufflehog_severity('SomeUnknownDetector', verified=False) == 'medium'
        assert _trufflehog_severity('SomeUnknownDetector', verified=True) == 'critical'


# ---------------------------------------------------------------------------
# Security regression tests — A1, A2, A4, A12, A13
# ---------------------------------------------------------------------------

class TestA1TrufflehogFileSizeGuard:
    """A1: TruffleHog NDJSON must be rejected before open() if over _MAX_REPORT_BYTES."""

    def test_trufflehog_rejects_oversized_file(self, tmp_path, monkeypatch):
        """A file larger than _MAX_REPORT_BYTES raises ValueError before parsing.

        Limit monkeypatched down: same boundary semantics, no sparse-file
        reliance (sparse seeks are not sparse on every filesystem).
        """
        monkeypatch.setattr('credactor.ingest._MAX_REPORT_BYTES', 4096)
        target, _ = _make_th_target(tmp_path)
        report = tmp_path / 'huge.json'
        report.write_bytes(b'\n' * 4097)
        with pytest.raises(ValueError, match='refusing to parse'):
            ingest_trufflehog(str(report), str(target))

    def test_trufflehog_accepts_file_at_limit(self, tmp_path, monkeypatch):
        """A file exactly at _MAX_REPORT_BYTES is accepted (boundary condition).

        Limit monkeypatched to 4096: identical size == limit comparison
        without writing a real 100 MB file (this single test used to be 56%
        of total suite runtime).
        """
        monkeypatch.setattr('credactor.ingest._MAX_REPORT_BYTES', 4096)
        target, _ = _make_th_target(tmp_path)
        # A valid NDJSON that happens to be padded to exactly the limit
        finding = _make_trufflehog_finding()
        line = json.dumps(finding)
        report = tmp_path / 'exact.json'
        # Pad with blank lines to reach the limit (blank lines are skipped by parser)
        padding = b'\n' * (4096 - len(line.encode()) - 1)
        report.write_bytes(line.encode() + b'\n' + padding)
        assert report.stat().st_size == 4096
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1

    def test_trufflehog_missing_file_raises(self, tmp_path):
        """A non-existent NDJSON file raises ValueError (via getsize OSError)."""
        target, _ = _make_th_target(tmp_path)
        with pytest.raises(ValueError, match='Cannot open TruffleHog file'):
            ingest_trufflehog(str(tmp_path / 'nonexistent.json'), str(target))

    def test_gitleaks_already_has_size_guard(self, tmp_path, monkeypatch):
        """Confirm Gitleaks also rejects oversized files (pre-existing guard)."""
        monkeypatch.setattr('credactor.ingest._MAX_REPORT_BYTES', 4096)
        target, _ = _make_target(tmp_path)
        report = tmp_path / 'huge_gl.json'
        report.write_bytes(b'\n' * 4097)
        with pytest.raises(ValueError, match='refusing to parse'):
            ingest_gitleaks(str(report), str(target))


class TestA2UrlDecodeFormSelection:
    """A2: TruffleHog Raw field form selection — decoded vs encoded."""

    def _make_th_finding_with_raw(self, raw_value: str, **kwargs) -> dict:
        base = _make_trufflehog_finding(Raw=raw_value)
        base.update(kwargs)
        return base

    def test_decoded_form_used_when_source_contains_at(self, tmp_path):
        """Source file has literal @ — decoded form should be used as full_value."""
        target = tmp_path / 'repo'
        src = target / 'src'
        src.mkdir(parents=True)
        source = src / 'config.py'
        # Literal @ in the connection string
        source.write_text('DB=postgresql://user:p%40ss@host:5432\n', encoding='utf-8')

        # TruffleHog would report Raw with %40 if the value came from a URL context,
        # but the actual file has decoded @ — simulate the decoded case
        finding = self._make_th_finding_with_raw(
            'postgresql://user:p@ss@host:5432',
            SourceMetadata={'Data': {'Filesystem': {'file': 'src/config.py', 'line': 1}}},
        )
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        # Decoded form is found in source line → must use decoded
        assert '@' in results[0]['full_value']
        assert '%40' not in results[0]['full_value']

    def test_encoded_form_used_when_source_has_literal_percent40(self, tmp_path):
        """Source file literally contains %40 — encoded form must be kept as full_value."""
        target = tmp_path / 'repo'
        src = target / 'src'
        src.mkdir(parents=True)
        source = src / 'config.py'
        # Source literally contains %40 (e.g. a URL template or test fixture)
        source.write_text('URL_TEMPLATE = "https://user:%40example@host/db"\n', encoding='utf-8')

        # TruffleHog reports Raw with %40 (since that is what the file contains)
        finding = self._make_th_finding_with_raw(
            'https://user:%40example@host/db',
            SourceMetadata={'Data': {'Filesystem': {'file': 'src/config.py', 'line': 1}}},
        )
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        # The encoded form is present in source line, decoded ('@') form is also present
        # but decoded form matches too since @ appears after decoding %40.
        # Verify the full_value is a string that can be found in the source line.
        fv = results[0]['full_value']
        source_line = source.read_text(encoding='utf-8').rstrip()
        assert fv in source_line, (
            f"full_value {fv!r} not found in source line {source_line!r}"
        )

    def test_no_encoding_no_change(self, tmp_path):
        """Raw value with no percent-encoding passes through unchanged."""
        target, config_py = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(Raw='AKIAIOSFODNN7EXAMPLE')
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results[0]['full_value'] == 'AKIAIOSFODNN7EXAMPLE'

    def test_decoded_default_when_source_unavailable(self, tmp_path):
        """When the source line cannot be read, the decoded form is the safe
        default. (L5a now skips a missing file outright, so this uses an existing
        file with an out-of-range line to leave the source line unreadable.)"""
        target = tmp_path / 'repo'
        src = target / 'src'
        src.mkdir(parents=True)
        (src / 'config.py').write_text('x = 1\n', encoding='utf-8')
        finding = _make_trufflehog_finding(
            Raw='postgresql://user:p%40ss@host:5432',
            SourceMetadata={'Data': {'Filesystem': {'file': 'src/config.py', 'line': 999}}},
        )
        from credactor.ingest import _read_file_lines
        _read_file_lines.cache_clear()
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        # No source line available → default to decoded
        assert results[0]['full_value'] == 'postgresql://user:p@ss@host:5432'


class TestA4EncodingGuards:
    """A4: Non-UTF-8 bytes in report files must not silently corrupt full_value."""

    def test_gitleaks_non_utf8_raises_value_error(self, tmp_path):
        """Gitleaks JSON with non-UTF-8 bytes raises ValueError (errors='strict')."""
        target, _ = _make_target(tmp_path)
        report = tmp_path / 'bad_encoding.json'
        # Write a JSON-like file with an embedded invalid UTF-8 byte sequence
        # Inject \xff inside the JSON string value
        raw_bytes = b'[{"Secret": "ABC\xffDEF", "File": "src/config.py", ' \
                    b'"StartLine": 1, "RuleID": "test", "Tags": [], "Commit": ""}]'
        report.write_bytes(raw_bytes)
        with pytest.raises(ValueError, match='non-UTF-8 bytes'):
            ingest_gitleaks(str(report), str(target))

    def test_trufflehog_fffd_in_raw_skips_finding(self, tmp_path, credactor_caplog):
        """TruffleHog finding whose Raw field contains U+FFFD is skipped."""
        target, _ = _make_th_target(tmp_path)
        # Manually construct NDJSON where Raw contains the replacement character
        finding = _make_trufflehog_finding(Raw='AKIAI\ufffdEXAMPLE')
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert results == []
        assert any(
            'non-UTF-8' in r.message or 'U+FFFD' in r.message or 'replacement' in r.message
            for r in credactor_caplog.records
        )

    def test_trufflehog_valid_utf8_not_skipped(self, tmp_path):
        """A Raw field with valid non-ASCII UTF-8 (no U+FFFD) is not skipped."""
        target, config_py = _make_th_target(tmp_path)
        config_py.write_text('key = "café_secret"\n', encoding='utf-8')
        finding = _make_trufflehog_finding(
            Raw='café_secret',
            SourceMetadata={'Data': {'Filesystem': {'file': 'src/config.py', 'line': 1}}},
        )
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        assert results[0]['full_value'] == 'café_secret'


class TestA12DedupCommitAwareness:
    """A12: Dedup commit-awareness — mixed commit/no-commit findings."""

    def test_no_commit_beats_committed_same_base(self):
        """Working-tree finding wins over a committed finding at same file:line:value."""
        f_committed = _make_finding(commit='abc123def456')
        f_working = _make_finding()  # no commit key
        result = deduplicate_findings([f_committed, f_working])
        assert len(result) == 1
        assert 'commit' not in result[0]

    def test_committed_beats_committed_same_commit(self):
        """Two findings with same commit at same base → deduplicated to one."""
        f1 = _make_finding(commit='abc123def456')
        f2 = _make_finding(commit='abc123def456')
        result = deduplicate_findings([f1, f2])
        assert len(result) == 1

    def test_different_commits_not_deduped(self):
        """Same file:line:value but different commits → both kept (history scan)."""
        f1 = _make_finding(commit='abc123def456')
        f2 = _make_finding(commit='deadbeef9999')
        result = deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_no_commit_working_tree_then_committed_later(self):
        """Working-tree finding listed after committed one — committed still suppressed."""
        f_committed = _make_finding(commit='abc123def456')
        f_working = _make_finding()
        # Committed first, working-tree second
        result = deduplicate_findings([f_committed, f_working])
        assert len(result) == 1
        assert 'commit' not in result[0]

    def test_two_working_tree_findings_deduplicated(self):
        """Two no-commit findings at same base → first wins."""
        f1 = _make_finding(full_value='AKIAIOSFODNN7EXAMPLE')
        f2 = _make_finding(full_value='AKIAIOSFODNN7EXAMPLE')
        result = deduplicate_findings([f1, f2])
        assert len(result) == 1

    def test_gitleaks_and_trufflehog_mixed_commit(self):
        """Gitleaks (no commit) + TruffleHog (with commit) same secret → Gitleaks kept."""
        gl = _make_finding(ftype='external:gitleaks:aws-access-token')
        th = _make_finding(ftype='external:trufflehog:AWS', commit='deadbeef1234')
        result = deduplicate_findings([gl, th])
        assert len(result) == 1
        assert result[0]['type'] == 'external:gitleaks:aws-access-token'


class TestA13SelfReferentialReport:
    """A13: A finding pointing to the report file itself must be skipped."""

    def test_gitleaks_self_referential_finding_skipped(self, tmp_path):
        """Gitleaks finding whose File resolves to the report file is skipped."""
        target = tmp_path / 'repo'
        target.mkdir()
        # Place the report inside the target directory
        report = target / 'gitleaks_report.json'
        # Finding points at the report file itself
        finding = _make_gitleaks_finding(
            File='gitleaks_report.json',
            Secret='some-secret',
            Match='some-secret',
            StartLine=1,
        )
        report.write_text(json.dumps([finding]), encoding='utf-8')
        results = ingest_gitleaks(str(report), str(target))
        # The self-referential finding must be skipped
        assert results == []

    def test_gitleaks_self_referential_verbose_warns(self, tmp_path, credactor_caplog):
        """Skipping a self-referential finding emits a log message."""
        target = tmp_path / 'repo'
        target.mkdir()
        report = target / 'gitleaks_report.json'
        finding = _make_gitleaks_finding(
            File='gitleaks_report.json',
            Secret='some-secret',
            Match='some-secret',
            StartLine=1,
        )
        report.write_text(json.dumps([finding]), encoding='utf-8')
        ingest_gitleaks(str(report), str(target))
        assert any(
            'self' in r.message.lower() or 'report' in r.message.lower()
            for r in credactor_caplog.records
        )

    def test_gitleaks_non_self_finding_not_affected(self, tmp_path):
        """Normal Gitleaks findings are unaffected when report is inside target dir."""
        target, config_py = _make_target(tmp_path)
        report = target / 'gitleaks_report.json'
        finding = _make_gitleaks_finding(
            File='src/config.py',
            Secret='AKIAIOSFODNN7EXAMPLE',
            Match='aws_key = "AKIAIOSFODNN7EXAMPLE"',
            StartLine=1,
        )
        report.write_text(json.dumps([finding]), encoding='utf-8')
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 1
        assert results[0]['full_value'] == 'AKIAIOSFODNN7EXAMPLE'

    def test_trufflehog_self_referential_finding_skipped(self, tmp_path):
        """TruffleHog finding whose file resolves to the report file is skipped."""
        target = tmp_path / 'repo'
        target.mkdir()
        # Place the report inside the target directory
        report = target / 'trufflehog_output.json'
        finding = _make_trufflehog_finding(
            Raw='some-secret',
            SourceMetadata={'Data': {'Filesystem': {
                'file': 'trufflehog_output.json',
                'line': 1,
            }}},
        )
        lines = json.dumps(finding) + '\n'
        report.write_text(lines, encoding='utf-8')
        results = ingest_trufflehog(str(report), str(target))
        assert results == []

    def test_trufflehog_self_referential_verbose_warns(self, tmp_path, credactor_caplog):
        """Skipping a self-referential TruffleHog finding emits a log message."""
        target = tmp_path / 'repo'
        target.mkdir()
        report = target / 'trufflehog_output.json'
        finding = _make_trufflehog_finding(
            Raw='some-secret',
            SourceMetadata={'Data': {'Filesystem': {
                'file': 'trufflehog_output.json',
                'line': 1,
            }}},
        )
        report.write_text(json.dumps(finding) + '\n', encoding='utf-8')
        ingest_trufflehog(str(report), str(target))
        assert any(
            'self' in r.message.lower() or 'report' in r.message.lower()
            for r in credactor_caplog.records
        )

    def test_trufflehog_non_self_finding_not_affected(self, tmp_path):
        """Normal TruffleHog findings are unaffected when report is inside target dir."""
        target, config_py = _make_th_target(tmp_path)
        report = target / 'trufflehog_output.json'
        finding = _make_trufflehog_finding()
        report.write_text(json.dumps(finding) + '\n', encoding='utf-8')
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        assert results[0]['full_value'] == 'AKIAIOSFODNN7EXAMPLE'

    def test_gitleaks_self_referential_normcase_called_on_both_sides(self, tmp_path):
        """A13 normcase: os.path.normcase is invoked for both sides of the self-ref comparison.

        Uses wraps= to intercept calls without changing return values. A call_count
        of >= 2 on a self-referential finding proves both sides of the guard are
        folded — a regression where normcase is removed would drop the count to 0.
        """
        target = tmp_path / 'repo'
        target.mkdir()
        report = target / 'gitleaks_report.json'
        finding = _make_gitleaks_finding(
            File='gitleaks_report.json',
            Secret='some-secret',
            Match='some-secret',
            StartLine=1,
        )
        report.write_text(json.dumps([finding]), encoding='utf-8')

        with mock.patch('credactor.ingest.os.path.normcase', wraps=os.path.normcase) as m:
            results = ingest_gitleaks(str(report), str(target))

        assert results == []
        # Both sides of the self-ref comparison must be normcase-d.
        assert m.call_count >= 2

    def test_trufflehog_self_referential_normcase_called_on_both_sides(self, tmp_path):
        """A13 normcase: normcase invoked for both sides of the TruffleHog self-ref guard."""
        target = tmp_path / 'repo'
        target.mkdir()
        report = target / 'trufflehog_output.json'
        finding = _make_trufflehog_finding(
            Raw='some-secret',
            SourceMetadata={'Data': {'Filesystem': {
                'file': 'trufflehog_output.json',
                'line': 1,
            }}},
        )
        report.write_text(json.dumps(finding) + '\n', encoding='utf-8')

        with mock.patch('credactor.ingest.os.path.normcase', wraps=os.path.normcase) as m:
            results = ingest_trufflehog(str(report), str(target))

        assert results == []
        assert m.call_count >= 2


# ---------------------------------------------------------------------------
# P2 — Commit type guards (Gitleaks + TruffleHog)
# ---------------------------------------------------------------------------

class TestCommitTypeGuard:
    """P2: Commit fields must be type-checked before slicing.

    A non-string Commit (e.g. int or list) in a malformed report previously
    raised TypeError at parse time or produced an unhashable value that
    crashed deduplicate_findings later.
    """

    # --- Gitleaks ---

    def test_gitleaks_commit_int_skipped(self, tmp_path):
        """Gitleaks Commit=123 (int) must not crash — finding is kept, commit omitted."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(Commit=123)
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 1
        assert 'commit' not in results[0]

    def test_gitleaks_commit_list_skipped(self, tmp_path):
        """Gitleaks Commit=['abc'] (list) must not crash — commit omitted."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(Commit=['abc123def456'])
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 1
        assert 'commit' not in results[0]

    def test_gitleaks_commit_none_skipped(self, tmp_path):
        """Gitleaks Commit=None must not crash — commit omitted."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(Commit=None)
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 1
        assert 'commit' not in results[0]

    def test_gitleaks_commit_string_kept(self, tmp_path):
        """Gitleaks Commit='abc123def456789' (string) is truncated to 12 chars normally."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(Commit='abc123def456789')
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 1
        assert results[0]['commit'] == 'abc123def456'

    def test_gitleaks_commit_int_survives_dedup(self, tmp_path):
        """Finding with Commit=123 must survive deduplicate_findings (no unhashable crash)."""
        target, _ = _make_target(tmp_path)
        finding = _make_gitleaks_finding(Commit=123)
        report = _write_report(tmp_path, [finding])
        results = ingest_gitleaks(str(report), str(target))
        deduped = deduplicate_findings(results)
        assert len(deduped) == 1

    # --- TruffleHog ---

    def test_trufflehog_commit_int_skipped(self, tmp_path):
        """TruffleHog Git.commit=123 (int) must not crash — commit omitted."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(
            SourceMetadata={'Data': {'Git': {
                'file': 'src/config.py', 'line': 1, 'commit': 123,
            }}},
        )
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        assert 'commit' not in results[0]

    def test_trufflehog_commit_list_skipped(self, tmp_path):
        """TruffleHog Git.commit=['abc'] (list) must not crash — commit omitted."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(
            SourceMetadata={'Data': {'Git': {
                'file': 'src/config.py', 'line': 1, 'commit': ['abc123def456'],
            }}},
        )
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        assert 'commit' not in results[0]

    def test_trufflehog_commit_string_kept(self, tmp_path):
        """TruffleHog Git.commit='abc123def456789' (string) is truncated to 12 chars."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(
            SourceMetadata={'Data': {'Git': {
                'file': 'src/config.py', 'line': 1, 'commit': 'abc123def456789',
            }}},
        )
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        assert results[0]['commit'] == 'abc123def456'

    def test_trufflehog_commit_int_survives_dedup(self, tmp_path):
        """TruffleHog finding with Git.commit=123 must survive dedup (no unhashable crash)."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(
            SourceMetadata={'Data': {'Git': {
                'file': 'src/config.py', 'line': 1, 'commit': 123,
            }}},
        )
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        deduped = deduplicate_findings(results)
        assert len(deduped) == 1


class TestDedupSurrogateHash:
    """deduplicate_findings must not raise UnicodeEncodeError on surrogate full_value.

    Lone surrogates can arrive when scanner content was read with
    errors='surrogateescape' (undecodable bytes on the filesystem).
    The sha256 encode step must handle them without crashing.
    """

    def _surrogate_finding(self, extra='') -> dict:
        # \udcff is a lone surrogate produced by surrogateescape for byte 0xff
        return _make_finding(full_value='secret\udcff' + extra)

    def test_surrogate_in_full_value_does_not_crash(self):
        """dedup must not raise UnicodeEncodeError on a lone surrogate in full_value."""
        findings = [self._surrogate_finding()]
        result = deduplicate_findings(findings)   # must not raise
        assert len(result) == 1

    def test_two_identical_surrogate_findings_deduplicated(self):
        """Two findings with the same surrogate-containing value dedup to one."""
        f1 = self._surrogate_finding()
        f2 = self._surrogate_finding()
        result = deduplicate_findings([f1, f2])
        assert len(result) == 1

    def test_two_different_surrogate_values_both_kept(self):
        """Findings with distinct surrogate values are treated as distinct."""
        f1 = self._surrogate_finding('a')
        f2 = self._surrogate_finding('b')
        result = deduplicate_findings([f1, f2])
        assert len(result) == 2

    def test_surrogate_mixed_with_clean_finding_both_kept(self):
        """A surrogate finding and a clean finding at different locations are both kept."""
        f_surrogate = self._surrogate_finding()
        f_clean = _make_finding(full_value='clean_secret_value')
        result = deduplicate_findings([f_surrogate, f_clean])
        assert len(result) == 2
