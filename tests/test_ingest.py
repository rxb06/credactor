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
    _BETTERLEAKS_VALIDATION_SEVERITY,
    _GITLEAKS_SEVERITY,
    _TRUFFLEHOG_SEVERITY,
    _betterleaks_severity,
    _gitleaks_severity,
    _synthesise_raw,
    _trufflehog_severity,
    deduplicate_findings,
    ingest_betterleaks,
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

    @pytest.mark.skipif(not hasattr(os, 'symlink'), reason='symlinks not supported')
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
        report.write_text('this is not json\n<html>404</html>\n{ unclosed\n', encoding='utf-8')
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
        target = tmp_path / 'repo'
        target.mkdir()
        secret_file = target / 'settings.py'
        # Credential: password is  s3cr3t@p4ss  (literal @)
        raw_credential = 'xmpp://bot:s3cr3t@p4ss@chat.example.com/room'
        secret_file.write_text(f'CHAT_URI = "{raw_credential}"\n', encoding='utf-8')

        # TruffleHog URL-encodes the @ inside the password → %40
        url_encoded_raw = 'xmpp://bot:s3cr3t%40p4ss@chat.example.com/room'
        assert url_encoded_raw != raw_credential  # sanity: they differ

        # Craft TruffleHog NDJSON pointing at the real file on disk.
        # Use an absolute path as TruffleHog Filesystem source would emit.
        finding_obj = {
            'DetectorName': 'GenericCredential',
            'Raw': url_encoded_raw,
            'Verified': False,
            'SourceMetadata': {
                'Data': {
                    'Filesystem': {
                        'file': str(secret_file),
                        'line': 1,
                    },
                },
            },
        }
        report = tmp_path / 'th_report.ndjson'
        report.write_text(json.dumps(finding_obj) + '\n', encoding='utf-8')

        _read_file_lines.cache_clear()
        findings = ingest_trufflehog(str(report), str(target))
        assert len(findings) == 1, 'expected exactly one finding from NDJSON'

        fv = findings[0]['full_value']
        assert '%40' not in fv, f'full_value still URL-encoded: {fv!r}'
        assert fv == raw_credential, f'full_value mismatch: {fv!r}'

        # Apply redaction via the same code path CLI uses.
        config = Config(no_backup=True)
        replaced, failed = batch_replace_in_file(str(secret_file), findings, config)

        assert replaced == 1, f'expected 1 replacement, got replaced={replaced} failed={failed}'
        assert failed == 0, f'unexpected failures: {failed}'

        content = secret_file.read_text(encoding='utf-8')
        assert raw_credential not in content, 'credential still present after redaction'
        assert 'REDACTED' in content, 'sentinel not written to file'

    def test_without_urldecode_redaction_would_fail(self, tmp_path):
        """Control: if full_value were left URL-encoded, batch_replace_in_file skips it."""
        from credactor.config import Config
        from credactor.redactor import batch_replace_in_file

        target = tmp_path / 'repo'
        target.mkdir()
        secret_file = target / 'settings.py'
        raw_credential = 'xmpp://bot:s3cr3t@p4ss@chat.example.com/room'
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
        assert replaced == 0, 'redaction should have failed without URL-decode'
        assert failed == 1

        content = secret_file.read_text(encoding='utf-8')
        assert raw_credential in content, 'file should be unchanged without URL-decode'


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
        results = ingest_gitleaks(str(report), str(target))  # must NOT raise
        assert len(results) == 1
        assert any(
            'invalid' in r.message.lower() or 'nul' in r.message.lower()
            for r in credactor_caplog.records
        )

    def test_trufflehog_nul_path_skips_one_not_batch(self, tmp_path, credactor_caplog):
        target, _ = _make_th_target(tmp_path)
        good = _make_trufflehog_finding()
        bad = _make_trufflehog_finding()
        bad['SourceMetadata']['Data']['Filesystem']['file'] = 'a\x00b'
        report = _write_ndjson(tmp_path, [good, bad])
        results = ingest_trufflehog(str(report), str(target))  # must NOT raise
        assert len(results) == 1
        assert any(
            'invalid' in r.message.lower() or 'nul' in r.message.lower()
            for r in credactor_caplog.records
        )


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
        assert result[0]['type'] == 'variable:api_key'  # native identity kept
        assert result[0]['severity'] == 'critical'  # severity merged up

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
                f'_trufflehog_severity({detector!r}, False) = {result!r}, expected {expected!r}'
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
        assert fv in source_line, f'full_value {fv!r} not found in source line {source_line!r}'

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
        raw_bytes = (
            b'[{"Secret": "ABC\xffDEF", "File": "src/config.py", '
            b'"StartLine": 1, "RuleID": "test", "Tags": [], "Commit": ""}]'
        )
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
            SourceMetadata={
                'Data': {
                    'Filesystem': {
                        'file': 'trufflehog_output.json',
                        'line': 1,
                    }
                }
            },
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
            SourceMetadata={
                'Data': {
                    'Filesystem': {
                        'file': 'trufflehog_output.json',
                        'line': 1,
                    }
                }
            },
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
            SourceMetadata={
                'Data': {
                    'Filesystem': {
                        'file': 'trufflehog_output.json',
                        'line': 1,
                    }
                }
            },
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
            SourceMetadata={
                'Data': {
                    'Git': {
                        'file': 'src/config.py',
                        'line': 1,
                        'commit': 123,
                    }
                }
            },
        )
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        assert 'commit' not in results[0]

    def test_trufflehog_commit_list_skipped(self, tmp_path):
        """TruffleHog Git.commit=['abc'] (list) must not crash — commit omitted."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(
            SourceMetadata={
                'Data': {
                    'Git': {
                        'file': 'src/config.py',
                        'line': 1,
                        'commit': ['abc123def456'],
                    }
                }
            },
        )
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        assert 'commit' not in results[0]

    def test_trufflehog_commit_string_kept(self, tmp_path):
        """TruffleHog Git.commit='abc123def456789' (string) is truncated to 12 chars."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(
            SourceMetadata={
                'Data': {
                    'Git': {
                        'file': 'src/config.py',
                        'line': 1,
                        'commit': 'abc123def456789',
                    }
                }
            },
        )
        report = _write_ndjson(tmp_path, [finding])
        results = ingest_trufflehog(str(report), str(target))
        assert len(results) == 1
        assert results[0]['commit'] == 'abc123def456'

    def test_trufflehog_commit_int_survives_dedup(self, tmp_path):
        """TruffleHog finding with Git.commit=123 must survive dedup (no unhashable crash)."""
        target, _ = _make_th_target(tmp_path)
        finding = _make_trufflehog_finding(
            SourceMetadata={
                'Data': {
                    'Git': {
                        'file': 'src/config.py',
                        'line': 1,
                        'commit': 123,
                    }
                }
            },
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
        result = deduplicate_findings(findings)  # must not raise
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


class TestDeeplyNestedJsonIsFatal:
    """S7: deeply-nested JSON must fail closed (fatal ValueError -> exit 2),
    not escape as an uncaught RecursionError (traceback, exit 1)."""

    def test_gitleaks_deeply_nested_is_fatal(self, tmp_path):
        target, _ = _make_target(tmp_path)
        report = tmp_path / 'nested.json'
        report.write_text('[' * 200000, encoding='utf-8')
        with pytest.raises(ValueError, match='nested'):
            ingest_gitleaks(str(report), str(target))

    def test_trufflehog_deeply_nested_is_fatal(self, tmp_path):
        target, _ = _make_target(tmp_path)
        report = tmp_path / 'nested.ndjson'
        report.write_text('[' * 200000, encoding='utf-8')
        with pytest.raises(ValueError, match='nested'):
            ingest_trufflehog(str(report), str(target))


class TestUnsupportedSourceAccounting:
    """A08 hardening: the run-level summary's count must always be explained by
    its type list, and the list is bounded (it repeats report-controlled
    strings)."""

    def test_malformed_filesystem_labeled_not_miscounted(self, tmp_path):
        from credactor.ingest import new_ingest_stats

        target, _ = _make_th_target(tmp_path)
        malformed = _make_trufflehog_finding(SourceMetadata={'Data': {'Filesystem': None}})
        docker = _make_trufflehog_finding(SourceMetadata={'Data': {'Docker': {'image': 'x'}}})
        report = _write_ndjson(tmp_path, [malformed, docker])
        stats = new_ingest_stats()
        results = ingest_trufflehog(str(report), str(target), stats=stats)
        assert results == []
        # Both records are counted, and BOTH are named: the null-Filesystem
        # record is labeled malformed, not silently folded into a count its
        # type list cannot explain (or mislabeled an unsupported source).
        assert stats['unsupported_source'] == 2
        assert stats['unsupported_types'] == {'Docker', 'Filesystem (malformed entry)'}

    def test_unsupported_type_list_bounded(self, tmp_path, credactor_caplog):
        from credactor.ingest import (
            _MAX_UNSUPPORTED_TYPE_NAME_LEN,
            _MAX_UNSUPPORTED_TYPE_NAMES,
            new_ingest_stats,
        )

        target, _ = _make_th_target(tmp_path)
        findings = [
            # A single record can carry an arbitrarily long source key.
            _make_trufflehog_finding(SourceMetadata={'Data': {'K' * 500: {}}})
        ]
        findings += [
            _make_trufflehog_finding(SourceMetadata={'Data': {f'Source{i:02d}': {}}})
            for i in range(25)
        ]
        report = _write_ndjson(tmp_path, findings)
        stats = new_ingest_stats()
        ingest_trufflehog(str(report), str(target), stats=stats)
        assert stats['unsupported_source'] == 26
        assert len(stats['unsupported_types']) == _MAX_UNSUPPORTED_TYPE_NAMES
        assert stats['unsupported_types_truncated'] is True
        assert all(len(t) <= _MAX_UNSUPPORTED_TYPE_NAME_LEN for t in stats['unsupported_types'])
        summary = [
            r.getMessage()
            for r in credactor_caplog.records
            if 'unsupported source type(s)' in r.getMessage()
        ]
        assert summary and '(further types omitted)' in summary[-1]


class TestReportPathRegularFileGuard:
    """Library-layer K-1: a non-regular report path must raise ValueError, not
    hang (FIFO) or leak an OS error (directory) — direct callers do not pass
    through the CLI's own report-path checks."""

    def test_directory_report_raises_valueerror(self, tmp_path):
        target = tmp_path / 'repo'
        target.mkdir()
        report_dir = tmp_path / 'report_dir'
        report_dir.mkdir()
        with pytest.raises(ValueError, match='not a regular file'):
            ingest_gitleaks(str(report_dir), str(target))
        with pytest.raises(ValueError, match='not a regular file'):
            ingest_trufflehog(str(report_dir), str(target))

    @pytest.mark.skipif(os.name != 'posix', reason='mkfifo is POSIX-only')
    def test_fifo_report_raises_instead_of_blocking(self, tmp_path):
        target = tmp_path / 'repo'
        target.mkdir()
        fifo = tmp_path / 'report.fifo'
        os.mkfifo(fifo)
        with pytest.raises(ValueError, match='not a regular file'):
            ingest_trufflehog(str(fifo), str(target))
        with pytest.raises(ValueError, match='not a regular file'):
            ingest_gitleaks(str(fifo), str(target))


class TestInvalidRecordSummary:
    """Invalid-record run-level summaries: per-record skips are INFO-only, so a
    wholly-invalid report was byte-indistinguishable from a clean run (exit 0)
    — the same silent-false-all-clear class the A08 unsupported-source summary
    closes."""

    def test_gitleaks_all_invalid_report_warns(self, tmp_path, credactor_caplog):
        from credactor.ingest import new_ingest_stats

        target = tmp_path / 'repo'
        target.mkdir()
        report = tmp_path / 'gl.json'
        report.write_text(
            json.dumps(
                [
                    42,  # non-object entry
                    {'RuleID': 'aws', 'File': 'x.py', 'StartLine': 1},  # no Secret
                    {'RuleID': 'aws', 'Secret': 'AKIAIOSFODNN7EXAMPLE'},  # no File
                ]
            ),
            encoding='utf-8',
        )
        stats = new_ingest_stats()
        results = ingest_gitleaks(str(report), str(target), stats=stats)
        assert results == []
        assert stats['invalid_record'] == 3
        summary = [
            r.getMessage()
            for r in credactor_caplog.records
            if 'skipped as invalid' in r.getMessage()
        ]
        assert len(summary) == 1 and summary[0].startswith('3 Gitleaks record(s)')

    def test_gitleaks_valid_records_do_not_warn(self, tmp_path, credactor_caplog):
        target, _ = _make_target(tmp_path)
        report = _write_report(tmp_path, [_make_gitleaks_finding()])
        results = ingest_gitleaks(str(report), str(target))
        assert len(results) == 1
        assert not any('skipped as invalid' in r.getMessage() for r in credactor_caplog.records)

    def test_trufflehog_invalid_records_warn_with_count(self, tmp_path, credactor_caplog):
        from credactor.ingest import new_ingest_stats

        target, _ = _make_th_target(tmp_path)
        empty_raw = _make_trufflehog_finding(Raw='')
        binary_raw = _make_trufflehog_finding(Raw='sec�ret')
        no_path = _make_trufflehog_finding(
            SourceMetadata={'Data': {'Filesystem': {'file': '', 'line': 1}}}
        )
        valid = _make_trufflehog_finding()
        report = _write_ndjson(tmp_path, [empty_raw, binary_raw, no_path, valid])
        stats = new_ingest_stats()
        results = ingest_trufflehog(str(report), str(target), stats=stats)
        assert len(results) == 1  # the valid record still ingests
        assert stats['invalid_record'] == 3
        summary = [
            r.getMessage()
            for r in credactor_caplog.records
            if 'skipped as invalid' in r.getMessage()
        ]
        assert len(summary) == 1 and summary[0].startswith('3 TruffleHog record(s)')


# ---------------------------------------------------------------------------
# 8.3 Betterleaks Parser Tests
# ---------------------------------------------------------------------------
# Betterleaks is a Gitleaks fork whose JSON report carries the Go struct field
# names verbatim, so the record mapping is deliberately Gitleaks-shaped. The
# classes below concentrate on the four places where it is NOT: the literal
# `null` clean report (D0), the `external:betterleaks:` type string (D1), the
# ValidationStatus severity precedence (D2) and the no-path/unsupported-source
# accounting (D3). Wire-format details are measured against betterleaks 1.8.1.

# Synthetic credential material, assembled by concatenation so that no
# credential literal is ever written into this repository.
_BL_SECRET = 'xoxb-' + '1234567890' + '-' + 'BETTERLEAKSFIXTURE0001'
_BL_LINE = 'slack_token = "' + _BL_SECRET + '"'
_BL_COMPONENT_SECRET = 'component' + '-secret-' + 'value0002'


def _make_betterleaks_finding(**kwargs) -> dict:
    """Return one realistic Betterleaks 1.8.1 record, overridden by kwargs.

    Keys are the Go field names verbatim (``report/json.go`` marshals
    ``[]Finding`` and most fields carry no struct tag), and every key present
    here is one the real binary emits on every finding. Fields the binary omits
    when unset — ``MatchContext``, ``CaptureGroups``, ``Fragment``,
    ``ComponentSets``, ``ValidationStatus``, ``ValidationReason``,
    ``ValidationMeta``, ``Link`` — are deliberately absent, so the default
    fixture is the shape of a plain ``betterleaks dir`` scan with no
    ``--validation`` pass.
    """
    base = {
        'RuleID': 'slack-bot-token',
        'Description': 'Slack Bot token',
        'StartLine': 1,
        'EndLine': 1,
        'StartColumn': 15,
        'EndColumn': 15 + len(_BL_SECRET),
        'Match': _BL_LINE,
        'Secret': _BL_SECRET,
        'Attributes': {
            'path': 'src/notify.py',
            'resource': 'fs.content',
            'confidence': 'high',
        },
        'Tags': [],
        'Fingerprint': 'src/notify.py:slack-bot-token:1',
        'File': 'src/notify.py',
        'SymlinkFile': '',
        'Commit': '',
        'Entropy': 3.9,
        'Author': '',
        'Email': '',
        'Date': '',
        'Message': '',
    }
    base.update(kwargs)
    return base


def _write_betterleaks_report(tmp_path: Path, findings: list | None) -> Path:
    """Write a Betterleaks JSON report to a temp file.

    ``None`` writes the literal ``null`` document the real binary emits for a
    zero-finding scan (see TestBetterleaksNullReport).
    """
    report = tmp_path / 'betterleaks_report.json'
    report.write_text(json.dumps(findings), encoding='utf-8')
    return report


def _make_bl_target(tmp_path: Path) -> tuple[Path, Path]:
    """Create a target directory holding src/notify.py with the fixture secret
    on line 1. Returns (target_dir, notify_py_path)."""
    target = tmp_path / 'repo'
    src = target / 'src'
    src.mkdir(parents=True, exist_ok=True)
    notify = src / 'notify.py'
    notify.write_text(_BL_LINE + '\n', encoding='utf-8')
    return target, notify


class TestBetterleaksFieldMapping:
    """A Betterleaks record maps onto the 7-key Finding contract, with D1's
    ``external:betterleaks:<RuleID>`` type string.

    Prevents two failures. A mis-copied key produces a Finding the redactor
    cannot act on (a wrong file/line/full_value fails the replacement and is
    reported as a stale report), and a wrong type prefix mis-attributes every
    betterleaks finding to Gitleaks in reports and in ``_derive_env_var_name``.
    """

    def test_all_fields_mapped(self, tmp_path):
        target, notify = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, [_make_betterleaks_finding()])
        results = ingest_betterleaks(str(report), str(target))

        assert len(results) == 1
        r = results[0]
        assert r['file'] == str(notify.resolve())
        assert r['line'] == 1
        assert r['type'] == 'external:betterleaks:slack-bot-token'
        assert r['severity'] == 'critical'
        assert r['full_value'] == _BL_SECRET
        assert r['value_preview'] == _BL_SECRET
        assert r['raw'] == _BL_LINE
        assert 'commit' not in r  # Commit='' on a `betterleaks dir` scan

    def test_finding_dict_shape(self, tmp_path):
        """Every key the rest of the pipeline reads is present."""
        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, [_make_betterleaks_finding()])
        results = ingest_betterleaks(str(report), str(target))
        assert len(results) == 1
        r = results[0]
        for key in ('file', 'line', 'type', 'severity', 'full_value', 'value_preview', 'raw'):
            assert key in r, f'Missing key: {key}'

    def test_multiple_findings(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        findings = [
            _make_betterleaks_finding(Secret=_BL_SECRET + 'A'),
            _make_betterleaks_finding(Secret=_BL_SECRET + 'B'),
            _make_betterleaks_finding(Secret=_BL_SECRET + 'C'),
        ]
        report = _write_betterleaks_report(tmp_path, findings)
        results = ingest_betterleaks(str(report), str(target))
        assert [r['full_value'] for r in results] == [
            _BL_SECRET + 'A',
            _BL_SECRET + 'B',
            _BL_SECRET + 'C',
        ]

    def test_type_prefix_follows_rule_id(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, [_make_betterleaks_finding(RuleID='jwt')])
        results = ingest_betterleaks(str(report), str(target))
        assert results[0]['type'] == 'external:betterleaks:jwt'

    def test_absent_rule_id_becomes_unknown(self, tmp_path):
        """A record with no RuleID keeps the Gitleaks path's 'unknown' literal."""
        target, _ = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding()
        del finding['RuleID']
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert results[0]['type'] == 'external:betterleaks:unknown'
        assert results[0]['severity'] == 'medium'

    def test_line_from_start_line_not_end_line(self, tmp_path):
        """StartLine drives `line`; a multi-line span still anchors at the start."""
        target, notify = _make_bl_target(tmp_path)
        notify.write_text(_BL_LINE + '\n' + 'x = 1\n' + 'y = 2\n', encoding='utf-8')
        from credactor.ingest import _read_file_lines

        _read_file_lines.cache_clear()
        finding = _make_betterleaks_finding(StartLine=1, EndLine=3)
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert results[0]['line'] == 1

    def test_bad_start_line_coerced_to_one(self, tmp_path):
        """StartLine must end up an int >= 1 — a 0, a negative or a string would
        index the wrong line (or raise) during raw synthesis and redaction."""
        target, _ = _make_bl_target(tmp_path)
        for bad in (0, -3, 'seven', None, 1.5, True):
            finding = _make_betterleaks_finding()
            finding['StartLine'] = bad
            report = _write_betterleaks_report(tmp_path, [finding])
            results = ingest_betterleaks(str(report), str(target))
            assert len(results) == 1, f'Finding dropped for StartLine={bad!r}'
            assert results[0]['line'] >= 1, f'line not coerced for StartLine={bad!r}'

    def test_long_secret_preview_truncated_but_value_intact(self, tmp_path):
        """value_preview is display-only; full_value must never be truncated —
        a shortened full_value would silently redact nothing."""
        target, notify = _make_bl_target(tmp_path)
        long_secret = 'bl' + 'x' * 80
        notify.write_text('token = "' + long_secret + '"\n', encoding='utf-8')
        from credactor.ingest import _read_file_lines

        _read_file_lines.cache_clear()
        report = _write_betterleaks_report(
            tmp_path, [_make_betterleaks_finding(Secret=long_secret)]
        )
        results = ingest_betterleaks(str(report), str(target))
        assert results[0]['full_value'] == long_secret
        assert results[0]['value_preview'] == long_secret[:60] + '...'


class TestBetterleaksNullReport:
    """D0: betterleaks writes the literal JSON document ``null`` — not ``[]`` —
    for a zero-finding scan. It must ingest as zero findings and must not raise.

    This is the regression that matters most in the whole feature. Without the
    null coercion every CLEAN upstream scan falls through to the non-list guard
    and exits 2 with 'must be a JSON array at top level (got NoneType)', i.e.
    the CI gate fails precisely when the repository is clean.
    """

    def test_literal_null_document_is_zero_findings(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        report = tmp_path / 'clean.json'
        report.write_text('null\n', encoding='utf-8')
        assert ingest_betterleaks(str(report), str(target)) == []

    def test_null_report_does_not_raise(self, tmp_path):
        """Stated separately from the return value: the fatal path is a raise,
        and a ValueError here is what turns a clean scan into exit 2."""
        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, None)
        assert report.read_text(encoding='utf-8') == 'null'
        ingest_betterleaks(str(report), str(target))

    def test_null_report_touches_no_stats(self, tmp_path):
        from credactor.ingest import new_ingest_stats

        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, None)
        stats = new_ingest_stats()
        assert ingest_betterleaks(str(report), str(target), stats=stats) == []
        assert stats['invalid_record'] == 0
        assert stats['unsupported_source'] == 0
        assert stats['missing_file'] == 0

    def test_null_report_is_silent(self, tmp_path, credactor_caplog):
        """A clean scan must not warn — a warning on every clean run trains
        users to ignore the warnings that do matter."""
        import logging

        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, None)
        ingest_betterleaks(str(report), str(target))
        warnings = [
            r.getMessage() for r in credactor_caplog.records if r.levelno >= logging.WARNING
        ]
        assert warnings == []

    def test_empty_array_is_also_zero_findings(self, tmp_path):
        """The Gitleaks-style empty array stays valid; D0 adds a case, it does
        not replace one."""
        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, [])
        assert ingest_betterleaks(str(report), str(target)) == []


class TestBetterleaksAttributesPrecedence:
    """Source metadata is read from ``Attributes`` first and falls back to the
    deprecated ``File``/``SymlinkFile``/``Commit`` mirrors, with both symlink
    fields ranking above both real-path fields.

    Prevents both directions of the mistake. Reading the deprecated mirrors
    first would break the day betterleaks removes them, and losing the fallback
    would break every report from a version that populates only those — the
    backward-compatible mapping is the fact the whole design rests on.
    """

    def test_attributes_path_beats_deprecated_file(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        other = target / 'src' / 'other.py'
        other.write_text(_BL_LINE + '\n', encoding='utf-8')
        finding = _make_betterleaks_finding(
            Attributes={'path': 'src/other.py', 'resource': 'fs.content'},
            File='src/notify.py',
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert len(results) == 1
        assert results[0]['file'] == str(other.resolve())

    def test_fs_symlink_beats_attributes_path(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        real = target / 'src' / 'real.py'
        real.write_text(_BL_LINE + '\n', encoding='utf-8')
        finding = _make_betterleaks_finding(
            Attributes={
                'fs.symlink': 'src/real.py',
                'path': 'src/notify.py',
                'resource': 'fs.content',
            },
            File='src/notify.py',
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert len(results) == 1
        assert results[0]['file'] == str(real.resolve())

    def test_deprecated_symlinkfile_beats_attributes_path(self, tmp_path):
        """The drift case the Attributes-first ordering exists to survive: a
        version that emits ``Attributes.path`` but exposes the symlink only
        through the deprecated mirror. Chaining Attributes straight through put
        the new-format real path ahead of the deprecated symlink path and
        inverted the symlink-first precedence. A dereferenced real file outside
        the target root is then dropped by the traversal guard, so the redaction
        goes missing in silence."""
        target, _ = _make_bl_target(tmp_path)
        real = target / 'src' / 'real.py'
        real.write_text(_BL_LINE + '\n', encoding='utf-8')
        finding = _make_betterleaks_finding(
            Attributes={'path': 'src/notify.py', 'resource': 'fs.content'},
            SymlinkFile='src/real.py',
            File='src/notify.py',
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert len(results) == 1
        assert results[0]['file'] == str(real.resolve())

    def test_deprecated_fields_only_still_work(self, tmp_path):
        """The compatibility case: no Attributes at all, only the deprecated
        File/Commit mirrors, still produces a complete Finding."""
        target, notify = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(File='src/notify.py', Commit='deadbeef12345678')
        del finding['Attributes']
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert len(results) == 1
        assert results[0]['file'] == str(notify.resolve())
        assert results[0]['commit'] == 'deadbeef1234'
        assert results[0]['full_value'] == _BL_SECRET

    def test_deprecated_symlinkfile_used_when_attributes_carry_no_path(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        real = target / 'src' / 'real.py'
        real.write_text(_BL_LINE + '\n', encoding='utf-8')
        finding = _make_betterleaks_finding(
            Attributes={'resource': 'fs.content'},
            SymlinkFile='src/real.py',
            File='src/notify.py',
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert len(results) == 1
        assert results[0]['file'] == str(real.resolve())

    def test_non_dict_attributes_falls_back_to_deprecated_fields(self, tmp_path):
        """A malformed Attributes value must not abort the record — the
        deprecated mirrors still carry the path."""
        target, notify = _make_bl_target(tmp_path)
        for bad in ('oops', 42, ['path'], None):
            finding = _make_betterleaks_finding(File='src/notify.py')
            finding['Attributes'] = bad
            report = _write_betterleaks_report(tmp_path, [finding])
            results = ingest_betterleaks(str(report), str(target))
            assert len(results) == 1, f'Finding dropped for Attributes={bad!r}'
            assert results[0]['file'] == str(notify.resolve())

    def test_non_string_path_is_an_invalid_record_not_an_unsupported_source(self, tmp_path):
        """A path that is present but not a string is a malformed record, and is
        counted as one -- parity with the Gitleaks parser, which charges a
        non-string File to invalid_record. Charging it to unsupported_source
        instead would tell the operator a source type could not be ingested
        when the report is simply corrupt."""
        from credactor.ingest import new_ingest_stats

        target, _ = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(
            Attributes={'path': ['src/notify.py'], 'resource': 'fs.content'},
            File='src/notify.py',
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        stats = new_ingest_stats()
        results = ingest_betterleaks(str(report), str(target), stats=stats)
        assert results == []
        assert stats['invalid_record'] == 1
        assert stats['unsupported_source'] == 0

    def test_falsy_non_string_path_is_an_invalid_record_too(self, tmp_path):
        """The classification must key off the TYPE, not the truthiness. These
        values are non-string and falsy, so a truthiness-first guard let every
        one of them skip the malformed branch and land in the pathless branch,
        telling the operator a source type could not be ingested when the record
        is simply corrupt. JSON ``null`` counts as corrupt too, which is what
        ingest_gitleaks does with the same value.

        Every candidate position is covered, not just the last: an ``or`` chain
        skips over a falsy non-string in any earlier position, so the miscount
        survived there even once the guard itself was fixed."""
        from credactor.ingest import new_ingest_stats

        target, _ = _make_bl_target(tmp_path)
        positions = (
            ('Attributes', 'fs.symlink'),
            ('SymlinkFile', None),
            ('Attributes', 'path'),
            ('File', None),
        )
        for bad in (0, False, [], {}, 0.0, None):
            for field, attr_key in positions:
                finding = _make_betterleaks_finding(File='', SymlinkFile='')
                finding['Attributes'] = {'resource': 'fs.content'}
                if attr_key is not None:
                    finding['Attributes'][attr_key] = bad
                else:
                    finding[field] = bad
                report = _write_betterleaks_report(tmp_path, [finding])
                stats = new_ingest_stats()
                where = f'{field}{"." + attr_key if attr_key else ""}={bad!r}'
                assert ingest_betterleaks(str(report), str(target), stats=stats) == []
                assert stats['invalid_record'] == 1, f'Not an invalid record for {where}'
                assert stats['unsupported_source'] == 0, f'Miscounted for {where}'

    def test_empty_string_paths_are_an_unsupported_source_not_corrupt(self, tmp_path):
        """The legitimate pathless case must survive the type check above:
        Betterleaks writes '' for the mirrors it does not populate, and a
        non-filesystem finding (stdin, S3) has no path at all."""
        from credactor.ingest import new_ingest_stats

        target, _ = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(File='', SymlinkFile='')
        finding['Attributes'] = {'path': '', 'resource': 's3.object'}
        report = _write_betterleaks_report(tmp_path, [finding])
        stats = new_ingest_stats()
        assert ingest_betterleaks(str(report), str(target), stats=stats) == []
        assert stats['unsupported_source'] == 1
        assert stats['invalid_record'] == 0


class TestBetterleaksSharedStatsIsolation:
    """The CLI passes ONE stats dict to every parser and runs Betterleaks last,
    so the Betterleaks summary must render only its OWN source labels. Reading
    the shared set reported another scanner's source types as Betterleaks', and
    a full shared 20-entry cap could hide the Betterleaks label entirely."""

    def test_summary_omits_another_parsers_source_labels(self, tmp_path, credactor_caplog):
        from credactor.ingest import new_ingest_stats

        target, _ = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(
            Attributes={'path': '', 'resource': 's3.object'},
            File='',
            SymlinkFile='',
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        stats = new_ingest_stats()
        # Pre-seed as if TruffleHog had already run against the same dict.
        stats['unsupported_source'] = 3
        stats['unsupported_types'].update({'Docker', 'Jenkins', 'Postman'})
        stats['unsupported_types_truncated'] = True

        ingest_betterleaks(str(report), str(target), stats=stats)

        summary = [
            r.getMessage()
            for r in credactor_caplog.records
            if 'skipped: no file path' in r.getMessage()
        ]
        assert len(summary) == 1
        assert "'s3.object'" in summary[0]
        for foreign in ('Docker', 'Jenkins', 'Postman'):
            assert foreign not in summary[0]
        assert '(further types omitted)' not in summary[0]
        # The shared counter is still deltaed correctly: 3 pre-seeded + 1 here.
        assert stats['unsupported_source'] == 4
        assert summary[0].startswith('1 Betterleaks finding(s)')


class TestBetterleaksSeverity:
    """D2 precedence: a decisive ValidationStatus (valid / invalid / revoked)
    wins outright, then a Tags override, then ``_GITLEAKS_SEVERITY``, then
    'medium'.

    Prevents both halves of the mistake: discarding betterleaks' provider
    verdict (its one real advantage over Gitleaks, and the reason a user pays
    for the ``--validation`` API calls), and letting a non-decisive status such
    as ``needs_validation`` read as 'not serious' by downgrading it.
    """

    def _severity_for(self, tmp_path, **kwargs) -> str:
        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, [_make_betterleaks_finding(**kwargs)])
        results = ingest_betterleaks(str(report), str(target))
        assert len(results) == 1
        return results[0]['severity']

    def test_valid_overrides_the_rule_table(self, tmp_path):
        """generic-api-key is 'medium' in the table; a provider-confirmed live
        secret is critical regardless."""
        assert (
            self._severity_for(tmp_path, RuleID='generic-api-key', ValidationStatus='valid')
            == 'critical'
        )

    def test_invalid_downgrades_a_critical_rule(self, tmp_path):
        assert (
            self._severity_for(tmp_path, RuleID='aws-access-token', ValidationStatus='invalid')
            == 'low'
        )

    def test_revoked_downgrades_a_critical_rule(self, tmp_path):
        assert (
            self._severity_for(tmp_path, RuleID='aws-access-token', ValidationStatus='revoked')
            == 'low'
        )

    def test_non_decisive_statuses_fall_through_to_the_table(self, tmp_path):
        """'', needs_validation, unknown and error are 'we did not find out',
        not 'this is fine'."""
        for status in ('', 'needs_validation', 'unknown', 'error'):
            got = self._severity_for(tmp_path, RuleID='aws-access-token', ValidationStatus=status)
            assert got == 'critical', f'ValidationStatus={status!r} downgraded to {got!r}'

    def test_absent_validation_status_uses_the_table(self, tmp_path):
        """The default `betterleaks dir` report has no ValidationStatus key at
        all — that is the common path, not the exception."""
        finding = _make_betterleaks_finding(RuleID='slack-webhook-url')
        assert 'ValidationStatus' not in finding
        assert self._severity_for(tmp_path, RuleID='slack-webhook-url') == 'high'

    def test_non_string_validation_status_ignored(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        for bad in (1, True, ['valid'], {'v': 'valid'}):
            finding = _make_betterleaks_finding(RuleID='aws-access-token')
            finding['ValidationStatus'] = bad
            report = _write_betterleaks_report(tmp_path, [finding])
            results = ingest_betterleaks(str(report), str(target))
            assert len(results) == 1, f'Finding dropped for ValidationStatus={bad!r}'
            assert results[0]['severity'] == 'critical'

    def test_unmapped_rule_id_is_medium(self, tmp_path):
        assert self._severity_for(tmp_path, RuleID='some-new-betterleaks-rule') == 'medium'

    def test_tags_override_honoured_when_status_not_decisive(self, tmp_path):
        got = self._severity_for(
            tmp_path,
            RuleID='generic-api-key',
            Tags=['critical'],
            ValidationStatus='needs_validation',
        )
        assert got == 'critical'

    def test_decisive_status_beats_a_tags_override(self, tmp_path):
        """The machine verdict outranks the rule author's tag — the same rule
        TruffleHog's Verified=True already follows."""
        got = self._severity_for(
            tmp_path, RuleID='generic-api-key', Tags=['critical'], ValidationStatus='revoked'
        )
        assert got == 'low'

    def test_validation_table_holds_only_the_decisive_statuses(self):
        """Locks the domain: adding 'unknown' or 'needs_validation' here would
        silently downgrade findings nobody validated."""
        assert _BETTERLEAKS_VALIDATION_SEVERITY == {
            'valid': 'critical',
            'invalid': 'low',
            'revoked': 'low',
        }
        for status in ('', 'needs_validation', 'unknown', 'error'):
            assert status not in _BETTERLEAKS_VALIDATION_SEVERITY

    def test_severity_helper_directly(self):
        assert _betterleaks_severity('aws-access-token') == 'critical'
        assert _betterleaks_severity('nope-not-a-rule') == 'medium'
        assert _betterleaks_severity('generic-api-key', 'valid') == 'critical'
        assert _betterleaks_severity('aws-access-token', 'invalid') == 'low'
        assert _betterleaks_severity('generic-api-key', '', ['high']) == 'high'
        assert _betterleaks_severity('generic-api-key', 'revoked', ['high']) == 'low'
        # Status is matched case-insensitively; a shouty status must not slip
        # past the table and read as 'not validated'.
        assert _betterleaks_severity('generic-api-key', 'VALID') == 'critical'

    def test_severity_helper_reuses_the_gitleaks_table_unchanged(self):
        """Betterleaks inherits Gitleaks' rule IDs, so the shared table is the
        correct source — and must not be mutated by the new parser."""
        before = dict(_GITLEAKS_SEVERITY)
        for rule_id, expected in _GITLEAKS_SEVERITY.items():
            assert _betterleaks_severity(rule_id) == expected
        assert before == _GITLEAKS_SEVERITY


class TestBetterleaksTags:
    """``Tags`` arrives as ``[]`` from every real 1.8.1 report, but Go marshals a
    nil slice as ``null``, so both forms must parse.

    Prevents one unset-Tags rule aborting an entire ingest with a TypeError.
    """

    def test_tags_empty_list(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, [_make_betterleaks_finding(Tags=[])])
        results = ingest_betterleaks(str(report), str(target))
        assert len(results) == 1
        assert results[0]['severity'] == 'critical'  # from the rule table

    def test_tags_json_null(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, [_make_betterleaks_finding(Tags=None)])
        raw_text = report.read_text(encoding='utf-8')
        assert '"Tags": null' in raw_text
        results = ingest_betterleaks(str(report), str(target))
        assert len(results) == 1
        assert results[0]['severity'] == 'critical'

    def test_tags_non_list_ignored(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        for bad in ('critical', 42, {'sev': 'critical'}):
            finding = _make_betterleaks_finding(RuleID='generic-api-key')
            finding['Tags'] = bad
            report = _write_betterleaks_report(tmp_path, [finding])
            results = ingest_betterleaks(str(report), str(target))
            assert len(results) == 1, f'Finding dropped for Tags={bad!r}'
            assert results[0]['severity'] == 'medium'

    def test_non_string_tag_entries_skipped(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(RuleID='generic-api-key', Tags=[1, None, 'high'])
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert results[0]['severity'] == 'high'


class TestBetterleaksUnsupportedSource:
    """D3: a finding with no resolvable path is an unsupported SOURCE, not an
    invalid record. It is counted in ``stats['unsupported_source']``, labelled
    in ``stats['unsupported_types']`` and summarised in a run-level WARN.

    Prevents telling the user a well-formed report is malformed, and — the part
    that must not regress — proves the gate is PATH PRESENCE rather than the
    ``resource`` string: a real ``betterleaks stdin`` finding carries
    ``resource='fs.content'`` with ``path=''``, so a resource allowlist would
    accept it and hand an empty path to the resolver.
    """

    def _ingest_one(self, tmp_path, finding):
        from credactor.ingest import new_ingest_stats

        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, [finding])
        stats = new_ingest_stats()
        results = ingest_betterleaks(str(report), str(target), stats=stats)
        return results, stats

    def test_stdin_finding_is_unsupported_not_invalid(self, tmp_path):
        """resource='fs.content' with an empty path — the real stdin shape."""
        finding = _make_betterleaks_finding(
            Attributes={'path': '', 'resource': 'fs.content'},
            File='',
            SymlinkFile='',
            Commit='',
        )
        results, stats = self._ingest_one(tmp_path, finding)
        assert results == []
        assert stats['unsupported_source'] == 1
        assert stats['invalid_record'] == 0, 'a pathless finding is not a malformed record'
        assert stats['unsupported_types'] == {'fs.content'}

    def test_remote_source_is_unsupported(self, tmp_path):
        finding = _make_betterleaks_finding(
            Attributes={'resource': 'github.issue'}, File='', SymlinkFile=''
        )
        results, stats = self._ingest_one(tmp_path, finding)
        assert results == []
        assert stats['unsupported_source'] == 1
        assert stats['invalid_record'] == 0
        assert stats['unsupported_types'] == {'github.issue'}

    def test_missing_attributes_labelled_unknown(self, tmp_path):
        finding = _make_betterleaks_finding(File='', SymlinkFile='')
        del finding['Attributes']
        results, stats = self._ingest_one(tmp_path, finding)
        assert results == []
        assert stats['unsupported_source'] == 1
        assert stats['unsupported_types'] == {'unknown'}

    def test_non_string_resource_labelled_unknown(self, tmp_path):
        finding = _make_betterleaks_finding(
            Attributes={'path': '', 'resource': 42}, File='', SymlinkFile=''
        )
        results, stats = self._ingest_one(tmp_path, finding)
        assert results == []
        assert stats['unsupported_source'] == 1
        assert stats['unsupported_types'] == {'unknown'}

    def test_run_level_warning_names_count_and_type(self, tmp_path, credactor_caplog):
        finding = _make_betterleaks_finding(
            Attributes={'path': '', 'resource': 's3.object'}, File='', SymlinkFile=''
        )
        self._ingest_one(tmp_path, finding)
        summary = [
            r.getMessage()
            for r in credactor_caplog.records
            if 'skipped: no file path' in r.getMessage()
        ]
        assert len(summary) == 1
        assert summary[0].startswith('1 Betterleaks finding(s)')
        assert 's3.object' in summary[0]

    def test_warning_fires_even_without_a_caller_stats_dict(self, tmp_path, credactor_caplog):
        """A direct caller passing stats=None must still see the summary — an
        all-unsupported report would otherwise be a silent exit-0 all-clear."""
        target, _ = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(
            Attributes={'path': '', 'resource': 'gitlab.mr'}, File='', SymlinkFile=''
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        assert ingest_betterleaks(str(report), str(target)) == []
        assert any('skipped: no file path' in r.getMessage() for r in credactor_caplog.records)

    def test_filesystem_findings_alongside_unsupported_ones_still_ingest(self, tmp_path):
        from credactor.ingest import new_ingest_stats

        target, notify = _make_bl_target(tmp_path)
        good = _make_betterleaks_finding()
        remote = _make_betterleaks_finding(
            Attributes={'resource': 'huggingface.model'}, File='', SymlinkFile=''
        )
        report = _write_betterleaks_report(tmp_path, [remote, good])
        stats = new_ingest_stats()
        results = ingest_betterleaks(str(report), str(target), stats=stats)
        assert len(results) == 1
        assert results[0]['file'] == str(notify.resolve())
        assert stats['unsupported_source'] == 1
        assert stats['invalid_record'] == 0

    def test_summary_counts_only_this_parser(self, tmp_path, credactor_caplog):
        """The CLI shares one stats dict across all three ingest calls, so the
        Betterleaks summary must report its own skips, not the running total."""
        from credactor.ingest import new_ingest_stats

        target, _ = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(
            Attributes={'path': '', 'resource': 'fs.content'}, File='', SymlinkFile=''
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        stats = new_ingest_stats()
        stats['unsupported_source'] = 7  # as if TruffleHog had already run
        ingest_betterleaks(str(report), str(target), stats=stats)
        assert stats['unsupported_source'] == 8
        summary = [
            r.getMessage()
            for r in credactor_caplog.records
            if 'skipped: no file path' in r.getMessage()
        ]
        assert len(summary) == 1 and summary[0].startswith('1 Betterleaks finding(s)')


class TestBetterleaksUnsupportedTypeCaps:
    """The unsupported-type label set holds report-controlled strings, so the
    Betterleaks path must respect the same 20-entry / 60-character bounds the
    TruffleHog path does.

    Prevents a report with a huge or high-cardinality ``resource`` value
    ballooning the set and flooding the run-level summary line.
    """

    def test_label_count_and_length_bounded(self, tmp_path, credactor_caplog):
        from credactor.ingest import (
            _MAX_UNSUPPORTED_TYPE_NAME_LEN,
            _MAX_UNSUPPORTED_TYPE_NAMES,
            new_ingest_stats,
        )

        target, _ = _make_bl_target(tmp_path)
        findings = [
            # A single record can carry an arbitrarily long resource label.
            _make_betterleaks_finding(
                Attributes={'path': '', 'resource': 'R' * 500}, File='', SymlinkFile=''
            )
        ]
        findings += [
            _make_betterleaks_finding(
                Attributes={'path': '', 'resource': f'source.{i:02d}'}, File='', SymlinkFile=''
            )
            for i in range(25)
        ]
        report = _write_betterleaks_report(tmp_path, findings)
        stats = new_ingest_stats()
        assert ingest_betterleaks(str(report), str(target), stats=stats) == []
        assert stats['unsupported_source'] == 26
        assert len(stats['unsupported_types']) == _MAX_UNSUPPORTED_TYPE_NAMES
        assert stats['unsupported_types_truncated'] is True
        assert all(len(t) <= _MAX_UNSUPPORTED_TYPE_NAME_LEN for t in stats['unsupported_types'])
        summary = [
            r.getMessage()
            for r in credactor_caplog.records
            if 'skipped: no file path' in r.getMessage()
        ]
        assert summary and '(further types omitted)' in summary[-1]


class TestBetterleaksInvalidRecords:
    """A non-object entry, or a record whose ``Secret`` is empty or not a
    string, is an invalid record: counted in ``stats['invalid_record']`` and
    named in a run-level WARN.

    Prevents the silent false all-clear — per-record skips are INFO-only, so a
    wholly invalid report (schema drift, or a post-processor stripping Secret)
    would otherwise be byte-indistinguishable from a clean scan and exit 0.
    """

    def test_non_object_entry_counted(self, tmp_path):
        from credactor.ingest import new_ingest_stats

        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, [42, 'nope', None, ['x']])
        stats = new_ingest_stats()
        assert ingest_betterleaks(str(report), str(target), stats=stats) == []
        assert stats['invalid_record'] == 4
        assert stats['unsupported_source'] == 0

    def test_empty_or_missing_secret_counted(self, tmp_path):
        from credactor.ingest import new_ingest_stats

        target, _ = _make_bl_target(tmp_path)
        no_secret = _make_betterleaks_finding()
        del no_secret['Secret']
        report = _write_betterleaks_report(
            tmp_path, [_make_betterleaks_finding(Secret=''), no_secret]
        )
        stats = new_ingest_stats()
        assert ingest_betterleaks(str(report), str(target), stats=stats) == []
        assert stats['invalid_record'] == 2

    def test_non_string_secret_counted(self, tmp_path):
        from credactor.ingest import new_ingest_stats

        target, _ = _make_bl_target(tmp_path)
        for bad in (12345, True, [], {}, None):
            finding = _make_betterleaks_finding()
            finding['Secret'] = bad
            report = _write_betterleaks_report(tmp_path, [finding])
            stats = new_ingest_stats()
            results = ingest_betterleaks(str(report), str(target), stats=stats)
            assert results == [], f'Expected skip for Secret={bad!r}'
            assert stats['invalid_record'] == 1, f'Not counted for Secret={bad!r}'

    def test_run_level_warning_names_count(self, tmp_path, credactor_caplog):
        target, _ = _make_bl_target(tmp_path)
        bad_secret = _make_betterleaks_finding(Secret='')
        report = _write_betterleaks_report(tmp_path, [42, bad_secret, _make_betterleaks_finding()])
        results = ingest_betterleaks(str(report), str(target))
        assert len(results) == 1  # the valid record still ingests
        summary = [
            r.getMessage()
            for r in credactor_caplog.records
            if 'skipped as invalid' in r.getMessage()
        ]
        assert len(summary) == 1 and summary[0].startswith('2 Betterleaks record(s)')

    def test_valid_records_do_not_warn(self, tmp_path, credactor_caplog):
        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, [_make_betterleaks_finding()])
        assert len(ingest_betterleaks(str(report), str(target))) == 1
        assert not any('skipped as invalid' in r.getMessage() for r in credactor_caplog.records)

    def test_summary_counts_only_this_parser(self, tmp_path, credactor_caplog):
        """One shared stats dict across all three parsers — the Betterleaks
        summary must not report Gitleaks' skips as its own."""
        from credactor.ingest import new_ingest_stats

        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, [42, 'nope'])
        stats = new_ingest_stats()
        stats['invalid_record'] = 5  # as if Gitleaks had already run
        ingest_betterleaks(str(report), str(target), stats=stats)
        assert stats['invalid_record'] == 7
        summary = [
            r.getMessage()
            for r in credactor_caplog.records
            if 'skipped as invalid' in r.getMessage()
        ]
        assert len(summary) == 1 and summary[0].startswith('2 Betterleaks record(s)')


class TestBetterleaksPathGuards:
    """The shared path guards apply to Betterleaks exactly as to Gitleaks:
    traversal out of the target, a symlink escaping the root, a finding that
    points at the report file itself, a path that is not on disk, and an
    embedded NUL.

    Prevents the new parser becoming a way round guards the other two enforce.
    An ingested path is attacker-influenced — it comes out of a report file —
    and a miss here means Credactor writes to a file outside the target.
    """

    def test_traversal_outside_target_blocked(self, tmp_path, credactor_caplog):
        target, _ = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(
            Attributes={'path': '../../etc/passwd', 'resource': 'fs.content'},
            File='../../etc/passwd',
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        assert ingest_betterleaks(str(report), str(target)) == []
        assert any(
            'traversal' in r.getMessage().lower() or 'outside' in r.getMessage().lower()
            for r in credactor_caplog.records
        )

    @pytest.mark.skipif(not hasattr(os, 'symlink'), reason='symlinks not supported')
    def test_symlink_escaping_root_blocked(self, tmp_path, credactor_caplog):
        target, _ = _make_bl_target(tmp_path)
        external = tmp_path / 'external_secret.txt'
        external.write_text(_BL_LINE + '\n', encoding='utf-8')
        link = target / 'src' / 'escape.py'
        try:
            link.symlink_to(external)
        except (OSError, NotImplementedError):
            pytest.skip('cannot create symlink in this environment')

        finding = _make_betterleaks_finding(
            Attributes={'path': 'src/escape.py', 'resource': 'fs.content'},
            File='src/escape.py',
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        assert ingest_betterleaks(str(report), str(target)) == []
        assert any(
            'traversal' in r.getMessage().lower() or 'outside' in r.getMessage().lower()
            for r in credactor_caplog.records
        )

    def test_self_referential_report_skipped(self, tmp_path, credactor_caplog):
        """A finding pointing at the report file itself would corrupt the report
        that is being read."""
        target = tmp_path / 'repo'
        target.mkdir()
        report = target / 'betterleaks_report.json'
        finding = _make_betterleaks_finding(
            Attributes={'path': 'betterleaks_report.json', 'resource': 'fs.content'},
            File='betterleaks_report.json',
        )
        report.write_text(json.dumps([finding]), encoding='utf-8')
        assert ingest_betterleaks(str(report), str(target)) == []
        assert any(
            'self' in r.getMessage().lower() or 'report file itself' in r.getMessage().lower()
            for r in credactor_caplog.records
        )

    def test_missing_file_counted_and_warned(self, tmp_path, credactor_caplog):
        from credactor.ingest import new_ingest_stats

        target, _ = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(
            Attributes={'path': 'src/ghost.py', 'resource': 'fs.content'}, File='src/ghost.py'
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        stats = new_ingest_stats()
        assert ingest_betterleaks(str(report), str(target), stats=stats) == []
        assert stats['missing_file'] == 1
        assert stats['invalid_record'] == 0
        assert any('missing file' in r.getMessage() for r in credactor_caplog.records)

    def test_nul_path_skips_one_record_not_the_batch(self, tmp_path, credactor_caplog):
        target, _ = _make_bl_target(tmp_path)
        good = _make_betterleaks_finding()
        bad = _make_betterleaks_finding(
            Attributes={'path': 'a\x00b', 'resource': 'fs.content'}, File='a\x00b'
        )
        report = _write_betterleaks_report(tmp_path, [bad, good])
        results = ingest_betterleaks(str(report), str(target))  # must NOT raise
        assert len(results) == 1
        assert any(
            'invalid' in r.getMessage().lower() or 'nul' in r.getMessage().lower()
            for r in credactor_caplog.records
        )

    def test_absolute_path_inside_target_accepted(self, tmp_path):
        """Betterleaks reports an absolute path when scanned with one; joining
        it against the target must still land on the same file."""
        target, notify = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(
            Attributes={'path': str(notify), 'resource': 'fs.content'}, File=str(notify)
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert len(results) == 1
        assert results[0]['file'] == str(notify.resolve())


class TestBetterleaksCommit:
    """``commit`` comes from ``Attributes['git.sha']``, falls back to the
    deprecated ``Commit`` mirror, and is truncated to 12 characters; a
    non-string value omits the key rather than crashing.

    Prevents two concrete failures: a dropped commit makes a history finding
    and a working-tree finding dedup as one, and an un-type-checked value
    raises TypeError on the slice or becomes an unhashable dedup key.
    """

    def test_git_sha_used_and_truncated(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(
            Attributes={
                'path': 'src/notify.py',
                'resource': 'git.patch_content',
                'git.sha': 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0',
            }
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert results[0]['commit'] == 'a1b2c3d4e5f6'

    def test_git_sha_beats_deprecated_commit(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(
            Attributes={'path': 'src/notify.py', 'git.sha': 'aaaaaaaaaaaa1111'},
            Commit='bbbbbbbbbbbb2222',
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert results[0]['commit'] == 'aaaaaaaaaaaa'

    def test_falls_back_to_deprecated_commit(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(
            Attributes={'path': 'src/notify.py', 'resource': 'git.patch_content'},
            Commit='bbbbbbbbbbbb2222',
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert results[0]['commit'] == 'bbbbbbbbbbbb'

    def test_empty_commit_omits_the_key(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, [_make_betterleaks_finding(Commit='')])
        results = ingest_betterleaks(str(report), str(target))
        assert 'commit' not in results[0]

    def test_non_string_commit_omitted_not_crashed(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        cases = [
            {'Attributes': {'path': 'src/notify.py', 'git.sha': 12345}, 'Commit': ''},
            {'Attributes': {'path': 'src/notify.py'}, 'Commit': ['deadbeef']},
            {'Attributes': {'path': 'src/notify.py'}, 'Commit': 42},
            {'Attributes': {'path': 'src/notify.py', 'git.sha': True}, 'Commit': ''},
        ]
        for overrides in cases:
            finding = _make_betterleaks_finding(**overrides)
            report = _write_betterleaks_report(tmp_path, [finding])
            results = ingest_betterleaks(str(report), str(target))
            assert len(results) == 1, f'Finding dropped for {overrides!r}'
            assert 'commit' not in results[0], f'Non-string commit kept for {overrides!r}'


class TestBetterleaksRawSynthesis:
    """``raw`` is contracted as ONE source line, so the on-disk line wins over
    ``Match``, a single-line ``Match`` is the fallback when that line cannot be
    read, and a multi-line ``Match`` is never used.

    Prevents inheriting the multi-line-raw weakness the Gitleaks path has:
    betterleaks' Match spans lines for some rules, and a multi-line string in a
    field every downstream consumer treats as one line corrupts report output
    and line-anchored redaction.
    """

    def test_on_disk_line_preferred_over_match(self, tmp_path):
        from credactor.ingest import _read_file_lines

        target, notify = _make_bl_target(tmp_path)
        _read_file_lines.cache_clear()
        finding = _make_betterleaks_finding(Match='ONLY-THE-MATCH-FRAGMENT')
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert results[0]['raw'] == _BL_LINE
        assert notify.read_text(encoding='utf-8').startswith(_BL_LINE)

    def test_stale_line_number_falls_back_to_single_line_match(self, tmp_path):
        """A report written before the file shrank points past EOF; the Match is
        then the best single line available."""
        from credactor.ingest import _read_file_lines

        target, _ = _make_bl_target(tmp_path)
        _read_file_lines.cache_clear()
        finding = _make_betterleaks_finding(StartLine=99, Match='token = "' + _BL_SECRET + '"')
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert results[0]['raw'] == 'token = "' + _BL_SECRET + '"'

    def test_unreadable_file_falls_back_to_single_line_match(self, tmp_path):
        from credactor.ingest import _read_file_lines

        target, notify = _make_bl_target(tmp_path)
        _read_file_lines.cache_clear()
        notify.chmod(0o000)
        if os.access(str(notify), os.R_OK):
            notify.chmod(0o644)
            pytest.skip('file permissions are not enforced for this user')
        try:
            finding = _make_betterleaks_finding(Match='token = "' + _BL_SECRET + '"')
            report = _write_betterleaks_report(tmp_path, [finding])
            results = ingest_betterleaks(str(report), str(target))
        finally:
            notify.chmod(0o644)
            _read_file_lines.cache_clear()
        assert len(results) == 1
        assert results[0]['raw'] == 'token = "' + _BL_SECRET + '"'

    def test_multiline_match_never_used_as_raw(self, tmp_path):
        from credactor.ingest import _read_file_lines

        target, _ = _make_bl_target(tmp_path)
        _read_file_lines.cache_clear()
        finding = _make_betterleaks_finding(
            StartLine=99, Match='line one\nslack_token = "' + _BL_SECRET + '"\nline three'
        )
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert '\n' not in results[0]['raw']
        assert results[0]['raw'] == _BL_SECRET

    def test_missing_or_non_string_match_falls_back_to_secret(self, tmp_path):
        from credactor.ingest import _read_file_lines

        target, _ = _make_bl_target(tmp_path)
        for bad in ('', 42, True, [], {}, None):
            _read_file_lines.cache_clear()
            finding = _make_betterleaks_finding(StartLine=99)
            finding['Match'] = bad
            report = _write_betterleaks_report(tmp_path, [finding])
            results = ingest_betterleaks(str(report), str(target))
            assert len(results) == 1, f'Finding dropped for Match={bad!r}'
            assert results[0]['raw'] == _BL_SECRET, f'raw wrong for Match={bad!r}'


class TestBetterleaksCaps:
    """The 10,000-finding and 20 MB report caps apply to Betterleaks too.

    Prevents an enormous report exhausting memory: the finding cap fires only
    after ``json.load`` has deserialised the whole document, so the byte cap has
    to reject the file first. Betterleaks records are fatter on the wire than
    Gitleaks ones (Fragment, MatchContext, Attributes and ComponentSets all
    serialise inline), so the byte cap bites sooner here, not later.
    """

    def test_over_ten_thousand_findings_truncated(self, tmp_path, credactor_caplog):
        target, _ = _make_bl_target(tmp_path)
        findings = [_make_betterleaks_finding(Secret=_BL_SECRET + str(i)) for i in range(10_001)]
        report = _write_betterleaks_report(tmp_path, findings)
        results = ingest_betterleaks(str(report), str(target))
        assert len(results) == 10_000
        assert any('truncating' in r.getMessage().lower() for r in credactor_caplog.records)

    def test_oversized_report_rejected_before_parsing(self, tmp_path, monkeypatch):
        monkeypatch.setattr('credactor.ingest._MAX_REPORT_BYTES', 4096)
        target, _ = _make_bl_target(tmp_path)
        report = tmp_path / 'huge.json'
        report.write_bytes(b'x' * 4097)  # one byte over the limit
        with pytest.raises(ValueError, match='refusing to parse'):
            ingest_betterleaks(str(report), str(target))

    def test_report_path_must_be_a_regular_file(self, tmp_path):
        """A directory (or a FIFO) would otherwise leak an OS error or block."""
        target, _ = _make_bl_target(tmp_path)
        report_dir = tmp_path / 'report_dir'
        report_dir.mkdir()
        with pytest.raises(ValueError, match='not a regular file'):
            ingest_betterleaks(str(report_dir), str(target))


class TestBetterleaksWrongFormatHints:
    """Feeding the wrong document to the Betterleaks parser must fail loudly and
    name the right flag or format.

    Prevents the silent-wrong-flag class of error. A SARIF document and a
    TruffleHog NDJSON dump both look like scanner output, and betterleaks can
    write SARIF to the same ``--report-path``, so a bare decoder message leaves
    the user with no idea which flag they wanted.
    """

    def test_sarif_document_raises_with_sarif_hint(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        report = tmp_path / 'results.sarif'
        report.write_text(
            json.dumps({'version': '2.1.0', 'runs': [{'results': []}]}), encoding='utf-8'
        )
        with pytest.raises(ValueError, match='SARIF'):
            ingest_betterleaks(str(report), str(target))

    def test_ndjson_raises_with_trufflehog_hint(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        report = tmp_path / 'th.json'
        report.write_text('{"DetectorName": "AWS"}\n{"DetectorName": "GCP"}\n', encoding='utf-8')
        with pytest.raises(ValueError, match='--from-trufflehog'):
            ingest_betterleaks(str(report), str(target))

    def test_non_array_scalar_raises_array_message(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        report = tmp_path / 'scalar.json'
        report.write_text('42', encoding='utf-8')
        with pytest.raises(ValueError, match='must be a JSON array'):
            ingest_betterleaks(str(report), str(target))

    def test_garbage_raises_not_valid_json(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        report = tmp_path / 'bad.json'
        report.write_text('not json at all', encoding='utf-8')
        with pytest.raises(ValueError, match='not valid JSON'):
            ingest_betterleaks(str(report), str(target))

    def test_non_utf8_report_raises(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        report = tmp_path / 'latin1.json'
        report.write_bytes(b'[{"Secret": "\xff\xfe"}]')
        with pytest.raises(ValueError, match='non-UTF-8'):
            ingest_betterleaks(str(report), str(target))

    def test_deeply_nested_json_is_fatal_not_a_traceback(self, tmp_path):
        """RecursionError is a RuntimeError, so without the conversion it
        escapes the CLI's `except ValueError` as exit 1 instead of exit 2."""
        target, _ = _make_bl_target(tmp_path)
        report = tmp_path / 'nested.json'
        report.write_text('[' * 200000, encoding='utf-8')
        with pytest.raises(ValueError, match='nested'):
            ingest_betterleaks(str(report), str(target))


class TestBetterleaksComponentSets:
    """A ``ComponentSet`` carries the other half of a multi-part credential.
    Only the top-level ``Secret`` is ingested, so the finding is still returned
    and one run-level WARN names how many findings carry components.

    Prevents the confirmed TruffleHog RawV2 defect class arriving through this
    parser: redact half a credential, report success, leave the more sensitive
    half live. Component secrets are reported by neither this finding nor any
    other, so the count has to be said out loud.
    """

    @staticmethod
    def _component_sets() -> list:
        """The real nested shape: lowercase outer keys, Go names inside."""
        return [
            {
                'components': [
                    {
                        'RuleID': 'aws-secret-access-key',
                        'Optional': False,
                        'StartLine': 2,
                        'Match': 'secret = "' + _BL_COMPONENT_SECRET + '"',
                        'Secret': _BL_COMPONENT_SECRET,
                    }
                ]
            }
        ]

    def test_top_level_finding_still_ingested(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(ComponentSets=self._component_sets())
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert len(results) == 1
        assert results[0]['full_value'] == _BL_SECRET

    def test_component_secret_is_not_ingested(self, tmp_path):
        """States the known v1 limitation the WARN exists to disclose."""
        target, _ = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(ComponentSets=self._component_sets())
        report = _write_betterleaks_report(tmp_path, [finding])
        results = ingest_betterleaks(str(report), str(target))
        assert all(r['full_value'] != _BL_COMPONENT_SECRET for r in results)

    def test_run_level_warning_names_the_count(self, tmp_path, credactor_caplog):
        target, _ = _make_bl_target(tmp_path)
        findings = [
            _make_betterleaks_finding(ComponentSets=self._component_sets()),
            _make_betterleaks_finding(
                Secret=_BL_SECRET + 'B', ComponentSets=self._component_sets()
            ),
            _make_betterleaks_finding(Secret=_BL_SECRET + 'C'),
        ]
        report = _write_betterleaks_report(tmp_path, findings)
        results = ingest_betterleaks(str(report), str(target))
        assert len(results) == 3
        summary = [
            r.getMessage()
            for r in credactor_caplog.records
            if 'multi-part component secrets' in r.getMessage()
        ]
        assert len(summary) == 1 and summary[0].startswith('2 Betterleaks finding(s)')

    def test_absent_or_empty_component_sets_do_not_warn(self, tmp_path, credactor_caplog):
        target, _ = _make_bl_target(tmp_path)
        with_empty = _make_betterleaks_finding(ComponentSets=[])
        report = _write_betterleaks_report(tmp_path, [_make_betterleaks_finding(), with_empty])
        assert len(ingest_betterleaks(str(report), str(target))) == 2
        assert not any(
            'multi-part component secrets' in r.getMessage() for r in credactor_caplog.records
        )

    def test_non_list_component_sets_ignored(self, tmp_path, credactor_caplog):
        target, _ = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(ComponentSets={'components': []})
        report = _write_betterleaks_report(tmp_path, [finding])
        assert len(ingest_betterleaks(str(report), str(target))) == 1
        assert not any(
            'multi-part component secrets' in r.getMessage() for r in credactor_caplog.records
        )


class TestBetterleaksDedupInteraction:
    """A native finding and an ingested Betterleaks finding at the same
    file:line:value collapse to one, and the survivor keeps the higher severity.

    Prevents the merged report double-counting every secret both tools see, and
    prevents the collapse silently discarding betterleaks' escalation — a
    ValidationStatus=valid critical dropped onto a native medium would lose the
    only piece of information the ``--validation`` pass bought.
    """

    def test_native_and_betterleaks_collapse_with_severity_merged_up(self, tmp_path):
        target, notify = _make_bl_target(tmp_path)
        finding = _make_betterleaks_finding(RuleID='generic-api-key', ValidationStatus='valid')
        report = _write_betterleaks_report(tmp_path, [finding])
        ingested = ingest_betterleaks(str(report), str(target))
        assert len(ingested) == 1
        assert ingested[0]['severity'] == 'critical'

        native = _make_finding(
            file=str(notify.resolve()),
            line=1,
            full_value=_BL_SECRET,
            ftype='variable:slack_token',
            severity='medium',
        )
        merged = deduplicate_findings([native, *ingested])
        assert len(merged) == 1
        assert merged[0]['type'] == 'variable:slack_token'  # native identity wins
        assert merged[0]['severity'] == 'critical'  # betterleaks escalation kept

    def test_gitleaks_and_betterleaks_duplicates_collapse(self, tmp_path):
        """Both scanners over the same tree report the same secret once."""
        target, notify = _make_bl_target(tmp_path)
        bl_report = _write_betterleaks_report(tmp_path, [_make_betterleaks_finding()])
        gl_report = _write_report(
            tmp_path,
            [
                _make_gitleaks_finding(
                    File='src/notify.py',
                    StartLine=1,
                    Secret=_BL_SECRET,
                    Match=_BL_LINE,
                    RuleID='slack-bot-token',
                )
            ],
        )
        gl = ingest_gitleaks(str(gl_report), str(target))
        bl = ingest_betterleaks(str(bl_report), str(target))
        assert len(gl) == 1 and len(bl) == 1
        assert gl[0]['file'] == bl[0]['file'] == str(notify.resolve())

        merged = deduplicate_findings([*gl, *bl])
        assert len(merged) == 1
        assert merged[0]['type'] == 'external:gitleaks:slack-bot-token'

    def test_betterleaks_findings_on_different_lines_are_kept(self, tmp_path):
        """Dedup must not over-merge: same value, two lines, two findings."""
        from credactor.ingest import _read_file_lines

        target, notify = _make_bl_target(tmp_path)
        notify.write_text(_BL_LINE + '\n' + _BL_LINE + '\n', encoding='utf-8')
        _read_file_lines.cache_clear()
        report = _write_betterleaks_report(
            tmp_path,
            [
                _make_betterleaks_finding(StartLine=1),
                _make_betterleaks_finding(StartLine=2),
            ],
        )
        ingested = ingest_betterleaks(str(report), str(target))
        _read_file_lines.cache_clear()
        assert len(deduplicate_findings(ingested)) == 2


class TestTrufflehogSharedStatsIsolation:
    """Twin of TestBetterleaksSharedStatsIsolation, for the parser that already
    existed. The CLI passes ONE stats dict to all three parsers, so TruffleHog's
    unsupported-source summary must report only its OWN count and its OWN source
    labels. Reading the shared counter absolutely was correct only while
    TruffleHog was the sole parser incrementing it; ingest_betterleaks is a
    second one."""

    def test_summary_omits_another_parsers_count_and_labels(self, tmp_path, credactor_caplog):
        from credactor.ingest import new_ingest_stats

        th_target, _ = _make_th_target(tmp_path)
        # A Betterleaks stdin finding: no file path, resource label s3.object.
        bl_finding = _make_betterleaks_finding(
            Attributes={'path': '', 'resource': 's3.object'},
            File='',
            SymlinkFile='',
        )
        bl_report = _write_betterleaks_report(tmp_path, [bl_finding])
        th_report = _write_ndjson(tmp_path, [_make_trufflehog_finding()])

        stats = new_ingest_stats()
        ingest_betterleaks(str(bl_report), str(th_target), stats=stats)
        results = ingest_trufflehog(str(th_report), str(th_target), stats=stats)

        assert len(results) == 1  # TruffleHog's own record still ingests
        assert stats['unsupported_source'] == 1  # Betterleaks' skip, shared
        assert not any(
            'TruffleHog finding(s) skipped: unsupported source type(s)' in r.getMessage()
            for r in credactor_caplog.records
        ), "TruffleHog reported another parser's skips as its own"

    def test_own_unsupported_still_summarised(self, tmp_path, credactor_caplog):
        """The isolation must not silence TruffleHog's real skips."""
        from credactor.ingest import new_ingest_stats

        target, _ = _make_th_target(tmp_path)
        docker = _make_trufflehog_finding(SourceMetadata={'Data': {'Docker': {'image': 'x'}}})
        report = _write_ndjson(tmp_path, [docker])
        stats = new_ingest_stats()
        stats['unsupported_source'] = 7  # as if Betterleaks had already run
        stats['unsupported_types'].add('s3.object')

        assert ingest_trufflehog(str(report), str(target), stats=stats) == []
        assert stats['unsupported_source'] == 8
        summary = [
            r.getMessage()
            for r in credactor_caplog.records
            if 'TruffleHog finding(s) skipped: unsupported source type(s)' in r.getMessage()
        ]
        assert len(summary) == 1
        assert summary[0].startswith('1 TruffleHog finding(s)')
        assert 'Docker' in summary[0]
        assert 's3.object' not in summary[0]


class TestRedactedReportIsFatal:
    """A report generated with the scanner's own ``--redact`` flag carries the
    placeholder in ``Secret``, not the secret.

    The redactor applies ``full_value`` as a plain substring replacement and then
    sweeps the file for further copies, so ingesting the literal ``REDACTED``
    rewrote every line containing that word, including Credactor's own
    ``REDACTED_BY_CREDACTOR`` sentinel, and reported the run as
    ``1 replaced | 0 failed``, exit 0. Both scanners take the flag, so both
    parsers must refuse the report rather than match loosely against it.
    """

    def test_betterleaks_full_redaction_is_fatal(self, tmp_path):
        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, [_make_betterleaks_finding(Secret='REDACTED')])
        with pytest.raises(ValueError, match=r'scanner-redacted Secret values'):
            ingest_betterleaks(str(report), str(target))

    def test_gitleaks_full_redaction_is_fatal(self, tmp_path):
        target, _ = _make_target(tmp_path)
        report = _write_report(tmp_path, [_make_gitleaks_finding(Secret='REDACTED')])
        with pytest.raises(ValueError, match=r'scanner-redacted Secret values'):
            ingest_gitleaks(str(report), str(target))

    def test_percentage_redaction_is_not_matched(self, tmp_path):
        """``--redact=20`` truncates to a ``<prefix>...`` rather than replacing,
        and that form is deliberately NOT refused. It cannot substring-match a
        line holding the full secret, so it already fails safe as an ordinary
        stale finding, and a '...' suffix is ordinary content."""
        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(
            tmp_path, [_make_betterleaks_finding(Secret=_BL_SECRET[:10] + '...')]
        )
        assert len(ingest_betterleaks(str(report), str(target))) == 1

    def test_elided_token_in_source_is_not_mistaken_for_a_redacted_report(self, tmp_path):
        """Regression: matching a '...' suffix aborted runs over reports that were
        never redacted at all. A generic rule captures an elided token in a README
        or a test fixture verbatim, and refusing the report left the real secrets
        sitting in the tree, which is worse than the corruption the guard is there
        to prevent."""
        from credactor.ingest import _read_file_lines

        elided = 'xoxb-123456789012-1234567890123-AbCdEfGhIj...'
        target, notify = _make_bl_target(tmp_path)
        notify.write_text(f'slack_token = "{elided}"\n', encoding='utf-8')
        _read_file_lines.cache_clear()
        report = _write_betterleaks_report(
            tmp_path,
            [
                _make_betterleaks_finding(
                    RuleID='generic-api-key',
                    Secret=elided,
                    Match=f'slack_token = "{elided}"',
                )
            ],
        )
        results = ingest_betterleaks(str(report), str(target))
        _read_file_lines.cache_clear()
        assert len(results) == 1
        assert results[0]['full_value'] == elided

    def test_gitleaks_elided_token_is_not_mistaken_either(self, tmp_path):
        elided = 'AKIAIOSFODNN7EXAMPLE...'
        target, config_py = _make_target(tmp_path)
        config_py.write_text(f'aws_key = "{elided}"\n', encoding='utf-8')
        report = _write_report(tmp_path, [_make_gitleaks_finding(Secret=elided)])
        assert len(ingest_gitleaks(str(report), str(target))) == 1

    def test_error_names_the_flag(self, tmp_path):
        """The message must point at the flag, not at the tree. The operator
        cannot fix this by editing files."""
        target, _ = _make_bl_target(tmp_path)
        report = _write_betterleaks_report(tmp_path, [_make_betterleaks_finding(Secret='REDACTED')])
        with pytest.raises(ValueError) as exc:
            ingest_betterleaks(str(report), str(target))
        assert '--redact' in str(exc.value)
        assert 'Betterleaks' in str(exc.value)

    def test_ordinary_secrets_are_unaffected(self, tmp_path):
        """The guard must not reject real values. An ellipsis anywhere but the
        end, and the word REDACTED as a substring, both still ingest."""
        from credactor.ingest import _read_file_lines

        target, _ = _make_bl_target(tmp_path)
        for secret in ('REDACTED_BY_CREDACTOR', 'xoxb-1...2-token', 'NOTREDACTED'):
            notify = target / 'src' / 'notify.py'
            notify.write_text(f'token = "{secret}"\n', encoding='utf-8')
            _read_file_lines.cache_clear()
            report = _write_betterleaks_report(
                tmp_path, [_make_betterleaks_finding(Secret=secret, Match=f'token = "{secret}"')]
            )
            results = ingest_betterleaks(str(report), str(target))
            assert len(results) == 1, f'Wrongly rejected Secret={secret!r}'
            assert results[0]['full_value'] == secret
        _read_file_lines.cache_clear()
