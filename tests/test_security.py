"""Security-focused tests for confirmed vulnerability mitigations."""

import io
import json
import logging
import os
import sys
import tempfile
from io import StringIO
from pathlib import Path
from typing import ClassVar

import pytest

from credactor._log import _BracketFormatter
from credactor.cli import main
from credactor.config import Config, ConfigError, apply_config_file, load_config_file
from credactor.ingest import _gitleaks_severity
from credactor.report import json_report, print_report, sarif_report
from credactor.scanner import _is_safe_value, scan_file
from credactor.suppressions import AllowList
from credactor.utils import (
    defuse_ci_commands,
    detect_encoding,
    display_chars,
    is_within_root,
    sanitize_for_display,
)
from credactor.walker import walk_and_scan


class TestPathContainment:
    """SEC-33: Verify is_within_root prevents prefix collisions."""

    def test_child_pathis_within_root(self):
        assert is_within_root('/tmp/repo/file.py', '/tmp/repo/')

    def test_exact_root_is_within(self):
        assert is_within_root('/tmp/repo', '/tmp/repo/')

    def test_prefix_collision_blocked(self):
        """repo_evil must NOT match repo — this was a regression in SEC-33."""
        assert not is_within_root('/tmp/repo_evil/file.py', '/tmp/repo/')

    def test_prefix_collision_no_trailing_sep(self):
        assert not is_within_root('/tmp/repo_evil/file.py', '/tmp/repo')

    def test_sibling_dir_blocked(self):
        assert not is_within_root('/tmp/repo2/file.py', '/tmp/repo/')

    def test_parent_dir_blocked(self):
        assert not is_within_root('/tmp/file.py', '/tmp/repo/')

    def test_unrelated_path_blocked(self):
        assert not is_within_root('/etc/passwd', '/tmp/repo/')

    @pytest.mark.skipif(
        sys.platform == 'win32', reason='normcase folds case on Windows by design (NTFS)'
    )
    def test_case_differs_treated_as_distinct_on_case_sensitive_fs(self):
        """On Linux, paths differing only in case are distinct — not within root."""
        assert not is_within_root('/tmp/REPO/file.py', '/tmp/repo/')


class TestSymlinkBoundary:
    """SEC-23: File symlinks resolving outside scan root are skipped."""

    @pytest.mark.skipif(sys.platform == 'win32', reason='Symlinks require admin on Windows')
    def test_scan_root_via_symlinked_alias(self, tmp_path):
        """A scan root reached THROUGH a symlink (macOS /var -> /private/var
        style) must still scan its files. The tmp_dir fixture used to hand
        tests such symlinked paths incidentally (tempfile's /var/...); pytest's
        tmp_path is pre-resolved, so this coverage is pinned deliberately."""
        from credactor.walker import walk_and_scan

        real = tmp_path / 'real'
        real.mkdir()
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        (real / 'app.py').write_text(f'aws = "{key}"\n', encoding='utf-8')
        alias = tmp_path / 'alias'
        os.symlink(real, alias)
        findings, _, _, _ = walk_and_scan(str(alias), config=Config(no_color=True))
        assert any(f['full_value'] == key for f in findings), findings

    @pytest.mark.skipif(sys.platform == 'win32', reason='Symlinks require admin on Windows')
    def test_external_symlink_skipped(self, tmp_dir):
        """A symlink pointing outside the scan root must not be scanned."""
        # Create an external file with a credential
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as ext:
            # credactor:ignore
            ext.write('api_key = "AKIA' + 'IOSFODNN7EXAMPLE"\n')
            ext_path = ext.name

        try:
            # Create symlink inside scan root pointing to external file
            link_path = os.path.join(tmp_dir, 'leak.py')
            os.symlink(ext_path, link_path)

            config = Config(no_color=True)
            findings, _, _, _ = walk_and_scan(tmp_dir, config=config)

            # The external file's credential must NOT appear in findings
            assert all(f['file'] != link_path for f in findings)
        finally:
            os.unlink(ext_path)

    @pytest.mark.skipif(sys.platform == 'win32', reason='Symlinks require admin on Windows')
    def test_internal_symlink_scanned(self, tmp_dir):
        """A symlink pointing within the scan root should be scanned."""
        # Resolve tmp_dir to handle macOS /var -> /private/var
        resolved_dir = os.path.realpath(tmp_dir)

        real_path = os.path.join(resolved_dir, 'real.py')
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(real_path, 'w') as f:
            f.write(f'api_key = "{key}"\n')

        link_path = os.path.join(resolved_dir, 'link.py')
        os.symlink(real_path, link_path)

        config = Config(no_color=True)
        findings, _, _, _ = walk_and_scan(resolved_dir, config=config)

        # Both the real file and the internal symlink should produce findings
        found_files = {f['file'] for f in findings}
        assert real_path in found_files
        assert link_path in found_files


class TestCIReadOnly:
    """SEC-26: --ci blocks --fix-all and forces --dry-run."""

    def test_ci_fix_all_rejected(self, tmp_dir):
        """--ci --fix-all must exit 2."""
        clean = os.path.join(tmp_dir, 'clean.py')
        with open(clean, 'w') as f:
            f.write('x = 1\n')
        with pytest.raises(SystemExit) as exc_info:
            main(['--ci', '--fix-all', tmp_dir])
        assert exc_info.value.code == 2


class TestTemplateSafeValue:
    """SEC-34: Unclosed template delimiters must not bypass detection."""

    def test_closed_template_is_safe(self):
        assert _is_safe_value('${DATABASE_URL}', None)

    def test_closed_jinja_is_safe(self):
        assert _is_safe_value('{%- set key -%}', None)

    def test_closed_helm_is_safe(self):
        assert _is_safe_value('{{ .Values.key }}', None)

    def test_unclosed_dollar_brace_not_safe(self):
        """${AKIA... without closing } must NOT be marked safe."""
        # credactor:ignore
        assert not _is_safe_value('${AKIA' + 'IOSFODNN7EXAMPLE', None)

    def test_unclosed_jinja_not_safe(self):
        assert not _is_safe_value('{%AKIA1234567890123456', None)

    def test_unclosed_helm_not_safe(self):
        assert not _is_safe_value('{{AKIA1234567890123456', None)


class TestSarifOutputInjection:
    """SEC-35: SARIF rule fields must HTML-escape attacker-controlled content."""

    def _make_finding(self, ftype, value='sk_live_test123456789abc'):
        return {
            'file': '/tmp/test.xml',
            'line': 1,
            'type': ftype,
            'severity': 'high',
            'full_value': value,
            'value_preview': value[:20],
            'raw': f'name="{ftype}" value="{value}"',
        }

    def test_sarif_rule_id_escapes_html(self):
        """HTML in finding type must be escaped in SARIF rule id."""
        finding = self._make_finding('xml-attr:key<img/onerror=alert(1)>')
        sarif = json.loads(sarif_report([finding], '/tmp'))
        rules = sarif['runs'][0]['tool']['driver']['rules']
        for rule in rules:
            assert '<img' not in rule['id']
            assert '&lt;' in rule['id'] or '<' not in rule['id']

    def test_sarif_short_description_escapes_html(self):
        """HTML in finding type must be escaped in SARIF shortDescription."""
        finding = self._make_finding('xml-attr:key<script>alert(1)</script>')
        sarif = json.loads(sarif_report([finding], '/tmp'))
        rules = sarif['runs'][0]['tool']['driver']['rules']
        for rule in rules:
            desc = rule['shortDescription']['text']
            assert '<script>' not in desc

    def test_sarif_full_description_escapes_html(self):
        """HTML in finding type must be escaped in SARIF fullDescription."""
        finding = self._make_finding('xml-attr:key"><script>')
        sarif = json.loads(sarif_report([finding], '/tmp'))
        rules = sarif['runs'][0]['tool']['driver']['rules']
        for rule in rules:
            desc = rule['fullDescription']['text']
            assert '<script>' not in desc


class TestTerminalEscapeInjection:
    """SEC-36: Text report must sanitise ANSI escape sequences."""

    def test_ansi_in_filepath_sanitised(self):
        """ANSI escape codes in file paths must not reach the terminal."""
        finding = {
            'file': '/tmp/\x1b[31mevil\x1b[0m.py',
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': 'secret123456',
            'value_preview': 'secret...',
            'raw': 'api_key = "secret123456"',
        }
        buf = StringIO()
        print_report([finding], '/tmp', no_color=True, stream=buf)
        output = buf.getvalue()
        assert '\x1b[' not in output

    def test_ansi_in_type_sanitised(self):
        """ANSI escape codes in finding type must not reach the terminal."""
        finding = {
            'file': '/tmp/test.xml',
            'line': 1,
            'type': 'xml-attr:\x1b[32mfake\x1b[0m',
            'severity': 'high',
            'full_value': 'secret123456',
            'value_preview': 'secret...',
            'raw': 'name="fake" value="secret123456"',
        }
        buf = StringIO()
        print_report([finding], '/tmp', no_color=True, stream=buf)
        output = buf.getvalue()
        # Strip the known ANSI codes from the report itself (color=False
        # disables them, but verify no injected codes remain)
        assert '\x1b[32m' not in output

    def test_ansi_in_raw_line_sanitised(self):
        """ANSI escape codes in raw source lines must not reach the terminal."""
        raw = 'api_key = "\x1b[5mBLINKING_SECRET\x1b[0m"'
        finding = {
            'file': '/tmp/test.py',
            'line': 1,
            'type': 'variable:api_key',
            'severity': 'high',
            'full_value': '\x1b[5mBLINKING_SECRET\x1b[0m',
            'value_preview': 'BLINK...',
            'raw': raw,
        }
        buf = StringIO()
        print_report([finding], '/tmp', no_color=True, stream=buf)
        output = buf.getvalue()
        assert '\x1b[5m' not in output


class TestBareDollarPrefixBypass:
    """SEC-37: Bare $ prefix must validate env var name syntax."""

    def test_valid_env_var_is_safe(self):
        """$DATABASE_URL is a valid env var reference — still safe."""
        assert _is_safe_value('$DATABASE_URL', None)

    def test_valid_short_env_var_is_safe(self):
        assert _is_safe_value('$HOME', None)

    def test_valid_underscore_prefix_is_safe(self):
        assert _is_safe_value('$_PRIVATE_KEY', None)

    def test_dollar_env_var_with_suffix_is_safe(self):
        """$HOME/.aws/credentials is a dynamic reference — safe."""
        assert _is_safe_value('$HOME/.aws/credentials', None)

    def test_dollar_env_var_with_colon_suffix_is_safe(self):
        """$TOKEN:prefix is a dynamic reference — safe."""
        assert _is_safe_value('$TOKEN:prefix', None)

    def test_dollar_env_var_with_dash_suffix_is_safe(self):
        """$VAR-suffix is a dynamic reference — safe."""
        assert _is_safe_value('$VAR-suffix', None)

    def test_dollar_slash_not_safe(self):
        """$/path/to/thing does not start with an identifier — not safe."""
        assert not _is_safe_value('$/path/to/secret', None)

    def test_dollar_plus_not_safe(self):
        """$+something does not start with an identifier — not safe."""
        assert not _is_safe_value('$+something', None)

    def test_bare_dollar_alone_not_safe(self):
        """Lone $ with nothing after it is not a valid env var."""
        assert not _is_safe_value('$', None)

    def test_dollar_starting_with_digit_not_safe(self):
        """$123abc does not match env var syntax (must start with letter/_)."""
        assert not _is_safe_value('$123abcdef', None)


class TestConfigTypeConfusion:
    """SEC-38: Malformed config values must not crash the scan."""

    def test_entropy_threshold_non_numeric(self):
        """String value for entropy_threshold falls back to default."""
        config = Config()
        apply_config_file(config, {'entropy_threshold': 'not_a_number'})
        assert config.entropy_threshold == 3.5

    def test_min_value_length_non_numeric(self):
        """String value for min_value_length falls back to default."""
        config = Config()
        apply_config_file(config, {'min_value_length': 'abc'})
        assert config.min_value_length == 8

    def test_entropy_threshold_list_type(self):
        """Array value for entropy_threshold falls back to default."""
        config = Config()
        apply_config_file(config, {'entropy_threshold': [1, 2, 3]})
        assert config.entropy_threshold == 3.5

    def test_min_value_length_dict_type(self):
        """Dict value for min_value_length falls back to default."""
        config = Config()
        apply_config_file(config, {'min_value_length': {'nested': 5}})
        assert config.min_value_length == 8

    def test_valid_values_still_work(self):
        """Valid numeric values must still be applied correctly."""
        config = Config()
        apply_config_file(config, {'entropy_threshold': 4.0, 'min_value_length': 12})
        assert config.entropy_threshold == 4.0
        assert config.min_value_length == 12


class TestConfigTrustBoundaryNonGit:
    """SEC-39 / M14: an implicitly-discovered config outside the project root is
    refused (not silently loaded) even in non-CI mode."""

    def test_parent_config_refused_without_git(self, tmp_dir, credactor_caplog):
        """A config above the scan dir, with no .git to anchor a project root, is
        an implicit outside-root config — M14 refuses it instead of loading it
        with only a warning (it could weaken detection or inject a replacement)."""
        resolved = os.path.realpath(tmp_dir)
        child = os.path.join(resolved, 'subdir')
        os.makedirs(child)
        # Place config in parent (tmp_dir), scan from child. No .git anywhere.
        config_path = os.path.join(resolved, '.credactor.toml')
        with open(config_path, 'w') as f:
            f.write('entropy_threshold = 4.0\n')
        result = load_config_file(child)
        assert result == {}
        assert any(
            'Refusing to load config from outside project root' in r.message
            for r in credactor_caplog.records
        )

    def test_outside_config_honored_with_explicit_path(self, tmp_dir):
        """M14: the same outside-root config IS loaded when the user points
        --config at it explicitly (non-CI opt-in)."""
        resolved = os.path.realpath(tmp_dir)
        child = os.path.join(resolved, 'subdir')
        os.makedirs(child)
        config_path = os.path.join(resolved, '.credactor.toml')
        with open(config_path, 'w') as f:
            f.write('entropy_threshold = 4.0\n')
        result = load_config_file(child, explicit_path=config_path)
        assert result.get('entropy_threshold') == 4.0

    def test_outside_config_refused_in_ci_even_with_explicit_path(self, tmp_dir):
        """M14 keeps SEC-29 intact: CI refuses an outside-root config even when
        passed explicitly via --config. GA-H5: the refusal is FATAL (ConfigError
        → exit 2), not a silent fallback to defaults — a stderr-only refusal
        would let the gate pass with defaults (false-clean) when the pipeline
        expected config-driven settings or [ingest] sources."""
        resolved = os.path.realpath(tmp_dir)
        child = os.path.join(resolved, 'subdir')
        os.makedirs(child)
        config_path = os.path.join(resolved, '.credactor.toml')
        with open(config_path, 'w') as f:
            f.write('entropy_threshold = 4.0\n')
        with pytest.raises(ConfigError, match='outside project root under --ci'):
            load_config_file(child, explicit_path=config_path, ci_mode=True)

    def test_config_above_git_project_root_refused(self, tmp_dir, credactor_caplog):
        """The .git-anchored refuse branch: a config ABOVE the project root is
        refused on implicit discovery even though parent traversal reaches it,
        and the error names the project root (not the scan dir)."""
        resolved = os.path.realpath(tmp_dir)
        project = os.path.join(resolved, 'project')
        scan_dir = os.path.join(project, 'src')
        os.makedirs(os.path.join(project, '.git'))
        os.makedirs(scan_dir)
        # config sits ABOVE the project root, in tmp_dir
        with open(os.path.join(resolved, '.credactor.toml'), 'w') as f:
            f.write('entropy_threshold = 4.0\n')
        result = load_config_file(scan_dir)
        assert result == {}
        assert any(
            'Refusing to load config from outside project root' in r.message
            and project in r.getMessage()
            for r in credactor_caplog.records
        )

    def test_parent_config_refused_implicitly_in_ci(self, tmp_dir):
        """The CI leg of 'refuse implicit outside-root in ALL modes'."""
        resolved = os.path.realpath(tmp_dir)
        child = os.path.join(resolved, 'subdir')
        os.makedirs(child)
        with open(os.path.join(resolved, '.credactor.toml'), 'w') as f:
            f.write('entropy_threshold = 4.0\n')
        result = load_config_file(child, ci_mode=True)
        assert result == {}


# ---------------------------------------------------------------------------
# Phase 2 — P2 audit items: verify existing defenses + A11 normcase fix
# ---------------------------------------------------------------------------


class TestA6AllowlistPathResolution:
    """A6: AllowList._root and ingest target paths must resolve consistently.

    Both AllowList(target) and ingest_gitleaks(..., target) call
    Path(target).resolve() on the same string, so they cannot disagree.
    This class confirms that behaviour with target='.' and target='./subdir'.
    """

    def test_file_suppression_matches_resolved_path(self, tmp_dir):
        """AllowList.is_file_suppressed must accept a path produced by
        Path(target / relpath).resolve(), which is exactly what ingest produces."""
        resolved_dir = str(Path(tmp_dir).resolve())
        # Write a .credactorignore that suppresses secret.py
        ignore_file = os.path.join(resolved_dir, '.credactorignore')
        with open(ignore_file, 'w') as f:
            f.write('secret.py\n')

        allowlist = AllowList(resolved_dir)

        # Simulate a resolved path as ingest would produce it
        suppressed_path = str(Path(resolved_dir) / 'secret.py')
        assert allowlist.is_file_suppressed(suppressed_path)

    def test_dot_target_resolves_same_as_absolute(self, tmp_dir):
        """AllowList('.') resolves the same root as AllowList(abs_path) for
        the same directory, so file-level suppression is path-consistent."""
        resolved_dir = str(Path(tmp_dir).resolve())
        ignore_file = os.path.join(resolved_dir, '.credactorignore')
        with open(ignore_file, 'w') as f:
            f.write('config.py\n')

        # '.' resolution depends on CWD; use the resolved absolute path directly
        al_abs = AllowList(resolved_dir)
        suppressed = str(Path(resolved_dir) / 'config.py')
        assert al_abs.is_file_suppressed(suppressed)

    def test_unsuppressed_path_not_suppressed(self, tmp_dir):
        """Paths not matching any glob must not be incorrectly suppressed."""
        resolved_dir = str(Path(tmp_dir).resolve())
        ignore_file = os.path.join(resolved_dir, '.credactorignore')
        with open(ignore_file, 'w') as f:
            f.write('secret.py\n')

        allowlist = AllowList(resolved_dir)
        other_path = str(Path(resolved_dir) / 'other.py')
        assert not allowlist.is_file_suppressed(other_path)


class TestA8ExternalTypeInjection:
    """A8: External finding types (Gitleaks RuleID, TruffleHog DetectorName)
    must not break JSON/SARIF serialization or inject HTML into SARIF viewers.

    Defense: json.dumps() for JSON, html.escape() + json.dumps() for SARIF.
    """

    def _external_finding(self, ftype: str) -> dict:
        return {
            'file': '/tmp/test.py',
            'line': 1,
            'type': ftype,
            'severity': 'high',
            'full_value': 'sk_live_test' + 'abc123456789',
            'value_preview': 'sk_live...',
            'raw': 'key = "sk_live_test' + 'abc123456789"',
        }

    def test_json_report_parseable_with_html_in_type(self):
        """json_report must produce valid JSON even with HTML in type field."""
        finding = self._external_finding('external:trufflehog:<script>alert(1)</script>')
        output = json_report([finding], '/tmp')
        parsed = json.loads(output)  # must not raise
        assert parsed['count'] == 1
        # The type value must be present (json.dumps escapes it correctly)
        assert 'external:trufflehog:' in parsed['findings'][0]['type']

    def test_json_report_parseable_with_json_metacharacters_in_type(self):
        """json_report must produce valid JSON even with `"` and `}` in type."""
        finding = self._external_finding('external:gitleaks:evil"}]')
        output = json_report([finding], '/tmp')
        parsed = json.loads(output)  # must not raise
        assert parsed['count'] == 1

    def test_sarif_report_parseable_with_html_in_type(self):
        """sarif_report must produce valid JSON even with HTML in type field."""
        finding = self._external_finding('external:trufflehog:<script>alert(1)</script>')
        output = sarif_report([finding], '/tmp')
        parsed = json.loads(output)  # must not raise
        assert parsed['version'] == '2.1.0'

    def test_sarif_html_escaped_in_rule_id(self):
        """HTML in DetectorName must be escaped in SARIF rule id."""
        finding = self._external_finding('external:trufflehog:<img/onerror=alert(1)>')
        output = sarif_report([finding], '/tmp')
        parsed = json.loads(output)
        rules = parsed['runs'][0]['tool']['driver']['rules']
        assert len(rules) == 1
        # Raw < must not appear in rule id
        assert '<img' not in rules[0]['id']

    def test_sarif_html_escaped_in_short_description(self):
        """HTML in type must be escaped in SARIF shortDescription."""
        finding = self._external_finding('external:gitleaks:<script>xss</script>')
        output = sarif_report([finding], '/tmp')
        parsed = json.loads(output)
        rules = parsed['runs'][0]['tool']['driver']['rules']
        desc = rules[0]['shortDescription']['text']
        assert '<script>' not in desc


class TestA9CommitFieldInjection:
    """A9: Commit values from external reports flow into json_report.
    json.dumps() must correctly escape JSON metacharacters in commit values.
    """

    def _finding_with_commit(self, commit: str) -> dict:
        return {
            'file': '/tmp/test.py',
            'line': 1,
            'type': 'external:gitleaks:generic-api-key',
            'severity': 'medium',
            'full_value': 'sk_live_test' + 'abc123456789',
            'value_preview': 'sk_live...',
            'raw': 'key = "sk_live_test' + 'abc123456789"',
            'commit': commit,
        }

    def test_json_report_parseable_with_metacharacters_in_commit(self):
        """json_report must produce valid JSON even with `"`, `}` in commit."""
        finding = self._finding_with_commit('abc"};evil()')
        output = json_report([finding], '/tmp')
        parsed = json.loads(output)  # must not raise
        assert parsed['count'] == 1

    def test_json_report_commit_value_round_trips(self):
        """The commit value must survive json.dumps/loads without corruption."""
        commit_val = 'abc123def456'
        finding = self._finding_with_commit(commit_val)
        output = json_report([finding], '/tmp')
        parsed = json.loads(output)
        assert parsed['findings'][0]['commit'] == commit_val

    def test_json_report_parseable_with_newline_in_commit(self):
        """json_report must produce valid JSON even with newlines in commit."""
        finding = self._finding_with_commit('abc\ndef')
        output = json_report([finding], '/tmp')
        parsed = json.loads(output)  # must not raise
        assert parsed['count'] == 1


class TestA10TagsTypeConfusion:
    """A10: Tags field in Gitleaks report may be a string, not a list.
    The call-site guard `tags if isinstance(tags, list) else []` at ingest.py:263
    prevents _gitleaks_severity from iterating over string characters.
    """

    def test_string_tags_does_not_override_severity(self):
        """_gitleaks_severity with tags='critical' (string) must NOT return
        'critical' — it should receive [] from the call-site guard instead.
        Verify the guard logic: call with [] as the call site would pass."""
        # Simulate call-site guard: tags='critical' → []
        tags_raw = 'critical'
        tags_safe = tags_raw if isinstance(tags_raw, list) else []
        result = _gitleaks_severity('generic-api-key', tags_safe)
        # Must not return 'critical' from string character iteration
        assert result != 'critical'

    def test_list_tags_with_severity_overrides(self):
        """_gitleaks_severity with tags=['critical'] (proper list) DOES override."""
        result = _gitleaks_severity('generic-api-key', ['critical'])
        assert result == 'critical'

    def test_list_tags_with_non_severity_values_falls_through(self):
        """_gitleaks_severity with tags=['database', 'config'] falls through
        to table lookup (no severity tag match)."""
        result = _gitleaks_severity('generic-api-key', ['database', 'config'])
        assert result == _gitleaks_severity('generic-api-key', [])

    def test_none_tags_falls_through_to_table(self):
        """None tags must fall through to table lookup without error."""
        result = _gitleaks_severity('generic-api-key', None)
        assert isinstance(result, str)
        assert result in {'critical', 'high', 'medium', 'low'}

    def test_list_with_non_string_items_skipped(self):
        """Non-string items in tags list (int, None, bool) must be skipped."""
        result = _gitleaks_severity('generic-api-key', [42, None, True])
        # Falls through to table lookup — same result as no tags
        assert result == _gitleaks_severity('generic-api-key', [])


class TestUnconfirmedEncodingWarns:
    """A non-UTF-8 file whose encoding cannot be positively confirmed is read as
    latin-1, which silently misreads multibyte encodings (e.g. UTF-16) and can
    miss secrets — making a clean scan a false all-clear. detect_encoding must
    warn in that case so the fallback is visible."""

    @staticmethod
    def _no_detectors(monkeypatch):
        # Simulate charset_normalizer not being installed, so the last-resort
        # latin-1 branch is exercised deterministically regardless of what the
        # test environment happens to have available. The library is imported
        # once at credactor.utils module load (not per call), so patch the
        # module-level binding, not sys.modules.
        monkeypatch.setattr('credactor.utils.charset_normalizer', None)

    def test_bomless_utf16_not_short_circuited_to_utf8(self, tmp_path):
        # BOM-less UTF-16 with an ASCII payload is NUL-interleaved ASCII bytes,
        # and bytes.isascii() is True for NUL — the fast path must NOT claim
        # utf-8 for it, or the installed detector never runs and every secret
        # in the file decodes to NUL-riddled text no pattern can match.
        pytest.importorskip('charset_normalizer')
        p = tmp_path / 'config.env'
        secret_line = 'db_password = "hunter2secret"\n'
        p.write_bytes((secret_line * 50).encode('utf-16-le'))  # no BOM

        enc = detect_encoding(str(p))

        # The detector must identify a UTF-16 family encoding; decoding with
        # its answer must surface the secret as scannable text.
        decoded = p.read_bytes().decode(enc)
        assert 'db_password' in decoded

    def test_bomless_utf16le_detected_without_detectors(self, tmp_path, monkeypatch):
        # NUL-interleaved ASCII is *valid UTF-8*, so the no-detector heuristic
        # claimed utf-8 and the secret decoded to NUL-riddled text no pattern
        # could match — silently, despite the manual promising a WARN. NULs
        # confined to one byte parity are the UTF-16 byte-order signature.
        self._no_detectors(monkeypatch)
        p = tmp_path / 'utf16le.py'
        p.write_bytes('aws_key = "AKIA4HJR6WPT3XLQ8NVB"\n'.encode('utf-16-le'))

        enc = detect_encoding(str(p))

        assert enc.replace('_', '-').lower().startswith('utf-16')
        assert 'aws_key' in p.read_bytes().decode(enc)

    def test_bomless_utf16be_detected_without_detectors(self, tmp_path, monkeypatch):
        self._no_detectors(monkeypatch)
        p = tmp_path / 'utf16be.py'
        p.write_bytes('aws_key = "AKIA4HJR6WPT3XLQ8NVB"\n'.encode('utf-16-be'))

        enc = detect_encoding(str(p))

        assert enc.replace('_', '-').lower().startswith('utf-16')
        assert 'aws_key' in p.read_bytes().decode(enc)

    def test_utf16_secret_found_end_to_end_without_detectors(self, tmp_path, monkeypatch):
        # The full scan path: a BOM-less UTF-16LE secret must produce a
        # finding on a stock install (no encoding extra).
        self._no_detectors(monkeypatch)
        p = tmp_path / 'cfg.py'
        p.write_bytes('aws_key = "AKIA4HJR6WPT3XLQ8NVB"\n'.encode('utf-16-le'))

        findings = scan_file(str(p), config=Config(no_color=True))

        assert [f for f in findings if f['type'] == 'pattern:AWS access key']

    def test_truncated_utf16_is_errored_not_crash(self, tmp_path, monkeypatch, credactor_caplog):
        # An odd-length BOM-less UTF-16LE file decodes as utf-16-le until the
        # incomplete final unit raises mid-stream. That must follow the
        # unreadable-file contract (warning + errored, --fail-on-error exit
        # 2), never a traceback and never a silent clean exit 0.
        self._no_detectors(monkeypatch)
        p = tmp_path / 'trunc.py'
        data = 'aws_key = "AKIA4HJR6WPT3XLQ8NVB"\n'.encode('utf-16-le')[:-1]
        p.write_bytes(data)

        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', '--fail-on-error', str(tmp_path)])

        assert exc.value.code == 2
        assert any('trunc.py' in r.getMessage() for r in credactor_caplog.records)

    def test_truncated_utf16_single_file_target_no_crash(self, tmp_path, monkeypatch):
        self._no_detectors(monkeypatch)
        p = tmp_path / 'trunc.py'
        p.write_bytes('aws_key = "AKIA4HJR6WPT3XLQ8NVB"\n'.encode('utf-16-le')[:-1])

        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', str(p)])

        assert exc.value.code == 0  # errored-but-warned, not found, not fatal

    def test_truncated_utf16le_not_misdetected_as_utf8_with_detectors(self, tmp_path):
        # MV-1: with the [encoding] extra installed, charset_normalizer.best()
        # returns 'utf_8' for a truncated / odd-length UTF-16LE file (its
        # NUL-interleaved bytes are valid UTF-8). That verdict short-circuited
        # the UTF-16 signature check and silently dissolved the secret into
        # mojibake. A utf-8/ascii verdict on NUL-bearing bytes must not be
        # trusted — genuine UTF-8/ASCII never contains NUL.
        pytest.importorskip('charset_normalizer')
        p = tmp_path / 'trunc.py'
        p.write_bytes('aws_key = "AKIA4HJR6WPT3XLQ8NVB"\n'.encode('utf-16-le')[:-1])

        enc = detect_encoding(str(p))

        assert enc.replace('_', '-').lower().startswith('utf-16')  # not 'utf-8'

    def test_truncated_utf16be_not_misdetected_as_utf8_with_detectors(self, tmp_path):
        pytest.importorskip('charset_normalizer')
        p = tmp_path / 'trunc.py'
        p.write_bytes('aws_key = "AKIA4HJR6WPT3XLQ8NVB"\n'.encode('utf-16-be')[:-1])

        enc = detect_encoding(str(p))

        assert enc.replace('_', '-').lower().startswith('utf-16')  # not 'utf-8'

    def test_truncated_utf16_errored_with_detectors_not_silent(self, tmp_path, credactor_caplog):
        # The manual's promise (lines 326-328: "never a silent all-clear") must
        # hold in the [encoding]-extra config too, not only on a stock install:
        # a truncated UTF-16 file is errored and warned, and --fail-on-error
        # makes it exit 2 — not a clean exit-0 [OK] that misses the secret.
        pytest.importorskip('charset_normalizer')
        p = tmp_path / 'trunc.py'
        p.write_bytes('aws_key = "AKIA4HJR6WPT3XLQ8NVB"\n'.encode('utf-16-le')[:-1])

        with pytest.raises(SystemExit) as exc:
            main(['--dry-run', '--fail-on-error', str(tmp_path)])

        assert exc.value.code == 2
        assert any('trunc.py' in r.getMessage() for r in credactor_caplog.records)

    def test_utf32_falls_back_to_latin1_and_warns(self, tmp_path, monkeypatch, credactor_caplog):
        # UTF-32 has NULs at both byte parities, so it fails the UTF-16
        # signature and must keep taking the loud latin-1 fallback.
        self._no_detectors(monkeypatch)
        p = tmp_path / 'config.env'
        p.write_bytes('API_KEY="AKIAZ7XK4PQR2WNDLMT3"\n'.encode('utf-32'))

        enc = detect_encoding(str(p))

        assert enc == 'latin-1'
        msgs = ' '.join(r.getMessage() for r in credactor_caplog.records)
        assert 'could not confirm encoding' in msgs
        assert 'credactor[encoding]' in msgs
        assert any(r.levelname == 'WARNING' for r in credactor_caplog.records)

    def test_valid_utf8_does_not_warn(self, tmp_path, monkeypatch, credactor_caplog):
        self._no_detectors(monkeypatch)
        p = tmp_path / 'ok.py'
        # Non-ASCII content: pure ASCII would return at the isascii() fast
        # path and never reach the no-detector utf-8 heuristic under test.
        p.write_text('x = "héllo wörld"\n', encoding='utf-8')

        enc = detect_encoding(str(p))

        assert enc == 'utf-8'
        assert not any(
            'could not confirm encoding' in r.getMessage() for r in credactor_caplog.records
        )


# ---------------------------------------------------------------------------
# SR-06: control characters and CI workflow commands in displayed text
# ---------------------------------------------------------------------------

_BIDI = [chr(c) for c in range(0x202A, 0x202F)] + [chr(c) for c in range(0x2066, 0x206A)]
_REPLACED = (
    [chr(c) for c in range(0x20) if c != 0x09]
    + ['\x7f']
    + [chr(c) for c in range(0x80, 0xA0)]
    + ['\u2028', '\u2029']
    + _BIDI
)
_AKIA = 'AKIA' + 'IOSFODNN7EXAMPLE'


def _command_lines(text: str) -> list[str]:
    """Lines a CI runner would read as a workflow command: GitHub trims leading
    whitespace before looking for '::', and finds '##[' anywhere in a line."""
    return [
        line
        for line in text.split('\n')
        if line.lstrip().startswith('::') or '##[' in line or '##vso[' in line.lower()
    ]


class TestDisplayChars:
    @pytest.mark.parametrize('ch', _REPLACED, ids=[f'U+{ord(c):04X}' for c in _REPLACED])
    def test_control_line_break_and_bidi_characters_become_question_marks(self, ch):
        assert display_chars(f'a{ch}b') == 'a?b'

    @pytest.mark.parametrize(
        'seq',
        [
            '\x1b[31m',
            '\x1b[2J',
            '\x1b[?25l',
            '\x1b[38;5;196m',
            '\x1b[1 q',
            '\x1b]0;window title\x07',
            '\x1b]8;;https://example.invalid\x1b\\',
        ],
        ids=['sgr', 'clear', 'private', 'sgr-256', 'intermediate', 'osc-bel', 'osc-st'],
    )
    def test_escape_sequences_are_removed_whole(self, seq):
        assert display_chars(f'a{seq}b') == 'ab'

    def test_lone_surrogates_become_question_marks(self):
        # Undecodable bytes arrive as lone surrogates (surrogateescape, or
        # os.fsdecode of a file name). Written out with surrogateescape they
        # are raw bytes again, which can spell a C1 or bidi control.
        assert display_chars('a\udce2\x1b[m\udc80\udcae\ud800b') == 'a????b'

    def test_tab_becomes_a_space(self):
        assert display_chars('\tkey = 1') == ' key = 1'

    def test_printable_text_is_kept(self):
        text = 'café 中文 😀 key = "x" # comment'
        assert display_chars(text) == text

    def test_old_name_is_gone(self):
        import credactor.utils

        assert not hasattr(credactor.utils, 'sanitize_for_terminal')


class TestDefuseCiCommands:
    @pytest.mark.parametrize(
        ('text', 'expected'),
        [
            ('::error::x', '?:error::x'),
            ('   ::warning file=a::x', '   ?:warning file=a::x'),
            ('\u00a0::notice::x', '\u00a0?:notice::x'),
            ('x ##[error]y', 'x #?[error]y'),
            ('##[set-output name=a;]b ##[group]c', '#?[set-output name=a;]b #?[group]c'),
            ('a ##vso[task.setvariable variable=x]y', 'a #?vso[task.setvariable variable=x]y'),
            ('##VSO[task.prependpath]/x', '#?VSO[task.prependpath]/x'),
        ],
    )
    def test_command_markers_are_broken(self, text, expected):
        assert defuse_ci_commands(text) == expected

    @pytest.mark.parametrize('text', ['a::b', 'std::string x', '## Heading', '#[x]', 'x #[y]'])
    def test_ordinary_text_is_kept(self, text):
        assert defuse_ci_commands(text) == text

    def test_sanitize_for_display_does_both(self):
        assert (
            sanitize_for_display('::error::a\x1b[31m\nb ##[warning]c')
            == '?:error::a?b #?[warning]c'
        )


class TestJsonOutputHasNoCommandMarkers:
    """JSON and SARIF often go to stdout in a pipeline; a marker in a path
    must not reach the job log as is, and the data must not change."""

    NAMES: ClassVar[list[str]] = [
        '##[error]boom.py',
        '##vso[task.setvariable variable=A]b.py',
        '##VSO[task.prependpath]c.py',
        '###[warning]d.py',
    ]

    def _findings(self, root):
        return [
            {
                'file': str(root / name),
                'line': 1,
                'type': 'pattern:AWS access key',
                'severity': 'critical',
                'full_value': _AKIA,
                'value_preview': _AKIA,
                'raw': f'k = "{_AKIA}"',
            }
            for name in self.NAMES
        ]

    def test_json(self, tmp_path):
        text = json_report(self._findings(tmp_path), str(tmp_path))
        assert _command_lines(text) == []
        assert [f['file'] for f in json.loads(text)['findings']] == self.NAMES

    def test_sarif(self, tmp_path):
        text = sarif_report(self._findings(tmp_path), str(tmp_path))
        assert _command_lines(text) == []
        results = json.loads(text)['runs'][0]['results']
        uris = [r['locations'][0]['physicalLocation']['artifactLocation']['uri'] for r in results]
        assert uris == self.NAMES


class TestLogFormatterSanitizes:
    @staticmethod
    def _format(msg, args):
        record = logging.LogRecord('credactor', logging.WARNING, __file__, 1, msg, args, None)
        return record, _BracketFormatter().format(record)

    def test_template_newline_kept_argument_newline_replaced(self):
        _, out = self._format('first\nsecond %s', ('a\nb',))
        assert out == '[WARN] first\nsecond a?b'

    def test_argument_after_a_template_newline_cannot_start_a_command(self):
        _, out = self._format('files:\n%s', ('::error::x',))
        assert _command_lines(out) == []

    def test_marker_split_across_arguments_after_a_template_newline(self):
        # Each argument is harmless alone; together they start a line.
        _, out = self._format('files:\n%s%s', (':', ':error::y'))
        assert _command_lines(out) == []

    def test_command_marker_split_across_template_and_argument(self):
        _, out = self._format('a #%s', ('#[error]x',))
        assert _command_lines(out) == []

    def test_mapping_argument(self):
        _, out = self._format('%(p)s done', ({'p': 'x\x1b[2Jy'},))
        assert out == '[WARN] xy done'

    def test_path_and_exception_arguments(self):
        _, out = self._format('%s: %s', (Path('a\nb'), OSError('bad\rthing')))
        assert '\n' not in out
        assert '\r' not in out

    def test_other_arguments_unchanged(self):
        _, out = self._format('%d file(s), %r', (3, 1.5))
        assert out == '[WARN] 3 file(s), 1.5'

    def test_record_is_not_changed(self):
        record, _ = self._format('%s', ('a\nb',))
        assert record.args == ('a\nb',)
        assert record.getMessage() == 'a\nb'


@pytest.mark.skipif(sys.platform == 'win32', reason='Windows file names cannot hold these')
class TestHostileNamesAndLines:
    """SR-06 acceptance: no path, source line or log argument can put a
    workflow command, an escape sequence or a line break into CI output."""

    NAMES: ClassVar[list[str]] = [
        '\n::error::X',
        'a\rb',
        'c\x1b[31md',
        'e\x9bf',
        'g\u2028h',
        'i\u202ej',
        '##[error]k',
    ]

    def _run(self, argv, capsys):
        with pytest.raises(SystemExit):
            main(argv)
        return capsys.readouterr()

    def _assert_clean(self, captured):
        for name, text in (('stdout', captured.out), ('stderr', captured.err)):
            assert _command_lines(text) == [], name
            for bad in ('\x1b', '\x9b', '\u202e', '\u2028', '\r'):
                assert bad not in text, (name, bad)

    @pytest.mark.parametrize('mode', ['--dry-run', '--ci'])
    def test_file_and_directory_names(self, tmp_path, capsys, mode):
        for i, name in enumerate(self.NAMES):
            (tmp_path / f'{name}{i}.py').write_text(f'aws_key = "{_AKIA}"\n', encoding='utf-8')
            sub = tmp_path / f'd{name}{i}'
            sub.mkdir()
            (sub / 'app.py').write_text(f'aws_key = "{_AKIA}"\n', encoding='utf-8')
        captured = self._run([mode, str(tmp_path)], capsys)
        assert captured.out.count('AKIA[REDACTED]') == 2 * len(self.NAMES)
        self._assert_clean(captured)

    def test_source_lines_holding_commands(self, tmp_path, capsys):
        (tmp_path / 'a.py').write_text(
            f'::error title=x::y key = "{_AKIA}"\n'
            f'  ::warning::z key2 = "{_AKIA}"\n'
            f'k = "{_AKIA}"  # ##[error]fake ##vso[task.setvariable variable=a]b\n',
            encoding='utf-8',
        )
        captured = self._run(['--ci', str(tmp_path)], capsys)
        assert captured.out.count('AKIA[REDACTED]') == 3
        self._assert_clean(captured)

    def test_gitignored_names(self, tmp_path, capsys):
        (tmp_path / '.gitignore').write_text('ignored*\n', encoding='utf-8')
        for i, name in enumerate(['::error::x', '##[error]y', 'z\nw']):
            (tmp_path / f'ignored{name}{i}.txt').write_text('x\n', encoding='utf-8')
        (tmp_path / 'b.py').write_text(f'k = "{_AKIA}"\n', encoding='utf-8')
        captured = self._run(['--ci', str(tmp_path)], capsys)
        assert 'not scanned -- covered by .gitignore' in captured.out
        self._assert_clean(captured)

    def test_target_path_in_the_scanning_line(self, tmp_path, capsys):
        target = tmp_path / '\n::error::t ##[warning]u'
        target.mkdir()
        (target / 'c.py').write_text(f'k = "{_AKIA}"\n', encoding='utf-8')
        self._assert_clean(self._run(['--ci', str(target)], capsys))

    def test_undecodable_bytes_in_a_line_and_a_name(self, tmp_path):
        # A strict UTF-8 stream must accept the report (no crash), and a
        # surrogateescape stream must not receive raw C1 or bidi bytes.
        line = 'k = "' + _AKIA + '"  # \udce2\x1b[m\udc80\udcae x \udcc2\x1b[m\udc9b2J'
        finding = {
            'file': str(tmp_path / 'e\udc9bf.py'),
            'line': 1,
            'type': 'pattern:AWS access key',
            'severity': 'critical',
            'full_value': _AKIA,
            'value_preview': _AKIA,
            'raw': line,
        }
        for errors in ('strict', 'surrogateescape'):
            raw = io.BytesIO()
            stream = io.TextIOWrapper(raw, encoding='utf-8', errors=errors)
            print_report([finding], str(tmp_path), no_color=True, stream=stream)
            stream.flush()
            data = raw.getvalue()
            for bad in (b'\xc2\x9b', b'\xe2\x80\xae', b'\x9b', b'\x80\xae'):
                assert bad not in data, (errors, bad)
            assert b'AKIA[REDACTED]' in data

    @pytest.mark.skipif(not sys.platform.startswith('linux'), reason='needs byte file names')
    def test_undecodable_file_name_on_disk(self, tmp_path, capsys):
        name = os.fsdecode(b'e\x9bf.py')
        (tmp_path / name).write_text(f'k = "{_AKIA}"\n', encoding='utf-8')
        captured = self._run(['--ci', str(tmp_path)], capsys)
        assert 'e?f.py' in captured.out
        for text in (captured.out, captured.err):
            assert not any(0xD800 <= ord(c) <= 0xDFFF for c in text)

    @pytest.mark.skipif(hasattr(os, 'getuid') and os.getuid() == 0, reason='root can traverse')
    def test_untraversable_directory_warning(self, tmp_path, capsys):
        locked = tmp_path / '\n::error::locked ##[error]v'
        locked.mkdir()
        (tmp_path / 'c.py').write_text('x = 1\n', encoding='utf-8')
        locked.chmod(0)
        try:
            captured = self._run(['--ci', str(tmp_path)], capsys)
        finally:
            locked.chmod(0o755)
        assert 'Cannot traverse' in captured.err
        self._assert_clean(captured)

    def test_errored_files_are_listed_one_per_line(self, tmp_path, capsys, monkeypatch):
        from credactor import cli

        paths = [str(tmp_path / 'one\n::error::x'), str(tmp_path / 'two')]
        cli._handle_errored_files(paths, Config())
        err = capsys.readouterr().err
        assert err.count('\n  - ') == 2
        assert _command_lines(err) == []
