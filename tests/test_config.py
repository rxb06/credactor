"""Tests for configuration loading."""

import os

import pytest

from credactor.config import (
    ENTROPY_DEFAULT,
    Config,
    ConfigError,
    apply_config_file,
    load_config_file,
)


class TestConfigPostInit:
    def test_rejects_negative_entropy(self):
        with pytest.raises(ValueError, match='entropy_threshold'):
            Config(entropy_threshold=-1.0)

    def test_rejects_excessive_entropy(self):
        with pytest.raises(ValueError, match='entropy_threshold'):
            Config(entropy_threshold=99.0)

    def test_rejects_zero_min_value_length(self):
        with pytest.raises(ValueError, match='min_value_length'):
            Config(min_value_length=0)

    def test_rejects_bad_replace_mode(self):
        with pytest.raises(ValueError, match='replace_mode'):
            Config(replace_mode='nonsense')

    def test_rejects_bad_output_format(self):
        with pytest.raises(ValueError, match='output_format'):
            Config(output_format='xml')

    def test_validate_replacement_rejects_empty_and_bad_chars(self):
        # S6: data-layer validation of custom_replacement (charset + non-empty),
        # gated on the mode that consumes it (sentinel/custom).
        with pytest.raises(ValueError, match='custom_replacement'):
            Config(replace_mode='custom', custom_replacement='').validate_replacement()
        with pytest.raises(ValueError, match='custom_replacement'):
            Config(replace_mode='custom', custom_replacement='bad;rm').validate_replacement()
        # valid value, and env mode (which derives names), do not raise
        Config(replace_mode='custom', custom_replacement='OK-1_x').validate_replacement()
        Config(replace_mode='env', custom_replacement='ignored;here').validate_replacement()

    def test_toml_replacement_charset_validated(self):
        # S6 (plan step 2.2): a .credactor.toml that sets a dangerous
        # 'replacement' must not smuggle an unsafe string into file writes.
        # apply_config_file applies the raw TOML value to custom_replacement; the
        # shared validate_replacement() (also run at the CLI front door and the
        # redactor sink) rejects it — so the TOML-application path is covered,
        # not only the direct-construction case above.
        cfg = Config(replace_mode='custom')
        apply_config_file(cfg, {'replacement': 'bad;rm -rf'})
        assert cfg.custom_replacement == 'bad;rm -rf'  # raw TOML value applied
        with pytest.raises(ValueError, match='custom_replacement'):
            cfg.validate_replacement()  # ...but rejected on validate

    def test_accepts_valid_extremes(self):
        Config(entropy_threshold=0.0, min_value_length=1)
        Config(entropy_threshold=6.0, min_value_length=200)


class TestConfigDefaults:
    def test_default_values(self):
        c = Config()
        assert c.entropy_threshold == 3.5
        assert c.min_value_length == 8
        assert c.skip_dirs == set()
        assert c.skip_files == set()
        assert c.extra_extensions == set()
        assert c.extra_safe_values == set()
        assert c.ci_mode is False
        assert c.dry_run is False
        assert c.fix_all is False
        assert c.staged_only is False
        assert c.scan_history is False
        assert c.scan_json is False
        assert c.no_backup is False
        assert c.no_color is False
        assert c.fail_on_error is False
        assert c.replace_mode == 'sentinel'
        assert c.custom_replacement == 'REDACTED_BY_CREDACTOR'
        assert c.output_format == 'text'
        assert c.target == '.'

    def test_custom_values(self):
        c = Config(entropy_threshold=4.0, min_value_length=12, ci_mode=True)
        assert c.entropy_threshold == 4.0
        assert c.min_value_length == 12
        assert c.ci_mode is True


class TestLoadConfigFile:
    def test_no_config_file(self, tmp_dir):
        result = load_config_file(tmp_dir)
        assert result == {}

    def test_explicit_path(self, tmp_dir):
        config_path = os.path.join(tmp_dir, '.credactor.toml')
        with open(config_path, 'w') as f:
            f.write('entropy_threshold = 4.0\n')
            f.write('min_value_length = 12\n')
        result = load_config_file(tmp_dir, config_path)
        assert result['entropy_threshold'] == 4.0
        assert result['min_value_length'] == 12

    def test_auto_discovery(self, tmp_dir):
        config_path = os.path.join(tmp_dir, '.credactor.toml')
        with open(config_path, 'w') as f:
            f.write('min_value_length = 10\n')
        result = load_config_file(tmp_dir)
        assert result['min_value_length'] == 10

    def test_parent_dir_discovery(self, tmp_dir):
        # A config at the project root (.git present) is discovered when scanning
        # a subdirectory — the supported monorepo case (M14 keeps this working;
        # only configs ABOVE the project root are refused).
        os.makedirs(os.path.join(tmp_dir, '.git'))
        config_path = os.path.join(tmp_dir, '.credactor.toml')
        with open(config_path, 'w') as f:
            f.write('min_value_length = 15\n')
        child = os.path.join(tmp_dir, 'sub', 'dir')
        os.makedirs(child)
        result = load_config_file(child)
        assert result['min_value_length'] == 15

    def test_parent_dir_discovery_five_levels(self, tmp_dir):
        # The documented contract is the target dir plus up to FIVE parent
        # directories. The walk's first iteration is the target itself, so
        # this needs max_depth + 1 iterations — pins the boundary at 5.
        os.makedirs(os.path.join(tmp_dir, '.git'))
        with open(os.path.join(tmp_dir, '.credactor.toml'), 'w') as f:
            f.write('min_value_length = 15\n')
        child = os.path.join(tmp_dir, 's1', 's2', 's3', 's4', 's5')
        os.makedirs(child)
        result = load_config_file(child)
        assert result['min_value_length'] == 15

    def test_parent_dir_discovery_stops_after_five_levels(self, tmp_dir):
        # Companion boundary: 6 parent levels up is out of reach, so the next
        # off-by-one in either direction fails one of this pair.
        os.makedirs(os.path.join(tmp_dir, '.git'))
        with open(os.path.join(tmp_dir, '.credactor.toml'), 'w') as f:
            f.write('min_value_length = 15\n')
        child = os.path.join(tmp_dir, 's1', 's2', 's3', 's4', 's5', 's6')
        os.makedirs(child)
        assert load_config_file(child) == {}

    def test_explicit_missing_returns_empty(self, tmp_dir):
        result = load_config_file(tmp_dir, '/nonexistent/.credactor.toml')
        assert result == {}

    def test_explicit_invalid_toml_raises(self, tmp_dir):
        # An explicitly named config that exists but won't parse must signal
        # the caller (which exits 2) rather than silently degrade to defaults.
        cfg = os.path.join(tmp_dir, 'bad.toml')
        with open(cfg, 'w') as f:
            f.write('min_value_length = = 9\n')
        with pytest.raises(ConfigError):
            load_config_file(tmp_dir, explicit_path=cfg)

    def test_implicit_invalid_toml_warns_and_skips(self, tmp_dir, credactor_caplog):
        # Scoped to --config only: a malformed config found by DISCOVERY must
        # not abort the scan — a stray broken .credactor.toml shouldn't take a
        # repo down. It warns and falls back to defaults (no raise).
        with open(os.path.join(tmp_dir, '.credactor.toml'), 'w') as f:
            f.write('min_value_length = = 9\n')
        result = load_config_file(tmp_dir)  # implicit discovery
        assert result == {}
        assert 'invalid toml' in credactor_caplog.text.lower()

    def test_load_config_ingest_section(self, tmp_dir):
        config_path = os.path.join(tmp_dir, '.credactor.toml')
        with open(config_path, 'w') as f:
            f.write('[ingest]\n')
            f.write('from_gitleaks = "/tmp/r.json"\n')
        file_data = load_config_file(tmp_dir)
        c = Config()
        apply_config_file(c, file_data)
        assert c.from_gitleaks == '/tmp/r.json'


class TestApplyConfigFile:
    def test_apply_threshold(self):
        c = Config()
        apply_config_file(c, {'entropy_threshold': 4.2})
        assert c.entropy_threshold == 4.2

    def test_apply_min_value_length(self):
        c = Config()
        apply_config_file(c, {'min_value_length': 16})
        assert c.min_value_length == 16

    def test_apply_entropy_invalid_type_uses_default(self, credactor_caplog):
        c = Config()
        apply_config_file(c, {'entropy_threshold': 'not-a-number'})
        assert c.entropy_threshold == 3.5
        assert any(
            'entropy_threshold' in r.message and 'invalid type' in r.message
            for r in credactor_caplog.records
        )

    def test_apply_entropy_out_of_range_uses_default(self, credactor_caplog):
        c = Config()
        apply_config_file(c, {'entropy_threshold': 99.0})
        assert c.entropy_threshold == 3.5
        assert any(
            'entropy_threshold' in r.message and 'out of valid range' in r.message
            for r in credactor_caplog.records
        )

    def test_apply_min_value_length_invalid_type_uses_default(self, credactor_caplog):
        c = Config()
        apply_config_file(c, {'min_value_length': 'not-a-number'})
        assert c.min_value_length == 8
        assert any(
            'min_value_length' in r.message and 'invalid type' in r.message
            for r in credactor_caplog.records
        )

    def test_apply_min_value_length_out_of_range_uses_default(self, credactor_caplog):
        c = Config()
        apply_config_file(c, {'min_value_length': 9999})
        assert c.min_value_length == 8
        assert any(
            'min_value_length' in r.message and 'out of valid range' in r.message
            for r in credactor_caplog.records
        )

    def test_apply_skip_dirs(self):
        c = Config()
        apply_config_file(c, {'skip_dirs': ['vendor', '.terraform']})
        assert 'vendor' in c.skip_dirs
        assert '.terraform' in c.skip_dirs

    def test_apply_skip_files(self):
        c = Config()
        apply_config_file(c, {'skip_files': ['generated.py']})
        assert 'generated.py' in c.skip_files

    def test_apply_extra_extensions(self):
        c = Config()
        apply_config_file(c, {'extra_extensions': ['.env.encrypted']})
        assert '.env.encrypted' in c.extra_extensions

    def test_apply_extra_safe_values(self):
        c = Config()
        apply_config_file(c, {'extra_safe_values': ['TestToken123']})
        assert 'testtoken123' in c.extra_safe_values

    # M8: a non-string element is skipped instead of crashing on .lower()
    def test_extra_safe_values_non_string_element_skipped(self, credactor_caplog):
        c = Config()
        apply_config_file(c, {'extra_safe_values': [123, 'OK']})
        assert c.extra_safe_values == {'ok'}
        assert any(
            'extra_safe_values' in r.message and 'not a string' in r.message
            for r in credactor_caplog.records
        )

    # M9: a bare string is rejected whole, not char-split into single letters
    def test_list_key_given_string_is_rejected(self, credactor_caplog):
        c = Config()
        apply_config_file(c, {'skip_dirs': 'vendor'})
        assert c.skip_dirs == set()
        assert any(
            'skip_dirs' in r.message and 'list of strings' in r.message
            for r in credactor_caplog.records
        )

    # M9: a non-iterable scalar is rejected instead of raising TypeError
    def test_list_key_given_scalar_is_rejected(self, credactor_caplog):
        c = Config()
        apply_config_file(c, {'skip_dirs': 5})
        assert c.skip_dirs == set()
        assert any('skip_dirs' in r.message for r in credactor_caplog.records)

    # M9 parity: a valid list still merges and keeps case (must NOT be lowercased)
    def test_skip_dirs_case_preserved(self):
        c = Config()
        apply_config_file(c, {'skip_dirs': ['VendorDir']})
        assert 'VendorDir' in c.skip_dirs

    # M15: extra_extensions entries are lowercased to match the lowercased suffix
    def test_extra_extensions_lowercased(self):
        from credactor.scanner import should_scan_file

        c = Config()
        apply_config_file(c, {'extra_extensions': ['.TXT']})
        assert should_scan_file('foo.txt', c.extra_extensions)

    # M15 (leading dot): an un-dotted entry warns — it only matches files named
    # exactly that, never files carrying that extension.
    def test_extra_extensions_no_leading_dot_warns(self, credactor_caplog):
        c = Config()
        apply_config_file(c, {'extra_extensions': ['txt']})
        assert any(
            'extra_extensions' in r.message and 'leading dot' in r.message
            for r in credactor_caplog.records
        )

    def test_extra_extensions_dotted_does_not_warn(self, credactor_caplog):
        c = Config()
        apply_config_file(c, {'extra_extensions': ['.txt']})
        assert not any('leading dot' in r.message for r in credactor_caplog.records)

    # M15 (leading dot): the un-dotted name-match is preserved, NOT auto-prepended
    # — `dockerfile` still matches a file named Dockerfile but not *.dockerfile.
    def test_extra_extensions_name_match_preserved(self):
        from credactor.scanner import should_scan_file

        c = Config()
        apply_config_file(c, {'extra_extensions': ['dockerfile']})
        assert should_scan_file('Dockerfile', c.extra_extensions)
        assert not should_scan_file('foo.dockerfile', c.extra_extensions)

    def test_apply_replacement(self):
        c = Config()
        apply_config_file(c, {'replacement': 'REMOVED'})
        assert c.custom_replacement == 'REMOVED'

    def test_unknown_keys_ignored(self):
        c = Config()
        apply_config_file(c, {'unknown_key': 'value'})
        assert not hasattr(c, 'unknown_key')

    def test_unknown_keys_warn(self, credactor_caplog):
        # A typo'd key must not be dropped silently — every malformed KNOWN key
        # already warns, and a typo can mean scanning at the wrong sensitivity.
        c = Config()
        apply_config_file(c, {'entropy_treshold': 3.0})
        assert c.entropy_threshold == ENTROPY_DEFAULT  # typo did not take effect
        assert any('entropy_treshold' in r.message for r in credactor_caplog.records)

    def test_known_keys_do_not_warn_as_unknown(self, credactor_caplog):
        # All eight consumed keys at once — a key dropped from _KNOWN_KEYS (or
        # a future consumed key not added to it) would warn spuriously here.
        c = Config()
        apply_config_file(
            c,
            {
                'entropy_threshold': 4.0,
                'min_value_length': 10,
                'skip_dirs': ['vendor'],
                'skip_files': ['generated.py'],
                'extra_extensions': ['.dockerfile'],
                'extra_safe_values': ['sample'],
                'replacement': 'GONE',
                'ingest': {'from_gitleaks': 'r.json'},
            },
        )
        assert not any('Unknown config key' in r.message for r in credactor_caplog.records)

    def test_merges_with_existing(self):
        c = Config(skip_dirs={'existing'})
        apply_config_file(c, {'skip_dirs': ['new_dir']})
        assert 'existing' in c.skip_dirs
        assert 'new_dir' in c.skip_dirs

    def test_apply_ingest_from_gitleaks(self):
        c = Config()
        apply_config_file(c, {'ingest': {'from_gitleaks': '/tmp/r.json'}})
        assert c.from_gitleaks == '/tmp/r.json'

    def test_apply_ingest_from_trufflehog(self):
        c = Config()
        apply_config_file(c, {'ingest': {'from_trufflehog': '/tmp/r.jsonl'}})
        assert c.from_trufflehog == '/tmp/r.jsonl'

    def test_apply_ingest_both_keys(self):
        c = Config()
        apply_config_file(
            c, {'ingest': {'from_gitleaks': '/tmp/g.json', 'from_trufflehog': '/tmp/t.jsonl'}}
        )
        assert c.from_gitleaks == '/tmp/g.json'
        assert c.from_trufflehog == '/tmp/t.jsonl'

    def test_apply_ingest_non_string_warns(self, capsys):
        c = Config()
        apply_config_file(c, {'ingest': {'from_gitleaks': 42}})
        assert c.from_gitleaks is None
        captured = capsys.readouterr()
        assert '[WARN]' in captured.err

    def test_apply_ingest_non_dict_warns(self, capsys):
        c = Config()
        apply_config_file(c, {'ingest': 'not-a-table'})
        assert c.from_gitleaks is None
        assert c.from_trufflehog is None
        captured = capsys.readouterr()
        assert '[WARN]' in captured.err

    def test_apply_ingest_empty_section(self):
        c = Config()
        apply_config_file(c, {'ingest': {}})
        assert c.from_gitleaks is None
        assert c.from_trufflehog is None

    def test_unknown_ingest_keys_warn(self, credactor_caplog):
        # Same typo guard as the top-level keys: a misspelled from_gitleaks
        # means ingestion silently never runs.
        c = Config()
        apply_config_file(c, {'ingest': {'from_gitleeks': 'r.json'}})
        assert any('ingest.from_gitleeks' in r.message for r in credactor_caplog.records)

    def test_apply_unknown_ingest_keys_ignored(self):
        c = Config()
        apply_config_file(c, {'ingest': {'unknown_key': 'x'}})
        assert not hasattr(c, 'unknown_key')


class TestReplacementValidation:
    def test_non_string_replacement_ignored_with_warning(self, credactor_caplog):
        # P8/#21: a non-str replacement now warns-and-ignores (keeps the default)
        # instead of being coerced to its repr — matching the ingest-key discipline.
        c = Config()
        apply_config_file(c, {'replacement': 123})
        assert c.custom_replacement == 'REDACTED_BY_CREDACTOR'
        assert any('replacement must be a string' in r.message for r in credactor_caplog.records)

    def test_string_replacement_applied(self):
        c = Config()
        apply_config_file(c, {'replacement': 'SCRUBBED'})
        assert c.custom_replacement == 'SCRUBBED'


def test_threshold_defaults_single_sourced():
    # P8/#4: the field defaults and the _SCALAR_VALIDATORS defaults must come from
    # the same constants (no triplication drift). scanner.py has no aliases of
    # its own any more — its no-Config fallbacks use these constants directly.
    from credactor.config import (
        _SCALAR_VALIDATORS,
        ENTROPY_DEFAULT,
        MIN_LEN_DEFAULT,
    )

    defaults = {key: default for key, _coerce, _bounds, default in _SCALAR_VALIDATORS}
    assert Config().entropy_threshold == ENTROPY_DEFAULT == defaults['entropy_threshold']
    assert Config().min_value_length == MIN_LEN_DEFAULT == defaults['min_value_length']
