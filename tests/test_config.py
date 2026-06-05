"""Tests for configuration loading."""

import os

import pytest

from credactor.config import Config, apply_config_file, load_config_file


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
        config_path = os.path.join(tmp_dir, '.credactor.toml')
        with open(config_path, 'w') as f:
            f.write('min_value_length = 15\n')
        child = os.path.join(tmp_dir, 'sub', 'dir')
        os.makedirs(child)
        result = load_config_file(child)
        assert result['min_value_length'] == 15

    def test_explicit_missing_returns_empty(self, tmp_dir):
        result = load_config_file(tmp_dir, '/nonexistent/.credactor.toml')
        assert result == {}

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
        assert any('entropy_threshold' in r.message and 'invalid type' in r.message
                   for r in credactor_caplog.records)

    def test_apply_entropy_out_of_range_uses_default(self, credactor_caplog):
        c = Config()
        apply_config_file(c, {'entropy_threshold': 99.0})
        assert c.entropy_threshold == 3.5
        assert any('entropy_threshold' in r.message and 'out of valid range' in r.message
                   for r in credactor_caplog.records)

    def test_apply_min_value_length_invalid_type_uses_default(self, credactor_caplog):
        c = Config()
        apply_config_file(c, {'min_value_length': 'not-a-number'})
        assert c.min_value_length == 8
        assert any('min_value_length' in r.message and 'invalid type' in r.message
                   for r in credactor_caplog.records)

    def test_apply_min_value_length_out_of_range_uses_default(self, credactor_caplog):
        c = Config()
        apply_config_file(c, {'min_value_length': 9999})
        assert c.min_value_length == 8
        assert any('min_value_length' in r.message and 'out of valid range' in r.message
                   for r in credactor_caplog.records)

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

    def test_apply_replacement(self):
        c = Config()
        apply_config_file(c, {'replacement': 'REMOVED'})
        assert c.custom_replacement == 'REMOVED'

    def test_unknown_keys_ignored(self):
        c = Config()
        apply_config_file(c, {'unknown_key': 'value'})
        assert not hasattr(c, 'unknown_key')

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

    def test_apply_unknown_ingest_keys_ignored(self):
        c = Config()
        apply_config_file(c, {'ingest': {'unknown_key': 'x'}})
        assert not hasattr(c, 'unknown_key')
