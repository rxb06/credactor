"""Tests for suppression mechanisms."""

import os

from credactor.suppressions import AllowList, has_inline_suppression


class TestInlineSuppression:
    def test_hash_comment(self):
        assert has_inline_suppression('api_key = "secret"  # credactor:ignore')

    def test_slash_comment(self):
        assert has_inline_suppression('const key = "secret"; // credactor:ignore')

    def test_case_insensitive(self):
        assert has_inline_suppression('key = "val"  # CREDACTOR:IGNORE')

    def test_no_suppression(self):
        assert not has_inline_suppression('api_key = "secret"  # important')

    # --- H8: directive must follow a comment opener (not a bare substring) ---
    def test_block_comment(self):
        assert has_inline_suppression('value = "x"  /* credactor:ignore */')

    def test_xml_comment(self):
        assert has_inline_suppression('<add value="x" />  <!-- credactor:ignore -->')

    def test_prose_mention_does_not_suppress(self):
        """A prose mention of the directive in a comment must NOT suppress."""
        assert not has_inline_suppression(
            'aws = "secret"  # TODO: stop using credactor:ignore everywhere')

    def test_string_mention_does_not_suppress(self):
        """The directive inside a string value (not a comment) must NOT suppress."""
        assert not has_inline_suppression('doc = "see credactor:ignore for details"')

    def test_prose_mention_does_not_silence_real_secret(self):
        """End-to-end: a real AWS key on a line whose comment only mentions the
        directive in prose is still reported (was silenced before H8)."""
        from credactor.scanner import scan_line
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        line = f'aws = "{key}"  # TODO: drop credactor:ignore usage'
        assert len(scan_line(1, line, 't.py')) == 1


class TestAllowList:
    def test_file_glob_suppression(self, tmp_dir):
        # Create .credactorignore
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('test_fixtures/*.py\n')

        al = AllowList(tmp_dir)

        # Create the file
        fixture_dir = os.path.join(tmp_dir, 'test_fixtures')
        os.makedirs(fixture_dir, exist_ok=True)
        fixture_file = os.path.join(fixture_dir, 'secrets.py')
        with open(fixture_file, 'w') as f:
            f.write('api_key = "secret"\n')

        assert al.is_file_suppressed(fixture_file)

    def test_file_line_suppression(self, tmp_dir):
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('config.py:42\n')

        al = AllowList(tmp_dir)
        config_file = os.path.join(tmp_dir, 'config.py')
        assert al.is_line_suppressed(config_file, 42)
        assert not al.is_line_suppressed(config_file, 43)

    def test_value_literal_suppression(self, tmp_dir):
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('test_fixture_value_abc123\n')

        al = AllowList(tmp_dir)
        assert al.is_value_suppressed('test_fixture_value_abc123')
        assert not al.is_value_suppressed('real_secret')

    # --- H9: value-literal suppressions must be visible (globs get no such
    # general warning, so this is the parity fix the report asks for) ---
    def test_value_literal_emits_load_warning(self, tmp_dir, credactor_caplog):
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('test_fixture_value_abc123\n')
        AllowList(tmp_dir)
        assert any('value-literal' in r.message for r in credactor_caplog.records)

    def test_globs_and_file_lines_emit_no_value_literal_warning(self, tmp_dir,
                                                                 credactor_caplog):
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('test_fixtures/*.py\nsrc/config.py:10\n')
        AllowList(tmp_dir)
        assert not any('value-literal' in r.message for r in credactor_caplog.records)

    def test_no_ignore_file(self, tmp_dir):
        al = AllowList(tmp_dir)
        fake_file = os.path.join(tmp_dir, 'anything.py')
        assert not al.is_file_suppressed(fake_file)
        assert not al.is_line_suppressed(fake_file, 1)
        assert not al.is_value_suppressed('anything')

    def test_combined_check(self, tmp_dir):
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('src/config.py:10\n')

        al = AllowList(tmp_dir)
        config_file = os.path.join(tmp_dir, 'src', 'config.py')
        assert al.is_suppressed(config_file, 10, 'any_value')
        assert not al.is_suppressed(config_file, 11, 'any_value')
