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

    def test_same_line_xml_suppression_end_to_end(self):
        """L7: a same-line `<!-- credactor:ignore -->` suppresses the XML secret
        (the docs now show the directive on the same line, which works)."""
        from credactor.config import Config
        from credactor.scanner import scan_line
        val = 'Xy9KmL2vQ7nR5tW8pA3bC6dE'   # high-entropy XML value
        line = f'<add key="Password" value="{val}" />  <!-- credactor:ignore -->'
        assert scan_line(1, line, 'web.config', config=Config()) == []


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

    # --- #14: a read error mid-load must be surfaced, not swallowed ---
    def test_load_logs_warning_on_read_error(self, tmp_dir, monkeypatch,
                                             credactor_caplog):
        import pathlib
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('somevalue\n')
        real_open = pathlib.Path.open

        def boom(self, *args, **kwargs):
            if self.name == '.credactorignore':
                raise OSError('disk error')
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(pathlib.Path, 'open', boom)
        AllowList(tmp_dir)  # must not raise
        assert any('could not be fully read' in r.message
                   for r in credactor_caplog.records)

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

    # --- M12: explicit `value:` prefix allowlists a value with . / + chars ---
    def test_value_prefix_suppresses_special_char_value(self, tmp_dir):
        # base64/JWT-shaped secret: contains / + . and = — un-allowlistable before
        secret = 'aB3/xY9+zQ' + '==.eyJhbGciOiJI'
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write(f'value:{secret}\n')
        al = AllowList(tmp_dir)
        assert al.is_value_suppressed(secret)

    def test_special_char_value_without_prefix_not_value_suppressed(self, tmp_dir):
        # locks the M12 gap: without the prefix the value routes to glob/path
        # matching and is never value-suppressed
        secret = 'aB3/xY9+zQ' + '==.foo'
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write(f'{secret}\n')
        al = AllowList(tmp_dir)
        assert not al.is_value_suppressed(secret)

    def test_value_prefix_does_not_break_path_suppression(self, tmp_dir):
        # a normal path entry is unaffected by the new prefix routing
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('src/config.py\n')
        al = AllowList(tmp_dir)
        cfg = os.path.join(tmp_dir, 'src', 'config.py')
        assert al.is_file_suppressed(cfg)

    def test_value_prefix_beats_file_line_routing(self, tmp_dir):
        # `value:dbhost:5432` is the VALUE literal 'dbhost:5432', NOT a file:line
        # entry — the value: prefix is handled before the file:line/char routing
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('value:dbhost:5432\n')
        al = AllowList(tmp_dir)
        assert al.is_value_suppressed('dbhost:5432')
        assert not al.is_line_suppressed(os.path.join(tmp_dir, 'dbhost'), 5432)

    # --- M13: file:line entries emit a positional line-drift load warning ---
    def test_file_line_emits_drift_warning(self, tmp_dir, credactor_caplog):
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('src/config.py:10\n')
        AllowList(tmp_dir)
        assert any('file:line' in r.message and 'line number only' in r.message
                   for r in credactor_caplog.records)

    # --- L6b: catch-all glob patterns warn (fnmatch has no globstar) ---
    def test_broad_glob_patterns_warn(self, tmp_dir, credactor_caplog):
        for pat in ('*/*', '**/*.*', '*/*/*'):
            credactor_caplog.clear()
            ignore_path = os.path.join(tmp_dir, '.credactorignore')
            with open(ignore_path, 'w') as f:
                f.write(pat + '\n')
            AllowList(tmp_dir)
            assert any('overly broad' in r.message
                       for r in credactor_caplog.records), pat

    def test_narrow_glob_does_not_warn_broad(self, tmp_dir, credactor_caplog):
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('tests/fixtures/*.py\n')
        AllowList(tmp_dir)
        assert not any('overly broad' in r.message for r in credactor_caplog.records)

    # --- L11: suppression_reason discriminates the matched kind ---
    def test_suppression_reason_discriminates(self, tmp_dir):
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('globbed/*.py\n')
            f.write('src/exact.py:7\n')
            f.write('value:my_secret_literal\n')
        al = AllowList(tmp_dir)
        glob_file = os.path.join(tmp_dir, 'globbed', 'a.py')
        line_file = os.path.join(tmp_dir, 'src', 'exact.py')
        assert al.suppression_reason(glob_file, 1, 'x') == 'glob'
        assert al.suppression_reason(line_file, 7, 'x') == 'file:line'
        assert al.suppression_reason(line_file, 8, 'my_secret_literal') == 'value-literal'
        assert al.suppression_reason(line_file, 8, 'other') is None
        # is_suppressed stays consistent with suppression_reason
        assert al.is_suppressed(glob_file, 1, 'x') is True
        assert al.is_suppressed(line_file, 8, 'other') is False

    def test_verbose_audit_names_suppression_kind(self, tmp_dir, credactor_caplog):
        from credactor.config import Config
        from credactor.scanner import scan_line
        ignore_path = os.path.join(tmp_dir, '.credactorignore')
        with open(ignore_path, 'w') as f:
            f.write('value:AKIAIOSFODNN7EXAMPLE\n')
        al = AllowList(tmp_dir)
        scan_line(1, 'key = "AKIA' + 'IOSFODNN7EXAMPLE"',
                  os.path.join(tmp_dir, 'app.py'), config=Config(), allowlist=al)
        assert any('allowlist (value-literal)' in r.message
                   for r in credactor_caplog.records)
