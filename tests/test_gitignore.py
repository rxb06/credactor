"""Tests for .gitignore pattern loading and matching."""

import os
from pathlib import Path

from credactor.gitignore import matches_gitignore, parse_gitignore_file


class TestParseGitignoreFile:
    """Pattern loading for a single .gitignore (the production path collects
    these during walk_and_scan's own walk; the old standalone tree-walking
    loader was test-only and is gone)."""

    def _parse(self, tmp_dir):
        return parse_gitignore_file(os.path.join(tmp_dir, '.gitignore'), Path(tmp_dir).resolve())

    def test_missing_file_returns_empty(self, tmp_dir):
        assert self._parse(tmp_dir) == []

    def test_loads_patterns(self, tmp_dir):
        with open(os.path.join(tmp_dir, '.gitignore'), 'w') as f:
            f.write('*.pyc\n__pycache__/\n')
        patterns = self._parse(tmp_dir)
        assert len(patterns) == 2
        assert patterns[0][0] == '*.pyc'
        assert patterns[1][0] == '__pycache__/'

    def test_skips_comments(self, tmp_dir):
        with open(os.path.join(tmp_dir, '.gitignore'), 'w') as f:
            f.write('# This is a comment\n*.pyc\n')
        patterns = self._parse(tmp_dir)
        assert len(patterns) == 1
        assert patterns[0][0] == '*.pyc'

    def test_skips_empty_lines(self, tmp_dir):
        with open(os.path.join(tmp_dir, '.gitignore'), 'w') as f:
            f.write('\n*.pyc\n\n*.log\n\n')
        assert len(self._parse(tmp_dir)) == 2

    def test_skips_negation_patterns(self, tmp_dir):
        with open(os.path.join(tmp_dir, '.gitignore'), 'w') as f:
            f.write('*.pyc\n!important.pyc\n')
        patterns = self._parse(tmp_dir)
        assert len(patterns) == 1
        assert patterns[0][0] == '*.pyc'

    def test_nested_gitignore_collected_by_walk(self, tmp_dir):
        # The production path inlines collection into walk_and_scan; a pattern
        # from a NESTED .gitignore must suppress files in its subtree.
        from credactor.config import Config
        from credactor.walker import walk_and_scan

        sub = os.path.join(tmp_dir, 'sub')
        os.makedirs(sub)
        with open(os.path.join(sub, '.gitignore'), 'w') as f:
            f.write('*.env\n')
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(os.path.join(sub, 'prod.env'), 'w') as f:
            f.write(f'AWS_KEY="{key}"\n')
        findings, skipped, _json, _err = walk_and_scan(tmp_dir, config=Config(no_color=True))
        assert findings == []
        assert any(s.endswith('prod.env') for s in skipped)

    def test_root_gitignore_suppresses_subdir_files(self, tmp_dir):
        # The most common layout: a single ROOT .gitignore whose pattern must
        # suppress matching files anywhere in the tree via the same walk.
        from credactor.config import Config
        from credactor.walker import walk_and_scan

        with open(os.path.join(tmp_dir, '.gitignore'), 'w') as f:
            f.write('*.env\n')
        sub = os.path.join(tmp_dir, 'deploy')
        os.makedirs(sub)
        # credactor:ignore
        key = 'AKIA' + 'IOSFODNN7EXAMPLE'
        with open(os.path.join(sub, 'prod.env'), 'w') as f:
            f.write(f'AWS_KEY="{key}"\n')
        findings, skipped, _json, _err = walk_and_scan(tmp_dir, config=Config(no_color=True))
        assert findings == []
        assert any(s.endswith('prod.env') for s in skipped)


class TestMatchesGitignore:
    def test_simple_extension_match(self, tmp_dir):
        patterns = [('*.pyc', tmp_dir)]
        filepath = os.path.join(tmp_dir, 'module.pyc')
        assert matches_gitignore(filepath, patterns)

    def test_no_match(self, tmp_dir):
        patterns = [('*.pyc', tmp_dir)]
        filepath = os.path.join(tmp_dir, 'module.py')
        assert not matches_gitignore(filepath, patterns)

    def test_directory_pattern(self, tmp_dir):
        patterns = [('__pycache__/', tmp_dir)]
        filepath = os.path.join(tmp_dir, '__pycache__', 'module.pyc')
        assert matches_gitignore(filepath, patterns)

    def test_directory_pattern_no_match_file(self, tmp_dir):
        patterns = [('logs/', tmp_dir)]
        filepath = os.path.join(tmp_dir, 'logs.txt')
        assert not matches_gitignore(filepath, patterns)

    def test_anchored_pattern(self, tmp_dir):
        patterns = [('src/config.py', tmp_dir)]
        filepath = os.path.join(tmp_dir, 'src', 'config.py')
        assert matches_gitignore(filepath, patterns)

    def test_anchored_no_match_wrong_dir(self, tmp_dir):
        patterns = [('src/config.py', tmp_dir)]
        filepath = os.path.join(tmp_dir, 'lib', 'config.py')
        assert not matches_gitignore(filepath, patterns)

    def test_wildcard_in_dir(self, tmp_dir):
        patterns = [('*.log', tmp_dir)]
        filepath = os.path.join(tmp_dir, 'sub', 'app.log')
        assert matches_gitignore(filepath, patterns)

    def test_outside_base_dir_no_match(self, tmp_dir):
        sub_dir = os.path.join(tmp_dir, 'project')
        os.makedirs(sub_dir)
        patterns = [('*.pyc', sub_dir)]
        filepath = os.path.join(tmp_dir, 'outside.pyc')
        assert not matches_gitignore(filepath, patterns)

    def test_double_star_pattern(self, tmp_dir):
        patterns = [('**/test_*.py', tmp_dir)]
        filepath = os.path.join(tmp_dir, 'deep', 'nested', 'test_foo.py')
        assert matches_gitignore(filepath, patterns)

    def test_empty_patterns(self, tmp_dir):
        filepath = os.path.join(tmp_dir, 'anything.py')
        assert not matches_gitignore(filepath, [])
