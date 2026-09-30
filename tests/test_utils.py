"""Tests for the shared utility helpers consolidated in Phase 1."""

from pathlib import Path

import pytest

from credactor.utils import group_by_file, in_git_dir, preview, relativize


class TestInGitDir:
    """SR-16: a .git component is found whatever its case, and with the
    trailing dots and spaces Windows drops when it opens the path."""

    @pytest.mark.parametrize(
        'path',
        ['.git/config', '.GIT/config', '.git./config', '.git /config', '.git. ./x', 'a/.Git/b'],
    )
    def test_git_component(self, tmp_path, path):
        assert in_git_dir(str(tmp_path / path), str(tmp_path))

    @pytest.mark.parametrize(
        'path', ['.gitignore', '.github/workflows/ci.yml', 'git/config', 'a.git/b']
    )
    def test_not_git(self, tmp_path, path):
        assert not in_git_dir(str(tmp_path / path), str(tmp_path))


class TestPreview:
    def test_short_value_unchanged(self):
        assert preview('short') == 'short'

    def test_exactly_n_chars_unchanged(self):
        assert preview('a' * 60) == 'a' * 60

    def test_long_value_gets_ellipsis(self):
        # The Phase-1 unification: ingest previews of >60-char values now match
        # the native scanner and gain the ellipsis.
        assert preview('a' * 61) == 'a' * 60 + '...'


class TestRelativize:
    def test_inside_root(self):
        assert relativize('/tmp/repo/src/a.py', Path('/tmp/repo')) == str(Path('src/a.py'))

    def test_outside_root_returns_original(self):
        assert relativize('/etc/passwd', Path('/tmp/repo')) == '/etc/passwd'


class TestGroupByFile:
    def test_groups_and_preserves_insertion_order(self):
        findings = [
            {'file': 'a', 'line': 1},
            {'file': 'b', 'line': 1},
            {'file': 'a', 'line': 2},
        ]
        grouped = group_by_file(findings)
        assert list(grouped.keys()) == ['a', 'b']
        assert [x['line'] for x in grouped['a']] == [1, 2]
