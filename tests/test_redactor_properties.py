"""Write-path property/fuzz harness (Phase 0.2).

Asserts the invariants the redactor must hold across replacement modes and
languages: the secret is removed, the .bak round-trips, nothing outside the
replaced span changes, no temp file leaks, permissions are preserved, redaction
is idempotent, and multiple secrets are all removed.

Invariant #2 (env-mode output is syntactically valid — the replacement is not
wrapped in the original quotes) was finding **H2**, now fixed; the test is a
live regression gate.

Secrets are constructed at runtime (no literals) so this module stays clean
under credactor's own self-scan.
"""
from __future__ import annotations

import os
import random
import string
import sys

import pytest

from credactor.config import Config
from credactor.redactor import batch_replace_in_file
from credactor.scanner import scan_file

_r = random.Random(424242)


def _secret() -> str:
    """A high-entropy GitHub-token-shaped value (deterministically detected)."""
    return 'ghp_' + ''.join(_r.choice(string.ascii_letters + string.digits) for _ in range(36))


def _redact(tmp_path, name: str, content: str, *, mode: str = 'sentinel',
            custom: str = 'REDACTED_BY_CREDACTOR'):
    p = tmp_path / name
    # newline='': write the content bytes EXACTLY as given. Text mode would
    # translate \n -> \r\n on Windows, and the byte-level invariants here
    # (no_collateral_edits) would then fail against the LF expectations even
    # though the redactor correctly preserved the file's own endings.
    p.write_text(content, encoding='utf-8', newline='')
    cfg = Config(replace_mode=mode, custom_replacement=custom, no_color=True)
    findings = scan_file(str(p), config=cfg)
    replaced, failed = batch_replace_in_file(str(p), findings, cfg)
    bak = tmp_path / (name + '.bak')
    return p, findings, replaced, failed, bak


# language -> a single-line assignment template with one quoted secret
_LANGS = {
    'app.py':   'api_key = "{s}"\n',
    'app.js':   'const apiKey = "{s}";\n',
    'app.go':   'var apiKey = "{s}"\n',
    'App.java': 'String apiKey = "{s}";\n',
    'app.rb':   'api_key = "{s}"\n',
    'app.php':  '$api_key = "{s}";\n',
    'app.sh':   'API_KEY="{s}"\n',
    'app.yaml': 'api_key: "{s}"\n',
}


@pytest.mark.parametrize('name,tmpl', list(_LANGS.items()))
@pytest.mark.parametrize('mode', ['sentinel', 'custom', 'env'])
def test_secret_removed(tmp_path, name, tmpl, mode):
    """#1 — after redaction the secret value no longer appears in the file."""
    s = _secret()
    p, findings, replaced, failed, bak = _redact(tmp_path, name, tmpl.format(s=s), mode=mode)
    assert replaced >= 1, f'nothing redacted in {name} ({mode}); findings={len(findings)}'
    assert s not in p.read_text(encoding='utf-8')


@pytest.mark.parametrize('name,tmpl', list(_LANGS.items()))
def test_bak_roundtrips(tmp_path, name, tmpl):
    """#4 — the .bak is a byte-identical copy of the original."""
    s = _secret()
    original = tmpl.format(s=s)
    p, *_rest, bak = _redact(tmp_path, name, original)
    assert bak.is_file()
    assert bak.read_text(encoding='utf-8') == original


@pytest.mark.parametrize('name,tmpl', list(_LANGS.items()))
def test_no_temp_leak(tmp_path, name, tmpl):
    """#5a — no .credactor.tmp file is left behind."""
    _redact(tmp_path, name, tmpl.format(s=_secret()))
    leaks = [f for f in os.listdir(tmp_path) if f.endswith('.credactor.tmp')]
    assert leaks == []


@pytest.mark.skipif(sys.platform == 'win32',
                    reason='POSIX permission bits are not honoured on Windows')
def test_permissions_preserved(tmp_path):
    """#5b — original file mode is restored after redaction."""
    p = tmp_path / 'perm.py'
    p.write_text(f'api_key = "{_secret()}"\n', encoding='utf-8')
    os.chmod(p, 0o600)
    cfg = Config(no_color=True)
    findings = scan_file(str(p), config=cfg)
    batch_replace_in_file(str(p), findings, cfg)
    assert (os.stat(p).st_mode & 0o777) == 0o600


def test_no_collateral_edits(tmp_path):
    """#3 — bytes outside the secret line are unchanged.

    Asserts on raw bytes (not .splitlines()) so it can catch line-ending
    changes too — .splitlines() treats \\n and \\r\\n alike and is blind to them.
    """
    s = _secret()
    content = f'# header comment\nbefore = 1\napi_key = "{s}"\nafter = 2\n'
    p, *_rest = _redact(tmp_path, 'app.py', content)
    raw = p.read_bytes()
    assert b'# header comment\nbefore = 1\n' in raw
    assert b'\nafter = 2\n' in raw
    assert s.encode() not in raw


def test_preserves_crlf_line_endings(tmp_path):
    """CRLF files must keep CRLF — redaction must not normalize line endings."""
    s = _secret()
    content = f'# header\r\nbefore = 1\r\napi_key = "{s}"\r\nafter = 2\r\n'
    p = tmp_path / 'app.py'
    p.write_text(content, encoding='utf-8', newline='')  # write CRLF verbatim
    cfg = Config(no_color=True)
    batch_replace_in_file(str(p), scan_file(str(p), config=cfg), cfg)
    raw = p.read_bytes()
    assert b'# header\r\nbefore = 1\r\n' in raw   # CRLF preserved on untouched lines
    assert b'\r\nafter = 2\r\n' in raw
    assert raw.count(b'\n') == raw.count(b'\r\n')  # every LF is part of a CRLF (not normalized)
    assert s.encode() not in raw


def test_idempotent(tmp_path):
    """#6 — a second scan after redaction finds nothing to replace."""
    p, *_rest = _redact(tmp_path, 'app.py', f'api_key = "{_secret()}"\n')
    again = scan_file(str(p), config=Config(no_color=True))
    assert again == []


def test_multiplicity(tmp_path):
    """#7 — many secrets, including two on one line, are all removed."""
    s1, s2, s3, s4 = _secret(), _secret(), _secret(), _secret()
    content = (
        f'a = "{s1}"\n'
        f'b = "{s2}"\n'
        f'c = "{s3}"; d = "{s4}"\n'  # two on one line
    )
    p, findings, replaced, failed, bak = _redact(tmp_path, 'multi.py', content)
    text = p.read_text(encoding='utf-8')
    for s in (s1, s2, s3, s4):
        assert s not in text, f'secret survived redaction: {s[:8]}…'


def test_env_mode_output_is_valid_python(tmp_path):
    """#2 — env-mode output must be syntactically valid: the env reference
    replaces the quoted literal instead of nesting inside the source quotes."""
    s = _secret()
    p, findings, replaced, failed, bak = _redact(
        tmp_path, 'app.py', f'api_key = "{s}"\n', mode='env')
    assert replaced == 1
    compile(p.read_text(encoding='utf-8'), 'app.py', 'exec')  # H2: valid syntax


def test_latin1_bytes_roundtrip(tmp_path):
    """S34: non-UTF-8 (latin-1) file — redaction removes the secret and the
    file matches the expected redacted bytes EXACTLY, pinning reader/writer
    codec consistency: a writer that fell back to a different encoding than
    the reader would corrupt the accented bytes on legacy codebases."""
    s = _secret()
    p = tmp_path / 'legacy.py'
    p.write_bytes(f'# café résumé\napi_key = "{s}"\n'.encode('latin-1'))
    cfg = Config(no_color=True, no_backup=True)
    findings = scan_file(str(p), config=cfg)
    assert findings, 'precondition: the secret must be detected in a latin-1 file'
    replaced, failed = batch_replace_in_file(str(p), findings, cfg)
    assert replaced >= 1
    assert failed == 0
    # Full-file equality: deterministic under ANY single-byte codec the
    # detector reports, since unchanged bytes round-trip identically and the
    # replaced line is pure ASCII.
    expected = ('# café résumé\n'.encode('latin-1')
                + b'api_key = "REDACTED_BY_CREDACTOR"\n')
    assert p.read_bytes() == expected
