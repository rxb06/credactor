"""Differential corpus (PA-01).

Each case is a small tree plus a command line. ``test_differential.py`` runs
the real CLI on it in-process and compares the complete, ordered findings, the
exit code, the log messages and the bytes of every file afterwards against a
committed snapshot, so a change that alters what Credactor reports or writes
cannot pass unnoticed.

Secret values are fake or documented example values, built by concatenation so
no provider-shaped literal appears in this file. Heuristic-shaped fixtures (for
example a password in a line) would still be flagged by a scan of this module
alone; the repository self-scan skips it through ``.credactorignore``
(``tests/*.py``). Snapshots store hash tokens, never the values themselves.

Many cases record behaviour that a later hardening task changes on purpose.
Their ``note`` names that task, so the snapshot diff in the fixing commit is
expected and reviewable.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from tests.benchmark.corpus import CASES as BENCHMARK_CASES

# --- fake values (concatenated so no literal appears in this file) ---------
AWS = 'AKIA' + 'IOSFODNN7EXAMPLE'
GITHUB = 'ghp_' + 'x9Kq2Lm8Rt4Wv6Yb1Nc3Pd5Fg7Hj0Sa2Ue4Io'
STRIPE = 'sk_' + 'live_' + 'Ab12Cd34Ef56Gh78Ij90Kl12'
SLACK = 'xoxb-' + '1234567890ab-' + 'Zq8Wm3Nx7Kp2'
PASSWORD = 'Summer' + '2024!'
STRONG = 'xK9#mL2' + '$vQ7@nR5'
JWT = (
    'eyJ'
    + 'hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
    + '.eyJ'
    + 'zdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6Ik'
    + '.'
    + 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
)
CONN_PASSWORD = 'S3cr3t' + 'Pa55'
CONN = 'postgres' + '://admin:' + CONN_PASSWORD + '@db.example.com:5432/app'
HEX = '9f86d081' + '884c7d65' + '9a2feaa0' + 'c55ad015'
PEM_HEADER = '-----BEGIN ' + 'RSA PRIVATE KEY-----'
PEM_FOOTER = '-----END ' + 'RSA PRIVATE KEY-----'
PEM_BODY = 'MIIEowIBAAKCAQEA' + 'q8Zx3Kp9Wm2Nv7Lt4Rs6Yb1Hc5Jd0Fg3Ue8Io2Aa'

# Every constructed value, so the snapshot writer can mask any that appear in
# a raw line or a log message even when it was not that finding's own value,
# and the guards can check that none of them ever reaches a snapshot. The full
# connection string is left out on purpose: only its password is secret, and
# the scheme and host may legitimately be shown around a masked password. It
# is still masked wherever it is a finding's own value.
SECRETS = [
    AWS,
    GITHUB,
    STRIPE,
    SLACK,
    PASSWORD,
    STRONG,
    JWT,
    CONN_PASSWORD,
    HEX,
    PEM_BODY,
]


@dataclass(frozen=True)
class Case:
    id: str
    files: dict[str, bytes]
    argv: tuple[str, ...]
    setup: Callable[[Path], None] | None = None  # runs after files are written
    answers: tuple[str, ...] = ()  # interactive answers; stdin then reports a TTY
    needs_git: bool = False  # the case builds a real repository in the tree
    posix_only: bool = False
    needs_encoding_extra: bool = False
    note: str = ''


def _t(text: str) -> bytes:
    return text.encode('utf-8')


# --- git helpers ---------------------------------------------------------------
# The runner makes git hermetic for the whole case (no user or system config,
# no GIT_* variables). These add fixed dates and a fixed identity per command;
# they never touch the user's git configuration.
_GIT_ENV = {
    'GIT_AUTHOR_DATE': '2026-01-01T00:00:00+0000',
    'GIT_COMMITTER_DATE': '2026-01-01T00:00:00+0000',
}
_GIT_FLAGS = [
    '-c',
    'user.name=differential',
    '-c',
    'user.email=differential@example.invalid',
    '-c',
    'core.autocrlf=false',
    '-c',
    'commit.gpgsign=false',
    '-c',
    'init.defaultBranch=main',
]


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ['git', *_GIT_FLAGS, *args],
        cwd=root,
        check=True,
        capture_output=True,
        env={**os.environ, **_GIT_ENV},
    )


def _commit(root: Path, message: str) -> None:
    _git(root, 'add', '-A')
    _git(root, 'commit', '-q', '--no-verify', '-m', message)


def _setup_init_only(root: Path) -> None:
    _git(root, 'init', '-q')


def _setup_staged(root: Path) -> None:
    _git(root, 'init', '-q')
    _git(root, 'add', 'staged.py', 'clean.py')
    # The working tree now differs from the index: the staged blob holds the
    # secret, the working file does not. --staged must read the index.
    (root / 'staged.py').write_bytes(_t('api_key = os.environ["API_KEY"]\n'))


def _setup_staged_shapes(root: Path) -> None:
    _git(root, 'init', '-q')
    _git(root, 'add', '-A')
    (root / 'with space.py').write_bytes(_t('x = 1\n'))


def _setup_history(root: Path) -> None:
    _git(root, 'init', '-q')
    (root / 'app.py').write_bytes(_t(f'token = "{GITHUB}"\n'))
    _commit(root, 'add token')
    (root / 'app.py').write_bytes(_t('token = os.environ["TOKEN"]\n'))
    _commit(root, 'remove token')


def _setup_history_edges(root: Path) -> None:
    _git(root, 'init', '-q')
    base = 'one = 1\ntwo = 2\nthree = 3\nfour = 4\nfive = 5\n'
    (root / 'base.py').write_bytes(_t(base))
    _commit(root, 'base')
    # The secret lands after unchanged lines, so its reported line number
    # depends on counting context lines in the hunk.
    edited = f'one = 1\ntwo = 2\napi_key = "{AWS}"\nthree = 3\nfour = 4\nfive = 5\n'
    (root / 'base.py').write_bytes(_t(edited))
    _commit(root, 'insert key')
    # An added content line that looks like a diff header (SR-31), and a line
    # holding a form feed, which str.splitlines() splits (PA-07).
    (root / 'a.py').write_bytes(_t(f'++ b/fake.py\ntoken = "{GITHUB}"\n'))
    (root / 'sep.py').write_bytes(_t(f'x = 1\x0capi_key = "{AWS}"\n'))
    _commit(root, 'edge lines')


def _setup_outside_symlink(root: Path) -> None:
    outside = root.parent / 'outside'
    outside.mkdir(exist_ok=True)
    (outside / 'secret.py').write_bytes(_t(f'api_key = "{AWS}"\n'))
    (root / 'link.py').symlink_to(outside / 'secret.py')


def _setup_unreadable(root: Path) -> None:
    os.chmod(root / 'locked.py', 0)


def _setup_hardlink(root: Path) -> None:
    os.link(root / 'app.py', root / 'copy.dat')


def _gitleaks(records: list[dict[str, object]]) -> bytes:
    return _t(json.dumps(records, indent=1))


def _ndjson(records: list[dict[str, object]], extra_lines: tuple[str, ...] = ()) -> bytes:
    lines = [json.dumps(r) for r in records] + list(extra_lines)
    return _t('\n'.join(lines) + '\n')


def _trufflehog_fs(path: str, secret: str, line: int, detector: str) -> dict[str, object]:
    return {
        'SourceMetadata': {'Data': {'Filesystem': {'file': path, 'line': line}}},
        'SourceName': 'trufflehog - filesystem',
        'DetectorName': detector,
        'Verified': False,
        'Raw': secret,
    }


def _gl(
    rule: object, path: str, line: object, secret: object, **extra: object
) -> dict[str, object]:
    record: dict[str, object] = {'RuleID': rule, 'File': path, 'Secret': secret}
    if line is not None:
        record['StartLine'] = line
    record.update(extra)
    return record


_LONG_PAD = 'c' * 4200
_KEY_LINE = f'api_key = "{AWS}"\n'

CASES: list[Case] = [
    Case(
        id='benchmark-corpus',
        files={c.filename: _t(c.content) for c in BENCHMARK_CASES},
        argv=('--ci', '.'),
        note='the labelled detection-benchmark corpus, one file per case',
    ),
    Case(
        id='providers-quoted',
        files={
            'providers.py': _t(
                f'aws_key = "{AWS}"\n'
                f'gh = "{GITHUB}"\n'
                f"stripe_key = '{STRIPE}'\n"
                f'slack = "{SLACK}"\n'
                f'jwt = "{JWT}"\n'
                f'dsn = "{CONN}"\n'
                f'digest_like = "{HEX}"\n'
            )
        },
        argv=('--ci', '.'),
    ),
    Case(
        id='providers-unquoted-and-comments',
        files={
            'app.env': _t(f'AWS_ACCESS_KEY_ID={AWS}\nGH_TOKEN={GITHUB}\n'),
            'comments.py': _t(
                f'# old key: {AWS}\n'
                f'// token {GITHUB}\n'
                f'# jwt in prose {JWT}\n'
                f'x = 1  # trailing {STRIPE}\n'
            ),
        },
        argv=('--ci', '.'),
        note='provider prefixes are scanned in comments; heuristic patterns are not',
    ),
    Case(
        id='multi-secret-lines',
        files={
            'multi.py': _t(
                f'a = "{AWS}"; b = "{GITHUB}"\n'
                f'c = "{AWS}"; d = "{AWS}"\n'
                f'api_key = "{AWS}"\n'
                f'password = "{PASSWORD}"; token = "{STRONG}"\n'
            )
        },
        argv=('--ci', '.'),
        note='distinct secrets, repeats, and pattern/assignment overlap on one line; '
        'SR-05 masks every value on a displayed line',
    ),
    Case(
        id='secret-in-file-name',
        files={
            f'{AWS}.py': _t(f'aws_key = "{AWS}"\n'),
            f'keys/{GITHUB}/app.py': _t(f'token = "{GITHUB}"\npassword = "{STRONG}"\n'),
        },
        argv=('--ci', '.'),
        note='SR-07: a secret found in the run is masked in file and directory names in every '
        'report format (names are not scanned, so a secret only in a name is not found)',
    ),
    Case(
        id='xml-attribute-orders',
        files={
            'web.config': _t(
                '<configuration>\n'
                f'  <add key="Password" value="{STRONG}" />\n'
                f'  <add value="{STRONG}x" name="ApiKey" />\n'
                '  <add key="Title" value="not a secret at all" />\n'
                '</configuration>\n'
            ),
            'settings.xml': _t(f'<setting name="client_secret" value="{STRONG}y"/>\n'),
        },
        argv=('--ci', '.'),
    ),
    Case(
        id='xml-lt-in-attributes',
        files={
            'web.config': _t(
                '<configuration>\n'
                f'  <add title="a<b" key="Password" value="{STRONG}" />\n'
                f'  <add key="Password" note="x<y" value="{STRONG}q" />\n'
                f'  <add value="{STRONG}r" hint="1<2" name="ApiKey" />\n'
                f'  <add key="ApiKey" value="{STRONG}<s" />\n'
                '</configuration>\n'
            )
        },
        argv=('--ci', '.'),
        note='PA-10 must keep every finding when it bounds the XML regexes',
    ),
    Case(
        id='pem-blocks',
        files={
            'key.pem': _t(f'{PEM_HEADER}\n{PEM_BODY}\n{PEM_BODY}\n{PEM_FOOTER}\n'),
            'after_block.py': _t(f'{PEM_HEADER}\n{PEM_BODY}\n{PEM_FOOTER}\n{_KEY_LINE}'),
            'suppressed_header.py': _t(
                f'{PEM_HEADER} # credactor:ignore\n{_KEY_LINE}password = "{PASSWORD}"\n'
            ),
        },
        argv=('--ci', '.'),
        note='SR-08: an ignored header no longer hides the lines after it (suppressed_header.py)',
    ),
    Case(
        id='pem-edge-cases',
        files={
            '.credactorignore': _t('allow.py:1\n'),
            'allow.py': _t(f'{PEM_HEADER}\n{_KEY_LINE}'),
            'body.py': _t(
                f'{PEM_HEADER}  # credactor:ignore\n{PEM_BODY}\n{PEM_FOOTER}\ntoken = "{GITHUB}"\n'
            ),
            'unclosed_short.py': _t(PEM_HEADER + '\n' + 'filler = 1\n' * 100 + _KEY_LINE),
            'unclosed_long.py': _t(
                PEM_HEADER + '\n' + 'filler = 1\n' * 600 + f'token = "{GITHUB}"\n'
            ),
        },
        argv=('--ci', '.'),
        note='allowlisted header and the 500-line unclosed-block cap; since SR-08 the lines '
        'after an allowlisted header are scanned (allow.py)',
    ),
    Case(
        id='multiline-strings',
        files={
            'doc.py': _t(f'CONFIG = """\nsection:\n  token: {JWT}\n"""\n'),
            'tpl.js': _t(f'const cfg = `\n  key: {GITHUB}\n`;\n'),
            'single.py': _t(f"BLOB = '''{AWS}'''\n"),
        },
        argv=('--ci', '.'),
    ),
    Case(
        id='multiline-mixed-delimiters',
        files={
            'mixed.py': _t(f'BLOB = \'\'\'\nkey: {GITHUB}\n\'\'\'\nDOC = """\nplain text\n"""\n'),
            'crlf_block.py': _t(f'x = 1\r\nDOC = """\r\n  token: {JWT}\r\n"""\r\n'),
            'cr_block.py': _t(f'x = 1\rDOC = """\r  token: {JWT}\r"""\r'),
        },
        argv=('--ci', '.'),
        note='PA-08 must reset its line cursor per delimiter; PA-07 must keep these lines',
    ),
    Case(
        id='line-separators',
        files={
            'seps.py': _t(
                f'a = 1\x0cpassword = "{PASSWORD}"\n'
                f'b = 2\x0btoken = "{STRONG}"\n'
                f'c = 3\u2028api_key = "{AWS}"\n'
                'd = 4\x85e = 5\x1cf = 6\n'
                f'gh = "{GITHUB}"\n'
            )
        },
        argv=('--fix-all', '--yes', '--no-backup', '.'),
        note='PA-07 must keep readlines() splitting: only \\n, \\r\\n and \\r end a line',
    ),
    Case(
        id='encodings-stable',
        files={
            'utf8_bom.py': b'\xef\xbb\xbf' + _t(_KEY_LINE),
            'crlf.py': _t(f'first = 1\r\npassword = "{PASSWORD}"\r\nlast = 2\r\n'),
            'cr_only.py': _t(f'first = 1\rtoken = "{GITHUB}"\rlast = 2\r'),
            'utf16le_bom.py': b'\xff\xfe' + _KEY_LINE.encode('utf-16-le'),
            'utf16le_nobom.py': _KEY_LINE.encode('utf-16-le'),
            'utf16be_bom.py': b'\xfe\xff' + f'token = "{GITHUB}"\n'.encode('utf-16-be'),
            'utf16be_nobom.py': f'token = "{GITHUB}"\n'.encode('utf-16-be'),
            'no_final_newline.py': _t(f'api_key = "{AWS}"'),
        },
        argv=('--ci', '.'),
    ),
    Case(
        id='encodings-latin1',
        files={
            'latin1.py': f'café = "déjà vu"\npassword = "{PASSWORD}ñ"\n'.encode('latin-1'),
        },
        argv=('--ci', '.'),
        needs_encoding_extra=True,
        note='the detection path differs without charset-normalizer',
    ),
    Case(
        id='dynamic-lookups',
        files={
            'runtime.py': _t(
                'password = os.getenv("DB_PASSWORD")\n'
                'api_key = config.get("api_key")\n'
                'token = settings.get("token", "x")\n'
                'secret = "${SECRET_FROM_ENV}"\n'
                'db_pass = "{{ vault_db_pass }}"\n'
                'client_secret = self.config.client_secret\n'
                f'password = "{PASSWORD}"  # migrate with os.getenv later\n'
            ),
            'main.tf': _t('password = var.db_password\ntoken = data.vault_generic_secret.t.data\n'),
            'app.js': _t('const apiKey = process.env.API_KEY;\n'),
        },
        argv=('--ci', '.'),
        note='the last runtime.py line records current behaviour; SR-11 changes it',
    ),
    Case(
        id='suppress-inline',
        files={
            'inline.py': _t(
                f'a = "{AWS}"  # credactor:ignore\n'
                f'b = "{GITHUB}"  // credactor:ignore\n'
                f'c = "{STRIPE}"  /* credactor:ignore */\n'
                f'd = "{AWS}"  <!-- credactor:ignore -->\n'
                f'e = "{AWS}"  -- credactor:ignore\n'
                f'# credactor:ignore\nf = "{AWS}"\n'
            )
        },
        argv=('--ci', '.'),
    ),
    Case(
        id='suppress-ignorefile',
        files={
            '.credactorignore': _t('ignored.py\ngen/*.py\nlines.py:2\nvalue:' + STRONG + '\n'),
            'ignored.py': _t(_KEY_LINE),
            'gen/a.py': _t(_KEY_LINE),
            'lines.py': _t(f'one = "{GITHUB}"\ntwo = "{GITHUB}"\n'),
            'values.py': _t(f'token = "{STRONG}"\nother = "{PASSWORD}x9"\n'),
        },
        argv=('--ci', '.'),
        note='SR-09 adds signals for these suppressions',
    ),
    Case(
        id='suppress-config',
        files={
            '.credactor.toml': _t(
                'extra_safe_values = ["' + PASSWORD.lower() + '"]\n'
                'skip_files = ["skipped.py"]\nskip_dirs = ["vendor"]\n'
            ),
            'app.py': _t(f'password = "{PASSWORD}"\n{_KEY_LINE}'),
            'skipped.py': _t(_KEY_LINE),
            'vendor/lib.py': _t(_KEY_LINE),
        },
        argv=('--ci', '.'),
        note='records current behaviour; SR-09 adds signals',
    ),
    Case(
        id='caps',
        files={
            'long_line.py': _t(
                f'early = "{AWS}"; pad = "{_LONG_PAD}"\nlate = "{_LONG_PAD}{GITHUB}"\n'
            ),
            'big_block.py': _t('DOC = """\n' + ('word ' * 1700) + f'\n{JWT}\n"""\n'),
        },
        argv=('--ci', '.'),
        note='records current truncation behaviour; SR-10 and SR-32 change it',
    ),
    Case(
        id='caps-boundaries',
        files={
            'at_cap.py': _t('a = "' + 'c' * 4090 + '"\n'),
            'at_cap_crlf.py': _t('a = "' + 'c' * 4090 + '"\r\n'),
            'over_cap.py': _t('a = "' + 'c' * 4091 + '"\n'),
            'straddle.py': _t('p = "' + 'c' * 4080 + f'"; k = "{AWS}"\n'),
            'block_straddle.py': _t('DOC = """' + 'w' * 8185 + f'{JWT}"""\n'),
        },
        argv=('--ci', '--fail-on-error', '.'),
        note='exact 4096/8192 boundaries; SR-10, SR-32 and PA-07 move them',
    ),
    Case(
        id='hash-context',
        files={
            'lock.py': _t(
                f'commit = "{HEX}0123abcd"\n'
                f'integrity = "sha384-{HEX}"\n'
                f'revision = "{HEX}"\n'
                f'api_key_rev = "{HEX}"\n'
                f'token = "{HEX}"\n'
            )
        },
        argv=('--ci', '.'),
    ),
    Case(
        id='gitignore',
        files={
            '.gitignore': _t('*.env\n!production.env\nbuild_out/\n'),
            'production.env': _t(f'AWS_ACCESS_KEY_ID={AWS}\n'),
            'local.env': _t(f'AWS_ACCESS_KEY_ID={AWS}\n'),
            'build_out/gen.py': _t(_KEY_LINE),
            'pkg/build_out/x.py': _t(_KEY_LINE),
            'sub/.gitignore': _t('secret_*.py\n'),
            'sub/secret_one.py': _t(_KEY_LINE),
            'sub/kept.py': _t(_KEY_LINE),
        },
        argv=('--ci', '.'),
        note='production.env records current behaviour; SR-12 changes it',
    ),
    Case(
        id='gitignore-syntax',
        files={
            '.gitignore': _t(
                '/root_only.py\ndocs/*.py\n**/gen/*.py\nlogs/\n!logs/keep.py\nfile?.py\n.env/\n'
            ),
            'root_only.py': _t(_KEY_LINE),
            'sub/root_only.py': _t(_KEY_LINE),
            'docs/top.py': _t(_KEY_LINE),
            'docs/deep/nested.py': _t(_KEY_LINE),
            'a/gen/x.py': _t(_KEY_LINE),
            'gen/y.py': _t(_KEY_LINE),
            'logs/keep.py': _t(_KEY_LINE),
            'file1.py': _t(_KEY_LINE),
            'file12.py': _t(_KEY_LINE),
            '.env': _t(f'AWS_ACCESS_KEY_ID={AWS}\n'),
        },
        argv=('--ci', '.'),
        note='anchoring, * versus /, **, parent-excluded negation, dir-only pattern '
        'against a file; SR-12 and PA-11 change some of it',
    ),
    Case(
        id='json-not-opted-in',
        files={'creds.json': _t(f'{{"api_key": "{AWS}"}}\n'), 'app.py': _t('x = 1\n')},
        argv=('--ci', '.'),
    ),
    Case(
        id='json-opted-in',
        files={'creds.json': _t(f'{{"api_key": "{AWS}"}}\n'), 'app.py': _t('x = 1\n')},
        argv=('--ci', '--scan-json', '.'),
    ),
    Case(
        id='single-file-target',
        files={'notes.md': _t(f'deploy key: {AWS}\n'), 'other.py': _t(_KEY_LINE)},
        argv=('--ci', 'notes.md'),
        note='a named file is scanned even with an unscanned extension',
    ),
    Case(
        id='ingest-gitleaks',
        files={
            'README.md': _t(f'Example:\n  token: {GITHUB}\n'),
            'app.py': _t(_KEY_LINE),
            'report/gitleaks.json': _gitleaks(
                [
                    _gl('github-pat', 'README.md', 2, GITHUB, Match=f'token: {GITHUB}', Tags=[]),
                    _gl('aws-access-token', 'app.py', 1, AWS, Match=AWS, Tags=[]),
                    _gl('x', '../outside.py', 1, AWS),
                    _gl('x', 'gone.py', 1, AWS),
                    _gl('x', 'app.py', 1, ''),
                ]
            ),
        },
        argv=('--ci', '--from-gitleaks', 'report/gitleaks.json', '.'),
        note='report kept inside the tree on purpose; it is .json so not scanned natively',
    ),
    Case(
        id='ingest-trufflehog',
        files={
            'notes.md': _t(f'key {AWS}\n'),
            'report/th.ndjson': _ndjson(
                [
                    _trufflehog_fs('notes.md', AWS, 1, 'AWS'),
                    {'SourceMetadata': {'Data': {'Github': {'link': 'x'}}}, 'Raw': AWS},
                ],
                extra_lines=('this line is not json',),
            ),
        },
        argv=('--ci', '--from-trufflehog', 'report/th.ndjson', '.'),
    ),
    Case(
        id='ingest-betterleaks-null',
        files={'app.py': _t('x = 1\n'), 'report/bl.json': _t('null\n')},
        argv=('--ci', '--from-betterleaks', 'report/bl.json', '.'),
    ),
    Case(
        id='ingest-betterleaks',
        files={
            'notes.md': _t(f'password: {STRONG}\n'),
            'report/bl.json': _gitleaks(
                [
                    {
                        'RuleID': 'generic-password',
                        'Attributes': {'path': 'notes.md'},
                        'StartLine': 1,
                        'Secret': STRONG,
                        'Match': f'password: {STRONG}',
                        'Tags': [],
                    }
                ]
            ),
        },
        argv=('--ci', '--from-betterleaks', 'report/bl.json', '.'),
    ),
    Case(
        id='ingest-dedup-severity',
        files={
            'app.py': _t(f'webhook_secret = "{STRONG}"\n'),
            'report/th.ndjson': _ndjson(
                [{**_trufflehog_fs('app.py', STRONG, 1, 'Generic'), 'Verified': True}]
            ),
        },
        argv=('--ci', '--from-trufflehog', 'report/th.ndjson', '.'),
        note='native medium finding merged with a verified external duplicate',
    ),
    Case(
        id='ingest-labels-and-lines',
        files={
            'notes.md': _t(f'key {AWS}\ntoken {GITHUB}\npw {STRONG}\n'),
            'report/gl.json': _gitleaks(
                [
                    _gl(AWS, 'notes.md', 1, AWS),
                    _gl('x ' + GITHUB, 'notes.md', 2, GITHUB),
                    _gl('bad\x1b[31m', 'notes.md', 3, STRONG),
                    _gl('r' * 70, 'notes.md', '3', STRONG),
                    _gl('ok', 'notes.md', True, AWS),
                    _gl('ok', 'notes.md', None, GITHUB),
                ]
            ),
        },
        argv=('--ci', '--from-gitleaks', 'report/gl.json', '.'),
        note='report-controlled labels and invalid line numbers; PA-04 replaces labels '
        'outside [A-Za-z0-9._-]{1,64} with unknown and masks secrets in the rest, and '
        'PA-05 changes the line numbers',
    ),
    Case(
        id='ingest-bad-field-types',
        files={
            'notes.md': _t(f'key {AWS}\n'),
            'report/gl.json': _gitleaks([_gl([1], 'notes.md', 1, AWS, Tags={})]),
        },
        argv=('--ci', '--from-gitleaks', 'report/gl.json', '.'),
        note='a list RuleID no longer crashes: PA-04 reports it as unknown and keeps '
        'the finding; SR-19 covers the remaining field types',
    ),
    Case(
        id='ingest-context-shapes',
        files={
            'multi.md': _t(f'one\ntoken {GITHUB}\nthree\nkey {AWS}\n'),
            'crlf.md': _t(f'x\r\ntoken: {GITHUB}\r\n'),
            'u16.md': b'\xff\xfe' + f'x\ntoken: {GITHUB}\n'.encode('utf-16-le'),
            'short.md': _t('only one line\n'),
            'long.md': _t('p' * 5000 + f' {AWS}\n'),
            'report/gl.json': _gitleaks(
                [
                    _gl('aws-access-token', 'multi.md', 4, AWS),
                    _gl('github-pat', 'multi.md', 2, GITHUB),
                    _gl('github-pat', 'crlf.md', 2, GITHUB),
                    _gl('github-pat', 'u16.md', 2, GITHUB),
                    _gl('github-pat', 'short.md', 9, GITHUB, Match=f'token: {GITHUB}'),
                    _gl('aws-access-token', 'short.md', 9, AWS),
                    _gl('aws-access-token', 'long.md', 1, AWS),
                ]
            ),
        },
        argv=('--ci', '--from-gitleaks', 'report/gl.json', '.'),
        note='context lines PA-06 must keep as they are',
    ),
    Case(
        id='ingest-fix-all',
        files={
            'app.py': _t(_KEY_LINE),
            'dsn.py': _t(f'DSN = "{CONN}"\n'),
            'README.md': _t(f'{PEM_HEADER}\n{PEM_BODY}\n{PEM_FOOTER}\n'),
            'short.py': _t('api_key = load()\n'),
            'stale.py': _t('x = 1\n'),
            'lines.py': _t(f'first = 1\ntoken = "{GITHUB}"\n'),
            'report/gl.json': _gitleaks(
                [
                    _gl('aws-access-token', 'app.py', 1, AWS),
                    _gl('generic', 'short.py', 1, 'api'),
                    _gl('aws-access-token', 'stale.py', 1, AWS),
                    _gl('private-key', 'README.md', 1, PEM_HEADER),
                    _gl('github-pat', 'lines.py', 'x', GITHUB),
                    _gl('pg', 'dsn.py', 1, CONN_PASSWORD),
                ]
            ),
        },
        argv=('--fix-all', '--yes', '--from-gitleaks', 'report/gl.json', '.'),
        note='current behaviour for SR-15, SR-17, SR-24 and PA-05; app.py and dsn.py '
        'are positive controls that must keep redacting',
    ),
    Case(
        id='ingest-fix-env',
        files={
            'app.py': _t(_KEY_LINE),
            'drift.py': _t(f'x = 1\n{_KEY_LINE}'),
            'report/gl.json': _gitleaks(
                [
                    _gl('aws-access-token', 'app.py', 1, AWS),
                    _gl('aws-access-token', 'drift.py', 1, AWS),
                ]
            ),
        },
        argv=(
            '--fix-all',
            '--yes',
            '--no-backup',
            '--replace-with',
            'env',
            '--from-gitleaks',
            'report/gl.json',
            '.',
        ),
        note='external env naming and the stale-report warning (drift.py)',
    ),
    Case(
        id='ingest-git-dir',
        files={
            'app.py': _t('x = 1\n'),
            '.git/config': _t(f'[github]\n\ttoken = {GITHUB}\n'),
            'report/gl.json': _gitleaks([_gl('github-pat', '.git/config', 2, GITHUB)]),
        },
        argv=('--fix-all', '--yes', '--from-gitleaks', 'report/gl.json', '.'),
        note='SR-16: the finding under .git is reported with a refuse reason, and the file '
        'is not rewritten',
    ),
    Case(
        id='fix-sentinel',
        files={
            'app.py': _t(f'{_KEY_LINE}password = "{PASSWORD}"\n# note {AWS}\nx = 1\n'),
            'cfg.yaml': _t(f'token: "{GITHUB}"\nother: 1\n'),
            'key.pem': _t(f'{PEM_HEADER}\n{PEM_BODY}\n{PEM_FOOTER}\n'),
        },
        argv=('--fix-all', '--yes', '.'),
        note='rewritten bytes and .bak bytes are hashed; the PEM block is refused',
    ),
    Case(
        id='fix-env-mode',
        files={
            'a.py': _t(f'{_KEY_LINE}auth = "Bearer {GITHUB}"\n'),
            'b.js': _t(f"const token = '{GITHUB}';\n"),
            'c.sh': _t(f'export PASSWORD="{PASSWORD}"\n'),
            'd.rb': _t(f"api_key = '{AWS}'\n"),
            'e.go': _t(f'apiKey := "{AWS}"\n'),
            'f.java': _t(f'String password = "{STRONG}";\n'),
            'g.php': _t(f"$api_key = '{AWS}';\n"),
            'h.ts': _t(f'const token: string = "{GITHUB}";\n'),
        },
        argv=('--fix-all', '--yes', '--no-backup', '--replace-with', 'env', '.'),
    ),
    Case(
        id='fix-env-quote-forms',
        files={
            'q.py': _t(
                f'a = """{AWS}"""\nb = b\'{GITHUB}\'\nc = f"{STRIPE}"\nd = r"{SLACK}"\n{_KEY_LINE}'
            )
        },
        argv=('--fix-all', '--yes', '--no-backup', '--replace-with', 'env', '.'),
        note='records the broken output for triple quotes and prefixed strings; SR-25 changes it',
    ),
    Case(
        id='fix-custom-replacement',
        files={'app.py': _t(_KEY_LINE)},
        argv=('--fix-all', '--yes', '--no-backup', '--replacement', 'CHANGE_ME_LATER', '.'),
    ),
    Case(
        id='fix-sweep-and-hash-context',
        files={
            '.credactorignore': _t('dupes.py:3\n'),
            'lock.py': _t(
                f'token = "{HEX}"\nrevision = "{HEX}"\napi_key_rev = "{HEX}"\nlater = 1  # {HEX}\n'
            ),
            'dupes.py': _t(
                f'first = "{AWS}"\nsecond = "{AWS}"  # credactor:ignore\nthird = "{AWS}"\n'
            ),
        },
        argv=('--fix-all', '--yes', '--no-backup', '.'),
        note='records current sweep behaviour; SR-21 and SR-22 change it',
    ),
    Case(
        id='fix-backup-collision-and-hardlink',
        files={
            'app.py': _t(_KEY_LINE),
            'app.py.bak': _t('older backup\n'),
            'tmpabc.credactor.bak': _t('leftover from an interrupted run\n'),
        },
        argv=('--fix-all', '--yes', '.'),
        setup=_setup_hardlink,
        posix_only=True,
        note='records current behaviour; SR-26 and SR-27 change it',
    ),
    Case(
        id='interactive-sweep',
        files={
            'app.py': _t(
                f'{_KEY_LINE}second = "{AWS}"  # credactor:ignore\n'
                f'old = "{GITHUB}"\nnote = 1  # {GITHUB}\n'
            )
        },
        argv=('--no-backup', '.'),
        answers=('y', 'n', 'y'),
        note='interactive approvals and the final sweep; SR-22 and PA-14 change this',
    ),
    Case(
        id='dry-run-and-fix-all',
        files={'app.py': _t(_KEY_LINE)},
        argv=('--dry-run', '--fix-all', '.'),
        note='dry-run wins; the file must be unchanged',
    ),
    Case(
        id='staged',
        files={
            'staged.py': _t(_KEY_LINE),
            'clean.py': _t('x = 1\n'),
            'unstaged.py': _t(f'token = "{GITHUB}"\n'),
        },
        argv=('--staged', '.'),
        setup=_setup_staged,
        needs_git=True,
        note='only the index blob of staged.py is scanned',
    ),
    Case(
        id='staged-nothing',
        files={'app.py': _t(_KEY_LINE)},
        argv=('--staged', '.'),
        setup=_setup_init_only,
        needs_git=True,
        note='nothing staged must stay a clean exit',
    ),
    Case(
        id='staged-shapes',
        files={
            'with space.py': _t(_KEY_LINE),
            'sub/crlf.py': _t(f'x = 1\r\npassword = "{PASSWORD}"\r\n'),
            'sub/u16.py': b'\xff\xfe' + f'token = "{GITHUB}"\n'.encode('utf-16-le'),
            'clean.py': _t('x = 1\n'),
        },
        argv=('--staged', '.'),
        setup=_setup_staged_shapes,
        needs_git=True,
        note='a path with a space, CRLF and UTF-16 blobs; PA-09 must match git show',
    ),
    Case(
        id='history',
        files={'README.txt': _t('hello\n')},
        argv=('--scan-history', '.'),
        setup=_setup_history,
        needs_git=True,
    ),
    Case(
        id='history-edges',
        files={'README.txt': _t('hello\n')},
        argv=('--scan-history', '.'),
        setup=_setup_history_edges,
        needs_git=True,
        note='context-line numbering, a header-like content line (SR-31) and a form '
        'feed line (PA-07)',
    ),
    Case(
        id='history-empty-repo',
        files={'README.txt': _t('hello\n')},
        argv=('--scan-history', '.'),
        setup=_setup_init_only,
        needs_git=True,
        note='a repository with no commits must stay a clean exit (SR-14)',
    ),
    Case(
        id='symlink-outside-root',
        files={'inside.py': _t('x = 1\n')},
        argv=('--ci', '.'),
        setup=_setup_outside_symlink,
        posix_only=True,
    ),
    Case(
        id='fail-on-error-unreadable',
        files={'locked.py': _t(_KEY_LINE), 'open.py': _t('x = 1\n')},
        argv=('--ci', '--fail-on-error', '.'),
        setup=_setup_unreadable,
        posix_only=True,
        note='skipped when running as root, which can read a mode-0 file',
    ),
]
