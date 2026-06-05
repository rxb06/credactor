"""Detection benchmark corpus (Phase 0.1).

A labelled set of positive cases (a credential that *should* be detected) and
negative cases (false-positive bait that must *not* be flagged). The benchmark
test (`tests/test_detection_benchmark.py`) writes each case to a temp file, runs
the real directory scan over it, and reports precision/recall per category.

Secret values are CONSTRUCTED at import time (never literals) so this module does
not itself trip credactor's own self-scan. Values are deterministic (seeded RNG)
so precision/recall are stable across runs.

Cases tagged ``gap=True`` are known recall/precision gaps documented by the
e2e report (H7/M1/M2/M3/M4/L1 and the git-SHA/base64 false positives); they are
included on purpose so the benchmark *measures* them. Fixing the corresponding
finding should flip the case and raise the ratchet floor.
"""
from __future__ import annotations

import random
import string
from dataclasses import dataclass

_r = random.Random(20260605)


def _alnum(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return ''.join(_r.choice(alphabet) for _ in range(n))


def _hex(n: int) -> str:
    return ''.join(_r.choice('0123456789abcdef') for _ in range(n))


_UPPER_NUM = string.ascii_uppercase + string.digits


@dataclass(frozen=True)
class Case:
    id: str
    category: str
    filename: str
    content: str
    expect: bool          # True = should be detected; False = must not be flagged
    gap: bool = False     # known gap today (documents a finding)
    note: str = ''


# --- constructed high-entropy secret values (no literals in this file) ---
_AWS = 'AKIA' + _alnum(16, _UPPER_NUM)
_GCP = 'AIza' + _alnum(35)
_STRIPE = 'sk_live_' + _alnum(24)
_GITHUB = 'ghp_' + _alnum(36)
_GITLAB = 'glpat-' + _alnum(20)
_SLACK = 'xoxb-' + _hex(12) + '-' + _alnum(12)
_NPM = 'npm_' + _alnum(36)
_PYPI = 'pypi-' + _alnum(20)
_JWT = 'eyJ' + _alnum(33) + '.eyJ' + _alnum(30) + '.' + _alnum(43)
# all 3 segments <=40 chars AND letter-starting -> matches _DOTTED_ACCESS_RE (L1)
_LETTER = string.ascii_letters
_JWT_COMPACT = (
    'eyJ' + _alnum(20) + '.eyJ' + _alnum(20)
    + '.' + _r.choice(_LETTER) + _alnum(17)
)
_HEX32 = _hex(32)
_STRONG_PW = _alnum(20)
_GIT_SHA = _hex(40)
_B64_ASSET = _alnum(80, string.ascii_letters + string.digits + '+/')
_PEM = (
    '-----BEGIN RSA PRIVATE KEY-----\n'
    + _alnum(64) + '\n' + _alnum(64) + '\n'
    + '-----END RSA PRIVATE KEY-----'
)

CASES: list[Case] = [
    # ---- positives: deterministic provider prefixes (must detect) ----
    Case('aws', 'provider', 'aws.py', f'aws_key = "{_AWS}"\n', True),
    Case('gcp', 'provider', 'gcp.py', f'gcp_key = "{_GCP}"\n', True),
    Case('stripe', 'provider', 'stripe.py', f'stripe = "{_STRIPE}"\n', True),
    Case('github', 'provider', 'github.py', f'gh = "{_GITHUB}"\n', True),
    Case('gitlab', 'provider', 'gitlab.py', f'gl = "{_GITLAB}"\n', True),
    Case('slack', 'provider', 'slack.py', f'slack = "{_SLACK}"\n', True),
    Case('npm', 'provider', 'npm.py', f'npm = "{_NPM}"\n', True),
    Case('pypi', 'provider', 'pypi.py', f'pypi = "{_PYPI}"\n', True),
    # ---- positives: structural (must detect) ----
    Case('jwt', 'structural', 'jwt.py', f'tok = "{_JWT}"\n', True),
    Case('conn', 'structural', 'conn.py',
         f'url = "postgresql://user:{_alnum(12)}@db.example.com:5432/prod"\n', True),
    Case('pem_inline', 'structural', 'pem_inline.py', f'KEY = """{_PEM}"""\n', True),
    # ---- positives: heuristic (must detect) ----
    Case('hex', 'heuristic', 'hex.py', f'h = "{_HEX32}"\n', True),
    Case('strong_pw', 'heuristic', 'strongpw.py', f'db_password = "{_STRONG_PW}"\n', True),
    # ---- positives that are KNOWN GAPS today (should detect, currently missed) ----
    Case('weak_pw_1', 'weak-password', 'weakpw1.py', 'password = "Summer2024!"\n', True,
         note='H7 FIXED: password-family entropy floor 3.0 (entropy 3.10)'),
    Case('weak_pw_2', 'weak-password', 'weakpw2.py', 'api_secret = "Password123"\n', True,
         gap=True, note='still missed: var name now matched (H11), but api_secret is '
                        'outside the H7 password-family carve-out, so entropy 3.28 < the '
                        '3.5 floor. Needs the carve-out extended to secret-family '
                        '(maintainer decision).'),
    Case('jwt_compact', 'structural', 'jwtc.py', f'tok = "{_JWT_COMPACT}"\n', True,
         gap=True, note='L1: compact JWT misread as dotted access'),
    Case('pem_file', 'key-file', 'server.pem', _PEM + '\n', True,
         note='M1 FIXED: .pem now in SCAN_EXTENSIONS'),
    Case('id_rsa', 'key-file', 'id_rsa', _PEM + '\n', True,
         note='M1 FIXED: extensionless key file now scanned'),
    Case('web_config', 'xml', 'web.config',
         f'<add key="DbPassword" value="{_STRONG_PW}xyz" />\n', True,
         note='M2 FIXED: .config now scanned'),
    Case('go_short', 'go', 'main.go', f'apiKey := "{_STRONG_PW}qZ"\n', True,
         note='M4 FIXED: Go := now matched'),
    Case('comment_secret', 'comment', 'legacy.py', f'# old_key = "{_AWS}"\n', True,
         gap=True, note='M3: pattern scan disabled on comment lines'),

    # ---- negatives: placeholders / safe values (must NOT flag) ----
    Case('ph_yourkey', 'placeholder', 'ph1.py', 'api_key = "your_api_key"\n', False),
    Case('ph_changeme', 'placeholder', 'ph2.py', 'password = "changeme"\n', False),
    Case('ph_xxxx', 'placeholder', 'ph3.py', 'token = "xxxxxxxx"\n', False),
    # ---- negatives: env / dynamic references ----
    Case('envref_py', 'dynamic-ref', 'env1.py', 'api_key = os.getenv("REAL_KEY")\n', False),
    Case('envref_js', 'dynamic-ref', 'env2.js', 'const k = process.env.REAL_KEY;\n', False),
    Case('vault', 'dynamic-ref', 'env3.py', 'secret = "vault:secret/data/app"\n', False),
    Case('template', 'dynamic-ref', 'env4.yaml', 'password: "{{ vault_password }}"\n', False),
    # ---- negatives: code shapes ----
    Case('funccall', 'code-shape', 'c1.py', 'key = get_secret("db")\n', False),
    Case('dotted', 'code-shape', 'c2.py', 'password = self.config.password\n', False),
    Case('path', 'code-shape', 'c3.py', 'p = "/home/user/.ssh/config"\n', False),
    Case('url', 'code-shape', 'c4.py', 'u = "https://api.example.com/v1/endpoint"\n', False),
    Case('hash_var', 'code-shape', 'c5.py', f'password_hash = "{_HEX32}"\n', False),
    Case('bcrypt', 'code-shape', 'c6.py',
         'pw = "$2b$12$' + _alnum(53) + '"\n', False),
    # ---- negatives: high-entropy NON-secrets (precision bait; some are current FPs) ----
    Case('git_sha', 'entropy-bait', 'b1.py', f'COMMIT = "{_GIT_SHA}"\n', False,
         gap=True, note='precision: 40-hex git SHA currently flagged as hex credential'),
    Case('uuid', 'entropy-bait', 'b2.py',
         'request_id = "550e8400-e29b-41d4-a716-446655440000"\n', False),
    Case('b64_asset', 'entropy-bait', 'b3.py', f'BLOB = "{_B64_ASSET}"\n', False,
         gap=True, note='precision: long base64 asset flagged as high-entropy string'),
]
