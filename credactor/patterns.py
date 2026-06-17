"""
Regex patterns, constants, and safe-value lists for credential detection.

Addresses: #17 (connection strings), #18 (PEM keys), #19 (provider prefixes),
           #20 (Vault/SOPS dynamic lookups), #21 (XML attributes)
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import NamedTuple

from .types import Severity

# ---------------------------------------------------------------------------
# File types to scan
# ---------------------------------------------------------------------------
SCAN_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.sh', '.bash',
    '.env', '.cfg', '.ini', '.toml',
    '.yaml', '.yml',
    '.rb', '.go', '.java', '.php', '.cs', '.kt',
    '.tf', '.hcl', '.conf', '.config', '.properties',
    '.xml',
    '.pem', '.key', '.crt',           # M1: standalone PEM / key / cert files
    '.txt',  # notes/scratch files — measured clean on prose and
             # sha256-pinned requirements; a real leak vector (2.4.1)
}

# M1: extensionless private-key files, matched by name in should_scan_file.
KEY_FILENAMES = {'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519'}

# Directories / files to skip entirely
SKIP_DIRS = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', '.tox',
             '.mypy_cache', '.pytest_cache', 'dist', 'build', '.eggs',
             '.idea', '.vscode', '.vs'}
SKIP_FILES = {'package-lock.json', 'yarn.lock', 'poetry.lock', 'pnpm-lock.yaml'}

# ---------------------------------------------------------------------------
# Placeholder / safe values – findings with these values are suppressed
# ---------------------------------------------------------------------------
SAFE_VALUES = {
    '', 'xxxxx', 'your_key_here', 'your_api_key', 'replace_me',
    'changeme', 'placeholder', 'none', 'null', 'true', 'false',
    'todo', '<your_key>', '<api_key>', 'example', 'test', 'dummy',
    'your_secret', 'your_token', 'your_password', 'enter_here',
    'your_client_id', 'your_client_secret', 'your_tenant_id',
    'xxxx', 'xxxxxx', 'xxxxxxx', 'xxxxxxxx',
    'redacted_by_credactor',
    # Test/mock/fake prefixed values
    'test_password', 'mock_password', 'fake_password',
    'test_api_key', 'mock_api_key', 'fake_api_key',
    'test_secret', 'mock_secret', 'fake_secret',
    'test_token', 'mock_token', 'fake_token',
    # Common .env.example placeholders
    'change_this', 'replace_this', 'update_me', 'set_me',
    'fill_in', 'add_your_key', 'put_your_key_here',
}

# ---------------------------------------------------------------------------
# Dynamic / runtime secret-retrieval patterns
# Lines containing these patterns fetch secrets at runtime — not hardcoded.
# Addresses #20: added Vault and SOPS patterns.
# ---------------------------------------------------------------------------
DYNAMIC_LOOKUP_RE = re.compile(
    r'(?:'
    r'Variable\.get'                     # Apache Airflow Variable store
    r'|os\.getenv'                       # os.getenv('KEY')
    r'|os\.environ(?:\.get)?\s*[\[({]'  # os.environ['KEY'] / os.environ.get(
    r'|environ\.get\s*\('               # environ.get(
    r'|getenv\s*\('                      # standalone getenv(
    r'|config\.get\s*\('                # config.get(
    r'|settings\.get\s*\('              # settings.get(
    r'|SecretClient.*\.get_secret'       # Azure Key Vault
    r'|boto3.*\.get_secret'             # AWS Secrets Manager
    r'|keyring\.get_password'           # system keyring
    # #20 – Hashicorp Vault / SOPS
    r'|vault:secret/'                   # Vault secret reference
    r'|ENC\[AES256_GCM,'               # SOPS-encrypted value
    r'|hvac\.Client'                    # Hashicorp Vault Python client
    r'|Vault\.read\s*\('               # Vault read call
    # Runtime env lookups across languages
    r'|process\.env\.'                  # JS/Node: process.env.VAR
    r'|Rails\.application\.credentials' # Ruby on Rails encrypted credentials
    # Terraform / HCL references
    r'|data\.\w+'                       # Terraform: any data.* source
    r'|var\.\w+'                        # Terraform: var.name references
    r'|local\.\w+'                      # Terraform: local.* values
    r'|module\.\w+'                     # Terraform: module.* outputs
    r'|random_password\.\w+'            # Terraform: random_password resource
    # Platform-specific runtime lookups
    r'|BuildConfig\.\w+'               # Android/Kotlin: compile-time constants
    r'|op://[\w/]+'                     # 1Password CLI: op://vault/item/field
    r'|doppler\.get\s*\('              # Doppler SDK
    r'|infisical\.get\s*\('            # Infisical SDK
    r'|SecretManager.*\.access_secret'  # GCP Secret Manager
    r'|config\.require_secret\s*\('    # Pulumi secret config
    r')',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Suspicious variable name patterns (case-insensitive)
# ---------------------------------------------------------------------------
CRED_VAR_PATTERNS = re.compile(
    r'\b('
    # prefix-tolerant like `secret` below: \b cannot match after '_', so
    # test_api_key / my_api_key / aws_api_key need the explicit optional
    # prefix (which demands a _/- separator — okapi_key stays unmatched).
    # The old standalone `apikey` alternative is subsumed.
    r'(?:\w+[_\-])?api[_\-]?key|api[_\-]?token|'
    r'auth[_\-]?token|access[_\-]?token|bearer[_\-]?token|'
    r'client[_\-]?secret|secret[_\-]?key|app[_\-]?secret|'
    r'(?:\w+[_\-])?secret(?:[_\-]\w+)?|'
    r'private[_\-]?key|signing[_\-]?key|'
    r'password|passwd|passphrase|pwd|'
    r'access[_\-]?key|access[_\-]?id|secret[_\-]?id|'
    r'client[_\-]?id|tenant[_\-]?id|app[_\-]?id|'
    r'ssh[_\-]?key|encryption[_\-]?key|'
    r'db[_\-]?password|database[_\-]?password|'
    r'db[_\-]?pass|db[_\-]?pwd|'
    r'postgres[_\-]?password|mysql[_\-]?(?:root[_\-]?)?password|'
    r'mongo[_\-]?(?:uri|url|password)|redis[_\-]?(?:url|password)|'
    r'database[_\-]?url|db[_\-]?(?:url|uri)|db[_\-]?conn(?:ection)?(?:[_\-]?string)?|'
    r'smtp[_\-]?password|mail[_\-]?password|'
    r'webhook[_\-]?secret|bot[_\-]?token|'
    r'consumer[_\-]?key|consumer[_\-]?secret|'
    # bare `token` last: a literal alternative only — \b cannot match after
    # '_' or inside camelCase, so snake/camel compounds (csrf_token,
    # next_page_token, pageToken, max_tokens) stay unmatched; a
    # prefix-tolerant variant that would catch them was rejected. \b DOES
    # match after '-'/'.' though, so kebab keys flag: vault-token /
    # session-token / id-token are genuine secrets (fail-closed), at the
    # accepted cost that kebab cursors (next-page-token:) with high-entropy
    # values flag too — suppressible via the usual mechanisms; see tests.
    r'refresh[_\-]?token|oauth[_\-]?token|token'
    r')\b',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# High-value credential value patterns — (regex, label, min_entropy, severity)
# #19: Added GCP, Stripe, Slack, GitHub, GitLab, npm, PyPI prefixes.
# #17: Added connection string pattern.
# #18: Added PEM private key header.
# ---------------------------------------------------------------------------
_JWT_RE = re.compile(
    r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
)
_AWS_RE = re.compile(
    r'\b(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b'
)
_HEX_RE = re.compile(r'\b[0-9a-fA-F]{32,64}\b')
_B64_RE = re.compile(r'[A-Za-z0-9+/=_\-]{60,}')

# #19 – Provider-specific token prefixes (deterministic, near-zero false positives)
_GCP_RE = re.compile(r'\bAIza[0-9A-Za-z_-]{35}\b')
_STRIPE_LIVE_RE = re.compile(r'\b[sr]k_live_[0-9a-zA-Z]{24,}\b')
_STRIPE_TEST_RE = re.compile(r'\b[sr]k_test_[0-9a-zA-Z]{24,}\b')
_SLACK_RE = re.compile(r'\bxox[bpsa]-[0-9A-Za-z-]{10,}\b')
_GITHUB_RE = re.compile(
    r'\b(?:ghp_|gho_|ghs_|ghu_|github_pat_)[0-9A-Za-z_]{16,}\b'
)
_GITLAB_RE = re.compile(r'\bglpat-[0-9A-Za-z_-]{20,}\b')
_NPM_RE = re.compile(r'\bnpm_[0-9a-zA-Z]{36}\b')
_PYPI_RE = re.compile(r'\bpypi-[0-9a-zA-Z_-]{16,}\b')

# #17 – Connection strings with embedded credentials (scheme://user:pass@host)
_CONN_STRING_RE = re.compile(
    r'[a-zA-Z][a-zA-Z0-9+.-]*://[^:@\s]+:[^@\s]+@[^\s"\']{3,}'
)

# #18 – PEM private key header
_PEM_KEY_RE = re.compile(r'-----BEGIN\s+(?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')

# severity: critical > high > medium > low
class ValuePattern(NamedTuple):
    pattern: re.Pattern[str]
    label: str
    min_entropy: float
    severity: Severity


VALUE_PATTERNS: list[ValuePattern] = [
    # Deterministic provider prefixes — critical severity. L12: min_entropy 0.0
    # because the fixed prefix + length already constrains the format, so the
    # entropy gate is redundant and would otherwise drop a format-valid but
    # low-entropy leaked token (a prefix + all-constant body). Matches the PEM
    # row, which already uses 0.0. Intentional FP-over-FN tradeoff: format-valid
    # placeholders (e.g. an AKIA + constant body in a .env.example) are also
    # flagged — a false positive is noise, a missed live key is a leak. Suppress
    # known placeholders via .credactorignore.
    ValuePattern(_AWS_RE,          'AWS access key',       0.0, 'critical'),
    ValuePattern(_GCP_RE,          'GCP API key',          0.0, 'critical'),
    ValuePattern(_STRIPE_LIVE_RE,  'Stripe live key',      0.0, 'critical'),
    ValuePattern(_GITHUB_RE,       'GitHub token',         0.0, 'critical'),
    ValuePattern(_GITLAB_RE,       'GitLab token',         0.0, 'critical'),
    ValuePattern(_SLACK_RE,        'Slack token',          0.0, 'critical'),
    ValuePattern(_NPM_RE,          'npm token',            0.0, 'critical'),
    ValuePattern(_PYPI_RE,         'PyPI token',           0.0, 'critical'),
    ValuePattern(_PEM_KEY_RE,      'private key header',   0.0, 'critical'),
    # Structural patterns — high severity
    ValuePattern(_JWT_RE,          'JWT token',            3.3, 'high'),
    ValuePattern(_CONN_STRING_RE,  'connection string',    2.5, 'high'),
    ValuePattern(_STRIPE_TEST_RE,  'Stripe test key',      3.0, 'medium'),
    # Heuristic patterns — medium/low severity
    ValuePattern(_HEX_RE,          'hex credential',       3.5, 'medium'),
    ValuePattern(_B64_RE,          'high-entropy string',  3.8, 'low'),
]

# ---------------------------------------------------------------------------
# Assignment detection — variable/key name on the left, value on the right
# #13: Fixed greedy capture for unquoted values.
# #21: Added XML attribute pattern.
# ---------------------------------------------------------------------------

# Standard assignment: VAR = "value" / VAR = 'value' / "key": "value"
# #13 fix: quoted values capture up to closing quote; unquoted values stop
# at whitespace or comment characters.
ASSIGNMENT_RE = re.compile(
    r'''
        ["']?                          # optional quote around key name
        (?P<var>[\w.\-]{1,128})        # variable or key name — bounded: no real
                                       # name is longer, and an unbounded + here
                                       # backtracks quadratically on a 4 KiB
                                       # unbroken word run (~280 ms per line)
        ["']?                          # optional closing quote around key name
        \s*(?::=|[:=])\s*              # assignment, dict colon, or Go := (M4)
        (?:
            (?P<q>["'])                # opening quote
            (?P<val_q>(?:(?!(?P=q)).)+)  # value: everything up to matching quote
            (?P=q)                     # closing quote
        |
            (?P<val_u>
                \$\{[A-Za-z_][A-Za-z0-9_]*\}   # complete ${POSIX_NAME}: keep the
                                               # closing brace so the safe-value
                                               # check sees a closed env ref —
                                               # ONLY the pure-name form; ${VAR:-x}
                                               # must keep arriving unclosed (the
                                               # fallback can be a real secret)
            |
                [^\s#;,\]}"']+         # unquoted: stop at whitespace/comment/delimiters/quotes
            )
        )
    ''',
    re.VERBOSE,
)

# #21 – XML attribute: <... key="Password" value="secret" ...>
# Supports both orderings: key/name before or after value.
_XML_KEY_FIRST = re.compile(
    r'<[^>]*?\b(?:key|name)\s*=\s*["\'](?P<xml_key>[^"\']+)["\']'
    r'[^>]*?\bvalue\s*=\s*["\'](?P<xml_val>[^"\']+)["\']',
    re.IGNORECASE,
)
_XML_VAL_FIRST = re.compile(
    r'<[^>]*?\bvalue\s*=\s*["\'](?P<xml_val>[^"\']+)["\']'
    r'[^>]*?\b(?:key|name)\s*=\s*["\'](?P<xml_key>[^"\']+)["\']',
    re.IGNORECASE,
)


def xml_attr_finditer(line: str) -> Iterator[tuple[str, str, tuple[int, int]]]:
    """Yield ``(xml_key, xml_val, val_span)`` from XML attribute matches in
    either order. ``val_span`` is the ``(start, end)`` of the value within
    *line*, used by the scanner's per-line span dedup (L2)."""
    # Hot-path guard: both patterns anchor on '<', so a line without it can never
    # match — skip the two regex passes on the overwhelming majority of lines.
    if '<' not in line:
        return
    seen = set()
    for pattern in (_XML_KEY_FIRST, _XML_VAL_FIRST):
        for m in pattern.finditer(line):
            key, val = m.group('xml_key'), m.group('xml_val')
            if (key, val) not in seen:
                seen.add((key, val))
                yield key, val, m.span('xml_val')

# ---------------------------------------------------------------------------
# Inline suppression comment pattern (#3)
# ---------------------------------------------------------------------------
# The directive must immediately follow a comment opener (only whitespace
# between), so a bare prose/string mention of "credactor:ignore" no longer
# silences a real secret on the same line.  Openers cover every scanned
# language's comment syntax (#, //, /*, <!--); SQL `--` is intentionally
# excluded — no scanned file type uses it and it recurs in non-comment text.
SUPPRESS_RE = re.compile(r'(?:#|//|/\*|<!--)\s*credactor:\s*ignore', re.IGNORECASE)
