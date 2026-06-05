"""
Regex patterns, constants, and safe-value lists for credential detection.

Addresses: #17 (connection strings), #18 (PEM keys), #19 (provider prefixes),
           #20 (Vault/SOPS dynamic lookups), #21 (XML attributes)
"""

import re

# ---------------------------------------------------------------------------
# File types to scan
# ---------------------------------------------------------------------------
SCAN_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.sh', '.bash',
    '.env', '.cfg', '.ini', '.toml',
    '.yaml', '.yml',
    '.rb', '.go', '.java', '.php', '.cs', '.kt',
    '.tf', '.hcl', '.conf', '.properties',
    '.xml',
}

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
    r'(?i)\b('
    r'api[_\-]?key|apikey|api[_\-]?token|'
    r'auth[_\-]?token|access[_\-]?token|bearer[_\-]?token|'
    r'client[_\-]?secret|secret[_\-]?key|app[_\-]?secret|'
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
    r'refresh[_\-]?token|oauth[_\-]?token'
    r')\b'
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
VALUE_PATTERNS = [
    # Deterministic provider prefixes — critical severity
    (_AWS_RE,          'AWS access key',       3.0, 'critical'),
    (_GCP_RE,          'GCP API key',          3.0, 'critical'),
    (_STRIPE_LIVE_RE,  'Stripe live key',      3.0, 'critical'),
    (_GITHUB_RE,       'GitHub token',         3.0, 'critical'),
    (_GITLAB_RE,       'GitLab token',         3.0, 'critical'),
    (_SLACK_RE,        'Slack token',          3.0, 'critical'),
    (_NPM_RE,          'npm token',            3.0, 'critical'),
    (_PYPI_RE,         'PyPI token',           3.0, 'critical'),
    (_PEM_KEY_RE,      'private key header',   0.0, 'critical'),
    # Structural patterns — high severity
    (_JWT_RE,          'JWT token',            3.3, 'high'),
    (_CONN_STRING_RE,  'connection string',    2.5, 'high'),
    (_STRIPE_TEST_RE,  'Stripe test key',      3.0, 'medium'),
    # Heuristic patterns — medium/low severity
    (_HEX_RE,          'hex credential',       3.5, 'medium'),
    (_B64_RE,          'high-entropy string',  3.8, 'low'),
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
        (?P<var>[\w.\-]+)              # variable or key name
        ["']?                          # optional closing quote around key name
        \s*[:=]\s*                     # assignment or dict colon
        (?:
            (?P<q>["'])                # opening quote
            (?P<val_q>(?:(?!(?P=q)).)+)  # value: everything up to matching quote
            (?P=q)                     # closing quote
        |
            (?P<val_u>[^\s#;,\]}"']+)  # unquoted: stop at whitespace/comment/delimiters/quotes
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


def xml_attr_finditer(line: str):
    """Yield (xml_key, xml_val) from XML attribute matches in either order."""
    seen = set()
    for pattern in (_XML_KEY_FIRST, _XML_VAL_FIRST):
        for m in pattern.finditer(line):
            key, val = m.group('xml_key'), m.group('xml_val')
            if (key, val) not in seen:
                seen.add((key, val))
                yield key, val


# Keep for backward compat in tests
XML_ATTR_RE = _XML_KEY_FIRST

# ---------------------------------------------------------------------------
# Inline suppression comment pattern (#3)
# ---------------------------------------------------------------------------
# The directive must immediately follow a comment opener (only whitespace
# between), so a bare prose/string mention of "credactor:ignore" no longer
# silences a real secret on the same line.  Openers cover every scanned
# language's comment syntax (#, //, /*, <!--); SQL `--` is intentionally
# excluded — no scanned file type uses it and it recurs in non-comment text.
SUPPRESS_RE = re.compile(r'(?:#|//|/\*|<!--)\s*credactor:\s*ignore', re.IGNORECASE)
