"""
Core scanning logic: line-level and file-level credential detection.

Addresses: #3 (inline suppression in scan), #10 (multi-line awareness),
           #12 (severity), #13 (fixed ASSIGNMENT_RE), #15 (.env.* files),
           #18 (PEM key blocks)
"""

from __future__ import annotations

import re
from pathlib import Path

from ._log import logger
from .config import Config
from .patterns import (
    _PEM_KEY_RE,
    ASSIGNMENT_RE,
    CRED_VAR_PATTERNS,
    DYNAMIC_LOOKUP_RE,
    KEY_FILENAMES,
    SAFE_VALUES,
    SCAN_EXTENSIONS,
    VALUE_PATTERNS,
    xml_attr_finditer,
)
from .suppressions import AllowList, has_inline_suppression
from .types import Finding
from .utils import detect_encoding, entropy, log_verbose

# Global defaults (can be overridden by Config)
ENTROPY_THRESHOLD = 3.5
MIN_VALUE_LENGTH = 8

# Human-chosen password/secret variables hold memorable, lower-entropy values
# that are still real credentials, so they get a lower entropy floor (H7).
PASSWORD_ENTROPY_FLOOR = 3.0
_PASSWORD_VAR_KEYWORDS = ('password', 'passwd', 'passphrase', 'private_key', 'secret_key')

# Max lines to skip inside a PEM block before force-resetting
# (increased from 100 to 500 to accommodate large RSA/EC keys without
# false-resetting mid-block)
_MAX_PEM_BLOCK_LINES = 500

# Max file size to scan (bytes) — skip silently above this
_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

# Function call heuristic: identifier(...) complete call
_FUNC_CALL_RE = re.compile(
    r'^[a-zA-Z_][\w.]*\(.*\)$', re.DOTALL,
)

# Truncated function call: unquoted capture stopped mid-call, e.g. "func(arg,"
_FUNC_CALL_TRUNC_RE = re.compile(
    r'^[a-zA-Z_][\w.]*\([^)]*,?$',
)

# Dotted property access: self.config.password, context.config.apiKey
# Two or more dot-separated identifiers = runtime reference, not a literal.
# Each segment must start with a letter/underscore and be <=40 chars to
# avoid matching JWT tokens (Base64-encoded dot-separated segments).
_DOTTED_ACCESS_RE = re.compile(
    r'^[a-zA-Z_]\w{0,39}(?:\.[a-zA-Z_]\w{0,39}){1,}(?:\[.*\])?$',
)

# Placeholder words commonly found in example/template config values
_PLACEHOLDER_WORDS = {
    'change', 'replace', 'your', 'here', 'insert',
    'update', 'fill', 'set', 'put', 'add', 'todo',
    'fixme', 'example', 'sample', 'default', 'enter',
}

# Strong single-word indicators that never appear in real credentials
_STRONG_PLACEHOLDER_WORDS = frozenset({
    'changeme', 'placeholder', 'replace', 'fixme', 'todo', 'change', 'insert',
})

# Hash/encrypted value prefixes — these store derived values, not raw secrets
_HASH_PREFIX_RE = re.compile(
    r'^\$(?:2[aby]\$|argon2[id]{0,2}\$|scrypt\$|pbkdf2)',
)

# Variable name suffixes indicating stored hashes, not raw credentials
_HASH_VAR_SUFFIXES = (
    '_hash', '_hashed', '_digest', '_checksum',
    '_fingerprint', '_hmac', '_encrypted', '_cipher',
)

# Cap line length to prevent regex backtracking on adversarial input
# (e.g. minified JS, base64 blobs).  Real credentials never span 4 KiB.
_MAX_LINE_LENGTH = 4096

# Line-level context check: if the line assigns to a hash/digest variable,
# hex values on that line are likely hash outputs, not raw credentials
_HASH_CONTEXT_RE = re.compile(
    r'(?:_hash|_hashed|_digest|_checksum|_fingerprint|_hmac|sha\d+|md5)\s*[:=]',
    re.IGNORECASE,
)


def _preview(val: str, n: int = 60) -> str:
    return val[:n] + ('...' if len(val) > n else '')


def _is_safe_value(val: str, extra_safe: set[str] | None = None) -> bool:
    """Return True if the value is clearly NOT a real hardcoded credential."""
    raw = val.strip()
    cleaned = raw.lower().strip('"\'')

    safe = SAFE_VALUES | extra_safe if extra_safe else SAFE_VALUES
    if cleaned in safe:
        return True

    # Environment variable / template references.
    # Require matching closing delimiters for brace syntax to prevent
    # false negatives on values like "${AKIA..." (unclosed brace).
    # Bare $VAR and $VAR_NAME (no braces) are safe — they're env var names.
    if cleaned.startswith('${{') and '}}' in cleaned:
        return True
    if cleaned.startswith('${') and '}' in cleaned:
        return True
    if cleaned.startswith('$') and not cleaned.startswith('${'):
        # Bare $VAR — validate that the text after $ begins with a
        # plausible POSIX env var name ([A-Za-z_][A-Za-z0-9_]*).  Uses
        # re.match (prefix) rather than fullmatch so that dynamic references
        # with suffixes ($HOME/.aws/credentials, $TOKEN:prefix, $VAR-suffix)
        # remain safe while pure non-identifier strings ($+foo, $/path,
        # $123abc) are correctly rejected.
        env_name = cleaned[1:]
        if env_name and re.match(r'[A-Za-z_][A-Za-z0-9_]*', env_name):
            return True
    if cleaned.startswith('{%') and '%}' in cleaned:
        return True
    if cleaned.startswith('{{') and '}}' in cleaned:
        return True

    # 1Password CLI secret reference: op://vault/item/field
    if cleaned.startswith('op://'):
        return True

    # HashiCorp Vault secret reference: vault:secret/path or vault://...
    if cleaned.startswith('vault:'):
        return True

    # Function call: full value looks like identifier(...)
    # e.g. get_secret(), Variable.get("key"), os.getenv("X")
    # Also catch truncated calls like "generate_password(length," where
    # the unquoted capture stopped at a space mid-argument list.
    if _FUNC_CALL_RE.match(raw) or _FUNC_CALL_TRUNC_RE.match(raw):
        return True

    # Dotted property access: self.config.password, context.config.apiKey
    # Runtime references, not hardcoded values
    if _DOTTED_ACCESS_RE.match(raw):
        return True

    # File paths: ./, ~/, Windows drive letter
    # NOTE: bare / prefix is NOT safe (could hide creds); require ./ or ~/
    if (cleaned.startswith('./')
            or cleaned.startswith('~/')
            or (len(cleaned) >= 3 and cleaned[1:3] in (':\\', ':/'))):
        return True

    # URLs without embedded credentials
    if '://' in cleaned and '@' not in cleaned and cleaned.startswith(('http', 'ftp')):
        return True

    # Path-like strings: require high slash density (>20%) AND at least
    # 3 slashes to reduce false negatives
    slash_count = raw.count('/')
    if slash_count >= 3 and (slash_count / max(len(raw), 1)) > 0.20:
        return True

    # Placeholder heuristic: values containing placeholder words
    # e.g. "change_this_password", "replace_your_key_here"
    tokens = set(cleaned.replace('_', ' ').replace('-', ' ').split())
    matches = tokens & _PLACEHOLDER_WORDS
    if len(matches) >= 2:
        return True
    # Strong single-word indicators (never appear in real credentials)
    if matches & _STRONG_PLACEHOLDER_WORDS:
        return True

    # Hashed/encrypted values: bcrypt, argon2, scrypt prefixes
    return bool(_HASH_PREFIX_RE.match(cleaned))


def _is_password_family(var_name: str) -> bool:
    """True for variables whose name marks a human-chosen password/secret, where
    a memorable (lower-entropy) value is still a real credential (H7)."""
    low = var_name.lower()
    return any(kw in low for kw in _PASSWORD_VAR_KEYWORDS)


def _severity_for_variable(var_name: str) -> str:
    """Assign severity based on the variable name pattern."""
    low = var_name.lower()
    if any(kw in low for kw in _PASSWORD_VAR_KEYWORDS):
        return 'high'
    if any(kw in low for kw in ('token', 'api_key', 'apikey', 'access_key')):
        return 'high'
    if any(kw in low for kw in ('client_id', 'tenant_id', 'app_id')):
        return 'low'
    return 'medium'


def scan_line(
    lineno: int,
    line: str,
    filepath: str,
    *,
    config: Config | None = None,
    allowlist: AllowList | None = None,
) -> list[Finding]:
    """Analyse a single line and return a list of credential findings."""
    findings: list[Finding] = []
    stripped = line.strip()

    if not stripped:
        return findings

    # #3 — inline suppression
    if has_inline_suppression(line):
        log_verbose(config, f'{filepath}:{lineno} suppressed by inline credactor:ignore')
        return findings

    if len(line) > _MAX_LINE_LENGTH:
        line = line[:_MAX_LINE_LENGTH]
        stripped = line.strip()

    ent_threshold = config.entropy_threshold if config else ENTROPY_THRESHOLD
    min_len = config.min_value_length if config else MIN_VALUE_LENGTH
    extra_safe = config.extra_safe_values if config else None

    is_comment = stripped.startswith('#') or stripped.startswith('//')

    # --- 1. High-value VALUE_PATTERNS scan ---
    for pattern, label, min_ent, severity in VALUE_PATTERNS:
        # M3: on comment lines, scan only the deterministic provider prefixes
        # (critical severity — AWS/GCP/Stripe-live/GitHub/.../PEM, near-zero
        # false positives) so a commented-out live key is still caught. The
        # heuristic/structural patterns (hex, base64, JWT, connection string)
        # stay code-only so example strings in prose comments don't false-flag.
        if is_comment and severity != 'critical':
            continue
        for match in pattern.finditer(line):
            val = match.group(0)

            # high-entropy / hex credential: additional path/slash guard
            if label in ('high-entropy string', 'hex credential'):
                if val.count('/') > 2:
                    continue
                start = match.start()
                if start == 0 or line[start - 1] not in ('"', "'"):
                    continue

            # hex/high-entropy: skip if line contains hash/digest variable
            is_hex_like = label in ('hex credential', 'high-entropy string')
            if is_hex_like and _HASH_CONTEXT_RE.search(line):
                log_verbose(config, f'{filepath}:{lineno} suppressed by hash context')
                continue

            if _is_safe_value(val, extra_safe):
                log_verbose(config, f'{filepath}:{lineno} suppressed by safe value heuristic')
                continue
            if len(val) < min_len and label != 'private key header':
                continue
            if min_ent > 0 and entropy(val) < min_ent:
                continue

            # Allowlist check
            if allowlist and allowlist.is_suppressed(filepath, lineno, val):
                log_verbose(config, f'{filepath}:{lineno} suppressed by allowlist')
                continue

            findings.append({
                'file':          filepath,
                'line':          lineno,
                'type':          f'pattern:{label}',
                'severity':      severity,
                'full_value':    val,
                'value_preview': _preview(val),
                'raw':           line.rstrip(),
            })
        if findings:
            return findings

    # --- 2. XML attribute check (#21) ---
    if not is_comment:
        for xml_key, xml_val in xml_attr_finditer(line):
            if not CRED_VAR_PATTERNS.search(xml_key):
                continue
            if _is_safe_value(xml_val, extra_safe):
                log_verbose(config, f'{filepath}:{lineno} suppressed by safe value heuristic')
                continue
            if len(xml_val.strip()) < min_len:
                continue
            if entropy(xml_val.strip()) < ent_threshold:
                continue
            if allowlist and allowlist.is_suppressed(filepath, lineno, xml_val):
                log_verbose(config, f'{filepath}:{lineno} suppressed by allowlist')
                continue
            findings.append({
                'file':          filepath,
                'line':          lineno,
                'type':          f'xml-attr:{xml_key}',
                'severity':      _severity_for_variable(xml_key),
                'full_value':    xml_val,
                'value_preview': _preview(xml_val),
                'raw':           line.rstrip(),
            })
        if findings:
            return findings

    # --- 3. Assignment check ---
    if is_comment and '=' not in line and ':' not in line:
        return findings
    if is_comment and any(kw in stripped for kw in ('def ', 'async def ', 'class ')):
        return findings

    if stripped.startswith(('def ', 'async def ', 'class ')):
        return findings

    if DYNAMIC_LOOKUP_RE.search(line):
        return findings

    for match in ASSIGNMENT_RE.finditer(line):
        var = match.group('var')
        # #13 fix: use the correct capture group (quoted vs unquoted)
        val = match.group('val_q') or match.group('val_u') or ''

        if not CRED_VAR_PATTERNS.search(var):
            continue
        # Skip hash/digest/checksum storage — these are derived values
        low_var = var.lower()
        if any(low_var.endswith(s) for s in _HASH_VAR_SUFFIXES):
            continue
        if _is_safe_value(val, extra_safe):
            log_verbose(config, f'{filepath}:{lineno} suppressed by safe value heuristic')
            continue
        val_stripped = val.strip()
        if len(val_stripped) < min_len:
            continue
        # H7: a password-family variable gets a lower entropy floor so memorable
        # weak passwords (e.g. "Summer2024!") are not silently dropped.
        floor = (min(ent_threshold, PASSWORD_ENTROPY_FLOOR)
                 if _is_password_family(var) else ent_threshold)
        if entropy(val_stripped) < floor:
            continue
        if allowlist and allowlist.is_suppressed(filepath, lineno, val_stripped):
            log_verbose(config, f'{filepath}:{lineno} suppressed by allowlist')
            continue

        findings.append({
            'file':          filepath,
            'line':          lineno,
            'type':          f'variable:{var}',
            'severity':      _severity_for_variable(var),
            'full_value':    val_stripped,
            'value_preview': _preview(val_stripped),
            'raw':           line.rstrip(),
        })

    return findings


def scan_file(
    filepath: str,
    *,
    config: Config | None = None,
    allowlist: AllowList | None = None,
) -> list[Finding]:
    """Scan a single file for credential findings.
    """
    findings: list[Finding] = []

    #file size guard to prevent OOM on huge files | Hard-Cap at 50MB
    try:
        file_size = Path(filepath).stat().st_size
        if file_size > _MAX_FILE_SIZE:
            logger.warning(
                'Skipping %s: file too large (%.1f MB > %.0f MB limit)',
                filepath, file_size / 1024 / 1024, _MAX_FILE_SIZE / 1024 / 1024,
            )
            return findings
    except OSError:
        pass  # proceed; open() will fail with a better message

    # detect encoding
    encoding = detect_encoding(filepath)

    try:
        with open(filepath, encoding=encoding, errors='surrogateescape') as fh:
            lines = fh.readlines()
    except OSError as exc:
        # Re-raise so the caller (walker._parallel_scan / the cli single-file and
        # --scan-json branches) records this in errored_files; otherwise
        # --fail-on-error silently passes over files it could not read.
        logger.warning('Cannot read %s: %s', filepath, exc)
        raise

    # Strip BOM from first line if present
    if lines and lines[0].startswith('\ufeff'):
        lines[0] = lines[0][1:]

    # PEM private key block detection (multi-line)
    in_pem_block = False
    pem_block_lines = 0
    for lineno, line in enumerate(lines, start=1):
        if _PEM_KEY_RE.search(line):
            in_pem_block = True
            pem_block_lines = 0
            # Check suppression — still skip body lines even if header suppressed
            if has_inline_suppression(line):
                continue
            if allowlist and allowlist.is_suppressed(filepath, lineno, line.strip()):
                continue
            findings.append({
                'file':          filepath,
                'line':          lineno,
                'type':          'pattern:private key block',
                'severity':      'critical',
                'full_value':    line.strip(),
                'value_preview': _preview(line.strip()),
                'raw':           line.rstrip(),
            })
        elif in_pem_block and '-----END' in line and 'PRIVATE KEY' in line:
            in_pem_block = False
            pem_block_lines = 0
        elif in_pem_block:
            pem_block_lines += 1
            if pem_block_lines > _MAX_PEM_BLOCK_LINES:
                in_pem_block = False
                pem_block_lines = 0
                logger.warning(
                    '%s:%d: unclosed PEM block (>%d lines) — resuming scan',
                    filepath, lineno, _MAX_PEM_BLOCK_LINES,
                )
                findings.extend(scan_line(lineno, line, filepath,
                                          config=config, allowlist=allowlist))
            else:
                continue  # skip lines inside PEM block
        else:
            findings.extend(scan_line(lineno, line, filepath,
                                      config=config, allowlist=allowlist))

    # basic multi-line detection: triple-quoted strings in Python
    _scan_multiline_strings(filepath, lines, findings, config, allowlist)

    return findings


def _scan_multiline_strings(
    filepath: str,
    lines: list[str],
    existing_findings: list[Finding],
    config: Config | None,
    allowlist: AllowList | None,
) -> None:
    """Detect credentials inside triple-quoted strings and JS template literals.
    This is a best-effort heuristic: it concatenates the contents of multi-line
    string blocks and runs the value-pattern scan on the combined text.
    """
    already_flagged = {f['line'] for f in existing_findings}
    min_len = config.min_value_length if config else MIN_VALUE_LENGTH
    extra_safe = config.extra_safe_values if config else None

    # Find triple-quote blocks (Python) and template literal blocks (JS/TS)
    delimiters = [('"""', '"""'), ("'''", "'''"), ('`', '`')]

    full_text = ''.join(lines)

    # Cap multiline block size to prevent ReDoS on huge triple-quoted strings
    _MAX_BLOCK_SIZE = 8192

    for open_delim, close_delim in delimiters:
        start = 0
        while True:
            idx = full_text.find(open_delim, start)
            if idx < 0:
                break
            end_idx = full_text.find(close_delim, idx + len(open_delim))
            if end_idx < 0:
                break  # no more closing delimiters — done with this delimiter type
            block = full_text[idx + len(open_delim):end_idx]
            if len(block) > _MAX_BLOCK_SIZE:
                block = block[:_MAX_BLOCK_SIZE]
            # Determine line number of the opening delimiter
            block_lineno = full_text[:idx].count('\n') + 1
            if block_lineno in already_flagged:
                start = end_idx + len(close_delim)
                continue

            # Run value patterns on the block
            for pattern, label, min_ent, severity in VALUE_PATTERNS:
                for match in pattern.finditer(block):
                    val = match.group(0)
                    if _is_safe_value(val, extra_safe):
                        continue
                    if len(val) < min_len and label != 'private key header':
                        continue
                    if min_ent > 0 and entropy(val) < min_ent:
                        continue
                    if allowlist and allowlist.is_suppressed(filepath, block_lineno, val):
                        continue
                    existing_findings.append({
                        'file':          filepath,
                        'line':          block_lineno,
                        'type':          f'multiline:{label}',
                        'severity':      severity,
                        'full_value':    val,
                        'value_preview': _preview(val),
                        'raw':           block.replace('\n', '\\n')[:120],
                    })
                    break  # one finding per block is enough

            start = end_idx + len(close_delim)


def should_scan_file(
    filename: str,
    extra_extensions: set[str] | None = None,
) -> bool:
    """Return True if the filename's extension (or name) is in the scan list.
    """
    p = Path(filename)
    suffix = p.suffix.lower() or p.name.lower()

    extensions = SCAN_EXTENSIONS | extra_extensions if extra_extensions else SCAN_EXTENSIONS
    if suffix in extensions:
        return True

    # M1: extensionless private-key files (id_rsa, id_ed25519, ...)
    if p.name.lower() in KEY_FILENAMES:
        return True

    # .env.* variants: .env.local, .env.staging, .env.production
    name_lower = p.name.lower()
    if name_lower == '.env' or name_lower == 'env':
        return True
    return name_lower.startswith('.env.') or name_lower.startswith('.env-')
