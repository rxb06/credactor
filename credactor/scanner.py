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
from .config import ENTROPY_DEFAULT, MIN_LEN_DEFAULT, Config
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
from .types import SEVERITY_RANK, Finding
from .utils import entropy, preview, read_lines

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
    r'^[a-zA-Z_][\w.]*\(.*\)$',
    re.DOTALL,
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
    'change',
    'replace',
    'your',
    'here',
    'insert',
    'update',
    'fill',
    'set',
    'put',
    'add',
    'todo',
    'fixme',
    'example',
    'sample',
    'default',
    'enter',
}

# Strong single-word indicators that never appear in real credentials
_STRONG_PLACEHOLDER_WORDS = frozenset(
    {
        'changeme',
        'placeholder',
        'replace',
        'fixme',
        'todo',
        'change',
        'insert',
    }
)

# Hash/encrypted value prefixes — these store derived values, not raw secrets
_HASH_PREFIX_RE = re.compile(
    r'^\$(?:2[aby]\$|argon2[id]{0,2}\$|scrypt\$|pbkdf2)',
)

# Variable name suffixes indicating stored hashes, not raw credentials
_HASH_VAR_SUFFIXES = (
    '_hash',
    '_hashed',
    '_digest',
    '_checksum',
    '_fingerprint',
    '_hmac',
    '_encrypted',
    '_cipher',
)

# Cap line length to prevent regex backtracking on adversarial input
# (e.g. minified JS, base64 blobs).  Real credentials never span 4 KiB.
_MAX_LINE_LENGTH = 4096

# Cap multiline block size to prevent ReDoS on huge triple-quoted strings.
_MAX_BLOCK_SIZE = 8192

# Key-scoped context check: a hex/base64 value whose OWN assignment key looks
# like a hash/digest/checksum/commit/integrity/revision field is a hash output,
# not a raw credential, so the quoted hex/Base64 value detectors skip it. S3: the
# widened name set stops --fix-all auto-rewriting commit SHAs, SRI integrity
# hashes, and checksums (which would silently corrupt code).
#
# SCAN-1: the terms are matched against the key bound to the matched value only
# (extracted by _HASH_KEY_RE), NOT line-global, so (a) a hash key on one part of
# a multi-assignment line cannot suppress an unrelated secret elsewhere, and (b)
# a credential keyword in the key (see _CRED_KEYWORDS) vetoes the suppression so
# api_key_rev / token_rev / private_key_rev / oauth_token_sri / api_key_commit
# still flag — the credential keyword takes precedence (matches the manual).
_HASH_CONTEXT_RE = re.compile(
    r'(?:_hash|_hashed|_digest|_checksum|_fingerprint|_hmac|sha\d+|md5'
    r'|commit|integrity|checksum|digest|rev|sri)$',
    re.IGNORECASE,
)

# Capture the assignment key immediately preceding a value's opening quote, i.e.
# the trailing `KEY :=/=/:` of the text before the value. Anchored at the end so
# it isolates the single key bound to THIS value on a multi-assignment line.
_HASH_KEY_RE = re.compile(
    r'["\']?(?P<key>[\w.\-]{1,128})["\']?\s*(?::=|[:=])\s*$',
)

# SCAN-1: credential keywords whose presence ANYWHERE in the key vetoes the
# hash-context suppression (the credential keyword takes precedence per the
# manual). These are plain substrings — unlike CRED_VAR_PATTERNS' \b-anchored
# alternatives — so a credential-keyed name with a hash-ish suffix such as
# api_key_rev / token_rev / private_key_rev / oauth_token_sri / api_key_commit /
# token_integrity is correctly NOT treated as a hash and flags again (as on
# origin/main). None of the genuine hash keys (commit/checksum/digest/integrity/
# md5/sha256/*_hash/git_rev) contains one of these, so they still suppress.
_CRED_KEYWORDS = (
    'api',
    'key',
    'token',
    'secret',
    'password',
    'passwd',
    'passphrase',
    'pwd',
    'auth',
    'cred',
    'oauth',
    'private',
    'bearer',
)

# The two entropy-based value detectors share the same extra guards (path/slash +
# quote-prefix, then hash-context suppression). Named once so the guard block and
# its membership test cannot drift apart.
_HEURISTIC_VALUE_LABELS = ('hex credential', 'high-entropy string')

# POSIX env var name — used by the bare $VAR safe-value check.
_ENV_VAR_NAME_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')


def _is_safe_value(
    val: str,
    extra_safe: set[str] | None = None,
    *,
    skip_dotted_access: bool = False,
    safe_values: set[str] | None = None,
) -> bool:
    """Return True if the value is clearly NOT a real hardcoded credential.

    ``skip_dotted_access`` (L1): when True, the dotted-property-access heuristic
    is bypassed. A compact JWT whose three segments are each <=40 chars matches
    ``_DOTTED_ACCESS_RE`` and would be wrongly treated as runtime access; the
    caller sets this only for values already matched by the deterministic JWT
    regex, so ordinary dotted access (``self.config.password``) is unaffected.

    ``safe_values`` is the pre-merged ``SAFE_VALUES | extra_safe`` set; the hot
    path passes it so the union isn't rebuilt per candidate (#34). When omitted
    the union is computed from ``extra_safe`` (preserves the simple call API).
    """
    raw = val.strip()
    cleaned = raw.lower().strip('"\'')

    safe = (
        safe_values
        if safe_values is not None
        else (SAFE_VALUES | extra_safe if extra_safe else SAFE_VALUES)
    )
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
        if env_name and _ENV_VAR_NAME_RE.match(env_name):
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
    if not skip_dotted_access and _DOTTED_ACCESS_RE.match(raw):
        return True

    # File paths: ./, ~/, Windows drive letter
    # NOTE: bare / prefix is NOT safe (could hide creds); require ./ or ~/
    if cleaned.startswith(('./', '~/')) or (len(cleaned) >= 3 and cleaned[1:3] in (':\\', ':/')):
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


def _is_hash_context_at(line: str, value_start: int) -> bool:
    """True if the heuristic hex/Base64 value at ``value_start`` is keyed like a
    hash/digest/commit/integrity field (a hash output, not a raw credential).

    SCAN-1: the key is taken from the single assignment immediately preceding the
    value's opening quote — scoped to THIS value, not line-global — so a hash key
    elsewhere on a multi-assignment line cannot suppress an unrelated secret. A
    credential keyword anywhere in the key vetoes the suppression (the credential
    keyword takes precedence), so api_key_rev / token_rev / private_key_rev /
    oauth_token_sri / api_key_commit still flag as on origin/main."""
    key_match = _HASH_KEY_RE.search(line[:value_start])
    if key_match is None:
        return False
    key = key_match.group('key').lower()
    if any(kw in key for kw in _CRED_KEYWORDS):
        return False
    return bool(_HASH_CONTEXT_RE.search(key))


def _severity_for_variable(var_name: str) -> str:
    """Assign severity based on the variable name pattern."""
    low = var_name.lower()
    if _is_password_family(var_name):
        return 'high'
    if any(kw in low for kw in ('token', 'api_key', 'apikey', 'access_key')):
        return 'high'
    if any(kw in low for kw in ('client_id', 'tenant_id', 'app_id')):
        return 'low'
    return 'medium'


def _make_finding(
    filepath: str,
    lineno: int,
    *,
    type: str,
    severity: str,
    value: str,
    raw: str,
) -> Finding:
    """Build the shared 7-key Finding dict (preview computed once via utils)."""
    return {
        'file': filepath,
        'line': lineno,
        'type': type,
        'severity': severity,
        'full_value': value,
        'value_preview': preview(value),
        'raw': raw,
    }


def _evaluate_candidate(
    val: str,
    *,
    min_len: int,
    floor: float,
    filepath: str,
    lineno: int,
    allowlist: AllowList | None,
    skip_dotted_access: bool = False,
    allow_short: bool = False,
    safe_values: set[str] | None = None,
) -> str | None:
    """Run the shared four-step acceptance gate and return *val* if it should be
    reported, else ``None``.

    Order (identical across all scan passes): safe-value heuristic -> minimum
    length -> entropy floor -> allowlist. The ``floor > 0`` short-circuit is
    load-bearing: VALUE_PATTERNS provider keys pass ``floor=0.0`` and must NOT
    acquire an entropy gate. ``allow_short`` skips the length check
    (deterministic critical-severity patterns, whose regexes pin their own
    length). ``safe_values`` is the pre-merged safe set (#34).
    """
    if _is_safe_value(val, safe_values=safe_values, skip_dotted_access=skip_dotted_access):
        logger.debug('%s:%d suppressed by safe value heuristic', filepath, lineno)
        return None
    if len(val) < min_len and not allow_short:
        return None
    if floor > 0 and entropy(val) < floor:
        return None
    reason = allowlist.suppression_reason(filepath, lineno, val) if allowlist else None
    if reason:
        logger.debug('%s:%d suppressed by allowlist (%s)', filepath, lineno, reason)
        return None
    return val


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
        logger.debug('%s:%d suppressed by inline credactor:ignore', filepath, lineno)
        return findings

    if len(line) > _MAX_LINE_LENGTH:
        line = line[:_MAX_LINE_LENGTH]
        stripped = line.strip()

    ent_threshold = config.entropy_threshold if config else ENTROPY_DEFAULT
    min_len = config.min_value_length if config else MIN_LEN_DEFAULT
    extra_safe = config.extra_safe_values if config else None
    # Merge the safe-value set once per line instead of per candidate (#34).
    safe_set = SAFE_VALUES | extra_safe if extra_safe else SAFE_VALUES

    is_comment = stripped.startswith(('#', '//'))

    # Candidates carry a transient (start, end) char span alongside each Finding
    # for cross-pass span dedup (L2). The span lives in a parallel tuple so the
    # Finding TypedDict stays clean.
    candidates: list[tuple[int, int, Finding]] = []

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

            # high-entropy / hex credential value detectors: a path/slash +
            # quote-prefix guard, then suppression when the line keys a hash.
            if label in _HEURISTIC_VALUE_LABELS:
                if val.count('/') > 2:
                    continue
                start = match.start()
                if start == 0 or line[start - 1] not in ('"', "'"):
                    continue
                # SCAN-1: suppress only when THIS value's own key is a hash key
                # (and not a credential key) — scoped, not line-global.
                if _is_hash_context_at(line, start - 1):
                    logger.debug('%s:%d suppressed by hash context', filepath, lineno)
                    continue

            # L1: a compact JWT (3 segments <=40 chars) matches _DOTTED_ACCESS_RE
            # inside _is_safe_value; bypass that one heuristic for JWT tokens only.
            accepted = _evaluate_candidate(
                val,
                min_len=min_len,
                floor=min_ent,
                filepath=filepath,
                lineno=lineno,
                allowlist=allowlist,
                skip_dotted_access=(label == 'JWT token'),
                allow_short=(severity == 'critical'),
                safe_values=safe_set,
            )
            if accepted is None:
                continue

            candidates.append(
                (
                    match.start(),
                    match.end(),
                    _make_finding(
                        filepath,
                        lineno,
                        type=f'pattern:{label}',
                        severity=severity,
                        value=val,
                        raw=line.rstrip(),
                    ),
                )
            )

    # --- 2. XML attribute check (#21) ---
    if not is_comment:
        for xml_key, xml_val, xml_span in xml_attr_finditer(line):
            if not CRED_VAR_PATTERNS.search(xml_key):
                continue
            # Gate on the stripped value (matches the prior length/entropy checks);
            # the Finding still stores the full xml_val for redaction matching.
            if (
                _evaluate_candidate(
                    xml_val.strip(),
                    min_len=min_len,
                    floor=ent_threshold,
                    filepath=filepath,
                    lineno=lineno,
                    allowlist=allowlist,
                    safe_values=safe_set,
                )
                is None
            ):
                continue
            candidates.append(
                (
                    xml_span[0],
                    xml_span[1],
                    _make_finding(
                        filepath,
                        lineno,
                        type=f'xml-attr:{xml_key}',
                        severity=_severity_for_variable(xml_key),
                        value=xml_val,
                        raw=line.rstrip(),
                    ),
                )
            )

    # --- 3. Assignment check ---
    # L2: pass 3 is skipped (not early-returned) under these conditions so passes
    # 1/2 candidates still reach the dedup.
    dynamic_lookup = DYNAMIC_LOOKUP_RE.search(line)
    run_assignment = not (
        (is_comment and '=' not in line and ':' not in line)
        or (is_comment and any(kw in stripped for kw in ('def ', 'async def ', 'class ')))
        or stripped.startswith(('def ', 'async def ', 'class '))
        or dynamic_lookup
    )
    # SEC-27: a runtime/dynamic lookup suppresses the assignment pass — surface it
    # on the --verbose audit trail. (Restores visibility of the suppression; it does
    # not change detection — a hardcoded default inside the lookup is still skipped.)
    if dynamic_lookup and not run_assignment:
        logger.debug('%s:%d assignment scan skipped — runtime/dynamic lookup', filepath, lineno)

    if run_assignment:
        for match in ASSIGNMENT_RE.finditer(line):
            var = match.group('var')
            # #13 fix: use the correct capture group (quoted vs unquoted)
            grp = 'val_q' if match.group('val_q') else 'val_u'
            val = match.group(grp) or ''

            if not CRED_VAR_PATTERNS.search(var):
                continue
            # Skip hash/digest/checksum storage — these are derived values
            low_var = var.lower()
            if any(low_var.endswith(s) for s in _HASH_VAR_SUFFIXES):
                continue
            val_stripped = val.strip()
            # H7: a password-family variable gets a lower entropy floor so memorable
            # weak passwords (e.g. "Summer2024!") are not silently dropped.
            floor = (
                min(ent_threshold, PASSWORD_ENTROPY_FLOOR)
                if _is_password_family(var)
                else ent_threshold
            )
            if (
                _evaluate_candidate(
                    val_stripped,
                    min_len=min_len,
                    floor=floor,
                    filepath=filepath,
                    lineno=lineno,
                    allowlist=allowlist,
                    safe_values=safe_set,
                )
                is None
            ):
                continue

            candidates.append(
                (
                    match.start(grp),
                    match.end(grp),
                    _make_finding(
                        filepath,
                        lineno,
                        type=f'variable:{var}',
                        severity=_severity_for_variable(var),
                        value=val_stripped,
                        raw=line.rstrip(),
                    ),
                )
            )

    return _dedup_findings(candidates)


def _dedup_findings(candidates: list[tuple[int, int, Finding]]) -> list[Finding]:
    """Collapse findings whose character spans overlap on the same line, keeping
    the highest-priority one (L2).

    A single secret matched by several patterns/passes (e.g. a 64-char hex hits
    both the hex and base64 patterns; an ``api_key = "AKIA..."`` hits both the
    AWS pattern and the assignment pass) is reported once, while genuinely
    distinct secrets on one line are all kept. Priority: higher severity first,
    then discovery order (VALUE_PATTERNS severity order, then XML, then
    assignment), so the most specific label wins ties.
    """
    if len(candidates) <= 1:
        return [f for _s, _e, f in candidates]
    order = sorted(
        range(len(candidates)),
        key=lambda i: (-SEVERITY_RANK.get(candidates[i][2]['severity'], 0), i),
    )
    kept_spans: list[tuple[int, int]] = []
    kept: set[int] = set()
    for i in order:
        s, e, _f = candidates[i]
        if any(s < ke and ks < e for ks, ke in kept_spans):
            continue  # overlaps an already-kept, higher-priority finding
        kept_spans.append((s, e))
        kept.add(i)
    # Emit in discovery order for stable output.
    return [candidates[i][2] for i in range(len(candidates)) if i in kept]


def scan_file(
    filepath: str,
    *,
    config: Config | None = None,
    allowlist: AllowList | None = None,
) -> list[Finding]:
    """Scan a single file for credential findings."""
    # File size guard to prevent OOM on huge files — hard cap at 50 MB.
    try:
        file_size = Path(filepath).stat().st_size
        if file_size > _MAX_FILE_SIZE:
            logger.warning(
                'Skipping %s: file too large (%.1f MB > %.0f MB limit)',
                filepath,
                file_size / 1024 / 1024,
                _MAX_FILE_SIZE / 1024 / 1024,
            )
            return []
    except OSError:
        pass  # proceed; open() will fail with a better message

    # read_lines may raise OSError; let it propagate so the caller
    # (walker._scan_files / the cli single-file and --scan-json branches)
    # records this in errored_files AND logs it once; otherwise --fail-on-error
    # silently passes over files it could not read. scan_file is a library
    # re-raiser: the caller owns the warning.
    lines = read_lines(filepath)

    return scan_lines(filepath, lines, config=config, allowlist=allowlist)


def scan_lines(
    filepath: str,
    lines: list[str],
    *,
    config: Config | None = None,
    allowlist: AllowList | None = None,
) -> list[Finding]:
    """Run the full scan \u2014 PEM-block detection, per-line passes, and the
    multi-line string pass \u2014 over *lines* (with terminators, as from
    ``readlines()``/``splitlines(keepends=True)``).

    Shared by ``scan_file`` (lines read from disk) and the staged scanner
    (lines decoded from the git index blob) so the two paths cannot drift:
    previously the staged path ran a bare per-line loop and missed PEM bodies
    and secrets inside triple-quoted / template-literal strings.

    May strip a BOM from ``lines[0]`` in place; both callers pass a fresh list.
    """
    findings: list[Finding] = []

    # Strip BOM from first line if present
    if lines and lines[0].startswith('\ufeff'):
        lines[0] = lines[0][1:]

    # scan_line truncates each line to _MAX_LINE_LENGTH before matching (the
    # cost of matching is superlinear in line length), so a secret past that
    # column is missed \u2014 say so once per file instead of scanning clean
    # silently. Mirrors the truncation condition at scan_line exactly.
    truncated = sum(1 for ln in lines if len(ln) > _MAX_LINE_LENGTH)
    if truncated:
        logger.warning(
            '%s: %d line(s) longer than %d chars \u2014 content past that limit '
            'was not scanned by per-line matching',
            filepath,
            truncated,
            _MAX_LINE_LENGTH,
        )

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
            # L11: the PEM-block suppression was previously absent from the
            # --verbose audit trail — log which allowlist rule fired.
            reason = (
                allowlist.suppression_reason(filepath, lineno, line.strip()) if allowlist else None
            )
            if reason:
                logger.debug('%s:%d suppressed by allowlist (%s)', filepath, lineno, reason)
                continue
            findings.append(
                _make_finding(
                    filepath,
                    lineno,
                    type='pattern:private key block',
                    severity='critical',
                    value=line.strip(),
                    raw=line.rstrip(),
                )
            )
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
                    filepath,
                    lineno,
                    _MAX_PEM_BLOCK_LINES,
                )
                findings.extend(
                    scan_line(lineno, line, filepath, config=config, allowlist=allowlist)
                )
            else:
                continue  # skip lines inside PEM block
        else:
            findings.extend(scan_line(lineno, line, filepath, config=config, allowlist=allowlist))

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
    min_len = config.min_value_length if config else MIN_LEN_DEFAULT
    extra_safe = config.extra_safe_values if config else None
    safe_set = SAFE_VALUES | extra_safe if extra_safe else SAFE_VALUES

    # Find triple-quote blocks (Python) and template literal blocks (JS/TS)
    delimiters = [('"""', '"""'), ("'''", "'''"), ('`', '`')]

    full_text = ''.join(lines)

    for open_delim, close_delim in delimiters:
        start = 0
        while True:
            idx = full_text.find(open_delim, start)
            if idx < 0:
                break
            end_idx = full_text.find(close_delim, idx + len(open_delim))
            if end_idx < 0:
                break  # no more closing delimiters — done with this delimiter type
            block = full_text[idx + len(open_delim) : end_idx]
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
                    if (
                        _evaluate_candidate(
                            val,
                            min_len=min_len,
                            floor=min_ent,
                            filepath=filepath,
                            lineno=block_lineno,
                            allowlist=allowlist,
                            allow_short=(severity == 'critical'),
                            safe_values=safe_set,
                        )
                        is None
                    ):
                        continue
                    existing_findings.append(
                        _make_finding(
                            filepath,
                            block_lineno,
                            type=f'multiline:{label}',
                            severity=severity,
                            value=val,
                            raw=block.replace('\n', '\\n')[:120],
                        )
                    )
                    break  # one finding per block is enough

            start = end_idx + len(close_delim)


def should_scan_file(
    filename: str,
    extra_extensions: set[str] | None = None,
) -> bool:
    """Return True if the filename's extension (or name) is in the scan list."""
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
    return name_lower.startswith(('.env.', '.env-'))
