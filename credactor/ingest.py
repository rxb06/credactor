"""
External scanner ingestion: Gitleaks JSON and TruffleHog NDJSON.
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import urllib.parse
from pathlib import Path
from typing import Any

from ._log import logger
from .types import SEVERITY_RANK, Finding
from .utils import is_within_root, preview, read_lines

# Maximum number of findings to ingest to prevent memory exhaustion
_MAX_FINDINGS = 10_000
# Maximum Gitleaks report file size — guards against OOM before json.load()
# deserialises the full array.  100 MB >> any real report (10 k findings ≈ 5 MB).
_MAX_REPORT_BYTES = 100_000_000

# ---------------------------------------------------------------------------
# Severity mapping tables
# ---------------------------------------------------------------------------

_SEVERITY_LEVELS = frozenset({'critical', 'high', 'medium', 'low'})

_GITLEAKS_SEVERITY: dict[str, str] = {
    'aws-access-token': 'critical',
    'aws-secret-access-key': 'critical',
    'gcp-api-key': 'critical',
    'gcp-service-account': 'critical',
    'github-pat': 'critical',
    'github-fine-grained-pat': 'critical',
    'github-oauth': 'critical',
    'github-app-token': 'critical',
    'gitlab-pat': 'critical',
    'gitlab-pipeline-trigger-token': 'critical',
    'slack-bot-token': 'critical',
    'slack-user-token': 'critical',
    'slack-webhook-url': 'high',
    'stripe-access-token': 'critical',
    'twilio-api-key': 'critical',
    'sendgrid-api-token': 'critical',
    'npm-access-token': 'critical',
    'pypi-upload-token': 'critical',
    'private-key': 'critical',
    'generic-api-key': 'medium',
    'jwt': 'high',
    'password-in-url': 'high',
}


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

def _gitleaks_severity(rule_id: str, tags: list[str] | None = None) -> str:
    """Map a Gitleaks RuleID (and optional Tags) to a Credactor severity string.

    Tags override: if any tag matches a severity level (case-insensitive),
    that takes precedence over the table lookup.
    """
    if tags:
        for tag in tags:
            if isinstance(tag, str) and tag.lower() in _SEVERITY_LEVELS:
                return tag.lower()
    return _GITLEAKS_SEVERITY.get(rule_id, 'medium')


# ---------------------------------------------------------------------------
# Raw line synthesis
# ---------------------------------------------------------------------------

@functools.lru_cache(maxsize=256)
def _read_file_lines(filepath: str) -> tuple[str, ...]:
    """Read all lines of a file and return as an immutable tuple (LRU-cached).

    Cached to avoid re-reading the same file for multiple findings.  Bounded at
    256 entries so importing this module into a long-running process (CI server,
    language server) cannot grow the cache without limit; 256 far exceeds the
    unique-file count of any realistic external-scanner report.
    """
    try:
        return tuple(read_lines(filepath, errors='replace'))
    except OSError:
        return ()


def _synthesise_raw(filepath: str, lineno: int) -> str:
    """Read the source line at *lineno* (1-indexed) from *filepath*.

    Returns the line stripped of trailing whitespace, or ``""`` when the file
    is unreadable (``_read_file_lines`` absorbs ``OSError``, returning ``()``)
    or *lineno* is out of range. Both callers validate *lineno* as an
    ``int >= 1`` before calling.
    """
    lines = _read_file_lines(filepath)
    if lines and 1 <= lineno <= len(lines):
        return lines[lineno - 1].rstrip()
    return ''


# ---------------------------------------------------------------------------
# Shared path-resolution helper for external scanners
# ---------------------------------------------------------------------------

def _resolve_external_finding_path(
    raw_file: str,
    target_resolved: str,
    filepath_resolved: str,
    *,
    scanner_name: str,
) -> str | None:
    """Resolve, traversal-check, and self-ref-check a path from an external
    scanner finding. Returns the resolved path, or ``None`` to skip.

    Combines path-traversal and self-reference guards plus the optional
    missing-file warning, so both ingest_gitleaks and
    ingest_trufflehog share identical handling.
    """
    try:
        resolved = str(Path(os.path.normpath(
            os.path.join(target_resolved, raw_file))).resolve())
    except ValueError:
        # L5b: a NUL byte (or similar) in the path makes Path.resolve() raise;
        # skip just this one finding rather than aborting the whole ingest batch
        # (the CLI turns an uncaught ValueError here into a fatal exit 2).
        logger.warning(
            'Skipping %s finding: path %r is invalid (e.g. embedded NUL).',
            scanner_name, raw_file,
        )
        return None

    if not is_within_root(resolved, target_resolved):
        logger.warning(
            'Skipping %s finding: path %r resolves outside target directory '
            '(possible path traversal).', scanner_name, raw_file,
        )
        return None

    if os.path.normcase(resolved) == os.path.normcase(filepath_resolved):
        logger.info(
            'Skipping %s finding: path resolves to the report file itself '
            '(%r); skipping to avoid self-corruption.',
            scanner_name, resolved,
        )
        return None

    if not os.path.isfile(resolved):
        # L5a: redaction (this tool's primary action) cannot touch a file that
        # isn't on disk, and a phantom finding inflates counts / exit codes —
        # skip it (was previously kept with only an info log).
        logger.warning(
            '%s finding references missing file %r; skipping.', scanner_name, resolved)
        return None

    return resolved


# ---------------------------------------------------------------------------
# Gitleaks parser
# ---------------------------------------------------------------------------

def _load_report_preamble(
    filepath: str, target: str, *, scanner_name: str,
) -> tuple[str, str]:
    """Resolve the report's target/filepath and run the size guards shared by both
    external-report parsers. Returns ``(target_resolved, filepath_resolved)``.

    The ``open()`` + decode step is intentionally NOT shared: Gitleaks uses
    ``errors='strict'`` + ``json.load`` while TruffleHog uses ``errors='replace'``
    + a per-line loop, and they diverge in how they use the handle.
    """
    target_path = Path(target).resolve()
    filepath_resolved = str(Path(filepath).resolve())
    if target_path.is_file():
        # Defensive guard: callers should pass the repo root directory, not a
        # file. Using the file's parent prevents broken path joins like
        # <file>/src/config.py, but a warning is emitted so the caller knows.
        logger.warning(
            '%s: target %r is a file; '
            'using its parent directory for path resolution.',
            scanner_name, str(target_path),
        )
        target_path = target_path.parent
    target_resolved = str(target_path)

    # Reject oversized files before the parser reads them into memory — the
    # 10,000-finding cap fires only after deserialisation, so a gigantic file
    # would OOM first.
    try:
        report_size = os.path.getsize(filepath)
    except OSError as exc:
        raise ValueError(
            f'Cannot open {scanner_name} file {filepath!r}: {exc}'
        ) from exc
    if report_size > _MAX_REPORT_BYTES:
        raise ValueError(
            f'{scanner_name} file {filepath!r} is {report_size:,} bytes; refusing to '
            f'parse files over {_MAX_REPORT_BYTES:,} bytes the configured limit.'
        )
    return target_resolved, filepath_resolved


def ingest_gitleaks(
    filepath: str,
    target: str,
) -> list[Finding]:
    """Parse a Gitleaks JSON report and return a list of Credactor finding dicts.

    Validates top-level is a list, caps at 10,000 findings, and checks
    resolved paths are within the target directory.
    """
    target_resolved, filepath_resolved = _load_report_preamble(
        filepath, target, scanner_name='Gitleaks')

    # Load JSON
    try:
        with open(filepath, encoding='utf-8', errors='strict') as fh:
            data = json.load(fh)
    except OSError as exc:
        raise ValueError(
            f'Cannot open Gitleaks file {filepath!r}: {exc}'
        ) from exc
    except UnicodeDecodeError as exc:
        raise ValueError(
            f'Gitleaks file {filepath!r} contains non-UTF-8 bytes; '
            f'cannot parse safely: {exc}'
        ) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f'Gitleaks file is not valid JSON ({filepath!r}): {exc}'
        ) from exc

    if not isinstance(data, list):
        raise ValueError(
            f'Gitleaks report must be a JSON array at top level '
            f'(got {type(data).__name__}). File: {filepath!r}'
        )

    if len(data) > _MAX_FINDINGS:
        logger.warning(
            'Gitleaks report contains %d findings; truncating to %d.',
            len(data), _MAX_FINDINGS,
        )
        data = data[:_MAX_FINDINGS]

    findings: list[Finding] = []

    for obj in data:
        if not isinstance(obj, dict):
            logger.info('Skipping non-object entry in Gitleaks report.')
            continue

        # --- Secret ---
        secret = obj.get('Secret', '')
        if not isinstance(secret, str) or not secret:
            logger.info('Skipping Gitleaks finding with empty Secret.')
            continue

        # --- File path ---
        # Use SymlinkFile if non-empty, otherwise File
        raw_file = obj.get('SymlinkFile') or obj.get('File', '')
        if not isinstance(raw_file, str) or not raw_file:
            logger.info('Skipping Gitleaks finding with non-string or empty File.')
            continue

        resolved = _resolve_external_finding_path(
            raw_file, target_resolved, filepath_resolved,
            scanner_name='Gitleaks',
        )
        if resolved is None:
            continue

        # --- Line number ---
        line = obj.get('StartLine', 1)
        if not isinstance(line, int) or line < 1:
            line = 1

        # --- raw context line ---
        match_ctx = obj.get('Match', '')
        if isinstance(match_ctx, str) and match_ctx:
            raw = match_ctx
        else:
            raw = _synthesise_raw(resolved, line)

        # --- Type ---
        rule_id = obj.get('RuleID', 'unknown')
        ftype = f'external:gitleaks:{rule_id}'

        # --- Severity ---
        tags = obj.get('Tags') or []
        severity = _gitleaks_severity(rule_id, tags if isinstance(tags, list) else [])

        # --- Finding dict ---
        finding: Finding = {
            'file': resolved,
            'line': line,
            'type': ftype,
            'severity': severity,
            'full_value': secret,
            'value_preview': preview(secret),
            'raw': raw,
        }

        # --- Commit (omit key when empty) ---
        # type-check before slicing — non-string Commit (e.g. int, list)
        # would raise TypeError or produce an unhashable value that crashes
        # deduplicate_findings later.
        commit = obj.get('Commit', '')
        if isinstance(commit, str) and commit:
            finding['commit'] = commit[:12]

        findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# TruffleHog severity mapping table
# ---------------------------------------------------------------------------

_TRUFFLEHOG_SEVERITY: dict[str, str] = {
    'AWS': 'high',
    'GCP': 'high',
    'Azure': 'high',
    'GitHub': 'high',
    'GitHubApp': 'high',
    'GitLab': 'high',
    'Slack': 'high',
    'SlackWebhook': 'medium',
    'Stripe': 'high',
    'Twilio': 'high',
    'SendGrid': 'high',
    'Mailgun': 'high',
    'NPMToken': 'high',
    'PyPI': 'high',
    'PrivateKey': 'critical',
    'JWT': 'high',
    'MongoDB': 'high',
    'PostgreSQL': 'high',
    'MySQL': 'high',
}


def _trufflehog_severity(detector_name: str, verified: bool) -> str:
    """Map a TruffleHog DetectorName + Verified flag to a Credactor severity.

    Verified=True always escalates to critical regardless of DetectorName.
    """
    if verified:
        return 'critical'
    return _TRUFFLEHOG_SEVERITY.get(detector_name, 'medium')


# ---------------------------------------------------------------------------
# TruffleHog parser
# ---------------------------------------------------------------------------

def _parse_trufflehog_record(
    obj: dict[str, Any],
    lineno_file: int,
    target_resolved: str,
    filepath_resolved: str,
) -> Finding | None:
    """Validate one TruffleHog NDJSON record and build its Finding.

    Returns ``None`` (with an info log naming the reason) for any record
    that should be skipped. Extracted verbatim from the read loop so the
    sequential validation steps are unit-testable in isolation and the
    loop stays readable.
    """
    # --- Raw secret ---
    raw_secret = obj.get('Raw', '')
    if not isinstance(raw_secret, str) or not raw_secret:
        logger.info(
            'TruffleHog line %d: skipping finding with empty Raw.',
            lineno_file,
        )
        return None
    if '\ufffd' in raw_secret:
        logger.info(
            'TruffleHog line %d: Raw field contains non-UTF-8 bytes '
            '(replacement character U+FFFD); skipping to avoid corrupted redaction.',
            lineno_file,
        )
        return None
    # TruffleHog URL-encodes special characters in URI-based credentials
    # (e.g. '@' → '%40').  Save both forms; the right one is selected
    # after source-line synthesis to verify which is in the file.
    _raw_encoded = raw_secret
    _raw_decoded = urllib.parse.unquote(raw_secret)

    # --- Source metadata ---
    source_meta = obj.get('SourceMetadata', {})
    data = source_meta.get('Data', {}) if isinstance(source_meta, dict) else {}

    file_path_raw: str = ''
    line_num: int = 1
    commit: str = ''
    source_found = False

    if isinstance(data, dict):
        # Filesystem source (preferred)
        fs = data.get('Filesystem')
        if isinstance(fs, dict):
            file_path_raw = fs.get('file', '') or ''
            line_num = fs.get('line', 1) or 1
            source_found = True
        else:
            # Git source
            git = data.get('Git')
            if isinstance(git, dict):
                file_path_raw = git.get('file', '') or ''
                line_num = git.get('line', 1) or 1
                raw_commit = git.get('commit', '') or ''
                # type-check before slicing — non-string commit
                # (e.g. int, list) would raise TypeError or produce an
                # unhashable value that crashes deduplicate_findings.
                if isinstance(raw_commit, str) and raw_commit:
                    commit = raw_commit[:12]
                source_found = True

    if not source_found:
        supported = {'Filesystem', 'Git'}
        unsupported = set(data.keys()) - supported if isinstance(data, dict) else set()
        logger.info(
            'TruffleHog line %d: unsupported source type %s; skipping.',
            lineno_file,
            list(unsupported) if unsupported else '(unknown)',
        )
        return None

    if not isinstance(file_path_raw, str) or not file_path_raw:
        logger.info(
            'TruffleHog line %d: skipping finding with non-string or empty file path.',
            lineno_file,
        )
        return None

    resolved = _resolve_external_finding_path(
        file_path_raw, target_resolved, filepath_resolved,
        scanner_name='TruffleHog',
    )
    if resolved is None:
        return None

    # Validate line number
    if not isinstance(line_num, int) or line_num < 1:
        line_num = 1

    # --- Synthesise raw context line ---
    raw_ctx = _synthesise_raw(resolved, line_num)

    # Select the encoding form that actually appears in the source line.
    # If TruffleHog URL-encoded the value (e.g. %40 → @) but the source file
    # contains the literal encoded form, the decoded form won't match and
    # redaction fails silently.  Prefer decoded; fall back to encoded only when
    # the encoded form is visible in the source line and the decoded form is not.
    if _raw_encoded == _raw_decoded:
        # No percent-encoding in this value — no choice to make.
        raw_secret = _raw_decoded
    elif raw_ctx and _raw_decoded in raw_ctx:
        raw_secret = _raw_decoded
    elif raw_ctx and _raw_encoded in raw_ctx:
        raw_secret = _raw_encoded
    else:
        # Source line unavailable or neither form matched; default to decoded
        # (what TruffleHog originally extracted, most likely correct).
        raw_secret = _raw_decoded

    if not raw_ctx:
        raw_ctx = raw_secret  # fallback per plan section 3.2.1

    # --- Type ---
    detector_name = obj.get('DetectorName', 'unknown')
    if not isinstance(detector_name, str):
        detector_name = 'unknown'
    ftype = f'external:trufflehog:{detector_name}'

    # --- Severity ---
    verified = bool(obj.get('Verified', False))
    severity = _trufflehog_severity(detector_name, verified)

    # --- Finding dict ---
    finding: Finding = {
        'file': resolved,
        'line': line_num,
        'type': ftype,
        'severity': severity,
        'full_value': raw_secret,
        'value_preview': preview(raw_secret),
        'raw': raw_ctx,
    }

    if commit:
        finding['commit'] = commit

    return finding


def ingest_trufflehog(
    filepath: str,
    target: str,
) -> list[Finding]:
    """Parse a TruffleHog NDJSON output file and return Credactor finding dicts.

    Validates each line as a JSON object, caps at 10,000 findings, and
    checks resolved paths are within the target directory.
    """
    target_resolved, filepath_resolved = _load_report_preamble(
        filepath, target, scanner_name='TruffleHog')

    try:
        # Closed via `with fh:` below; opened inside try only to convert OSError
        # into a ValueError with a clearer message.
        fh = open(filepath, encoding='utf-8', errors='replace')  # noqa: SIM115
    except OSError as exc:
        raise ValueError(
            f'Cannot open TruffleHog file {filepath!r}: {exc}'
        ) from exc

    findings: list[Finding] = []
    count = 0
    saw_content = False   # any non-blank line
    saw_object = False    # any line that parsed to a JSON object

    with fh:
        for lineno_file, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            saw_content = True

            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.info(
                    'TruffleHog file line %d: skipping invalid JSON: %s',
                    lineno_file, exc,
                )
                continue

            if not isinstance(obj, dict):
                logger.info(
                    'TruffleHog file line %d: skipping non-object JSON value.',
                    lineno_file,
                )
                continue
            saw_object = True

            if count >= _MAX_FINDINGS:
                logger.warning(
                    'TruffleHog report exceeds %d findings; truncating.', _MAX_FINDINGS,
                )
                break

            finding = _parse_trufflehog_record(
                obj, lineno_file, target_resolved, filepath_resolved)
            if finding is None:
                continue

            findings.append(finding)
            count += 1

    # MV-6: a report with content but not a single JSON object on any line is a
    # malformed report (garbage, an HTML error page, or a Gitleaks JSON array fed
    # to the NDJSON path), not a clean "no findings" result. Fail closed like
    # ingest_gitleaks rather than returning [] — a silent zero-findings exit 0 on
    # a wrong/typo'd report is a false all-clear. An empty / blank-only file is a
    # legitimate "no findings" (saw_content False) and still returns [].
    if saw_content and not saw_object:
        raise ValueError(
            f'TruffleHog file {filepath!r} is not valid NDJSON: '
            f'no JSON object found on any non-empty line.'
        )

    return findings


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

# Dedup base key: (normalised_path, line, sha256_prefix_of_full_value).
BaseKey = tuple[str, int, str]


def deduplicate_findings(
    findings: list[Finding],
) -> list[Finding]:
    """Remove duplicate findings, keeping the first (highest-fidelity) occurrence.

    Dedup key: (normalised_file_path, line_number, sha256_prefix_of_full_value).

    Commit-aware rules (section 7.3 of the plan):
    - Findings with different ``commit`` values are NOT deduplicated.
    - A no-commit (working-tree) finding beats a committed finding at the same
      file:line:value — the working-tree one is kept and the committed one is
      dropped.

    Expected call order from cli.py: native findings first, then gitleaks,
    then trufflehog.  First occurrence wins, so priority is automatically
    Credactor > Gitleaks > TruffleHog.
    """
    def _base(f: Finding) -> BaseKey:
        path_norm = os.path.normpath(os.path.realpath(f.get('file', '')))
        line = f.get('line', 1)
        # Use surrogateescape so lone surrogate code points (which can arrive
        # from scanner paths read with errors='surrogateescape') don't raise
        # UnicodeEncodeError and crash the dedup pass.
        value_hash = hashlib.sha256(
            f.get('full_value', '').encode('utf-8', errors='surrogateescape')
        ).hexdigest()[:16]
        return (path_norm, line, value_hash)

    # Pass 1: collect (path, line, value_hash) bases that have at least one
    # no-commit (working-tree) finding.  This lets us suppress committed
    # duplicates that arrive *before* the working-tree finding in the list.
    no_commit_bases: set[BaseKey] = set()
    for f in findings:
        if not f.get('commit'):
            no_commit_bases.add(_base(f))

    # Pass 2: deduplicate in order; first occurrence wins.
    result: list[Finding] = []
    seen: dict[tuple[str, int, str, str | None], int] = {}

    for f in findings:
        base = _base(f)
        commit = f.get('commit')

        if commit and base in no_commit_bases:
            # A working-tree finding covers this committed dup — skip.
            continue

        key = (*base, commit)  # None for working-tree, hash for history
        if key in seen:
            # L5c: a true duplicate (same file:line:value, same commit) is
            # dropped — but it must not silently downgrade the survivor's
            # severity. The native finding wins by source order, yet an external
            # TruffleHog Verified duplicate may carry 'critical'; merge to the
            # higher severity so the escalation is honoured (count unchanged).
            survivor = result[seen[key]]
            dropped_sev = f.get('severity', 'medium')
            if (SEVERITY_RANK.get(dropped_sev, 1)
                    > SEVERITY_RANK.get(survivor.get('severity', 'medium'), 1)):
                logger.info(
                    'Dedup raised severity %s -> %s at %s:%s (kept %s, merged %s).',
                    survivor.get('severity'), dropped_sev,
                    survivor.get('file'), survivor.get('line'),
                    survivor.get('type'), f.get('type'),
                )
                survivor['severity'] = dropped_sev
            continue
        seen[key] = len(result)
        result.append(f)

    removed = len(findings) - len(result)
    if removed:
        logger.info('Deduplicated %d finding(s).', removed)

    return result
