"""
External scanner ingestion: Gitleaks JSON, Betterleaks JSON and TruffleHog NDJSON.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ._log import logger
from .patterns import CRED_VAR_PATTERNS
from .types import SEVERITY_RANK, Finding
from .utils import KnownSecrets, in_git_dir, is_within_root, name_secrets, preview, read_lines

# Maximum number of findings to ingest to prevent memory exhaustion
_MAX_FINDINGS = 10_000
# Maximum ingest report file size — guards against OOM before the non-streaming
# stdlib json.load() deserialises the whole document (it transiently uses on the
# order of 10x the file size in memory). 20 MB keeps ~4x headroom over the
# largest realistic report (10 k findings ≈ 5 MB) without leaving a 100 MB ->
# ~1 GB transient-allocation vector.
_MAX_REPORT_BYTES = 20_000_000

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


# Betterleaks' `--validation` pass asks the provider whether the secret is live.
# That verdict outranks the rule table: it is direct evidence, not a heuristic.
# Only the decisive statuses are mapped here. The inconclusive ones ('',
# 'needs_validation', 'unknown' and 'error') fall through to the rule table on
# purpose, because "not validated" must not read as "not serious".
_BETTERLEAKS_VALIDATION_SEVERITY: dict[str, str] = {
    'valid': 'critical',
    'invalid': 'low',
    'revoked': 'low',
}


def _betterleaks_severity(
    rule_id: str,
    validation_status: str = '',
    tags: list[str] | None = None,
) -> str:
    """Map a Betterleaks finding to a Credactor severity string.

    Precedence: a decisive ``ValidationStatus`` (provider-confirmed live or
    dead) wins outright, then a Tags override, then the shared Gitleaks rule
    table, then 'medium'. Betterleaks is a Gitleaks fork and inherits its rule
    IDs — 20 of the 22 ids in ``_GITLEAKS_SEVERITY`` are present verbatim in
    its bundled config — so reusing that table is deliberate, not a shortcut.

    Putting the machine verdict above a rule author's Tags mirrors the
    TruffleHog rule where ``Verified: true`` short-circuits its own table.
    """
    if isinstance(validation_status, str):
        decisive = _BETTERLEAKS_VALIDATION_SEVERITY.get(validation_status.lower())
        if decisive is not None:
            return decisive
    return _gitleaks_severity(rule_id, tags)


# ---------------------------------------------------------------------------
# Report labels (PA-04)
# ---------------------------------------------------------------------------
# A rule or detector name is copied into the finding type, and SARIF turns the
# type into a rule id, so the report decides what those fields say. Only a
# plain label is kept; anything else becomes 'unknown' and is counted. The
# finding itself is kept either way.
_LABEL_RE = re.compile(r'[A-Za-z0-9._-]{1,64}')


def _report_label(value: object, stats: dict[str, Any] | None) -> str:
    """Return *value* if it is a plain label, else ``'unknown'``, counting the
    replacement in ``stats['relabelled']``. Callers pass ``'unknown'`` for a
    missing label, so that is not counted."""
    if isinstance(value, str) and _LABEL_RE.fullmatch(value):
        return value
    if stats is not None:
        stats['relabelled'] += 1
    return 'unknown'


# A report's commit id is emitted verbatim in JSON, so the same holds: only a
# hex id is kept (SHA-1 or SHA-256), and not one that shares a run of
# _COMMIT_SHARED characters with the secret (a hex secret would pass the
# charset check). The finding is kept without it.
_COMMIT_RE = re.compile(r'[0-9a-fA-F]{7,64}')
_COMMIT_SHARED = 6


def _report_commit(value: object, secret: str, stats: dict[str, Any] | None) -> str:
    """Return *value* cut to 12 characters if it is a usable commit id, else
    ``''``, counting a rejected string in ``stats['bad_commit']``. A missing or
    non-string commit is ``''`` without being counted."""
    if not isinstance(value, str) or not value:
        return ''
    kept = value[:12]
    shares = any(
        kept[i : i + _COMMIT_SHARED] in secret for i in range(len(kept) - _COMMIT_SHARED + 1)
    )
    if _COMMIT_RE.fullmatch(value) and not shares:
        return kept
    if stats is not None:
        stats['bad_commit'] += 1
    return ''


def _warn_bad_commits(stats: dict[str, Any], start: int, scanner_name: str) -> None:
    count = stats['bad_commit'] - start
    if count:
        logger.warning(
            '%d %s finding(s) had a commit id that is not 7 to 64 hex characters, '
            'or shares part of the secret; ingested without it.',
            count,
            scanner_name,
        )


# SR-16: .git holds repository metadata and hooks, not source. A finding
# there (a token in a remote URL in .git/config, say) is a real leak to fix by
# hand, so it is reported, but a rewrite there could break the repository.
_GIT_PATH_REASON = 'the path is inside .git; fix it by hand and rotate the credential'


def _mark_git_path(
    finding: Finding, raw_file: str, target_resolved: str, stats: dict[str, Any] | None
) -> None:
    """Refuse the write for a finding under .git, checking the path as the
    report gave it and as it resolved, so a symlink into .git counts too."""
    joined = os.path.normpath(os.path.join(target_resolved, raw_file))
    if in_git_dir(finding['file'], target_resolved) or in_git_dir(joined, target_resolved):
        finding['refuse_reason'] = _GIT_PATH_REASON
        if stats is not None:
            stats['protected_path'] += 1


# SR-15 (decision D2, floor of 4): a reported secret this short, or one that
# is itself a credential name, would be replaced wherever it happens to occur
# ('a' inside 'api_key'). It is reported, but never drives a rewrite.
_MIN_REPORTED_SECRET = 4
_IMPLAUSIBLE_REASON = (
    'the reported secret is too short or a credential name to be replaced safely; '
    'check the report and fix the value by hand'
)


def _mark_implausible(finding: Finding, stats: dict[str, Any] | None) -> None:
    secret = finding['full_value']
    if len(secret) >= _MIN_REPORTED_SECRET and not CRED_VAR_PATTERNS.fullmatch(secret):
        return
    finding.setdefault('refuse_reason', _IMPLAUSIBLE_REASON)
    if stats is not None:
        stats['implausible'] += 1


def _warn_implausible(stats: dict[str, Any], start: int, scanner_name: str) -> None:
    count = stats['implausible'] - start
    if count:
        logger.warning(
            '%d %s finding(s) report a secret too short or a credential name: '
            'they are reported, but not rewritten.',
            count,
            scanner_name,
        )


def _warn_git_paths(stats: dict[str, Any], start: int, scanner_name: str) -> None:
    count = stats['protected_path'] - start
    if count:
        logger.warning(
            '%d %s finding(s) are inside .git: they are reported, but not rewritten. '
            'Fix each by hand (for a remote URL, remove the token from it) and '
            'rotate the credential.',
            count,
            scanner_name,
        )


# PA-05 (decision DA-4): a line number the report does not give cannot choose
# the line to rewrite. The finding is kept at line 0 (unknown), reported and
# unresolved, but never written. It used to become line 1.
_BAD_LINE_REASON = (
    'the report gives no valid line number, so the line to rewrite is unknown; '
    'find the value and fix it by hand'
)


def _valid_line(value: object) -> int:
    """*value* if it is a line number (an int of at least 1, not a bool),
    else 0."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value
    return 0


def _mark_bad_line(finding: Finding, stats: dict[str, Any] | None) -> None:
    if finding['line'] >= 1:
        return
    finding.setdefault('refuse_reason', _BAD_LINE_REASON)
    if stats is not None:
        stats['bad_line'] += 1


def _warn_bad_lines(stats: dict[str, Any], start: int, scanner_name: str) -> None:
    count = stats['bad_line'] - start
    if count:
        logger.warning(
            '%d %s finding(s) have no valid line number in the report: they are '
            'reported at line 0, but not rewritten.',
            count,
            scanner_name,
        )


# Counters that each parser reports on, as a delta against the shared stats.
_FIXED_UP_KEYS = ('relabelled', 'bad_commit', 'protected_path', 'implausible', 'bad_line')


def _counts_at_start(stats: dict[str, Any]) -> dict[str, int]:
    return {key: stats[key] for key in _FIXED_UP_KEYS}


def _warn_fixed_up(
    stats: dict[str, Any], start: dict[str, int], scanner_name: str, label_field: str
) -> None:
    """This parser's run-level summaries of the records it kept but changed."""
    _warn_relabelled(stats, start['relabelled'], scanner_name, label_field)
    _warn_bad_commits(stats, start['bad_commit'], scanner_name)
    _warn_git_paths(stats, start['protected_path'], scanner_name)
    _warn_implausible(stats, start['implausible'], scanner_name)
    _warn_bad_lines(stats, start['bad_line'], scanner_name)


def _warn_relabelled(stats: dict[str, Any], start: int, scanner_name: str, field: str) -> None:
    """Run-level summary of the labels this parser replaced (a delta against
    the shared *stats*, like the other summaries)."""
    count = stats['relabelled'] - start
    if count:
        logger.warning(
            '%d %s finding(s) had a %s that is not a plain label (letters, digits, '
            "'.', '_' or '-', at most 64 characters); reported as 'unknown'.",
            count,
            scanner_name,
            field,
        )


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
    or *lineno* is out of range. The callers pass 0 for a line the report did
    not give (PA-05), which is out of range.
    """
    lines = _read_file_lines(filepath)
    if lines and 1 <= lineno <= len(lines):
        return lines[lineno - 1].rstrip()
    return ''


# ---------------------------------------------------------------------------
# Shared path-resolution helper for external scanners
# ---------------------------------------------------------------------------


def new_ingest_stats() -> dict[str, Any]:
    """Per-run skip counters shared by all three parsers (and across every report
    when the CLI passes one dict to each ingest call). Drives the run-level
    stale-report and unsupported-source summaries — per-finding logs alone
    scroll past and can leave an exit-0 run looking clean (E04/A08).

    Because the dict is shared, a parser must build its own summary from a delta
    against the counter value it saw on entry, not from the counter itself. The
    two ``unsupported_types`` keys are the exception. They collect a union across
    parsers, for callers that want one view of a whole run, and no summary is
    built from them; each parser keeps a private copy of the same shape for its
    own labels. Their 20-entry cap is separate from any parser's, so
    ``unsupported_types_truncated`` can be set here when no summary was actually
    truncated.
    """
    return {
        'missing_file': 0,
        'unsupported_source': 0,
        'unsupported_types': set(),
        'unsupported_types_truncated': False,
        'invalid_record': 0,
        'relabelled': 0,
        'bad_commit': 0,
        'protected_path': 0,
        'implausible': 0,
        'bad_line': 0,
    }


# The unsupported-type set holds report-controlled strings, so both the entry
# count and each entry's length are bounded: the file-size cap bounds parse
# memory, but without these a single record carrying a huge or high-cardinality
# source key would balloon the set and flood the run-level summary line.
_MAX_UNSUPPORTED_TYPE_NAMES = 20
_MAX_UNSUPPORTED_TYPE_NAME_LEN = 60


def _note_unsupported_types(stats: dict[str, Any], labels: set[str]) -> None:
    """Fold *labels* into ``stats['unsupported_types']`` under the bounds above."""
    types = stats['unsupported_types']
    for label in labels:
        if len(label) > _MAX_UNSUPPORTED_TYPE_NAME_LEN:
            label = label[: _MAX_UNSUPPORTED_TYPE_NAME_LEN - 3] + '...'
        if label in types:
            continue
        if len(types) >= _MAX_UNSUPPORTED_TYPE_NAMES:
            stats['unsupported_types_truncated'] = True
            continue
        types.add(label)


def _resolve_external_finding_path(
    raw_file: str,
    target_resolved: str,
    filepath_resolved: str,
    *,
    scanner_name: str,
    stats: dict[str, Any] | None = None,
) -> str | None:
    """Resolve, traversal-check, and self-ref-check a path from an external
    scanner finding. Returns the resolved path, or ``None`` to skip.

    Combines path-traversal and self-reference guards plus the optional
    missing-file warning, so ingest_gitleaks, ingest_trufflehog and
    ingest_betterleaks share identical handling.
    """
    try:
        resolved = str(Path(os.path.normpath(os.path.join(target_resolved, raw_file))).resolve())
    except ValueError:
        # L5b: a NUL byte (or similar) in the path makes Path.resolve() raise;
        # skip just this one finding rather than aborting the whole ingest batch
        # (the CLI turns an uncaught ValueError here into a fatal exit 2).
        logger.warning(
            'Skipping %s finding: path %r is invalid (e.g. embedded NUL).',
            scanner_name,
            raw_file,
        )
        return None

    if not is_within_root(resolved, target_resolved):
        logger.warning(
            'Skipping %s finding: path %r resolves outside target directory '
            '(possible path traversal).',
            scanner_name,
            raw_file,
        )
        return None

    if os.path.normcase(resolved) == os.path.normcase(filepath_resolved):
        logger.info(
            'Skipping %s finding: path resolves to the report file itself '
            '(%r); skipping to avoid self-corruption.',
            scanner_name,
            resolved,
        )
        return None

    if not os.path.isfile(resolved):
        # L5a: redaction (this tool's primary action) cannot touch a file that
        # isn't on disk, and a phantom finding inflates counts / exit codes —
        # skip it (was previously kept with only an info log).
        logger.warning('%s finding references missing file %r; skipping.', scanner_name, resolved)
        if stats is not None:
            stats['missing_file'] += 1
        return None

    return resolved


def _usable_secret(value: object) -> bool:
    """Whether a report's secret can be used: a non-empty string with no lone
    surrogate. No scanner writes one (Go's JSON encoder turns invalid bytes
    into U+FFFD), and one would crash the dedup hash (SR-19)."""
    if not isinstance(value, str) or not value:
        return False
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return True


# SR-19: every field a parser reads is type-checked, but a field read later
# must not be able to crash a run either. A record whose parse raises one of
# these is parsed again from its location and secret alone, so it is kept with
# the rule unknown; if that fails too, it is counted invalid.
_RECORD_ERRORS = (TypeError, AttributeError, KeyError)
_CORE_FIELDS = ('Secret', 'Raw', 'File', 'SymlinkFile', 'StartLine')
_CORE_ATTRIBUTES = ('fs.symlink', 'path')
_CORE_SOURCE_FIELDS = ('file', 'line')


def _core_record(obj: dict[str, Any]) -> dict[str, Any]:
    """The fields of *obj* that locate the finding and give its secret, in
    the shape each parser reads them."""
    core = {key: obj[key] for key in _CORE_FIELDS if key in obj}
    attrs = obj.get('Attributes')
    if isinstance(attrs, dict):
        core['Attributes'] = {key: attrs[key] for key in _CORE_ATTRIBUTES if key in attrs}
    meta = obj.get('SourceMetadata')
    data = meta.get('Data') if isinstance(meta, dict) else None
    if isinstance(data, dict):
        sources = {
            name: {key: entry[key] for key in _CORE_SOURCE_FIELDS if key in entry}
            for name, entry in data.items()
            if name in ('Filesystem', 'Git') and isinstance(entry, dict)
        }
        core['SourceMetadata'] = {'Data': sources}
    return core


def _parse_or_salvage(
    parse: Callable[[dict[str, Any]], Finding | None],
    obj: dict[str, Any],
    stats: dict[str, Any],
    where: str,
) -> Finding | None:
    """Run *parse* on *obj*, falling back to its core fields on an error."""
    counters = {key: value for key, value in stats.items() if isinstance(value, int)}
    try:
        return parse(obj)
    except _RECORD_ERRORS as exc:
        error = type(exc).__name__
    # Undo what the failed attempt counted, so the retry counts it once.
    stats.update(counters)
    try:
        finding = parse(_core_record(obj))
    except _RECORD_ERRORS:
        stats.update(counters)
        stats['invalid_record'] += 1
        logger.warning('%s could not be read (%s); skipped as invalid.', where, error)
        return None
    if finding is not None:
        logger.warning(
            '%s could not be read in full (%s); kept its location and secret, '
            'with the rule unknown.',
            where,
            error,
        )
    return finding


# ---------------------------------------------------------------------------
# Gitleaks parser
# ---------------------------------------------------------------------------


def _load_report_preamble(
    filepath: str,
    target: str,
    *,
    scanner_name: str,
) -> tuple[str, str]:
    """Resolve the report's target/filepath and run the size guards shared by every
    external-report parser. Returns ``(target_resolved, filepath_resolved)``.

    The ``open()`` + decode step is intentionally NOT shared: the JSON-array
    parsers (Gitleaks, Betterleaks) use ``errors='strict'`` + ``json.load``
    while TruffleHog uses ``errors='replace'`` + a per-line loop, and they
    diverge in how they use the handle.
    """
    target_path = Path(target).resolve()
    filepath_resolved = str(Path(filepath).resolve())
    if target_path.is_file():
        # Defensive guard: callers should pass the repo root directory, not a
        # file. Using the file's parent prevents broken path joins like
        # <file>/src/config.py, but a warning is emitted so the caller knows.
        logger.warning(
            '%s: target %r is a file; using its parent directory for path resolution.',
            scanner_name,
            str(target_path),
        )
        target_path = target_path.parent
    target_resolved = str(target_path)

    # Reject oversized files before the parser reads them into memory — the
    # 10,000-finding cap fires only after deserialisation, so a gigantic file
    # would OOM first.
    try:
        report_size = os.path.getsize(filepath)
    except OSError as exc:
        raise ValueError(f'Cannot open {scanner_name} file {filepath!r}: {exc}') from exc
    if not os.path.isfile(filepath):
        # K-1 at the library layer: getsize succeeds on a FIFO (size 0) or a
        # directory, and the parsers' open() would then block forever on a
        # FIFO. The CLI pre-checks its own report path, but direct callers
        # reach here first (same guard _parse_toml applies for the same reason).
        raise ValueError(f'{scanner_name} report path is not a regular file: {filepath!r}')
    if report_size > _MAX_REPORT_BYTES:
        # K-2: the boundary is inclusive — a report of exactly _MAX_REPORT_BYTES
        # parses; only strictly-larger files are refused. The limit is a
        # built-in constant, not configurable.
        raise ValueError(
            f'{scanner_name} file {filepath!r} is {report_size:,} bytes; refusing to '
            f'parse reports over the {_MAX_REPORT_BYTES:,}-byte built-in limit. '
            f'Split the report or narrow the scanner scope.'
        )
    return target_resolved, filepath_resolved


def _reject_redacted_report(secret: str, *, scanner_name: str, flag: str) -> None:
    """Fail closed on a report whose ``Secret`` fields the scanner itself redacted.

    Gitleaks and Betterleaks both take a ``--redact`` flag that rewrites
    ``Secret`` inside the report. At its default 100% it writes the literal
    ``REDACTED``, and that form does damage rather than just being useless. The
    redactor applies ``full_value`` as a plain substring replacement and then
    sweeps the file for further copies, so ingesting it rewrites every line
    holding that word, including Credactor's own ``REDACTED_BY_CREDACTOR``
    sentinel, which is what a re-scan of an already-redacted tree reports. The
    run then reports success. Refusing the report is fatal (exit 2) and writes
    no bytes. There is no partly usable case, because the flag redacts every
    finding.

    The percentage form (``--redact=20``, a ``<prefix>...`` truncation) is not
    matched here, on purpose. It cannot substring-match a line holding the full
    secret, so it already fails safe as an ordinary stale finding (warned,
    unresolved, exit 1), and a trailing ``...`` is ordinary content that a
    generic rule captures verbatim from an elided token in a README or a test
    fixture. Refusing on it aborted whole runs over reports that were never
    redacted, leaving the real secrets in place.
    """
    if secret == 'REDACTED':
        raise ValueError(
            f'{scanner_name} report contains scanner-redacted Secret values '
            f'(found {secret!r}); it cannot be used for redaction. Regenerate '
            f'the report without the {scanner_name} {flag} flag. That flag '
            f'rewrites Secret inside the report, so Credactor would replace the '
            f'placeholder text rather than the secret.'
        )


def _parse_gitleaks_record(
    obj: dict[str, Any],
    target_resolved: str,
    filepath_resolved: str,
    stats: dict[str, Any],
) -> Finding | None:
    """Validate one Gitleaks record and build its Finding. Returns ``None``
    (logged, and counted when the record is invalid) for a record to skip."""
    # --- Secret ---
    secret = obj.get('Secret', '')
    if not _usable_secret(secret):
        logger.info('Skipping Gitleaks finding with an empty or unusable Secret.')
        stats['invalid_record'] += 1
        return None
    _reject_redacted_report(secret, scanner_name='Gitleaks', flag='--redact')

    # --- File path ---
    # Use SymlinkFile if non-empty, otherwise File
    raw_file = obj.get('SymlinkFile') or obj.get('File', '')
    if not isinstance(raw_file, str) or not raw_file:
        logger.info('Skipping Gitleaks finding with non-string or empty File.')
        stats['invalid_record'] += 1
        return None

    resolved = _resolve_external_finding_path(
        raw_file,
        target_resolved,
        filepath_resolved,
        scanner_name='Gitleaks',
        stats=stats,
    )
    if resolved is None:
        return None

    # --- Line number ---
    line = _valid_line(obj.get('StartLine'))

    # --- raw context line ---
    match_ctx = obj.get('Match', '')
    raw = match_ctx if isinstance(match_ctx, str) and match_ctx else _synthesise_raw(resolved, line)

    # --- Type ---
    rule_id = _report_label(obj.get('RuleID', 'unknown'), stats)
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
    # type-check before slicing: a non-string Commit (e.g. int, list)
    # would raise TypeError or produce an unhashable value that crashes
    # deduplicate_findings later.
    commit = _report_commit(obj.get('Commit', ''), secret, stats)
    if commit:
        finding['commit'] = commit
    _mark_git_path(finding, raw_file, target_resolved, stats)
    _mark_implausible(finding, stats)
    _mark_bad_line(finding, stats)

    return finding


def ingest_gitleaks(
    filepath: str,
    target: str,
    stats: dict[str, Any] | None = None,
) -> list[Finding]:
    """Parse a Gitleaks JSON report and return a list of Credactor finding dicts.

    Validates top-level is a list, caps at 10,000 findings, and checks
    resolved paths are within the target directory. *stats* (see
    ``new_ingest_stats``) accumulates skip counters for the CLI's run-level
    summaries; ``None`` keeps them private to this call.
    """
    target_resolved, filepath_resolved = _load_report_preamble(
        filepath, target, scanner_name='Gitleaks'
    )
    if stats is None:
        stats = new_ingest_stats()
    fixed_up_start = _counts_at_start(stats)

    # Load JSON
    try:
        with open(filepath, encoding='utf-8', errors='strict') as fh:
            data = json.load(fh)
    except OSError as exc:
        raise ValueError(f'Cannot open Gitleaks file {filepath!r}: {exc}') from exc
    except UnicodeDecodeError as exc:
        raise ValueError(
            f'Gitleaks file {filepath!r} contains non-UTF-8 bytes; cannot parse safely: {exc}'
        ) from exc
    except json.JSONDecodeError as exc:
        # K-4: 'Extra data' after a complete first JSON value is the signature
        # of an NDJSON report fed to the wrong flag — say so instead of leaving
        # only the raw decoder text.
        hint = (
            ' (the file looks like NDJSON — TruffleHog reports go to --from-trufflehog)'
            if exc.msg.startswith('Extra data')
            else ''
        )
        raise ValueError(f'Gitleaks file is not valid JSON ({filepath!r}): {exc}{hint}') from exc
    except RecursionError as exc:
        # Deeply-nested JSON (e.g. '['*200k) exhausts the interpreter recursion
        # limit. RecursionError is a RuntimeError, not one of the above, so it
        # would otherwise escape as an uncaught traceback (exit 1) instead of
        # the contracted fatal exit 2. Fail closed like any unparseable report.
        raise ValueError(
            f'Gitleaks file {filepath!r} is too deeply nested to parse safely: {exc}'
        ) from exc

    if not isinstance(data, list):
        raise ValueError(
            f'Gitleaks report must be a JSON array at top level '
            f'(got {type(data).__name__}). File: {filepath!r}'
        )

    if len(data) > _MAX_FINDINGS:
        logger.warning(
            'Gitleaks report contains %d findings; truncating to %d.',
            len(data),
            _MAX_FINDINGS,
        )
        data = data[:_MAX_FINDINGS]

    findings: list[Finding] = []
    invalid_start = stats['invalid_record']

    for index, obj in enumerate(data, start=1):
        if not isinstance(obj, dict):
            logger.info('Skipping non-object entry in Gitleaks report.')
            stats['invalid_record'] += 1
            continue
        finding = _parse_or_salvage(
            lambda rec: _parse_gitleaks_record(rec, target_resolved, filepath_resolved, stats),
            obj,
            stats,
            f'Gitleaks record {index}',
        )
        if finding is not None:
            findings.append(finding)

    invalid = stats['invalid_record'] - invalid_start
    if invalid:
        # Same class as the A08 unsupported-source summary: the per-record
        # skips are INFO-only, so a wholly-invalid report (schema drift, or a
        # post-processor that strips Secret fields) would otherwise be
        # byte-indistinguishable from a clean run and exit 0.
        logger.warning(
            '%d Gitleaks record(s) skipped as invalid (non-object entry, or '
            'empty/missing Secret or File) — check the report and scanner '
            'version; an all-invalid report is otherwise indistinguishable '
            'from a clean scan.',
            invalid,
        )
    _warn_fixed_up(stats, fixed_up_start, 'Gitleaks', 'RuleID')

    return findings


# ---------------------------------------------------------------------------
# Betterleaks ingestion
# ---------------------------------------------------------------------------
# Betterleaks writes a JSON array whose objects carry Go field names verbatim
# (no struct tags), so the Gitleaks field mapping reads them unchanged. This
# parser is separate on purpose: the Gitleaks path works and stays untouched.
# The deltas are the type string, the ValidationStatus severity, non-filesystem
# source accounting, and the JSON-null clean report below.


def _betterleaks_summaries(
    stats: dict[str, Any],
    own_unsupported: dict[str, Any],
    invalid_start: int,
    unsupported_start: int,
    component_sets: int,
) -> None:
    """Emit ``ingest_betterleaks``'s three run-level summaries.

    Extracted from the parser to keep it under the statement ceiling, and
    because the scoping rules here are the subtle part: the counts are deltas
    against the shared *stats* dict (the CLI passes one to every parser), while
    the source-type labels come from *own_unsupported*, a parser-local view.
    Rendering the labels from the shared set reported another scanner's source
    types as Betterleaks'.
    """
    invalid_here = stats['invalid_record'] - invalid_start
    if invalid_here:
        # Per-record skips are INFO-only, so a wholly-invalid report (schema
        # drift, or a post-processor that strips Secret fields) would otherwise
        # be byte-indistinguishable from a clean scan and exit 0.
        logger.warning(
            '%d Betterleaks record(s) skipped as invalid (non-object entry, '
            'empty/missing Secret, or a non-string file path) — check the report '
            'and scanner version; an all-invalid report is otherwise '
            'indistinguishable from a clean scan.',
            invalid_here,
        )

    unsupported_here = stats['unsupported_source'] - unsupported_start
    if unsupported_here:
        types = sorted(str(t) for t in own_unsupported['unsupported_types'])
        if own_unsupported['unsupported_types_truncated']:
            types.append('(further types omitted)')
        logger.warning(
            '%d Betterleaks finding(s) skipped: no file path, source type(s) %s — '
            'only filesystem and git sources can be ingested.',
            unsupported_here,
            types if types else '(unknown)',
        )

    if component_sets:
        logger.warning(
            '%d Betterleaks finding(s) carry multi-part component secrets that were '
            'NOT ingested and will not be redacted — only the primary secret of each '
            'is handled. Check those findings with the scanner directly.',
            component_sets,
        )


def _parse_betterleaks_record(
    obj: dict[str, Any],
    target_resolved: str,
    filepath_resolved: str,
    stats: dict[str, Any],
    own_unsupported: dict[str, Any],
) -> Finding | None:
    """Validate one Betterleaks record and build its Finding. Returns ``None``
    (logged and counted) for a record to skip."""
    # --- Secret ---
    secret = obj.get('Secret', '')
    if not _usable_secret(secret):
        logger.info('Skipping Betterleaks finding with an empty or unusable Secret.')
        stats['invalid_record'] += 1
        return None
    _reject_redacted_report(secret, scanner_name='Betterleaks', flag='--redact')

    # --- Source metadata ---
    # Attributes is the forward-looking source; File/SymlinkFile/Commit are
    # deprecated mirrors that Betterleaks still populates. Read Attributes
    # ahead of its mirror within each role so the parser survives their
    # eventual removal.
    raw_attrs = obj.get('Attributes')
    attrs: dict[str, Any] = raw_attrs if isinstance(raw_attrs, dict) else {}
    # The candidates are ordered by role, not by field generation: both
    # symlink fields rank above both real-path fields, which is the
    # symlink-before-path precedence the Gitleaks path already documents.
    # Reading Attributes straight through (fs.symlink, path, SymlinkFile,
    # File) inverted that under the schema drift the Attributes-first
    # ordering exists to survive. A version emitting Attributes.path while
    # exposing the symlink only through the deprecated mirror would resolve
    # the real file, and a real file outside the target root is then dropped
    # by the traversal guard, so the redaction goes missing in silence.
    #
    # The candidates are taken one at a time rather than through an `or`
    # chain. `or` skips over a falsy non-string (`0`, `False`, `[]`, `{}`)
    # in any position but the last, so a corrupt value there reached the
    # pathless branch and was charged to unsupported_source instead of
    # invalid_record. An absent key and an empty string both mean "not set"
    # (Betterleaks writes '' for the mirrors it does not populate) and fall
    # through to the next candidate. Anything else is taken and type-checked
    # below.
    raw_file: Any = ''
    for source, key in (
        (attrs, 'fs.symlink'),
        (obj, 'SymlinkFile'),
        (attrs, 'path'),
        (obj, 'File'),
    ):
        if key not in source or source[key] == '':
            continue
        raw_file = source[key]
        break
    if not isinstance(raw_file, str):
        # A path that is present but not a string is a malformed record,
        # not an unsupported source. This matches the Gitleaks parser,
        # which counts a non-string File the same way, JSON `null`
        # included. Keeping the two apart matters: the unsupported-source
        # summary would otherwise tell the operator a source type could not
        # be ingested when the report is simply corrupt.
        logger.info('Skipping Betterleaks finding with a non-string file path.')
        stats['invalid_record'] += 1
        return None
    if not raw_file:
        # No path at all: a non-filesystem source (stdin, GitHub, GitLab,
        # Hugging Face, S3). Structurally un-redactable rather than
        # malformed, so it is counted as an unsupported source, NOT an
        # invalid record. Gate on path presence, not on the `resource`
        # label: a `stdin` finding carries resource='fs.content' with an
        # empty path, so a resource allowlist would wrongly accept it.
        label = attrs.get('resource')
        logger.info(
            'Skipping Betterleaks finding from unsupported source %r (no file path).',
            label,
        )
        stats['unsupported_source'] += 1
        labels = {str(label) if isinstance(label, str) and label else 'unknown'}
        _note_unsupported_types(stats, labels)
        # ...and again into a parser-local view. The CLI shares one stats
        # dict across all three parsers and runs Betterleaks last, so
        # rendering the summary from the shared set would report another
        # scanner's source types (and its truncation flag) as Betterleaks'.
        _note_unsupported_types(own_unsupported, labels)
        return None

    resolved = _resolve_external_finding_path(
        raw_file,
        target_resolved,
        filepath_resolved,
        scanner_name='Betterleaks',
        stats=stats,
    )
    if resolved is None:
        return None

    # --- Line number ---
    line = _valid_line(obj.get('StartLine'))

    # --- raw context line ---
    # Prefer the on-disk line: Finding['raw'] is contracted as a single
    # source line and Betterleaks' Match can span lines for some rules.
    raw = _synthesise_raw(resolved, line)
    if not raw:
        match_ctx = obj.get('Match', '')
        if isinstance(match_ctx, str) and match_ctx and '\n' not in match_ctx:
            raw = match_ctx
        else:
            raw = secret

    # --- Type ---
    rule_id = _report_label(obj.get('RuleID', 'unknown'), stats)
    ftype = f'external:betterleaks:{rule_id}'

    # --- Severity ---
    tags = obj.get('Tags') or []
    status = obj.get('ValidationStatus', '')
    severity = _betterleaks_severity(
        rule_id,
        status if isinstance(status, str) else '',
        tags if isinstance(tags, list) else [],
    )

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
    # Type-check before slicing: a non-string value would raise TypeError
    # or produce an unhashable dedup key later.
    commit = _report_commit(attrs.get('git.sha') or obj.get('Commit', ''), secret, stats)
    if commit:
        finding['commit'] = commit

    _mark_git_path(finding, raw_file, target_resolved, stats)
    _mark_implausible(finding, stats)
    _mark_bad_line(finding, stats)

    return finding


def ingest_betterleaks(
    filepath: str,
    target: str,
    stats: dict[str, Any] | None = None,
) -> list[Finding]:
    """Parse a Betterleaks JSON report and return a list of Credactor findings.

    Same shape as ``ingest_gitleaks`` — JSON array, 10,000-finding cap, paths
    confined to the target — with four Betterleaks-specific behaviours:

    * a top-level JSON ``null`` (what Betterleaks writes for a clean scan) is
      an empty report, not a malformed one;
    * source metadata is read from ``Attributes`` first, falling back to the
      deprecated ``File``/``SymlinkFile``/``Commit`` mirrors;
    * findings with no file path (``stdin``, GitHub, GitLab, Hugging Face, S3)
      are counted as unsupported sources, not invalid records;
    * ``ValidationStatus`` drives severity when it is decisive.

    *stats* (see ``new_ingest_stats``) accumulates skip counters; a local dict
    is used when ``None`` so the run-level summaries fire for direct callers.
    """
    target_resolved, filepath_resolved = _load_report_preamble(
        filepath, target, scanner_name='Betterleaks'
    )
    if stats is None:
        stats = new_ingest_stats()
    # The CLI shares one stats dict across every ingest call, so the summaries
    # below must count only THIS parser's skips.
    invalid_start = stats['invalid_record']
    unsupported_start = stats['unsupported_source']
    fixed_up_start = _counts_at_start(stats)

    try:
        with open(filepath, encoding='utf-8', errors='strict') as fh:
            data = json.load(fh)
    except OSError as exc:
        raise ValueError(f'Cannot open Betterleaks file {filepath!r}: {exc}') from exc
    except UnicodeDecodeError as exc:
        raise ValueError(
            f'Betterleaks file {filepath!r} contains non-UTF-8 bytes; cannot parse safely: {exc}'
        ) from exc
    except json.JSONDecodeError as exc:
        hint = (
            ' (the file looks like NDJSON — TruffleHog reports go to --from-trufflehog)'
            if exc.msg.startswith('Extra data')
            else ''
        )
        raise ValueError(f'Betterleaks file is not valid JSON ({filepath!r}): {exc}{hint}') from exc
    except RecursionError as exc:
        # RecursionError is a RuntimeError, so without this it escapes the
        # CLI's `except ValueError` as an uncaught traceback (exit 1) instead
        # of the contracted fatal exit 2.
        raise ValueError(
            f'Betterleaks file {filepath!r} is too deeply nested to parse safely: {exc}'
        ) from exc

    if data is None:
        # Betterleaks writes literal `null` for a zero-finding report, where
        # Gitleaks writes `[]`. Without this a CLEAN upstream scan would hit
        # the non-list guard below and exit 2 with 'must be a JSON array',
        # failing the gate on every clean run.
        data = []

    if not isinstance(data, list):
        hint = (
            ' (a SARIF document is a JSON object — pass the JSON report instead)'
            if isinstance(data, dict)
            else ''
        )
        raise ValueError(
            f'Betterleaks report must be a JSON array at top level '
            f'(got {type(data).__name__}). File: {filepath!r}{hint}'
        )

    if len(data) > _MAX_FINDINGS:
        logger.warning(
            'Betterleaks report contains %d findings; truncating to %d.',
            len(data),
            _MAX_FINDINGS,
        )
        data = data[:_MAX_FINDINGS]

    findings: list[Finding] = []
    component_sets = 0
    own_unsupported: dict[str, Any] = {
        'unsupported_types': set(),
        'unsupported_types_truncated': False,
    }

    for index, obj in enumerate(data, start=1):
        if not isinstance(obj, dict):
            logger.info('Skipping non-object entry in Betterleaks report.')
            stats['invalid_record'] += 1
            continue
        finding = _parse_or_salvage(
            lambda rec: _parse_betterleaks_record(
                rec, target_resolved, filepath_resolved, stats, own_unsupported
            ),
            obj,
            stats,
            f'Betterleaks record {index}',
        )
        if finding is None:
            continue
        # A ComponentSet carries the other half of a multi-part credential
        # (an access-key id plus its secret key, say) with its own line and
        # value. Only the top-level Secret is ingested, so those component
        # secrets are reported by neither this finding nor any other — count
        # them for the run-level summary rather than redacting half a
        # credential and reporting success.
        comps = obj.get('ComponentSets')
        if isinstance(comps, list) and comps:
            component_sets += 1
        findings.append(finding)

    _betterleaks_summaries(stats, own_unsupported, invalid_start, unsupported_start, component_sets)
    _warn_fixed_up(stats, fixed_up_start, 'Betterleaks', 'RuleID')

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
    stats: dict[str, Any] | None = None,
    own_unsupported: dict[str, Any] | None = None,
) -> Finding | None:
    """Validate one TruffleHog NDJSON record and build its Finding.

    Returns ``None`` (with an info log naming the reason) for any record
    that should be skipped. Extracted verbatim from the read loop so the
    sequential validation steps are unit-testable in isolation and the
    loop stays readable.
    """
    # --- Raw secret ---
    raw_secret = obj.get('Raw', '')
    if not _usable_secret(raw_secret):
        logger.info(
            'TruffleHog line %d: skipping finding with an empty or unusable Raw.',
            lineno_file,
        )
        if stats is not None:
            stats['invalid_record'] += 1
        return None
    if '\ufffd' in raw_secret:
        logger.info(
            'TruffleHog line %d: Raw field contains non-UTF-8 bytes '
            '(replacement character U+FFFD); skipping to avoid corrupted redaction.',
            lineno_file,
        )
        if stats is not None:
            stats['invalid_record'] += 1
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
    raw_line: object = None
    raw_commit: object = ''
    source_found = False

    if isinstance(data, dict):
        # Filesystem source (preferred)
        fs = data.get('Filesystem')
        if isinstance(fs, dict):
            file_path_raw = fs.get('file', '') or ''
            raw_line = fs.get('line')
            source_found = True
        else:
            # Git source
            git = data.get('Git')
            if isinstance(git, dict):
                file_path_raw = git.get('file', '') or ''
                raw_line = git.get('line')
                raw_commit = git.get('commit', '') or ''
                source_found = True

    if not source_found:
        supported = {'Filesystem', 'Git'}
        keys = set(data.keys()) if isinstance(data, dict) else set()
        unsupported = {str(k) for k in keys - supported}
        # A Filesystem/Git key that is present but not a usable object is a
        # malformed supported-source record, not an unsupported source — label
        # it as such so the run-level summary's count is always explained by
        # its type list and the 'only filesystem and git' advice is never
        # pointed at records that WERE filesystem/git.
        malformed = {f'{k} (malformed entry)' for k in keys & supported}
        labels = unsupported | malformed
        logger.info(
            'TruffleHog line %d: unsupported source type %s; skipping.',
            lineno_file,
            sorted(labels) if labels else '(unknown)',
        )
        if stats is not None:
            stats['unsupported_source'] += 1
            _note_unsupported_types(stats, labels)
        if own_unsupported is not None:
            # ...and again into a parser-local view, for the same reason
            # ingest_betterleaks keeps one: the CLI shares a single stats dict
            # across all three parsers, so rendering the summary from the shared
            # set would report another scanner's source types as TruffleHog's.
            _note_unsupported_types(own_unsupported, labels)
        return None

    if not isinstance(file_path_raw, str) or not file_path_raw:
        logger.info(
            'TruffleHog line %d: skipping finding with non-string or empty file path.',
            lineno_file,
        )
        if stats is not None:
            stats['invalid_record'] += 1
        return None

    resolved = _resolve_external_finding_path(
        file_path_raw,
        target_resolved,
        filepath_resolved,
        scanner_name='TruffleHog',
        stats=stats,
    )
    if resolved is None:
        return None

    line_num = _valid_line(raw_line)

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
    detector_name = _report_label(obj.get('DetectorName', 'unknown'), stats)
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

    # Checked only now, so a record skipped above is not counted, and against
    # the form of the secret that was chosen. A non-string commit (int, list)
    # is dropped: slicing one would crash deduplicate_findings.
    commit = _report_commit(raw_commit, raw_secret, stats)
    if commit:
        finding['commit'] = commit
    _mark_git_path(finding, file_path_raw, target_resolved, stats)
    _mark_implausible(finding, stats)
    _mark_bad_line(finding, stats)

    return finding


def ingest_trufflehog(
    filepath: str,
    target: str,
    stats: dict[str, Any] | None = None,
) -> list[Finding]:
    """Parse a TruffleHog NDJSON output file and return Credactor finding dicts.

    Validates each line as a JSON object, caps at 10,000 findings, and
    checks resolved paths are within the target directory. *stats* (see
    ``new_ingest_stats``) accumulates skip counters for the CLI's run-level
    summaries; a local dict is used when ``None`` so the unsupported-source
    summary below fires for direct callers too.
    """
    target_resolved, filepath_resolved = _load_report_preamble(
        filepath, target, scanner_name='TruffleHog'
    )
    if stats is None:
        stats = new_ingest_stats()
    # The CLI shares one stats dict across every ingest call, so the summaries
    # below must count only THIS parser's skips.
    invalid_start = stats['invalid_record']
    unsupported_start = stats['unsupported_source']
    fixed_up_start = _counts_at_start(stats)
    own_unsupported: dict[str, Any] = {
        'unsupported_types': set(),
        'unsupported_types_truncated': False,
    }

    try:
        # Closed via `with fh:` below; opened inside try only to convert OSError
        # into a ValueError with a clearer message.
        fh = open(filepath, encoding='utf-8', errors='replace')  # noqa: SIM115
    except OSError as exc:
        raise ValueError(f'Cannot open TruffleHog file {filepath!r}: {exc}') from exc

    findings: list[Finding] = []
    count = 0
    saw_content = False  # any non-blank line
    saw_object = False  # any line that parsed to a JSON object
    first_line_is_array = False  # first non-blank line opens a JSON array

    with fh:
        for lineno_file, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            if not saw_content:
                first_line_is_array = line.startswith('[')
            saw_content = True

            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.info(
                    'TruffleHog file line %d: skipping invalid JSON: %s',
                    lineno_file,
                    exc,
                )
                continue
            except RecursionError as exc:
                # A deeply-nested line is resource exhaustion, not an ordinary
                # malformed line: fail closed (fatal exit 2) rather than skip.
                raise ValueError(
                    f'TruffleHog file {filepath!r} line {lineno_file} is too '
                    f'deeply nested to parse safely: {exc}'
                ) from exc

            if not isinstance(obj, dict):
                logger.info(
                    'TruffleHog file line %d: skipping non-object JSON value.',
                    lineno_file,
                )
                continue
            saw_object = True

            if count >= _MAX_FINDINGS:
                logger.warning(
                    'TruffleHog report exceeds %d findings; truncating.',
                    _MAX_FINDINGS,
                )
                break

            parse = functools.partial(
                _parse_trufflehog_record,
                lineno_file=lineno_file,
                target_resolved=target_resolved,
                filepath_resolved=filepath_resolved,
                stats=stats,
                own_unsupported=own_unsupported,
            )
            finding = _parse_or_salvage(parse, obj, stats, f'TruffleHog line {lineno_file}')
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
        # K-4 twin: a leading '[' is the signature of a Gitleaks JSON array fed
        # to the NDJSON flag.
        hint = (
            ' (a JSON array looks like a Gitleaks report — use --from-gitleaks)'
            if first_line_is_array
            else ''
        )
        raise ValueError(
            f'TruffleHog file {filepath!r} is not valid NDJSON: '
            f'no JSON object found on any non-empty line.{hint}'
        )

    # A08: records from unsupported sources (github, docker, s3, ...) are
    # skipped at INFO level per record; without this summary an
    # all-unsupported report is byte-indistinguishable from a clean run and
    # exits 0 — a false all-clear in CI.
    unsupported_here = stats['unsupported_source'] - unsupported_start
    if unsupported_here:
        types = sorted(str(t) for t in own_unsupported['unsupported_types'])
        if own_unsupported['unsupported_types_truncated']:
            types.append('(further types omitted)')
        logger.warning(
            '%d TruffleHog finding(s) skipped: unsupported source type(s) %s — '
            'only filesystem and git sources can be ingested.',
            unsupported_here,
            types if types else '(unknown)',
        )

    invalid_here = stats['invalid_record'] - invalid_start
    if invalid_here:
        # Same class as the unsupported-source summary above: these skips are
        # INFO-only per record, and a report whose records all carry empty or
        # binary secrets (TruffleHog emits U+FFFD for binary matches) would
        # otherwise be a silent exit-0 all-clear — dropping even Verified
        # findings invisibly.
        logger.warning(
            '%d TruffleHog record(s) skipped as invalid (empty or binary '
            'non-UTF-8 Raw secret, or missing file path) — these findings, '
            'Verified ones included, are not ingested and cannot be redacted; '
            'handle them with the scanner directly.',
            invalid_here,
        )
    _warn_fixed_up(stats, fixed_up_start, 'TruffleHog', 'DetectorName')

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
    then trufflehog, then betterleaks.  First occurrence wins, so priority is
    automatically Credactor > Gitleaks > TruffleHog > Betterleaks.
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
    known: KnownSecrets | None = None  # built on first use (PA-04, SR-07)

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
            if SEVERITY_RANK.get(dropped_sev, 1) > SEVERITY_RANK.get(
                survivor.get('severity', 'medium'), 1
            ):
                if known is None:
                    known = name_secrets(x['full_value'] for x in findings)
                logger.info(
                    'Dedup raised severity %s -> %s at %s:%s (kept %s, merged %s).',
                    survivor.get('severity'),
                    dropped_sev,
                    known.redact(survivor.get('file', '')),
                    survivor.get('line'),
                    known.redact(survivor.get('type', '')),
                    known.redact(f.get('type', '')),
                )
                survivor['severity'] = dropped_sev
            continue
        seen[key] = len(result)
        result.append(f)

    removed = len(findings) - len(result)
    if removed:
        logger.info('Deduplicated %d finding(s).', removed)

    return result
