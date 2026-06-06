"""
Shared type definitions for Credactor.

Defines the ``Finding`` dictionary shape used across scanner, ingest, walker,
report, and redactor modules. Using a ``TypedDict`` keeps the runtime shape
unchanged (it's still a plain ``dict``) while letting static type checkers
and IDEs catch typos in finding keys.
"""

from __future__ import annotations

from typing import Literal, NotRequired, TypedDict


class Finding(TypedDict):
    """A credential-detection finding.

    Fields are populated by the native scanner (``scanner.scan_line``),
    external ingest parsers (``ingest.ingest_gitleaks`` /
    ``ingest.ingest_trufflehog``), and the multiline scanner.

    Keys
    ----
    file:           absolute path to the source file.
    line:           1-indexed line number.
    type:           detection category, e.g.
                    ``pattern:AWS access key``, ``variable:api_key``,
                    ``xml-attr:Password``, ``external:gitleaks:aws-access-token``,
                    ``multiline:JWT token``.
    severity:       one of ``critical`` / ``high`` / ``medium`` / ``low``.
    full_value:     the literal credential text as it appears in the source
                    (used for redaction matching).
    value_preview:  truncated, safe-for-display version of ``full_value``.
    raw:            the source line containing the finding (rstripped).
    commit:         optional 12-char commit prefix when the finding came
                    from git-history scanning or an external scanner's
                    git source metadata.
    """

    file:          str
    line:          int
    type:          str
    severity:      str
    full_value:    str
    value_preview: str
    raw:           str
    commit:        NotRequired[str]


# Severity ordering, highest first. Shared by the scanner's per-line span dedup
# (L2) and the ingest dedup's severity merge (L5c) so both rank severities the
# same way.
SEVERITY_RANK: dict[str, int] = {'critical': 3, 'high': 2, 'medium': 1, 'low': 0}

# The fixed severity domain, shared by VALUE_PATTERNS (patterns.ValuePattern)
# and the Finding.severity field documented above.
Severity = Literal['critical', 'high', 'medium', 'low']
