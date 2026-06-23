"""
Output formatting: text (with colors), JSON, SARIF.

Addresses: #2/#29 (masked secrets), #7 (JSON/SARIF), #31 (ANSI color),
           #32 (progress indicator)
"""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path
from typing import Any, TextIO

from . import __version__
from .types import Finding
from .utils import group_by_file, mask_secret, relativize, sanitize_for_terminal

# ---------------------------------------------------------------------------
# ANSI color helpers (#31)
# ---------------------------------------------------------------------------
_COLORS = {
    'reset': '\033[0m',
    'bold': '\033[1m',
    'red': '\033[91m',
    'magenta': '\033[95m',
    'yellow': '\033[93m',
    'cyan': '\033[96m',
    'green': '\033[92m',
    'dim': '\033[2m',
}

_SEVERITY_COLOR = {
    'critical': 'magenta',  # distinct from high so the top two severities differ
    'high': 'red',
    'medium': 'yellow',
    'low': 'cyan',
}


def _c(text: str, color: str, *, use_color: bool = True) -> str:
    """Wrap text in ANSI color codes if use_color is True."""
    if not use_color:
        return text
    code = _COLORS.get(color, '')
    return f'{code}{text}{_COLORS["reset"]}' if code else text


def _should_use_color(no_color: bool, stream: TextIO = sys.stdout) -> bool:
    """Determine whether to use ANSI color output on *stream*."""
    if no_color:
        return False
    return stream.isatty()


# ---------------------------------------------------------------------------
# Text report (#2, #29 — masked secrets)
# ---------------------------------------------------------------------------
def print_report(
    findings: list[Finding],
    root: str,
    *,
    no_color: bool = False,
    stream: TextIO = sys.stdout,
) -> None:
    """Print the human-readable text report (secrets masked, paths sanitized).

    Prints nothing for empty findings: the 'clean scan' message is owned by
    ``cli._emit_report`` alone, so a second (drift-prone) copy of that message
    does not live here — and a 0-finding report frame with the 'rotate your
    credentials' footer would be misleading.
    """
    if not findings:
        return
    color = _should_use_color(no_color, stream)
    root_path = Path(root).resolve()
    by_file = group_by_file(findings)

    print(f'\n{"=" * 70}', file=stream)
    header = f'  CREDENTIAL SCAN REPORT  --  {len(findings)} finding(s) in {len(by_file)} file(s)'
    print(_c(header, 'bold', use_color=color), file=stream)
    print(f'{"=" * 70}\n', file=stream)

    for filepath, file_findings in sorted(by_file.items()):
        safe_rel = sanitize_for_terminal(relativize(filepath, root_path))
        print(_c(f'  FILE: {safe_rel}', 'bold', use_color=color), file=stream)
        print(f'  {"─" * 60}', file=stream)
        for finding in file_findings:
            severity = finding['severity']
            sev_color = _SEVERITY_COLOR.get(severity, 'dim')

            # #2/#29 — mask the credential in the raw line display
            masked_raw = _mask_in_line(finding['raw'], finding['full_value'])

            safe_type = sanitize_for_terminal(finding['type'])
            safe_raw = sanitize_for_terminal(masked_raw[:120])
            sev_label = _c(f'[{severity.upper()}]', sev_color, use_color=color)
            print(f'  Line {finding["line"]:>4}  {sev_label}  [{safe_type}]', file=stream)
            print(f'           {safe_raw}', file=stream)
        print(file=stream)

    print(f'{"=" * 70}', file=stream)
    print('  ACTION REQUIRED: Rotate/revoke any real credentials above.', file=stream)
    print('  Use environment variables or a secrets manager instead.', file=stream)
    print(f'{"=" * 70}\n', file=stream)


def _mask_in_line(raw_line: str, full_value: str) -> str:
    """Replace the credential in the raw line with a masked version.

    If ``full_value`` is not a verbatim substring of ``raw_line`` the substring
    replace would silently no-op and print the raw line WITH the secret. This
    happens for ingested findings whose stored value differs from the on-disk
    form (e.g. a TruffleHog URL-decoded value vs the encoded source). Fail
    closed: show only the masked value rather than the raw line, so a credential
    is never emitted unmasked.
    """
    masked = mask_secret(full_value)
    if full_value and full_value in raw_line:
        return raw_line.replace(full_value, masked, 1)
    return masked


# ---------------------------------------------------------------------------
# JSON output (#7)
# ---------------------------------------------------------------------------
def json_report(findings: list[Finding], root: str) -> str:
    """Return findings as a JSON string."""
    root_path = Path(root).resolve()
    output = []
    for f in findings:
        rel = relativize(f['file'], root_path)
        output.append(
            {
                'file': rel,
                'line': f['line'],
                'type': f['type'],
                'severity': f['severity'],
                'value': mask_secret(f['full_value']),
                'commit': f.get('commit'),
            }
        )
    return json.dumps({'findings': output, 'count': len(output)}, indent=2)


# ---------------------------------------------------------------------------
# SARIF output (#7)
# ---------------------------------------------------------------------------
def sarif_report(findings: list[Finding], root: str) -> str:
    """Return findings as a SARIF 2.1.0 JSON string."""
    root_path = Path(root).resolve()

    rules: dict[str, dict[str, Any]] = {}
    rule_index: dict[str, int] = {}
    results = []

    for f in findings:
        safe_type = html.escape(f['type'])
        rule_id = safe_type.replace(':', '-')
        if rule_id not in rules:
            rule_index[rule_id] = len(rules)
            rules[rule_id] = {
                'id': rule_id,
                'shortDescription': {'text': safe_type},
                'fullDescription': {
                    'text': f'Credactor detected a potential hardcoded credential ({safe_type})',
                },
                'help': {
                    'text': (
                        'Remove the hardcoded credential and use an'
                        ' environment variable or secrets manager instead.'
                    ),
                },
                'defaultConfiguration': {
                    'level': _sarif_level(f['severity']),
                },
            }

        rel = relativize(f['file'], root_path)

        # Column positions for precise annotation. Omit them when the value
        # isn't found on the stored line rather than pointing at a wrong column.
        raw_line = f['raw']
        full_val = f['full_value']
        idx = raw_line.find(full_val) if full_val else -1

        region: dict[str, Any] = {
            'startLine': f['line'],
            'endLine': f['line'],
        }
        if idx >= 0:
            region['startColumn'] = idx + 1
            region['endColumn'] = idx + 1 + len(full_val)

        results.append(
            {
                'ruleId': rule_id,
                'ruleIndex': rule_index[rule_id],
                'level': _sarif_level(f['severity']),
                'message': {
                    'text': (
                        f'Potential credential detected: {html.escape(f["type"])}'
                        f' ({html.escape(mask_secret(f["full_value"]))})'
                    ),
                },
                'locations': [
                    {
                        'physicalLocation': {
                            'artifactLocation': {'uri': rel},
                            'region': region,
                        },
                    }
                ],
            }
        )

    sarif = {
        '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
        'version': '2.1.0',
        'runs': [
            {
                'tool': {
                    'driver': {
                        'name': 'Credactor',
                        'version': __version__,
                        'informationUri': 'https://github.com/rxb06/credactor',
                        'rules': list(rules.values()),
                    },
                },
                # S13: startColumn/endColumn are computed with str.find/len, i.e.
                # Unicode code points. SARIF 2.1.0 defaults to utf16CodeUnits when
                # columnKind is absent, so GitHub would mis-highlight any line with
                # astral-plane chars before the secret. Declare the actual unit.
                'columnKind': 'unicodeCodePoints',
                'results': results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


_SARIF_LEVELS = {
    'critical': 'error',
    'high': 'error',
    'medium': 'warning',
    'low': 'note',
}


def _sarif_level(severity: str) -> str:
    """Map our severity to SARIF level."""
    return _SARIF_LEVELS.get(severity, 'warning')


# ---------------------------------------------------------------------------
# Gitignore skip report
# ---------------------------------------------------------------------------
def print_gitignore_skipped(
    skipped: list[str], root: str, *, no_color: bool = False, stream: TextIO = sys.stdout
) -> None:
    """List the files a ``.gitignore`` pattern excluded from the scan."""
    if not skipped:
        return
    root_path = Path(root).resolve()
    color = _should_use_color(no_color, stream)
    print(
        _c(
            f'\n  [{len(skipped)} file(s) not scanned -- covered by .gitignore]',
            'dim',
            use_color=color,
        ),
        file=stream,
    )
    for s in sorted(skipped):
        rel = relativize(s, root_path)
        print(f'    {sanitize_for_terminal(rel)}', file=stream)
    print(file=stream)
