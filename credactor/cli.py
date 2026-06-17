"""
CLI entry point using argparse.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

from . import __version__
from ._log import configure as _configure_log
from ._log import logger
from .config import Config, ConfigError, apply_config_file, load_config_file
from .redactor import fix_all, interactive_review
from .report import json_report, print_gitignore_skipped, print_report, sarif_report
from .scanner import scan_file
from .suppressions import AllowList
from .types import Finding
from .utils import group_by_file, sanitize_for_terminal
from .walker import (
    GitUnavailableError,
    scan_git_history,
    scan_staged_files,
    walk_and_scan,
)

# Guard against scanning system/sensitive directories — an exact match against
# the resolved scan target rejects requests to scan well-known system roots.
# fmt: off
_PROTECTED_DIRS: frozenset[str] = frozenset({
    # --- Linux / macOS ---
    '/', '/etc', '/usr', '/var', '/boot', '/sys', '/proc',
    '/bin', '/sbin', '/lib', '/opt', '/root',
    '/home', '/tmp', '/var/tmp',
    '/dev', '/run', '/mnt', '/media', '/snap', '/srv',
    # --- macOS-specific ---
    '/System', '/Library', '/Applications', '/private',
    '/Volumes',
    # --- Windows ---
    'C:\\', 'C:\\Windows', 'C:\\Windows\\System32',
    'C:\\Program Files', 'C:\\Program Files (x86)',
    'C:\\ProgramData', 'C:\\Users',
})
# fmt: on


def _resolve_protected_dirs() -> frozenset[str]:
    """Add resolved forms of symlinked roots (macOS ``/etc`` -> ``/private/etc``,
    ``/var`` -> ``/private/var``, etc.) so the protected-dir guard cannot be
    bypassed by passing the symlink form. The literal originals are kept for
    systems without the symlink."""
    resolved: set[str] = set(_PROTECTED_DIRS)
    for d in _PROTECTED_DIRS:
        try:
            p = Path(d)
            if p.exists():
                resolved.add(str(p.resolve()))
        except OSError:
            pass
    return frozenset(resolved)


_PROTECTED_DIRS_RESOLVED: frozenset[str] = _resolve_protected_dirs()

# M5: a custom replacement string must match the documented contract exactly —
# alphanumeric, underscore, hyphen only. fullmatch (not search) is required: the
# regex `$` matches before a trailing newline, so search would let "X\n" slip
# through and inject a source line.
_SAFE_REPLACEMENT_RE = re.compile(r'[A-Za-z0-9_-]*')


def _fatal(msg: str, *args: object) -> NoReturn:
    """Log an error and exit with code 2 — the CLI's standard fatal path."""
    logger.error(msg, *args)
    sys.exit(2)


def build_parser() -> argparse.ArgumentParser:
    """Define every CLI flag, grouped: mode, output, replacement, config, ingest."""
    parser = argparse.ArgumentParser(
        prog='credactor',
        description=(
            'Detect and redact hardcoded credentials before they hit version control. '
            'Scans source files for API keys, tokens, passwords, private keys, and '
            'connection strings using regex signatures, entropy analysis, and '
            'context-aware variable inspection.'
        ),
        epilog=(
            'Exit codes: 0 = no findings (clean), '
            '1 = unresolved findings detected, '
            '2 = error (path not found, permission denied, --fail-on-error)\n\n'
            'Examples:\n'
            '  credactor .                          Scan current directory interactively\n'
            '  credactor --dry-run src/              Preview findings without modifying\n'
            '  credactor --staged --ci               Pre-commit hook (read-only)\n'
            '  credactor --fix-all --secure-delete   Redact all and wipe backups\n'
            '  credactor -f sarif . > report.sarif   GitHub Code Scanning output\n'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        '--version', action='version',
        version=f'%(prog)s {__version__}',
    )

    parser.add_argument(
        'target', nargs='?', default='.',
        help='directory or file to scan (default: current directory)',
    )

    # Mode flags
    mode = parser.add_argument_group('scan mode')
    mode.add_argument(
        '--ci', action='store_true',
        help='CI/CD mode — report findings and exit 1, no interactive prompts; '
             'suitable for pipeline gates',
    )
    mode.add_argument(
        '--dry-run', action='store_true',
        help='show what would be found without modifying any files; '
             'use this to preview before committing to replacements',
    )
    mode.add_argument(
        '--fix-all', action='store_true',
        help='replace all findings in a single batch (no per-finding prompts); '
             'asks for one confirmation before proceeding — pass --yes to skip it '
             'in non-interactive/CI runs',
    )
    mode.add_argument(
        '--yes', '-y', action='store_true', dest='assume_yes',
        help='skip the --fix-all confirmation prompt; required for '
             'non-interactive use (a piped/CI run without a TTY otherwise aborts)',
    )
    mode.add_argument(
        '--staged', action='store_true',
        help='scan only git-staged files (git diff --cached); '
             'read-only — no files are modified, ideal for pre-commit hooks',
    )
    mode.add_argument(
        '--scan-history', action='store_true',
        help='scan git commit history (up to 100 commits) for leaked credentials; '
             'reports the commit hash where each secret was introduced; '
             'read-only — committed secrets cannot be redacted in place',
    )

    # Output flags
    output = parser.add_argument_group('output')
    output.add_argument(
        '--format', '-f', choices=['text', 'json', 'sarif'], default='text',
        dest='output_format',
        help='output format: text (human-readable, default), '
             'json (machine-readable), sarif (SARIF 2.1.0 for GitHub Code Scanning)',
    )
    output.add_argument(
        '--no-color', action='store_true',
        help='disable ANSI color codes in text output; '
             'auto-disabled when stdout is not a terminal',
    )

    # Replacement flags
    replace = parser.add_argument_group('replacement and backup')
    replace.add_argument(
        '--replace-with', choices=['sentinel', 'env', 'custom'], default='sentinel',
        dest='replace_mode',
        help='replacement strategy: '
             'sentinel = REDACTED_BY_CREDACTOR (fails loudly at runtime), '
             'env = language-aware env var lookup (e.g. os.environ["KEY"]), '
             'custom = your own string via --replacement',
    )
    replace.add_argument(
        '--replacement', type=str, default=None,
        help='custom replacement string used with --replace-with sentinel or custom '
             '(default: REDACTED_BY_CREDACTOR). An explicit value here overrides a '
             "'replacement' set in .credactor.toml.",
    )
    replace.add_argument(
        '--no-backup', action='store_true',
        help='skip creating .bak backup files before modifying; '
             'WARNING: original file content is lost — only use if git history '
             'is your safety net',
    )
    replace.add_argument(
        '--secure-backup-dir', type=str, default=None, metavar='DIR',
        help='store .bak backup files in DIR instead of beside the original files; '
             'keeps plaintext backups outside the repository tree',
    )
    replace.add_argument(
        '--secure-delete', action='store_true',
        help='after successful replacement, overwrite .bak files with random data '
             'and delete them; prevents credential recovery from backups via '
             'disk forensics',
    )

    # Configuration
    config_group = parser.add_argument_group('configuration')
    config_group.add_argument(
        '--config', type=str, default=None, metavar='PATH',
        help='path to .credactor.toml config file; by default searches current '
             'directory and up to 5 parent directories',
    )
    config_group.add_argument(
        '--scan-json', action='store_true',
        help='include .json files in the scan; by default JSON files are '
             'collected but only scanned when explicitly requested',
    )
    config_group.add_argument(
        '--fail-on-error', action='store_true',
        help='exit with code 2 if any files could not be scanned '
             '(e.g. permission denied, encoding errors); useful in CI to '
             'ensure complete coverage',
    )
    config_group.add_argument(
        '--verbose', '-v', action='store_true',
        help='show detailed scan activity on stderr including suppressed '
             'findings, skipped files, and safe-value decisions',
    )

    # External tool ingestion
    ingest = parser.add_argument_group('external tool ingestion (BETA)')
    ingest.add_argument(
        '--from-gitleaks', type=str, default=None, metavar='FILE',
        help='[BETA] ingest findings from a Gitleaks JSON report file; '
             'file paths in the report are resolved relative to the '
             'target directory',
    )
    ingest.add_argument(
        '--from-trufflehog', type=str, default=None, metavar='FILE',
        help='[BETA] ingest findings from a TruffleHog JSON output file '
             '(newline-delimited); file paths are resolved relative to '
             'the target directory',
    )

    return parser


def main(argv: list[str] | None = None) -> None:
    """Console entry point: run the scan and exit (130 on Ctrl-C)."""
    try:
        _main_inner(argv)
    except KeyboardInterrupt:
        print('\nInterrupted.', file=sys.stderr)
        sys.exit(130)


# ---------------------------------------------------------------------------
# Pipeline helpers extracted from _main_inner
# ---------------------------------------------------------------------------

def _emit_report(findings: list[Finding], target: str, config: Config) -> None:
    """Emit findings to stdout in the configured format.

    Handles the empty-findings case (clean exit message in text mode) and
    unifies the json/sarif/text dispatch that previously appeared twice
    inside _main_inner.
    """
    if not findings and config.output_format == 'text':
        print(
            '\n[OK] No hardcoded credentials detected at the current sensitivity '
            f'(entropy floor {config.entropy_threshold:g}). '
            'Review weak or short secrets manually.\n'
        )
        return
    if config.output_format == 'json':
        print(json_report(findings, target))
    elif config.output_format == 'sarif':
        print(sarif_report(findings, target))
    else:
        print_report(findings, target, no_color=config.no_color)


def _handle_errored_files(errored_files: list[str], config: Config) -> None:
    """Report files that errored during scan; honour ``--fail-on-error``."""
    if not errored_files:
        return
    logger.warning(
        '%d file(s) could not be scanned:\n%s',
        len(errored_files),
        '\n'.join(f'  - {sanitize_for_terminal(fp)}' for fp in errored_files),
    )
    if config.fail_on_error:
        _fatal('Exiting due to --fail-on-error.')


def _config_from_args(args: argparse.Namespace) -> Config:
    """Translate parsed argparse Namespace into a validated ``Config``."""
    return Config(
        ci_mode=args.ci,
        dry_run=args.dry_run,
        fix_all=args.fix_all,
        assume_yes=args.assume_yes,
        staged_only=args.staged,
        scan_history=args.scan_history,
        scan_json=args.scan_json,
        no_backup=args.no_backup,
        secure_backup_dir=args.secure_backup_dir,
        secure_delete=args.secure_delete,
        no_color=args.no_color or bool(os.environ.get('NO_COLOR')),
        fail_on_error=args.fail_on_error,
        verbose=args.verbose,
        replace_mode=args.replace_mode,
        output_format=args.output_format,
        target=args.target,
        config_path=args.config,
        from_gitleaks=args.from_gitleaks,
        from_trufflehog=args.from_trufflehog,
    )


def _validate_invocation(config: Config) -> None:
    """Reject incompatible flag combinations and warn on hazardous configs."""
    if config.scan_history and (config.from_gitleaks or config.from_trufflehog):
        _fatal(
            '--scan-history cannot be combined with --from-gitleaks or --from-trufflehog. '
            'External findings reference on-disc files; history scan references committed content.',
        )

    if config.ci_mode:
        if config.fix_all:
            _fatal('--ci and --fix-all are mutually exclusive. --ci is read-only by design.')
        if not config.dry_run:
            config.dry_run = True

    if config.dry_run and config.fix_all and not config.staged_only and not config.scan_history:
        # --staged/--scan-history warn about an ignored --fix-all below and
        # --ci rejects it above; the plain combination was the only one that
        # preferred dry-run silently. dry-run winning is the safe outcome —
        # this is consistency of signal, not a behaviour change.
        logger.warning(
            '--dry-run takes precedence; ignoring --fix-all — no files will '
            'be modified.',
        )

    if config.staged_only:
        # M7: --staged is documented read-only (pre-commit hook use), so force
        # dry-run — a staged scan never rewrites the working tree out from under
        # a commit. It still reports and exits 1 on findings. Warn on --fix-all
        # regardless of any pre-existing --dry-run so the ignored write is visible.
        if config.fix_all:
            logger.warning(
                '--staged is read-only; ignoring --fix-all and scanning in '
                'dry-run. Redact the working tree in a separate, unstaged run.',
            )
        config.dry_run = True

    if config.scan_history:
        # History findings reference committed content and carry a synthetic
        # 'file (commit abc123)' path no write pass can open, so every
        # interactive/--fix-all replacement would fail — force dry-run like
        # --staged (M7). Removing a committed secret means rewriting history
        # (git filter-repo / BFG) and rotating the key, not editing the tree.
        if config.fix_all:
            logger.warning(
                '--scan-history is read-only; ignoring --fix-all and scanning '
                'in dry-run. To purge committed secrets, rewrite history '
                '(e.g. git filter-repo) and rotate the affected keys.',
            )
        config.dry_run = True

    if hasattr(os, 'getuid') and os.getuid() == 0:
        logger.warning(
            'Running as root — backup files may have restrictive ownership. '
            'Consider running as a regular user.',
        )

    if config.replace_mode == 'env' and (config.fix_all or not config.ci_mode):
        logger.warning(
            '--replace-with env changes string literals to function calls. '
            'Ensure environment variables are set before running the modified code.',
        )


def _validate_replacement(config: Config) -> None:
    """Reject any custom replacement string outside the documented charset.

    Run AFTER config load so a replacement supplied via ``.credactor.toml`` is
    validated on the same footing as the ``--replacement`` CLI flag (H5) — the
    guard previously ran only against the CLI value.

    M5: enforce an allowlist (alphanumeric, underscore, hyphen) matching the
    user-facing error message, instead of a shell-only denylist that let markup
    and quote characters (``<>"'/``) through to inject into XML/HTML/code. The
    allowlist also subsumes the M6 newline/control-character rejection.
    """
    if config.replace_mode not in ('sentinel', 'custom'):
        return
    if not _SAFE_REPLACEMENT_RE.fullmatch(config.custom_replacement):
        _fatal(
            'Replacement string contains characters outside the allowed set.\n'
            '  Value: %r\n'
            '  Use only alphanumeric characters, underscores, and hyphens.',
            config.custom_replacement,
        )


def _validate_target(target: str) -> Path:
    """Resolve and validate the scan target; exit(2) on protected/home paths.

    Returns the resolved ``Path`` for reuse by the banner and network-mount
    warning logic.
    """
    if not Path(target).exists():
        _fatal('path not found: %s', target)

    target_resolved_path = Path(target).resolve()
    resolved = str(target_resolved_path)

    if (
        resolved in _PROTECTED_DIRS_RESOLVED
        or (sys.platform == 'win32' and len(resolved) == 3 and resolved[1:] == ':\\')
    ):
        _fatal(
            'refusing to scan system directory: %s\n'
            '  Credactor is designed to scan project directories only.\n'
            '  Point it at your project root (e.g. credactor ./my-project)',
            resolved,
        )

    if resolved == str(Path.home().resolve()):
        _fatal(
            'refusing to scan home directory: %s\n'
            '  Scanning ~ includes thousands of directories and will hang.\n'
            '  Point it at your project root (e.g. credactor ./my-project)',
            resolved,
        )

    return target_resolved_path


def _print_banner(target_resolved_path: Path) -> None:
    """Emit the scan-start banner and the network-mount warning if relevant."""
    print(f'Scanning: {target_resolved_path}', file=sys.stderr)
    print('  Note: Credactor scans forward (into subdirectories) only.',
          file=sys.stderr)
    print('  For best results, point it at your project root directory.',
          file=sys.stderr)
    resolved = str(target_resolved_path)
    if resolved.startswith(('/mnt/', '/media/', '/Volumes/', '/net/')):
        logger.warning(
            'Target appears to be on a mounted/network volume. '
            'Atomic file operations (os.replace) may not be reliable on '
            'NFS/SMB. Use --dry-run first.',
        )


def _handle_fix_all(findings: list[Finding], target: str, config: Config) -> int:
    """Confirm with the user and run ``fix_all``. Returns unresolved count."""
    # With -f json/sarif the report on stdout must stay a single parseable
    # document, so every human-facing line here goes to stderr instead.
    out = sys.stdout if config.output_format == 'text' else sys.stderr
    by_file = group_by_file(findings)
    print(f'\n  --fix-all will modify {len(by_file)} file(s) '
          f'with {len(findings)} replacement(s).', file=out)
    if not config.no_backup:
        print('  .bak backups will be created (contain original secrets).', file=out)
    else:
        print('  ┌─────────────────────────────────────────────────────────┐', file=out)
        print('  │  DANGER: --no-backup is set. Original values will be    │', file=out)
        print('  │  PERMANENTLY LOST. Ensure you have git history or       │', file=out)
        print('  │  another recovery mechanism before proceeding.          │', file=out)
        print('  └─────────────────────────────────────────────────────────┘', file=out)
    print('  Tip: run with --dry-run first to preview changes.', file=out)
    # L3: --yes skips the interactive gate for non-interactive/CI use. Without it
    # a non-TTY stdin (pipe, </dev/null) raises EOFError below and aborts — the
    # documented behavior, now with an explicit opt-in instead of a footgun.
    if config.assume_yes:
        print('  Proceeding (--yes).', file=out)
    elif sys.stdin is None or not sys.stdin.isatty():
        # A pipe whose first line starts with 'y' would otherwise answer the
        # confirmation below — scripts must opt in explicitly with --yes.
        print('  Aborted: confirmation requires a TTY — pass --yes for '
              'non-interactive use.', file=out)
        sys.exit(1)
    else:
        try:
            # Bare input() so the prompt itself can't land in a redirected
            # JSON/SARIF document (input(prompt) writes the prompt to stdout).
            print('  Proceed? [y/N]: ', end='', file=out, flush=True)
            answer = input().strip().lower()
        except (KeyboardInterrupt, EOFError):
            print('\n  Aborted.', file=out)
            sys.exit(1)
        if answer not in ('y', 'yes'):
            print('  Aborted.', file=out)
            sys.exit(1)
    return fix_all(findings, target, config)


def _collect_findings(
    target: str,
    config: Config,
    allowlist: AllowList,
) -> tuple[list[Finding], list[str]]:
    """Dispatch the native scan based on ``staged_only``/``scan_history``/walk.

    Returns ``(findings, errored_files)``. Also runs the JSON-file
    side-walk when ``--scan-json`` is set in directory mode.
    """
    # L4: a not-a-repo / git-unavailable failure for --staged/--scan-history is a
    # hard error (exit 2), never a false-clean exit 0.
    try:
        if config.staged_only:
            return scan_staged_files(target, config=config, allowlist=allowlist)
        if config.scan_history:
            return scan_git_history(target, config=config, allowlist=allowlist), []
    except GitUnavailableError as exc:
        _fatal('%s', exc)

    # H1: an explicitly-named file is scanned directly — os.walk() on a file
    # yields nothing, so routing a file target through walk_and_scan silently
    # finds zero. scan_file does not gate on extension (the user named it).
    if Path(target).is_file():
        # MV-2: a .credactorignore loads only for a directory scan (its root is
        # the scanned dir), so a single-file target applies none. Warn when one
        # sits beside the file rather than letting its suppressions silently fail
        # to apply — inline "# credactor:ignore" still works on a file target.
        if (Path(target).resolve().parent / '.credactorignore').is_file():
            logger.warning(
                '.credactorignore is not applied to a single-file target — its '
                'entries load only for a directory scan. Use inline '
                '"# credactor:ignore", or scan the directory.'
            )
        try:
            return scan_file(target, config=config, allowlist=allowlist), []
        except (OSError, UnicodeDecodeError) as exc:
            # UnicodeDecodeError: a confidently-detected multibyte encoding
            # (e.g. truncated UTF-16) that fails mid-stream is an unreadable
            # file, not a crash — same errored-files contract as OSError.
            logger.warning('Cannot read %s: %s', target, exc)
            return [], [target]

    findings, gitignore_skipped, json_files, errored_files = walk_and_scan(
        target, config=config, allowlist=allowlist,
    )

    if config.output_format == 'text':
        print_gitignore_skipped(gitignore_skipped, target, no_color=config.no_color)
        # Avoid a false-clean impression: .json files are collected but only
        # scanned under --scan-json, so flag that the type was held back.
        if not config.scan_json and json_files:
            print(f'  [note] {len(json_files)} .json file(s) present but not scanned — '
                  f'pass --scan-json to include them.', file=sys.stderr)

    if config.scan_json and json_files:
        # --scan-json is already the explicit opt-in, so scan every collected
        # .json in every mode. (A numbered interactive picker used to gate
        # this again in plain text mode — a second gate on an already-gated
        # path, ~70 lines, removed.)
        for path in json_files:
            try:
                findings.extend(scan_file(path, config=config, allowlist=allowlist))
            except (OSError, UnicodeDecodeError) as exc:
                logger.warning('Cannot read %s: %s', path, exc)
                errored_files.append(path)

    return findings, errored_files


def _ingest_external(
    findings: list[Finding],
    target: str,
    config: Config,
    allowlist: AllowList,
) -> list[Finding]:
    """Merge external scanner findings (Gitleaks/TruffleHog) into *findings*.

    Validates that the report file exists and that the target is a directory
    (external scanners report file paths relative to a repo root). Runs
    deduplication when any external source contributed findings.
    """
    if not (config.from_gitleaks or config.from_trufflehog):
        return findings

    from .ingest import deduplicate_findings, ingest_gitleaks, ingest_trufflehog

    def _suppressed(f: Finding) -> bool:
        return allowlist.is_suppressed(f['file'], f['line'], f['full_value'])

    def _ingest_one(
        name: str, report_path: str,
        ingest_fn: Callable[[str, str], list[Finding]],
    ) -> None:
        if not Path(report_path).is_file():
            _fatal('%s file not found: %s', name, report_path)
        if Path(target).is_file():
            _fatal(
                '--from-%s requires a directory target, not a file. '
                'Pass the repository root directory so that file paths in the '
                '%s report can be resolved correctly.',
                name.lower(), name,
            )
        try:
            ext = ingest_fn(report_path, target)
            findings.extend(f for f in ext if not _suppressed(f))
        except ValueError as exc:
            _fatal('%s', exc)

    if config.from_gitleaks:
        _ingest_one('Gitleaks', config.from_gitleaks, ingest_gitleaks)
    if config.from_trufflehog:
        _ingest_one('TruffleHog', config.from_trufflehog, ingest_trufflehog)

    return deduplicate_findings(findings)


def _main_inner(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    config = _config_from_args(args)
    _configure_log(verbose=config.verbose)

    target = config.target
    target_resolved_path = _validate_target(target)

    # An explicit --config that doesn't resolve to a file is fatal: silently
    # falling back to defaults would drop every intended setting (thresholds,
    # extra_extensions, [ingest]) and can flip a failing gate to a pass via a
    # filename typo. Implicit discovery finding nothing stays a normal no-op.
    if config.config_path and not Path(config.config_path).is_file():
        _fatal('Config file not found: %s', config.config_path)
    try:
        file_data = load_config_file(target, config.config_path, ci_mode=config.ci_mode)
    except ConfigError as exc:
        # An explicit --config that exists but won't parse (invalid TOML /
        # unreadable) is fatal for the same reason a missing one is: degrading
        # to defaults silently drops every intended setting.
        _fatal('%s', exc)
    if file_data:
        apply_config_file(config, file_data)

    # Validate invocation flags AFTER the config file is applied so a
    # .credactor.toml [ingest] table can't slip past the --scan-history/ingest
    # rejection (mirrors the post-config _validate_replacement / H5 check below).
    _validate_invocation(config)

    # M10: an explicit --replacement overrides a config-file 'replacement'
    # (precedence CLI > config > default). argparse default is None, so a
    # non-None args.replacement means the flag was actually passed.
    if args.replacement is not None:
        if config.replace_mode == 'env':
            # env mode generates language-aware references; a fixed replacement
            # string is never consulted — say so instead of silently ignoring it.
            logger.warning(
                '--replacement has no effect with --replace-with env; '
                'env mode generates language-aware references, not a fixed string.',
            )
        config.custom_replacement = args.replacement

    # Validate the EFFECTIVE replacement (after config load) so a
    # .credactor.toml-supplied value can't bypass the injection guard (H5).
    _validate_replacement(config)

    allowlist = AllowList(target)
    _print_banner(target_resolved_path)

    findings, errored_files = _collect_findings(target, config, allowlist)
    findings = _ingest_external(findings, target, config, allowlist)
    _handle_errored_files(errored_files, config)

    _emit_report(findings, target, config)
    if not findings:
        sys.exit(0)

    if config.ci_mode or config.dry_run:
        sys.exit(1)

    if config.fix_all:
        unresolved = _handle_fix_all(findings, target, config)
        sys.exit(1 if unresolved > 0 else 0)

    # Non-text formats in non-CI mode: report and exit 1
    if config.output_format != 'text':
        sys.exit(1)

    # Interactive mode (default, text only). The manual promises a TTY
    # requirement: without this gate a pipe of y-prefixed text answers the
    # per-finding prompts and rewrites files. Exit 1, not 2 — the findings
    # above were reported and remain unresolved, same as the EOF path.
    if sys.stdin is None or not sys.stdin.isatty():
        logger.error(
            'Interactive mode requires a TTY on stdin. Use --dry-run/--ci to '
            'report, or --fix-all --yes to redact unattended.',
        )
        sys.exit(1)
    unresolved = interactive_review(findings, target, config)
    sys.exit(1 if unresolved > 0 else 0)
