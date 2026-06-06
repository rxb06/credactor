"""
Directory walking, git-staged scanning, git-history scanning, and parallelism.

"""

from __future__ import annotations

import errno
import os
import re
import subprocess
import sys
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ._log import logger
from .config import Config
from .gitignore import matches_gitignore, parse_gitignore_file
from .patterns import SKIP_DIRS, SKIP_FILES
from .scanner import scan_file, scan_line, should_scan_file
from .suppressions import AllowList
from .types import Finding
from .utils import is_within_root, log_verbose, relativize, sanitize_for_terminal

# Subprocess timeouts (seconds). Staged/rev-parse use a short bound; the
# history `git log -p` walk needs a longer one — intentionally distinct.
_GIT_TIMEOUT_S = 30
_GIT_LOG_TIMEOUT_S = 120
# Thread-pool sizing for the parallel file scan (#27): cap workers to avoid fd
# exhaustion, and scan small batches sequentially.
_MAX_SCAN_WORKERS = 8
_SEQUENTIAL_BATCH_THRESHOLD = 4


class GitUnavailableError(RuntimeError):
    """Git itself is unavailable or the target is not a git repository, for a
    ``--staged`` / ``--scan-history`` scan (L4).

    The discriminator is ``git rev-parse --show-toplevel``: if that fails the
    directory isn't a usable repo, so the CLI turns this into a hard exit 2
    rather than a false-clean exit 0. A later ``git log`` / ``git diff`` failure
    *inside* a confirmed repo (e.g. a valid repo with zero commits) is NOT this
    error — it stays a non-fatal empty result.
    """


def _progress_callback_factory(total: int, no_color: bool) -> Callable[[int], None]:
    """Return a callback that prints a progress line to stderr."""
    def _progress(done: int) -> None:
        if sys.stderr.isatty() and not no_color:
            sys.stderr.write(f'\r  Scanning... {done}/{total} files')
            sys.stderr.flush()
            if done == total:
                sys.stderr.write('\r' + ' ' * 40 + '\r')
                sys.stderr.flush()
    return _progress


def walk_and_scan(
    root: str,
    *,
    config: Config,
    allowlist: AllowList | None = None,
) -> tuple[list[Finding], list[str], list[str], list[str]]:
    """Single-pass directory walk
    Returns (findings, gitignore_skipped, json_files_available, errored_files).
    """
    root_path = Path(root).resolve()
    gi_patterns: list[tuple[str, Path]] = []

    scannable: list[str] = []
    json_files: list[str] = []
    gitignore_skipped: list[str] = []

    extra_skip_dirs = SKIP_DIRS | config.skip_dirs
    extra_skip_files = SKIP_FILES | config.skip_files

    # Forward-only scanning: os.walk descends into children only.
    # Additionally filter out symlinks that escape the scan root to
    # prevent traversal into parent or unrelated directories.
    # Append separator so '/tmp/repo' won't prefix-match '/tmp/repo_evil'.
    # Gitignore patterns are accumulated during the same walk pass —
    # os.walk is top-down by default, so a .gitignore at dir D is parsed
    # before any of D's subtree files are checked.
    root_str = str(root_path) + os.sep
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [
            d for d in dirnames
            if d not in extra_skip_dirs
            and is_within_root(str(Path(os.path.join(dirpath, d)).resolve()), root_str)
        ]
        if '.gitignore' in filenames:
            gi_patterns.extend(parse_gitignore_file(
                os.path.join(dirpath, '.gitignore'),
                Path(dirpath).resolve(),
            ))
        for filename in filenames:
            if filename in extra_skip_files:
                continue
            full_path = os.path.join(dirpath, filename)

            if os.path.islink(full_path):
                try:
                    resolved_file = str(Path(full_path).resolve())
                    if not is_within_root(resolved_file, root_str):
                        continue
                except OSError:
                    continue

            # Gitignore check
            if gi_patterns and matches_gitignore(full_path, gi_patterns):
                gitignore_skipped.append(full_path)
                continue

            # Allowlist file-level suppression
            if allowlist and allowlist.is_file_suppressed(full_path):
                log_verbose(f'{full_path} suppressed by allowlist (file-level)')
                continue

            p = Path(filename)
            suffix = p.suffix.lower()

            if suffix == '.json':
                json_files.append(full_path)
                continue

            if should_scan_file(filename, config.extra_extensions):
                scannable.append(full_path)

    # #27 — parallel file scanning
    findings, errored = _parallel_scan(scannable, config, allowlist)

    return findings, gitignore_skipped, json_files, errored


def _parallel_scan(
    files: list[str],
    config: Config,
    allowlist: AllowList | None,
) -> tuple[list[Finding], list[str]]:
    """Scan files using a thread pool (#27).

    Returns (findings, errored_files).
    """
    all_findings: list[Finding] = []
    errored: list[str] = []

    if not files:
        return all_findings, errored

    progress = _progress_callback_factory(len(files), config.no_color)
    done_count = 0

    # Use threads (I/O-bound); limit to 8 workers to avoid fd exhaustion
    max_workers = min(_MAX_SCAN_WORKERS, len(files))
    if max_workers <= 1 or len(files) <= _SEQUENTIAL_BATCH_THRESHOLD:
        # Sequential for small batches
        for i, fp in enumerate(files, 1):
            try:
                all_findings.extend(scan_file(fp, config=config, allowlist=allowlist))
            except Exception as exc:
                errored.append(fp)
                logger.warning('Error scanning %s: %s', fp, exc)
            progress(i)
        return all_findings, errored

    lock = threading.Lock()
    emfile_files: set[str] = set()
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_file = {
            executor.submit(scan_file, fp, config=config, allowlist=allowlist): fp
            for fp in files
        }
        for future in as_completed(future_to_file):
            fp = future_to_file[future]
            try:
                result = future.result()
            except OSError as exc:
                if exc.errno == errno.EMFILE:
                    # Record EMFILE-only failures for a post-pool sequential retry;
                    # warn once (not per fd-exhausted file).
                    if not emfile_files:
                        logger.warning(
                            'Too many open files — remaining files will be scanned sequentially.',
                        )
                    emfile_files.add(fp)
                else:
                    errored.append(fp)
                    logger.warning('Error scanning %s: %s', fp, exc)
                result = []
            except Exception as exc:
                errored.append(fp)
                logger.warning('Error scanning %s: %s', fp, exc)
                result = []
            with lock:
                done_count += 1
                progress(done_count)
                all_findings.extend(result)

    # Sequential retry of ONLY the EMFILE-failed files (fds are now freed). A file
    # that errored for any other reason stays in `errored` and is not re-scanned;
    # an EMFILE file that fails again is appended to `errored` with a logged reason.
    if emfile_files:
        for fp in emfile_files:
            try:
                all_findings.extend(scan_file(fp, config=config, allowlist=allowlist))
            except Exception as exc:
                errored.append(fp)
                logger.warning('Error re-scanning %s: %s', fp, exc)

    return all_findings, errored


# ---------------------------------------------------------------------------
# #6 — Git staged-only scanning
# ---------------------------------------------------------------------------
def _is_safe_relpath(p: str) -> bool:
    """True if *p* has no ``..`` path component. Uses a component check, not a
    substring, so a filename like ``secret..py`` is not falsely rejected."""
    return not any(part == '..' for part in Path(p).parts)


def _require_git_repo(root: str, *, want_toplevel: bool = False) -> str:
    """Probe that *root* is a usable git repo; raise GitUnavailableError if not.

    ``want_toplevel`` selects the rev-parse subcommand: ``--show-toplevel`` (needs
    a work tree — for --staged) vs ``--git-dir`` (also accepts bare/empty repos —
    the canonical --scan-history target, so it isn't falsely rejected). Returns
    rev-parse's stdout (the toplevel path when *want_toplevel*, else the git-dir,
    which the caller may ignore)."""
    sub = '--show-toplevel' if want_toplevel else '--git-dir'
    try:
        probe = subprocess.run(
            ['git', 'rev-parse', sub],
            capture_output=True, text=True, cwd=root, timeout=_GIT_TIMEOUT_S,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise GitUnavailableError(f'Cannot run git: {exc}') from exc
    if probe.returncode != 0:
        raise GitUnavailableError(
            f'not a git repository (git rev-parse failed): {probe.stderr.strip()}')
    return probe.stdout.strip()


def scan_staged_files(
    root: str,
    *,
    config: Config,
    allowlist: AllowList | None = None,
) -> tuple[list[Finding], list[str]]:
    """Scan only files staged in the git index (``git diff --cached``).

    Returns (findings, errored_files).
    """
    root_path = Path(root).resolve()
    # `git diff --cached` lists paths relative to the repo root, so resolve them
    # against the toplevel, not the scan root (which may be a subdirectory).
    # rev-parse is also the not-a-repo discriminator (L4): --staged needs a work
    # tree, hence want_toplevel.
    toplevel = Path(_require_git_repo(str(root_path), want_toplevel=True))
    try:
        result = subprocess.run(
            ['git', 'diff', '--cached', '--name-only', '-z', '--diff-filter=ACMR'],
            capture_output=True, text=True, cwd=str(root_path), timeout=_GIT_TIMEOUT_S,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        # rev-parse already proved git is usable; a diff failure here is a
        # non-fatal empty result, not a not-a-repo error.
        logger.error('git diff failed: %s', exc)
        return [], []
    if result.returncode != 0:
        logger.error('git diff failed: %s', result.stderr.strip())
        return [], []
    # -z yields NUL-separated, unquoted paths: a unicode/special-char filename
    # would otherwise be octal-quoted and silently skipped (a staged-secret miss).
    raw_staged = [p for p in result.stdout.split('\0') if p]

    # Warn if suppression/config files are staged alongside code — a malicious
    # contributor could stage .credactor.toml or .credactorignore changes to
    # silently disable detection in the same PR.
    _CONFIG_BASENAMES = {'.credactor.toml', '.credactorignore'}
    staged_configs = [f for f in raw_staged if Path(f).name in _CONFIG_BASENAMES]
    if staged_configs:
        logger.warning(
            'Suppression/config files staged alongside code changes: %s. '
            'Review these for detection-bypass attempts.',
            ', '.join(staged_configs),
        )

    findings: list[Finding] = []
    errored: list[str] = []
    for line in raw_staged:
        # Reject paths with '..' components (traversal guard, consistent with the
        # git-history scanner).
        if not _is_safe_relpath(line):
            continue
        full_path = str(toplevel / line)
        try:
            resolved = str(Path(full_path).resolve())
        except OSError:
            continue
        if not is_within_root(resolved, str(root_path) + os.sep):
            continue
        if not should_scan_file(line, config.extra_extensions):
            continue

        # Scan the STAGED index blob, not the working-tree file: the two can
        # differ, and a pre-commit gate must see exactly what is being committed.
        # Per-line scan mirrors scan_git_history; scan_file's multi-line passes
        # (PEM blocks, and secrets spanning triple-quoted / template-literal
        # strings) are NOT applied here. A PEM header line is still caught by
        # scan_line, but a secret split across physical lines is not.
        try:
            blob = subprocess.run(
                ['git', 'show', f':{line}'],
                capture_output=True, cwd=str(root_path), timeout=_GIT_TIMEOUT_S,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.warning('Cannot read staged %s: %s', line, exc)
            errored.append(full_path)
            continue
        if blob.returncode != 0:
            logger.warning('Cannot read staged %s: %s', line,
                           blob.stderr.decode('utf-8', 'replace').strip())
            errored.append(full_path)
            continue

        content = blob.stdout.decode('utf-8', errors='surrogateescape')
        for lineno, src in enumerate(content.splitlines(), start=1):
            findings.extend(
                scan_line(lineno, src, full_path, config=config, allowlist=allowlist))

    return findings, errored


# ---------------------------------------------------------------------------
# #11 — Git history scanning
# ---------------------------------------------------------------------------
def scan_git_history(
    root: str,
    *,
    config: Config,
    allowlist: AllowList | None = None,
    max_commits: int = 100,
) -> list[Finding]:
    """Scan ``git log -p`` output for credentials in committed history."""
    root_path = Path(root).resolve()
    # L4: probe with --git-dir (not --show-toplevel) so a bare/empty repo — a
    # canonical --scan-history target — isn't falsely rejected. A valid repo with
    # zero commits makes `git log` exit non-zero below, but rev-parse passes, so
    # that stays a non-fatal empty result. See _require_git_repo.
    _require_git_repo(str(root_path))
    try:
        result = subprocess.run(
            ['git', 'log', f'-{max_commits}', '-p', '--diff-filter=ACMR',
             '--no-color', '--format=commit %H'],
            capture_output=True, text=True, cwd=str(root_path), timeout=_GIT_LOG_TIMEOUT_S,
        )
        if result.returncode != 0:
            # e.g. a valid repo with no commits yet — nothing to scan, not fatal.
            logger.error('git log failed: %s', result.stderr.strip())
            return []
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        logger.error('Cannot run git: %s', exc)
        return []

    findings: list[Finding] = []
    current_commit = ''
    current_file = ''
    diff_lineno = 0

    for line in result.stdout.splitlines():
        if line.startswith('commit '):
            current_commit = line.split(' ', 1)[1][:12]
            continue
        if line.startswith('+++ b/'):
            current_file = line[6:]
            # Reject '..' path components from git output (traversal guard).
            if not _is_safe_relpath(current_file):
                current_file = ''
            diff_lineno = 0
            continue
        if line.startswith('@@'):
            # Parse hunk header: @@ -old,count +new,count @@
            hunk_match = re.search(r'\+(\d+)', line)
            diff_lineno = int(hunk_match.group(1)) - 1 if hunk_match else 0
            continue
        if line.startswith('+') and not line.startswith('+++'):
            diff_lineno += 1
            added_line = line[1:]  # strip the leading '+'
            line_findings = scan_line(diff_lineno, added_line,
                                      f'{current_file} (commit {current_commit})',
                                      config=config, allowlist=allowlist)
            for f in line_findings:
                f['commit'] = current_commit
            findings.extend(line_findings)
        elif not line.startswith('-'):
            diff_lineno += 1

    return findings


# ---------------------------------------------------------------------------
# JSON file selection (interactive, kept from original)
# ---------------------------------------------------------------------------
def _parse_selection(answer: str, n: int) -> list[int] | str:
    """Parse a selection string ('1,3,5', '2-4', or a mix) into ordered,
    de-duplicated 1-based indices in [1, n]. Returns an error message string on
    invalid input. Pure (no I/O) so it is unit-testable on its own."""
    selected: list[int] = []
    for token in answer.replace(' ', '').split(','):
        if '-' in token:
            parts = token.split('-', 1)
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                lo, hi = int(parts[0]), int(parts[1])
                if 1 <= lo <= hi <= n:
                    selected.extend(range(lo, hi + 1))
                else:
                    return f'Range {token} out of bounds (1-{n}).'
            else:
                return f'Invalid range: {token}'
        elif token.isdigit():
            idx = int(token)
            if 1 <= idx <= n:
                selected.append(idx)
            else:
                return f'Number {token} out of bounds (1-{n}).'
        else:
            return f'Unrecognised token: {token!r}'
    return list(dict.fromkeys(selected))


def select_json_files(
    json_files: list[str],
    root: str,
) -> list[str]:
    """Let the user pick which .json files to scan from a numbered list."""
    root_path = Path(root).resolve()

    if not json_files:
        print('  No .json files available to scan.\n')
        return []

    print(f'\n  Found {len(json_files)} .json file(s):\n')
    for i, path in enumerate(json_files, 1):
        rel = relativize(path, root_path)
        print(f'    [{i:>3}]  {sanitize_for_terminal(rel)}')

    print()
    print('  Enter file numbers to scan (e.g. 1,3,5  or  2-4  or  all):')

    while True:
        try:
            answer = input('  Selection: ').strip().lower()
        except (KeyboardInterrupt, EOFError):
            print('\n  Skipping .json scan.')
            return []

        if not answer:
            print('  Skipping .json scan.\n')
            return []

        if answer == 'all':
            return json_files

        result = _parse_selection(answer, len(json_files))
        if isinstance(result, str):
            print(f'  {result}')
            continue
        selected = [json_files[i - 1] for i in result]
        print(f'  Selected {len(selected)} file(s) for .json scan.\n')
        return selected
