"""
Configuration loading from ``.credactor.toml`` files.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._log import logger
from .utils import is_within_root

# Single source of truth for the two numeric thresholds — referenced by the
# Config field defaults, __post_init__, and _SCALAR_VALIDATORS so they can't drift.
ENTROPY_BOUNDS: tuple[float, float] = (0.0, 6.0)
ENTROPY_DEFAULT: float = 3.5
MIN_LEN_BOUNDS: tuple[int, int] = (1, 200)
MIN_LEN_DEFAULT: int = 8

# Parsed-TOML config shape.
TomlData = dict[str, Any]


@dataclass
class Config:
    """Runtime configuration — populated from CLI flags and/or config file."""

    # Thresholds
    entropy_threshold: float = ENTROPY_DEFAULT
    min_value_length: int = MIN_LEN_DEFAULT

    # Directories / files
    skip_dirs: set[str] = field(default_factory=set)
    skip_files: set[str] = field(default_factory=set)
    extra_extensions: set[str] = field(default_factory=set)
    extra_safe_values: set[str] = field(default_factory=set)

    # Behaviour flags (populated by CLI)
    ci_mode: bool = False
    dry_run: bool = False
    fix_all: bool = False
    assume_yes: bool = False  # L3: skip the --fix-all confirmation prompt
    staged_only: bool = False
    scan_history: bool = False
    scan_json: bool = False
    no_backup: bool = False
    secure_backup_dir: str | None = None
    secure_delete: bool = False
    no_color: bool = False
    fail_on_error: bool = False
    verbose: bool = False
    replace_mode: str = 'sentinel'  # 'sentinel' | 'env' | 'custom'
    custom_replacement: str = 'REDACTED_BY_CREDACTOR'
    output_format: str = 'text'  # 'text' | 'json' | 'sarif'
    target: str = '.'
    config_path: str | None = None
    from_gitleaks: str | None = None
    from_trufflehog: str | None = None
    backup_warn_shown: bool = False

    def __post_init__(self) -> None:
        lo_e, hi_e = ENTROPY_BOUNDS
        if not lo_e <= self.entropy_threshold <= hi_e:
            raise ValueError(
                f'entropy_threshold must be in [{lo_e}, {hi_e}], '
                f'got {self.entropy_threshold}')
        lo_m, hi_m = MIN_LEN_BOUNDS
        if not lo_m <= self.min_value_length <= hi_m:
            raise ValueError(
                f'min_value_length must be in [{lo_m}, {hi_m}], '
                f'got {self.min_value_length}')
        if self.replace_mode not in ('sentinel', 'env', 'custom'):
            raise ValueError(
                f'replace_mode must be sentinel|env|custom, '
                f'got {self.replace_mode!r}')
        if self.output_format not in ('text', 'json', 'sarif'):
            raise ValueError(
                f'output_format must be text|json|sarif, '
                f'got {self.output_format!r}')


def _find_project_root(start: Path) -> Path | None:
    """Walk up from *start* looking for a ``.git`` directory.

    Returns the directory containing ``.git``, or ``None`` if not found.
    """
    p = start.resolve()
    for _ in range(20):  # reasonable upper bound
        if (p / '.git').exists():
            return p
        if p.parent == p:
            break
        p = p.parent
    return None


def load_config_file(
    root: str,
    explicit_path: str | None = None,
    ci_mode: bool = False,
) -> TomlData:
    """Load a .credactor.toml config file and return the raw dict.

    Searches for .credactor.toml in root, then parent dirs up to /.
    If explicit_path is given, only that path is tried.
    """
    if explicit_path:
        candidates = [Path(explicit_path)]
    else:
        # Limit traversal depth to prevent picking up config files
        # from shared parent directories (e.g. /tmp/.credactor.toml).
        # Walk up at most 5 levels — enough for monorepo nesting.
        max_depth = 5
        candidates = []
        p = Path(root).resolve()
        for _ in range(max_depth):
            candidates.append(p / '.credactor.toml')
            if p.parent == p:
                break
            p = p.parent

    project_root = _find_project_root(Path(root).resolve())

    for candidate in candidates:
        if candidate.is_file():
            _cand = str(candidate.resolve())
            _scan = str(Path(root).resolve())

            if project_root:
                _root = str(project_root)
                outside = not is_within_root(_cand, _root)
            else:
                outside = not is_within_root(_cand, _scan)

            if outside:
                ref = project_root or root
                if explicit_path and not ci_mode:
                    # M14: an outside-root config is honoured only when the user
                    # points --config at it explicitly (non-CI). Implicit
                    # discovery of a config above the project root — or any
                    # outside config in CI — is refused: it can silently weaken
                    # detection or inject a replacement (couples with H5).
                    logger.warning(
                        'Loading config from outside project root via --config: '
                        '%s (project root: %s)', candidate, ref,
                    )
                else:
                    hint = '' if ci_mode else ' Pass --config to load it explicitly.'
                    logger.error(
                        'Refusing to load config from outside project root: '
                        '%s (project root: %s).%s', candidate, ref, hint,
                    )
                    return {}
            return _parse_toml(candidate)

    return {}


def _parse_toml(path: Path) -> TomlData:
    """Parse a TOML file using stdlib tomllib (Python 3.11+)."""
    import tomllib
    try:
        with open(path, 'rb') as fh:
            return tomllib.load(fh)
    except OSError as exc:
        logger.warning('Could not read config %s: %s', path, exc)
        return {}
    except tomllib.TOMLDecodeError as exc:
        logger.warning('Invalid TOML in %s: %s', path, exc)
        return {}


# Scalar config keys validated uniformly: (key, coerce, (lo, hi), default).
# An invalid type or out-of-range value logs a warning and falls back to the
# default — identical behaviour to the per-field blocks this table replaced.
_SCALAR_VALIDATORS = (
    ('entropy_threshold', float, ENTROPY_BOUNDS, ENTROPY_DEFAULT),
    ('min_value_length', int, MIN_LEN_BOUNDS, MIN_LEN_DEFAULT),
)


def _coerce_scalar(
    key: str, raw: object, coerce: Callable[[Any], Any],
    bounds: tuple[float, float], default: Any,
) -> Any:
    """Coerce *raw* via *coerce* and range-check it against *bounds*; warn and
    return *default* on a type error or out-of-range value."""
    lo, hi = bounds
    try:
        val = coerce(raw)
    except (ValueError, TypeError):
        logger.warning('%s has invalid type, using default %s', key, default)
        return default
    if not lo <= val <= hi:
        logger.warning(
            '%s=%s out of valid range (%s-%s), using default %s', key, val, lo, hi, default)
        return default
    return val


def _coerce_str_list(key: str, raw: object, *, lower: bool = False) -> list[str]:
    """Normalize a config list key into a list of strings, warn-and-skipping a
    malformed shape or element.

    A bare string or non-sequence is rejected whole — a string would otherwise
    char-split through ``set.update`` (``"vendor"`` -> ``{'v','e',...}``) and a
    scalar would raise ``TypeError`` (M9). Non-string elements are dropped rather
    than crashing on ``.lower()`` (M8). ``lower`` lowercases entries, used for
    extra_safe_values (case-insensitive match) and extra_extensions (M15).
    """
    if isinstance(raw, str) or not isinstance(raw, (list, tuple)):
        logger.warning('%s must be a list of strings, ignoring', key)
        return []
    out: list[str] = []
    for el in raw:
        if not isinstance(el, str):
            logger.warning('%s entry %r is not a string, skipping', key, el)
            continue
        out.append(el.lower() if lower else el)
    return out


def _apply_ingest_config(config: Config, file_data: TomlData) -> None:
    """Apply the optional ``[ingest]`` table (from_gitleaks / from_trufflehog)."""
    ingest = file_data.get('ingest', {})
    if not isinstance(ingest, dict):
        logger.warning('[ingest] config section must be a table, ignoring')
        return
    if 'from_gitleaks' in ingest:
        val = ingest['from_gitleaks']
        if not isinstance(val, str):
            logger.warning('ingest.from_gitleaks must be a string path, ignoring')
        else:
            config.from_gitleaks = val
    if 'from_trufflehog' in ingest:
        val = ingest['from_trufflehog']
        if not isinstance(val, str):
            logger.warning('ingest.from_trufflehog must be a string path, ignoring')
        else:
            config.from_trufflehog = val


def apply_config_file(config: Config, file_data: TomlData) -> None:
    """Merge values from a parsed config file into the Config object."""
    for key, coerce, bounds, default in _SCALAR_VALIDATORS:
        if key in file_data:
            setattr(config, key, _coerce_scalar(key, file_data[key], coerce, bounds, default))
    if 'skip_dirs' in file_data:
        config.skip_dirs.update(_coerce_str_list('skip_dirs', file_data['skip_dirs']))
    if 'skip_files' in file_data:
        config.skip_files.update(_coerce_str_list('skip_files', file_data['skip_files']))
    if 'extra_extensions' in file_data:
        exts = _coerce_str_list('extra_extensions', file_data['extra_extensions'], lower=True)
        for ext in exts:
            # M15: an un-dotted entry only matches a file named *exactly* that
            # (the should_scan_file name fallback), never files carrying that
            # extension — surface the likely footgun without changing matching
            # (auto-prepending '.' would break the legitimate Dockerfile match).
            if ext and not ext.startswith('.'):
                logger.warning(
                    "extra_extensions entry %r has no leading dot; it will only "
                    "match files named exactly %r, not files with that extension",
                    ext, ext)
        config.extra_extensions.update(exts)
    if 'extra_safe_values' in file_data:
        config.extra_safe_values.update(
            _coerce_str_list('extra_safe_values', file_data['extra_safe_values'], lower=True))
    if 'replacement' in file_data:
        val = file_data['replacement']
        if not isinstance(val, str):
            logger.warning('replacement must be a string, ignoring')
        else:
            config.custom_replacement = val
    _apply_ingest_config(config, file_data)
