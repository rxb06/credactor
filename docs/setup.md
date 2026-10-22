# Setup

## Requirements

- Python 3.11 or newer. Tested in CI on Linux and Windows, Python 3.11 to 3.13.
- No required dependencies. Optional: the `[encoding]` extra (`charset-normalizer`) for files in encodings other than UTF-8, Latin-1 or simple UTF-16.

## Installation

### From PyPI

```bash
pip install credactor
```

### With uv

Install it as a tool, or run it once without installing:

```bash
uv tool install credactor
uvx credactor --dry-run .
```

For the encoding extra: `uv tool install 'credactor[encoding]'`.

### With Homebrew

On macOS and Linux:

```bash
brew install rxb06/tap/credactor
```

The Homebrew formula includes the `[encoding]` extra, so nothing else is needed.

### From Source

To install from source so `credactor` works globally from any directory:

```bash
git clone https://github.com/rxb06/credactor.git
cd credactor
pip install -e .
```

If you use uv, install the clone as a tool instead:

```bash
uv tool install --editable .
```

After this, `credactor` is available from any directory in your terminal:

```bash
credactor --dry-run /path/to/project
```

To uninstall:

```bash
pip uninstall credactor
```

### Run Without Installing

If you want to run it from the cloned repo without a global install:

```bash
git clone https://github.com/rxb06/credactor.git
cd credactor
python -m credactor --help
```

### Optional Dependencies

Better encoding detection for legacy codebases:

```bash
pip install charset-normalizer
```

Or install the `encoding` extra, which pulls it in:

```bash
pip install 'credactor[encoding]'          # from PyPI
uv tool install 'credactor[encoding]'      # with uv
pip install -e '.[encoding]'               # from a clone
```

The Homebrew formula already includes it.

## Configuration

### Config File

`.credactor.toml` in your project root, or a parent directory up to the repository root (the tool walks upward from the scan target, at most 5 levels). A config discovered **above** the repository root is refused: it is skipped with an `[ERROR]` on stderr ("Refusing to load config from outside project root"), not silently, and the scan continues with defaults. Pointing `--config` at it explicitly loads it with a warning, except under `--ci`, where an outside-root `--config` is refused and the run stops with exit 2.

The nearest file wins, and parent configs are not merged. A config you name with `--config` must load: if it is missing, unreadable or not valid TOML, the run exits 2. A discovered config that fails to parse only prints a warning, and the scan uses the defaults.

```toml
# .credactor.toml

entropy_threshold = 3.5    # Shannon entropy floor
min_value_length = 8       # Ignore shorter values

# Extra directories to skip (merged with defaults)
skip_dirs = [".terraform", "vendor"]
skip_files = ["generated_config.py"]

# Extra extensions to scan (final suffix only: ".encrypted", not ".env.encrypted")
extra_extensions = [".encrypted"]

# Values to never flag
extra_safe_values = ["test_fixture_token_abc123"]

# Replacement text for sentinel and custom modes (an explicit --replacement wins).
# Use at least one letter, digit, underscore or hyphen and nothing else.
# Any other value exits 2.
replacement = "REDACTED_BY_CREDACTOR"

# External scanner ingestion: merge Gitleaks, TruffleHog or Betterleaks
# findings into the redaction pipeline. Values are report paths, resolved
# against the current working directory (not the config file or the scan
# target). A report that is missing or an empty value exits 2. The scan
# target must be a directory (the repository root) so the file paths inside
# the report resolve. Each entry is used when the matching --from-gitleaks,
# --from-trufflehog or --from-betterleaks flag is not passed; a same-kind
# CLI flag takes precedence over the entry below.
[ingest]
from_gitleaks = "gitleaks-report.json"
from_trufflehog = "trufflehog-output.json"
from_betterleaks = "betterleaks-report.json"
```

Override path:

```bash
credactor --config /path/to/.credactor.toml .
```

### Suppression

#### Inline

```python
api_key = "test_key_for_unit_tests"  # credactor:ignore
```

```javascript
const key = "test_key";  // credactor:ignore
```

The directive works in a `#`, `//`, `/* */` or `<!-- -->` comment on the same line as the secret. A directive on the line above does not apply. Findings from an ingested Gitleaks, TruffleHog or Betterleaks report are not stopped by an inline directive; only `.credactorignore` filters them.

#### Allowlist

`.credactorignore` in the directory you scan (the scan root). It is read only when the target is a directory. A single-file target (`credactor app.py`) does not apply it and warns if one sits beside the file, so use an inline `credactor:ignore` there or scan the directory instead.

Example:

```
# Glob patterns (fnmatch, NO globstar: ** behaves like a single *)
tests/fixtures/*.py
tests/*/test_data/*

# Specific line (positional, matched by line number only; re-check
# after large edits, since a new secret can drift onto the line)
config/defaults.py:42

# Specific value (anywhere)
test_fixture_value_abc123

# Value containing . / ? or * (base64, JWT, connection string): use the
# value: prefix so it is not mistaken for a glob/path
value:eyJhbGciOiJIUzI1NiJ9.payload.sig
```

Broad glob patterns and value-literal / positional suppressions are reported as warnings on stderr at load time, so they get reviewed for detection-bypass.

## Pre-commit Hooks and CI/CD

See the [CI Integration Guide](ci_integration.md) for pre-commit hook setup (framework and standalone) and CI pipeline configuration (GitHub Actions, GitLab CI).

## Running Tests

```bash
pip install -e ".[dev,encoding]"
python -m pytest tests/ -v
```

See [CONTRIBUTING.md](../CONTRIBUTING.md#running-tests) for the full development setup and the four checks CI runs (pytest, ruff check, ruff format --check, mypy).

## Project Structure

```
credactor/
    __init__.py          # version
    __main__.py          # python -m entry point
    _log.py              # logging configuration
    cli.py               # argument parsing, main flow
    config.py            # .credactor.toml loading
    gitignore.py         # .gitignore matching
    ingest.py            # external scanner ingestion (Gitleaks, TruffleHog, Betterleaks)
    patterns.py          # regexes, constants
    redactor.py          # file modification, backups
    report.py            # text/JSON/SARIF output
    scanner.py           # detection logic
    suppressions.py      # inline ignore, allowlist
    types.py             # Finding TypedDict and shared types
    utils.py             # entropy, encoding detection
    walker.py            # directory traversal, git modes
scripts/
    audit_wheel.py       # supply chain: verify wheel matches repo
tests/
    __init__.py
    conftest.py
    benchmark/                     # detection benchmark corpus
    differential/                  # differential snapshot tests
    test_action.py
    test_audit_wheel.py
    test_cli.py
    test_config.py
    test_detection_benchmark.py
    test_gitignore.py
    test_ingest.py
    test_patterns.py
    test_redactor.py
    test_redactor_properties.py
    test_report.py
    test_safe_values.py
    test_scanner.py
    test_security.py
    test_suppressions.py
    test_utils.py
    test_walker.py
    test_workflows.py
examples/
    ci-credactor.yml     # example CI workflow
hooks/
    pre-commit           # standalone pre-commit hook
.pre-commit-hooks.yaml   # pre-commit framework hook
action.yml               # GitHub Action definition
requirements-ci.in       # CI dependency source (human-readable)
requirements-ci.txt      # CI dependency lockfile (hash-pinned)
```
