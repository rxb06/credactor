# Setup

## Requirements

- Python 3.11+
- No required dependencies. Optional: the `[encoding]` extra (`charset-normalizer`) for non-UTF-8 files.

## Installation

### From PyPI

```bash
pip install credactor
```

### From Source

To install from source so `credactor` works globally from any directory:

```bash
git clone https://github.com/rxb06/credactor.git
cd credactor
pip install -e .
```

If `pip` is managed by `uv` and you are outside a virtualenv, use `pip3` or add `--system`:

```bash
pip3 install -e .
# or
pip install --system -e .
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

If you installed from PyPI, you can pull in the recommended encoding extra directly:

```bash
pip install 'credactor[encoding]'
```

## Configuration

### Config File

`.credactor.toml` in your project root, or a parent directory up to the repository root (the tool walks upward from the scan target, at most 5 levels). A config discovered **above** the repository root is refused. It is skipped with an `[ERROR]` on stderr ("Refusing to load config from outside project root"), not silently, unless you point `--config` at it explicitly, and it is always refused in `--ci` mode.

```toml
# .credactor.toml

entropy_threshold = 3.5    # Shannon entropy floor
min_value_length = 8       # Ignore shorter values

# Extra directories to skip (merged with defaults)
skip_dirs = [".terraform", "vendor"]
skip_files = ["generated_config.py"]

# Extra extensions to scan (final suffix only — ".encrypted", not ".env.encrypted")
extra_extensions = [".encrypted"]

# Values to never flag
extra_safe_values = ["test_fixture_token_abc123"]

replacement = "REDACTED_BY_CREDACTOR"

# External scanner ingestion (BETA) — merge Gitleaks/TruffleHog findings
# into the redaction pipeline. Values are paths to the report files; the
# scan target must be a DIRECTORY (the repo root) so report-relative file
# paths resolve. Used when --from-gitleaks / --from-trufflehog are not passed;
# a same-kind CLI flag takes precedence over the entry below.
[ingest]
from_gitleaks = "gitleaks-report.json"
from_trufflehog = "trufflehog-output.json"
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

#### Allowlist

`.credactorignore` in your project root:

```
# Glob patterns (fnmatch — NO globstar; ** behaves like a single *)
tests/fixtures/*.py
tests/*/test_data/*

# Specific line (positional — matched by line number only; re-check
# after large edits, since a new secret can drift onto the line)
config/defaults.py:42

# Specific value (anywhere)
test_fixture_value_abc123

# Value containing . / ? or * (base64, JWT, connection string) — use the
# value: prefix so it is not mistaken for a glob/path
value:eyJhbGciOiJIUzI1NiJ9.payload.sig
```

Broad glob patterns and value-literal / positional suppressions are reported as warnings on stderr at load time, so they get reviewed for detection-bypass.

## Pre-commit Hooks and CI/CD

See the [CI Integration Guide](ci_integration.md) for pre-commit hook setup (framework and standalone) and CI pipeline configuration (GitHub Actions, GitLab CI).

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

## Project Structure

```
credactor/
    __init__.py          # version
    __main__.py          # python -m entry point
    _log.py              # logging configuration
    cli.py               # argument parsing, main flow
    config.py            # .credactor.toml loading
    gitignore.py         # .gitignore matching
    ingest.py            # external scanner ingestion (Gitleaks/TruffleHog)
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
requirements-ci.in       # CI dependency source (human-readable)
requirements-ci.txt      # CI dependency lockfile (hash-pinned)
```
