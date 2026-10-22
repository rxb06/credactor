# Contributing

Thanks for your interest in Credactor. Bug reports, feature requests, and pull requests are welcome via [GitHub Issues](https://github.com/rxb06/credactor/issues). Report security vulnerabilities privately through [GitHub Security Advisories](https://github.com/rxb06/credactor/security/advisories/new), not a public issue (see [SECURITY.md](SECURITY.md)).

## Development Setup

```bash
git clone https://github.com/rxb06/credactor.git
cd credactor
pip install -e ".[dev,encoding]"
```

The `dev` extra installs the *latest* tool releases. CI runs exact
hash-pinned versions instead. To reproduce CI's toolchain locally
(same ruff/mypy/pytest), use:

```bash
pip install --require-hashes -r requirements-ci.txt
```

## Running Tests

```bash
pytest tests/ -v
ruff check credactor/ tests/ scripts/
ruff format --check credactor/ tests/ scripts/
mypy credactor/ scripts/
```

The CI test job runs these four checks on Linux and Windows with Python 3.11
to 3.13, with pytest run under coverage (`make lint` covers the last three).
CI also runs a self-scan, a wheel build audit and a self-test of the GitHub
Action. A type error fails the build, so run mypy locally before pushing. To
run the lint, type-check, and self-scan automatically on every commit (the
hooks use the project venv's own tools, so commit with the venv active):

```bash
pip install pre-commit && pre-commit install
```

### Behaviour snapshots

`tests/differential/` runs the real CLI over a fixed corpus and compares the
complete findings (every field, in order), the exit code, the log messages and
the bytes of every file afterwards against committed snapshots. A change that
alters any of these fails the suite with a diff. If the change is intended,
regenerate the snapshots and explain the difference in the commit:

```bash
pytest tests/differential --update-differential
git status && git diff tests/differential/expected
```

Snapshots store hashes, never secret values. Add a case to
`tests/differential/corpus.py` when you add behaviour that is not yet covered.

## Build and Audit

```bash
pip install --require-hashes -r requirements-ci.txt
python -m build --no-isolation
python scripts/audit_wheel.py
```

`--no-isolation` builds with the hash-pinned setuptools installed above instead
of downloading a fresh, unpinned backend. CI and the release workflow build the
same way.

The artifact audit (`scripts/audit_wheel.py`) checks the built wheel and sdist against git HEAD. Every file that comes from the repository must match its committed copy byte for byte (sha256), every `credactor/` file must be present, nothing untracked may appear apart from the build metadata, no sdist member may escape the archive root, and the package metadata (name, version, dependencies, extras, entry point) must match `pyproject.toml`. It fails if no wheel or sdist was built. See [docs/security.md](docs/security.md#supply-chain-hardening) for details.

## Code Style

- Linted with [Ruff](https://docs.astral.sh/ruff/) (`ruff check`) and
  format-checked (`ruff format --check`; single quotes, 100-column lines). Run
  `ruff format credactor/ tests/ scripts/` before committing so CI's format
  check passes
- Type hints on all public functions (mypy strict)
- No external runtime dependencies, stdlib only

## CI Pipeline

Every PR runs:

- **test**: lint, format check, type check, and pytest with coverage on Python 3.11 to 3.13, on Linux and Windows
- **self-scan**: Credactor scans its own tree (SARIF uploaded to Code Scanning)
- **build-audit**: builds the wheel and sdist and checks both, byte for byte, against the committed source
- **action-selftest**: runs the GitHub Action from this checkout on Linux and Windows and checks its outputs and the cases it must refuse

All CI dependencies are hash-pinned via `requirements-ci.txt` (`--require-hashes`). GitHub Actions are pinned to commit SHAs.

## Pull Request Process

1. Branch from `develop` (`feat/`, `fix/`, `security/`, `docs/`). `develop` is the integration branch; `main` tracks releases
2. Ensure all CI checks pass
3. One logical change per PR
4. Security fixes use `security/` prefix and reference SEC-XX identifiers

## Development Process

AI tools were used during development for code review, bug detection, security auditing, and documentation structuring. All output was reviewed and validated manually. The architecture, design decisions, and feature selection are the maintainer's own.
