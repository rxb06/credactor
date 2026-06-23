# Contributing

Thanks for your interest in Credactor. Bug reports, feature requests, and pull requests are welcome via [GitHub Issues](https://github.com/rxb06/credactor/issues).

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
mypy credactor/ scripts/
```

CI runs exactly these three checks (`make lint` covers the last two). A type
error fails the build, so run mypy locally before pushing. To run the lint,
type-check, and self-scan automatically on every commit (the hooks use the
project venv's own tools, so commit with the venv active):

```bash
pip install pre-commit && pre-commit install
```

## Build and Audit

```bash
pip install build
python -m build
python scripts/audit_wheel.py
```

The wheel audit (`scripts/audit_wheel.py`) verifies that the built wheel exactly matches the files tracked in the git repo (nothing extra smuggled in, nothing tracked left out), and fails if no wheel was built at all. See [docs/security.md](docs/security.md#supply-chain-hardening) for details.

## Code Style

- Linted with [Ruff](https://docs.astral.sh/ruff/) (`ruff check`); **no
  auto-formatter is used**. Do not run `ruff format`. Match the surrounding
  style instead (single quotes, 100-column lines)
- Type hints on all public functions (mypy strict)
- No external runtime dependencies, stdlib only

## CI Pipeline

Every PR runs:

- **test** - lint, type check, and pytest across Python 3.11–3.13 on Linux and Windows
- **self-scan** - Credactor scans its own codebase (SARIF uploaded to Code Scanning)
- **build-audit** - builds the wheel and verifies contents match the repo

All CI dependencies are hash-pinned via `requirements-ci.txt` (`--require-hashes`). GitHub Actions are pinned to commit SHAs.

## Pull Request Process

1. Branch from `develop` (`feat/`, `fix/`, `security/`, `docs/`). `develop` is the integration branch; `main` tracks releases
2. Ensure all CI checks pass
3. One logical change per PR
4. Security fixes use `security/` prefix and reference SEC-XX identifiers

## Development Process

AI tools were used during development for code review, bug detection, security auditing, and documentation structuring. All output was reviewed and validated manually. The architecture, design decisions, and feature selection are the maintainer's own.
