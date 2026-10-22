<!-- Branch from `develop` (the integration branch); `main` tracks releases. -->

**What & why**
Brief description of the change and the problem it solves (link any issue).

**Type**
- [ ] Bug fix
- [ ] New feature
- [ ] Detection/redaction pattern
- [ ] Docs / chore

**Checklist**
- [ ] `pytest tests/` passes
- [ ] `make lint` clean (`ruff check` and `ruff format --check` over credactor/ tests/ scripts/, `mypy` over credactor/ scripts/, the same checks CI runs)
- [ ] `python -m credactor --ci .` exits 0 (the same working-tree scan CI runs; it skips gitignored files and .json files, so also check the diff by hand)
- [ ] Tests added/updated for the change
- [ ] No real credentials in the diff, tests, or fixtures
