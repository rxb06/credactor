"""Shared fixtures for Credactor tests."""

import logging
import os

import pytest

from credactor._log import configure as _configure_log
from credactor.config import Config


@pytest.fixture(autouse=True)
def _reset_log_level():
    """Reset the credactor logger to WARNING between tests.

    Tests that call main() with --verbose flip the handler to DEBUG; without
    this fixture the elevated level would leak into subsequent tests.
    """
    _configure_log(verbose=False)
    yield
    _configure_log(verbose=False)


@pytest.fixture
def credactor_caplog(caplog):
    """caplog that captures credactor logger records despite propagate=False.

    The credactor logger sets propagate=False so pytest's default caplog
    (which attaches to the root logger) misses its records.  This fixture
    attaches caplog.handler directly and sets the capture level to DEBUG.
    """
    from credactor._log import logger
    caplog.set_level(logging.DEBUG, logger='credactor')
    logger.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        logger.removeHandler(caplog.handler)


@pytest.fixture
def config():
    """Default Config for testing."""
    return Config()


@pytest.fixture
def tmp_dir(tmp_path):
    """str alias of pytest's built-in ``tmp_path`` — one tmp mechanism for the
    whole suite. Kept as a separate name so the ~90 existing call sites stay
    untouched; new tests may use either spelling."""
    return str(tmp_path)


@pytest.fixture
def make_file(tmp_dir):
    """Factory to create a file with given content inside tmp_dir."""
    def _make(name: str, content: str) -> str:
        path = os.path.join(tmp_dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(content)
        return path
    return _make
