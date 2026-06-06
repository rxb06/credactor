"""
Central logging setup for credactor.

Usage in modules:
    from ._log import logger
    logger.warning('Something went wrong: %s', detail)

Call ``configure(verbose, no_color)`` once at startup (from cli._main_inner)
to adjust the log level.  The handler is registered at import time so that
unit tests using ``capsys`` receive output without needing to call configure().
"""
from __future__ import annotations

import logging
import sys
from typing import ClassVar, TextIO

logger = logging.getLogger('credactor')
logger.setLevel(logging.DEBUG)   # let the handler filter; logger sees everything
logger.propagate = False


class _BracketFormatter(logging.Formatter):
    """Emit messages with the bracket prefixes credactor uses on stderr."""

    _PREFIX: ClassVar[dict[int, str]] = {
        logging.DEBUG:   '  [SKIP] ',
        logging.INFO:    '  [INFO] ',
        logging.WARNING: '[WARN] ',
        logging.ERROR:   '[ERROR] ',
    }

    def format(self, record: logging.LogRecord) -> str:
        return self._PREFIX.get(record.levelno, '') + record.getMessage()


class _DynamicStderrHandler(logging.StreamHandler[TextIO]):
    """StreamHandler that re-resolves sys.stderr on every emit call.

    pytest's capsys fixture temporarily replaces sys.stderr with a capture
    buffer.  A handler that stored sys.stderr at construction time would
    bypass that replacement.  By re-binding self.stream before each emit we
    always write to whichever stream is currently sys.stderr.
    """

    def emit(self, record: logging.LogRecord) -> None:
        self.stream = sys.stderr
        super().emit(record)


_handler = _DynamicStderrHandler()
_handler.setLevel(logging.WARNING)   # default: WARN and ERROR only
_handler.setFormatter(_BracketFormatter())
logger.addHandler(_handler)


def configure(verbose: bool = False, no_color: bool = False) -> None:
    """Adjust log output level.  Call once at the start of main()."""
    _handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
