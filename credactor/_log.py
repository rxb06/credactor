"""
Central logging setup for credactor.

Usage in modules:
    from ._log import logger
    logger.warning('Something went wrong: %s', detail)

Call ``configure(verbose)`` once at startup (from cli._main_inner) to adjust
the log level.  The handler is registered at import time so that unit tests
using ``capsys`` receive output without needing to call configure().
"""

from __future__ import annotations

import copy
import logging
import os
import sys
from collections.abc import Mapping
from typing import Any, ClassVar, TextIO

logger = logging.getLogger('credactor')
logger.setLevel(logging.DEBUG)  # let the handler filter; logger sees everything
logger.propagate = False


class _BracketFormatter(logging.Formatter):
    """Emit messages with the bracket prefixes credactor uses on stderr."""

    _PREFIX: ClassVar[dict[int, str]] = {
        logging.DEBUG: '  [SKIP] ',
        logging.INFO: '  [INFO] ',
        logging.WARNING: '[WARN] ',
        logging.ERROR: '[ERROR] ',
    }

    def format(self, record: logging.LogRecord) -> str:
        # SR-06: the arguments are untrusted (paths, report fields); the
        # template is not, and may hold deliberate line breaks. Sanitize a
        # copy, so other handlers (pytest's caplog) keep the original record.
        # Imported here because utils imports this module.
        from .utils import defuse_ci_commands

        if record.args:
            record = copy.copy(record)
            record.args = _sanitize_args(record.args)
        # An argument can still meet the template to form a command marker.
        return defuse_ci_commands(self._PREFIX.get(record.levelno, '') + record.getMessage())


def _sanitize_arg(value: object) -> object:
    from .utils import sanitize_for_display

    if isinstance(value, str):
        return sanitize_for_display(value)
    if isinstance(value, (os.PathLike, BaseException)):
        return sanitize_for_display(str(value))
    return value


def _sanitize_args(args: Any) -> Any:
    if isinstance(args, Mapping):
        return {key: _sanitize_arg(value) for key, value in args.items()}
    return tuple(_sanitize_arg(value) for value in args)


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
_handler.setLevel(logging.WARNING)  # default: WARN and ERROR only
_handler.setFormatter(_BracketFormatter())
logger.addHandler(_handler)


def configure(verbose: bool = False) -> None:
    """Adjust log output level.  Call once at the start of main()."""
    _handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
