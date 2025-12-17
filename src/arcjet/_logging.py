from __future__ import annotations

import logging
import os
from typing import Final


_LEVELS: Final[dict[str, int]] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warn": logging.WARNING,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "fatal": logging.FATAL,
    "critical": logging.CRITICAL,
}


def _env_log_level(default: int = logging.WARNING) -> int:
    lvl = (os.getenv("ARCJET_LOG_LEVEL") or "").strip().lower()
    if not lvl:
        return default
    # Accept numeric levels as well (e.g., "10" for DEBUG)
    if lvl.isdigit():
        try:
            return int(lvl)
        except Exception:
            return default
    return _LEVELS.get(lvl, default)


# Library logger following stdlib best practices
logger = logging.getLogger("arcjet")
if not logger.handlers:
    # Attach a NullHandler so importing the library doesn't configure logging.
    logger.addHandler(logging.NullHandler())

# Set level from environment so users can opt-in via ARCJET_LOG_LEVEL
logger.setLevel(_env_log_level(logging.WARNING))
