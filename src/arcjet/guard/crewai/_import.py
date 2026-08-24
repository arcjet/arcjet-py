"""Lazy CrewAI imports so ``import arcjet.guard.crewai`` does not need the extra.

The public module is importable without ``crewai`` installed: unit tests and
``import arcjet.guard`` must keep working on interpreters the extra does not
support (CrewAI is ``>=3.10,<3.14``). The first call that actually talks to
CrewAI — registering hooks or wrapping a tool — loads the peer and names the
extra if it is missing.

``importlib`` is used instead of a static import so type checkers do not need
the extra installed.
"""

from __future__ import annotations

import importlib
from typing import Any

_CREWAI_EXTRA = 'Install CrewAI support with: pip install "arcjet[crewai]"'


def load_crewai_hooks() -> Any:
    """The ``crewai.hooks`` module, or an :class:`ImportError` naming the extra."""
    try:
        return importlib.import_module("crewai.hooks")
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise ImportError(_CREWAI_EXTRA) from exc


def load_crewai_base_tool() -> type[Any]:
    """CrewAI's ``BaseTool``, or an :class:`ImportError` naming the extra."""
    try:
        module = importlib.import_module("crewai.tools.base_tool")
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise ImportError(_CREWAI_EXTRA) from exc
    return module.BaseTool


def crewai_present() -> bool:
    """Whether the CrewAI extra is importable in this process."""
    try:
        importlib.import_module("crewai")
    except ImportError:
        return False
    return True
