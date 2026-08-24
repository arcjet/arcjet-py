"""Lazy CrewAI imports, so this package works without CrewAI installed.

The public module is importable without ``crewai``: unit tests and
``import arcjet.guard`` must keep working on interpreters CrewAI does not
support (it requires Python ``>=3.10,<3.14``). The first call that actually
talks to CrewAI — registering hooks or wrapping a tool — loads the peer, and
says what to install if it is missing or too old.

CrewAI is deliberately **not** an Arcjet dependency or extra. It pulls
``chromadb``, which carries an unpatched critical RCE (CVE-2026-45829), and
an Arcjet install must not be the thing that puts that in someone's
environment. Anyone using this module already installs CrewAI themselves, so
the floor is enforced here instead of in package metadata — which also gives
a better error than a resolver conflict.

``importlib`` is used rather than static imports so type checkers do not need
CrewAI installed either.
"""

from __future__ import annotations

import importlib
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Final, Optional

from arcjet._errors import ArcjetMisconfiguration

#: The floor `@on` and `HookAborted` landed in. Below this the hook cannot
#: deny with a reason, and `register_hook` does not exist.
MINIMUM_CREWAI: Final[tuple[int, int, int]] = (1, 15, 3)

_INSTALL_HINT: Final[str] = (
    'Install it with: pip install "crewai>=1.15.3,<2" (CrewAI is not an '
    "Arcjet dependency, because it pulls chromadb, which carries an "
    "unpatched critical RCE — CVE-2026-45829)"
)


def _release(raw: str) -> tuple[int, ...]:
    """The numeric release segment of *raw*, e.g. ``"1.15.3rc1"`` → ``(1, 15, 3)``.

    Local parsing rather than ``packaging.version``: that is not an Arcjet
    dependency, and a three-part release is all this comparison needs.
    """
    parts: list[int] = []
    for chunk in raw.split(".")[:3]:
        digits = ""
        for char in chunk:
            if not char.isdigit():
                break
            digits += char
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts)


def _installed_version() -> Optional[str]:
    try:
        return version("crewai")
    except PackageNotFoundError:  # pragma: no cover - depends on the install
        return None


def _require_crewai() -> None:
    """Refuse a CrewAI too old to deny a tool call, before anything is wired.

    A version below the floor has no ``@on``/``HookAborted``, so the hook
    could not stop a tool. Reported here, at registration or wrap time, rather
    than as an ``AttributeError`` from inside a hook — where CrewAI would
    swallow it and run the tool.
    """
    installed = _installed_version()
    if installed is None:
        return
    release = _release(installed)
    if release and release < MINIMUM_CREWAI:
        floor = ".".join(str(part) for part in MINIMUM_CREWAI)
        raise ArcjetMisconfiguration(
            f"arcjet.guard.crewai needs crewai >= {floor}, but {installed} is "
            f"installed. Below {floor} there is no @on / HookAborted, so a "
            f"hook cannot stop a tool call. Upgrade with: "
            f'pip install "crewai>={floor},<2"'
        )


def load_crewai_hooks() -> Any:
    """The ``crewai.hooks`` module, or an error naming what to install."""
    _require_crewai()
    try:
        return importlib.import_module("crewai.hooks")
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise ImportError(f"arcjet.guard.crewai needs CrewAI. {_INSTALL_HINT}") from exc


def load_crewai_base_tool() -> type[Any]:
    """CrewAI's ``BaseTool``, or an error naming what to install."""
    _require_crewai()
    try:
        module = importlib.import_module("crewai.tools.base_tool")
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise ImportError(f"arcjet.guard.crewai needs CrewAI. {_INSTALL_HINT}") from exc
    return module.BaseTool


def crewai_present() -> bool:
    """Whether CrewAI is importable in this process."""
    try:
        importlib.import_module("crewai")
    except ImportError:
        return False
    return True
