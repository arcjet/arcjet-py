"""Lazy Strands Agents imports, so this package works without the extra.

The public module is importable without ``strands-agents``: unit tests and
``import arcjet.guard`` must keep working. The first call that wraps a tool
or builds hooks loads the peer, and says what to install if it is missing or
too old.

The floor is 1.11.0 — the first 1.x whose ``BeforeToolCallEvent`` has
``cancel_tool``. 1.10.0 (2025-09-29) does not; PR 964 merged 2025-10-03 and
shipped in 1.11.0 (2025-10-08). Verified on 1.54.0. The default extra set
does not pull chromadb.

``importlib`` is used rather than static imports so type checkers do not need
the extra installed either. The distribution is ``strands-agents``; the
import package is ``strands``.
"""

from __future__ import annotations

import importlib
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Final, Optional

from arcjet._errors import ArcjetMisconfiguration

#: First 1.x with ``BeforeToolCallEvent.cancel_tool``. Below this the hook
#: cannot skip the handler. Verified on 1.54.0.
MINIMUM_STRANDS_AGENTS: Final[tuple[int, int, int]] = (1, 11, 0)

_INSTALL_HINT: Final[str] = (
    'Install it with: pip install "arcjet[strands-agents]" (strands-agents>=1.11.0,<2)'
)


def _release(raw: str) -> tuple[int, ...]:
    """The numeric release segment of *raw*, e.g. ``"1.54.0rc1"`` → ``(1, 54, 0)``.

    Local parsing rather than ``packaging.version``: that is not an Arcjet
    dependency, and a three-part release is all this comparison needs. Pre-
    release suffixes (``rc1``) are stripped; post-releases (``1.54.0.post1``)
    also compare as ``(1, 54, 0)`` because only the leading digit run is kept.
    A short or non-numeric release such as ``"1.11"`` or ``"1.11.post1"``
    collapses to ``(1, 11)``, which compares less than the three-part floor
    and is refused — not treated as unknown and skipped. An empty parse
    (``"weird"``) is the skip path.
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
        return version("strands-agents")
    except PackageNotFoundError:  # pragma: no cover - depends on the install
        return None


def _require_strands_agents() -> None:
    """Refuse a peer too old to cancel a tool, before anything is wired.

    Below the floor ``BeforeToolCallEvent`` has no ``cancel_tool``, so a hook
    cannot skip the handler. Reported at wrap / hook-build time rather than
    as an ``AttributeError`` from inside a callback the SDK would propagate.
    """
    installed = _installed_version()
    if installed is None:
        return
    release = _release(installed)
    if release and release < MINIMUM_STRANDS_AGENTS:
        floor = ".".join(str(part) for part in MINIMUM_STRANDS_AGENTS)
        raise ArcjetMisconfiguration(
            f"arcjet.guard.strands_agents needs strands-agents >= {floor}, "
            f"but {installed} is installed. Below {floor} "
            f"BeforeToolCallEvent has no cancel_tool, so a hook cannot skip "
            f"the handler. Upgrade with: "
            f'pip install "strands-agents>={floor},<2"'
        )


def load_strands() -> Any:
    """The ``strands`` package, or an error naming what to install."""
    _require_strands_agents()
    try:
        return importlib.import_module("strands")
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise ImportError(
            f"arcjet.guard.strands_agents needs Strands Agents. {_INSTALL_HINT}"
        ) from exc


def load_decorated_function_tool() -> type[Any]:
    """Strands' ``DecoratedFunctionTool``, or an error naming what to install."""
    _require_strands_agents()
    try:
        module = importlib.import_module("strands.tools.decorator")
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise ImportError(
            f"arcjet.guard.strands_agents needs Strands Agents. {_INSTALL_HINT}"
        ) from exc
    return module.DecoratedFunctionTool


def load_strands_hooks() -> Any:
    """The ``strands.hooks`` package, or an error naming what to install."""
    _require_strands_agents()
    try:
        return importlib.import_module("strands.hooks")
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise ImportError(
            f"arcjet.guard.strands_agents needs Strands Agents. {_INSTALL_HINT}"
        ) from exc


def strands_agents_present() -> bool:
    """Whether the ``strands`` package is importable in this process."""
    try:
        importlib.import_module("strands")
    except ImportError:
        return False
    return True
