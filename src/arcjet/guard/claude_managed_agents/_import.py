"""Lazy Anthropic imports, so this package works without the extra.

The public module is importable without ``anthropic``: unit tests and
``import arcjet.guard`` must keep working. The helpers duck-type the
events API (``sessions.events.send``, ``agent.custom_tool_use``) so a
missing extra does not fail the wrap. The floor is checked when the
peer *is* installed, so a too-old SDK is refused at wrap time rather
than as an ``AttributeError`` from inside a tool call.

The floor is 0.92.0 — the first release whose changelog adds Claude
Managed Agents (``client.beta.agents``, ``client.beta.sessions``,
``client.beta.environments``, beta ``managed-agents-2026-04-01``).
``EnvironmentWorker`` landed later (0.103.0); this adapter duck-types
a worker tool's ``call`` so the extra floor stays at agents / sessions
/ environments, not the worker helper.

``importlib`` is used rather than static imports so type checkers do not
need the extra installed either.
"""

from __future__ import annotations

import importlib
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Final, Optional

from arcjet._errors import ArcjetMisconfiguration

#: First release that ships ``client.beta.agents`` / ``sessions`` /
#: ``environments`` (changelog: "add support for Claude Managed Agents").
MINIMUM_ANTHROPIC: Final[tuple[int, int, int]] = (0, 92, 0)

_INSTALL_HINT: Final[str] = (
    'Install it with: pip install "arcjet[claude-managed-agents]" '
    "(anthropic>=0.92.0,<2)"
)


def _release(raw: str) -> tuple[int, ...]:
    """The numeric release segment of *raw*, e.g. ``"0.92.0rc1"`` → ``(0, 92, 0)``.

    Local parsing rather than ``packaging.version``: that is not an Arcjet
    dependency, and a three-part release is all this comparison needs. Pre-
    release suffixes (``rc1``) are stripped; post-releases (``0.92.0.post1``)
    also compare as ``(0, 92, 0)`` because only the leading digit run is kept.
    A short or non-numeric release such as ``"0.92"`` or ``"0.92.post1"``
    collapses to ``(0, 92)``, which compares less than the three-part floor
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
        return version("anthropic")
    except PackageNotFoundError:  # pragma: no cover - depends on the install
        return None


def _require_anthropic() -> None:
    """Refuse a peer too old to expose beta agents / sessions / environments.

    Below 0.92.0 there is no ``client.beta.agents`` namespace this adapter
    can honestly use. Reported at wrap time. A missing install is left to
    the import path — the helpers duck-type ``send`` / ``call``.
    """
    installed = _installed_version()
    if installed is None:
        return
    release = _release(installed)
    if release and release < MINIMUM_ANTHROPIC:
        floor = ".".join(str(part) for part in MINIMUM_ANTHROPIC)
        raise ArcjetMisconfiguration(
            f"arcjet.guard.claude_managed_agents needs anthropic >= {floor}, "
            f"but {installed} is installed. Below {floor} there is no "
            f"client.beta.agents / sessions / environments API (beta "
            f"managed-agents-2026-04-01). Upgrade with: "
            f'pip install "anthropic>={floor},<2"'
        )


def load_anthropic() -> Any:
    """The ``anthropic`` package, or an error naming what to install."""
    _require_anthropic()
    try:
        return importlib.import_module("anthropic")
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise ImportError(
            f"arcjet.guard.claude_managed_agents needs the Anthropic SDK. "
            f"{_INSTALL_HINT}"
        ) from exc


def anthropic_present() -> bool:
    """Whether ``anthropic`` is importable in this process."""
    try:
        importlib.import_module("anthropic")
    except ImportError:
        return False
    return True


#: Where the SDK has exported ``ToolError``. Checked in order; the public
#: ``anthropic.lib.tools`` path is preferred over the private module.
_TOOL_ERROR_MODULES: Final[tuple[str, ...]] = (
    "anthropic.lib.tools",
    "anthropic.lib.tools._beta_functions",
)


def load_tool_error() -> Optional[type[BaseException]]:
    """Anthropic's ``ToolError``, if the extra is installed.

    ``SessionToolRunner`` sets ``is_error`` on ``user.custom_tool_result``
    only when the local tool raises. ``ToolError`` keeps the denial JSON as
    ``content`` instead of ``repr(exc)``.
    """
    if not anthropic_present():
        return None
    _require_anthropic()
    for name in _TOOL_ERROR_MODULES:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        candidate = getattr(module, "ToolError", None)
        if isinstance(candidate, type) and issubclass(candidate, BaseException):
            return candidate
    return None
