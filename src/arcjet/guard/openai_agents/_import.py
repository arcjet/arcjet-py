"""Lazy OpenAI Agents imports, so this package works without the extra.

The public module is importable without ``openai-agents``: unit tests and
``import arcjet.guard`` must keep working. The first call that wraps a tool
loads the peer, and says what to install if it is missing or too old.

``importlib`` is used rather than static imports so type checkers do not need
the extra installed either.
"""

from __future__ import annotations

import importlib
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Final, Optional

from arcjet._errors import ArcjetMisconfiguration

#: Floor where authored ``FunctionTool.tool_input_guardrails`` and
#: ``ToolGuardrailFunctionOutput.reject_content`` are the skip-invoke path.
MINIMUM_OPENAI_AGENTS: Final[tuple[int, int, int]] = (0, 19, 0)

_INSTALL_HINT: Final[str] = (
    'Install it with: pip install "arcjet[openai-agents]" (openai-agents>=0.19.0,<1)'
)


def _release(raw: str) -> tuple[int, ...]:
    """The numeric release segment of *raw*, e.g. ``"0.22.0rc1"`` → ``(0, 22, 0)``.

    Local parsing rather than ``packaging.version``: that is not an Arcjet
    dependency, and a three-part release is all this comparison needs. Pre-
    release suffixes (``rc1``) are stripped; post-releases (``0.22.0.post1``)
    also compare as ``(0, 22, 0)`` because only the leading digit run is kept.
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
        return version("openai-agents")
    except PackageNotFoundError:  # pragma: no cover - depends on the install
        return None


def _require_openai_agents() -> None:
    """Refuse a peer too old to skip invoke, before anything is wired.

    Below the floor there is no ``reject_content`` skip-invoke path we can
    honestly use. Reported at wrap time rather than as an ``AttributeError``
    from inside a tool call.
    """
    installed = _installed_version()
    if installed is None:
        return
    release = _release(installed)
    if release and release < MINIMUM_OPENAI_AGENTS:
        floor = ".".join(str(part) for part in MINIMUM_OPENAI_AGENTS)
        raise ArcjetMisconfiguration(
            f"arcjet.guard.openai_agents needs openai-agents >= {floor}, but "
            f"{installed} is installed. Below {floor} there is no "
            f"FunctionTool.tool_input_guardrails reject_content path that "
            f"skips invoke. Upgrade with: "
            f'pip install "openai-agents>={floor},<1"'
        )


def load_agents_tool() -> Any:
    """The ``agents.tool`` module, or an error naming what to install."""
    _require_openai_agents()
    try:
        return importlib.import_module("agents.tool")
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise ImportError(
            f"arcjet.guard.openai_agents needs OpenAI Agents. {_INSTALL_HINT}"
        ) from exc


def load_agents_tool_guardrails() -> Any:
    """The ``agents.tool_guardrails`` module, or an error naming what to install."""
    _require_openai_agents()
    try:
        return importlib.import_module("agents.tool_guardrails")
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise ImportError(
            f"arcjet.guard.openai_agents needs OpenAI Agents. {_INSTALL_HINT}"
        ) from exc


def load_function_tool() -> type[Any]:
    """OpenAI Agents' ``FunctionTool``, or an error naming what to install."""
    return load_agents_tool().FunctionTool


def openai_agents_present() -> bool:
    """Whether the ``agents`` package is importable in this process."""
    try:
        importlib.import_module("agents")
    except ImportError:
        return False
    return True
