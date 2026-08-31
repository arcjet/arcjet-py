"""Lazy Claude Agent SDK imports, so this package works without the extra.

The public module is importable without ``claude-agent-sdk``: unit tests and
``import arcjet.guard`` must keep working. The first call that wraps a tool
or builds hooks loads the peer, and says what to install if it is missing or
too old.

The floor is 0.2.127. 0.2.83 was the mcp CVE + timeout fail-close line;
0.2.127 includes that and the background-task PreToolUse stdin fix, so this
adapter does not have to caveat that path. Verified on 0.2.148.

``importlib`` is used rather than static imports so type checkers do not need
the extra installed either.
"""

from __future__ import annotations

import importlib
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Final, Optional

from arcjet._errors import ArcjetMisconfiguration

#: Floor that includes the mcp CVE + timeout fail-close fix (0.2.83) and the
#: background-task PreToolUse stdin fix, so we do not have to caveat that
#: path. Verified on 0.2.148.
MINIMUM_CLAUDE_AGENT_SDK: Final[tuple[int, int, int]] = (0, 2, 127)

_INSTALL_HINT: Final[str] = (
    'Install it with: pip install "arcjet[claude-agent-sdk]" '
    "(claude-agent-sdk>=0.2.127,<1)"
)


def _release(raw: str) -> tuple[int, ...]:
    """The numeric release segment of *raw*, e.g. ``"0.2.148rc1"`` → ``(0, 2, 148)``.

    Local parsing rather than ``packaging.version``: that is not an Arcjet
    dependency, and a three-part release is all this comparison needs. Pre-
    release suffixes (``rc1``) are stripped; post-releases (``0.2.148.post1``)
    also compare as ``(0, 2, 148)`` because only the leading digit run is kept.
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
        return version("claude-agent-sdk")
    except PackageNotFoundError:  # pragma: no cover - depends on the install
        return None


def _require_claude_agent_sdk() -> None:
    """Refuse a peer too old to deny honestly, before anything is wired.

    Below the floor this adapter would have to caveat the PreToolUse stdin
    fix (and would sit under the 0.2.83 mcp CVE line). Reported at wrap /
    hook-build time rather than as an ``AttributeError`` from inside a
    handler the SDK would swallow into ``str(e)``.
    """
    installed = _installed_version()
    if installed is None:
        return
    release = _release(installed)
    if release and release < MINIMUM_CLAUDE_AGENT_SDK:
        floor = ".".join(str(part) for part in MINIMUM_CLAUDE_AGENT_SDK)
        raise ArcjetMisconfiguration(
            f"arcjet.guard.claude_agent_sdk needs claude-agent-sdk >= {floor}, "
            f"but {installed} is installed. Below {floor} the PreToolUse "
            f"background-task stdin path is incomplete and the 0.2.83 mcp "
            f"CVE / timeout fail-close line is not guaranteed. Upgrade with: "
            f'pip install "claude-agent-sdk>={floor},<1"'
        )


def load_claude_agent_sdk() -> Any:
    """The ``claude_agent_sdk`` package, or an error naming what to install."""
    _require_claude_agent_sdk()
    try:
        return importlib.import_module("claude_agent_sdk")
    except ImportError as exc:  # pragma: no cover - depends on the install
        raise ImportError(
            f"arcjet.guard.claude_agent_sdk needs the Claude Agent SDK. {_INSTALL_HINT}"
        ) from exc


def load_sdk_mcp_tool() -> type[Any]:
    """The SDK's ``SdkMcpTool``, or an error naming what to install."""
    return load_claude_agent_sdk().SdkMcpTool


def load_hook_matcher() -> type[Any]:
    """The SDK's ``HookMatcher``, or an error naming what to install."""
    return load_claude_agent_sdk().HookMatcher


def claude_agent_sdk_present() -> bool:
    """Whether ``claude_agent_sdk`` is importable in this process."""
    try:
        importlib.import_module("claude_agent_sdk")
    except ImportError:
        return False
    return True
