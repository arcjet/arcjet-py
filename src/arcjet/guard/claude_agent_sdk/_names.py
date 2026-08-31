"""Qualify and match Claude Agent SDK tool names for ``exclude``.

Authored ``@tool`` / ``SdkMcpTool`` handlers are reached from
``create_sdk_mcp_server`` as ``mcp__{server}__{name}`` on ``PreToolUse``.
A bare authored name must not match every server's tool of that name: two
servers can expose the same name with only one of them wrapped, and a
loose match would drop the gate on the unprotected one.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Union

ExcludeEntry = Union[str, Mapping[str, str]]


def mcp_tool_name(server: str, name: str) -> str:
    """The ``PreToolUse`` name for an authored SDK MCP tool."""
    return f"mcp__{server}__{name}"


def exclude_name(entry: ExcludeEntry) -> str:
    """Exact ``PreToolUse`` name this exclude entry matches.

    A mapping ``{"server": ..., "name": ...}`` is qualified. A bare string
    is used as-is (a built-in such as ``"Bash"``, or an already-qualified
    ``mcp__support__lookup_order``).
    """
    if isinstance(entry, str):
        if not entry:
            raise ValueError(
                "exclude entry must be a non-empty tool name or "
                "{'server': ..., 'name': ...}; got an empty string"
            )
        return entry
    fields = dict(entry)
    server = fields.get("server")
    name = fields.get("name")
    if not isinstance(server, str) or not server:
        raise ValueError(
            "exclude mapping needs a non-empty 'server' string "
            "(the mcp_servers key), so the PreToolUse name can be "
            f"qualified as mcp__{{server}}__{{name}}; got {entry!r}"
        )
    if not isinstance(name, str) or not name:
        raise ValueError(
            "exclude mapping needs a non-empty 'name' string "
            "(the @tool name), so the PreToolUse name can be "
            f"qualified as mcp__{{server}}__{{name}}; got {entry!r}"
        )
    return mcp_tool_name(server, name)


def excluded_names(entries: Sequence[ExcludeEntry] | None) -> frozenset[str]:
    """Exact names :func:`guard_hooks` PreToolUse should skip."""
    if not entries:
        return frozenset()
    return frozenset(exclude_name(entry) for entry in entries)


def is_excluded(tool_name: str, excluded: frozenset[str]) -> bool:
    """Whether *tool_name* is an exact exclude match."""
    return bool(tool_name) and tool_name in excluded


def as_exclude_entry(value: Any) -> ExcludeEntry:
    """Narrow a caller value to :data:`ExcludeEntry`, or raise."""
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        return value
    raise TypeError(
        "exclude entries must be a tool name string or "
        f"{{'server': ..., 'name': ...}}, got {type(value).__name__}"
    )
