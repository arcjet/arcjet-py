"""Optional CrewAI tool-call integration.

Install ``arcjet[crewai]`` to use this module. Core Guard clients do not
import CrewAI, and this package does not import :mod:`arcjet.guard.langchain`.

Two surfaces, matching the JS Eve-pattern split (authored wrap vs
invoke-wide hook):

* :func:`register_arcjet_hooks` — a ``PRE_TOOL_CALL`` registrar. Every tool
  a crew, LiteAgent, MCP adapter, or crew-injected tool list executes hits
  this hook. A deny is ``HookAborted(reason, source="arcjet")`` so the tool
  does not run. CrewAI swallows every other exception.
* :func:`guard_tool` — wrap a standalone CrewAI ``BaseTool`` you call
  yourself. ``BaseTool.run`` never dispatches ``PRE_TOOL_CALL``. This path
  raises :class:`~arcjet.guard.ArcjetDeniedError` /
  :class:`~arcjet.guard.ArcjetUnavailableError`.

There is no inbound helper and no approval helper. Screen user text with
the core :func:`~arcjet.guard.guard` / :func:`~arcjet.guard.guard_sync`
call before ``crew.kickoff``. ``human_input`` is HITL, not a policy gate.

Only PRE is registered. POST_TOOL_CALL is never a policy surface — it fires
on blocked calls too — and this module does not register it at all, so it
cannot deny or rewrite a result. The decision is captured in PRE. The
agent-facing block message is always ``Tool execution blocked by hook.
Tool: {name}``; ``HookAborted.reason`` is telemetry only.

The hook path is synchronous and needs ``launch_arcjet_sync``. Correlation
is caller-owned (``correlation_id`` / :func:`~arcjet.guard.arcjet_sequence`);
crew, task, and agent names are metadata and are never minted into an id.
"""

from __future__ import annotations

from ._hooks import (
    ArcjetCrewAIHooks,
    ToolPolicy,
    register_arcjet_hooks,
    unregister_arcjet_hooks,
)
from ._names import free_text_arguments, sanitize_tool_name
from ._tool import guard_tool

__all__ = [
    "ArcjetCrewAIHooks",
    "ToolPolicy",
    "free_text_arguments",
    "guard_tool",
    "register_arcjet_hooks",
    "sanitize_tool_name",
    "unregister_arcjet_hooks",
]
