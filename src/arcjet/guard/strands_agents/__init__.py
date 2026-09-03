"""Optional Strands Agents tool-call integration.

Install ``arcjet[strands-agents]`` to use this module. Core Guard clients
do not import Strands Agents, and this package does not import
:mod:`arcjet.guard.langchain`, :mod:`arcjet.guard.crewai`,
:mod:`arcjet.guard.openai_agents`, or :mod:`arcjet.guard.claude_agent_sdk`.

Three names:

* :func:`guard_tool` — wrap an authored ``@tool`` /
  ``DecoratedFunctionTool.stream`` so the handler never runs on DENY.
  The deny is an error-status tool result whose text is the JSON
  ``ArcjetDenialResult``. Do not throw (the SDK swallows into
  ``Error: {Type} - {message}``). ``stream`` is the wrap point so
  caller-owned ``invocation_state`` is visible. Tool kwargs are never
  a correlation source.
* :func:`guard_hooks` — ``BeforeToolCallEvent.cancel_tool`` set to the
  JSON ``ArcjetDenialResult`` for unwrapped MCP / vended / built-ins.
  ``AfterToolCallEvent`` is capture-only (``strands.phase: after``).
  Branded ``guard_tool`` wrappers are skipped on the before path.
  ``BeforeToolsEvent.cancel`` is not set: official docs say a batch
  cancel skips per-tool ``BeforeToolCallEvent`` hooks (same reason the
  JS adapter avoided it).
* :func:`strands_agent_context` — read a caller-owned
  ``correlationId`` / ``sessionId`` / ``requestId`` from
  ``invocation_state``. Never mints. Never reads ``trace_id``. Never
  reads ``agent.id`` / SessionManager auto-ids.

There is no ``guard_inbound`` helper and no ``guard_approval``.
``event.interrupt()`` is HITL, not a policy gate. There is no dedicated
prompt hook on this bus — screen user text with core
:func:`~arcjet.guard.guard` / :func:`~arcjet.guard.guard_sync` before
``agent()``.

``protect()`` / the request path is fail-open — check
:meth:`~arcjet.guard.Decision.has_failed_open`. These helpers are
fail-closed (default ``on_guard_error="deny"``).

See https://docs.arcjet.com/guards/strands-agents-py/
"""

from __future__ import annotations

from ._context import strands_agent_context
from ._hooks import guard_hooks
from ._tool import guard_tool

__all__ = [
    "guard_tool",
    "guard_hooks",
    "strands_agent_context",
]
