"""Optional Google ADK tool-call integration.

Install ``arcjet[google-adk]`` to use this module. Core Guard clients do
not import Google ADK, and this package does not import
:mod:`arcjet.guard.langchain`, :mod:`arcjet.guard.crewai`,
:mod:`arcjet.guard.openai_agents`, :mod:`arcjet.guard.claude_agent_sdk`,
:mod:`arcjet.guard.claude_managed_agents`, or
:mod:`arcjet.guard.strands_agents`.

Three names:

* :func:`guard_tool` — an ``LlmAgent.before_tool_callback``. It is not a
  ``FunctionTool`` wrap. A ``DENY`` returns a skip dict with
  ``arcjetDenied``; ``None`` allows the tool. Never ``{}`` (falsy in
  ADK's callback chain, so the tool would run). Parameter names must be
  ``tool``, ``args``, ``tool_context``.
* :func:`guard_plugin` — a Runner ``BasePlugin``. Put it first on
  ``App(..., plugins=[...])`` (or the deprecated
  ``Runner(..., plugins=[...])``). Do not also attach :func:`guard_tool`
  to the same tools — plugins run first and a second gate double-calls
  Guard. Deny is the same skip dict; ``None`` allows. Never ``{}``.
* :func:`google_adk_context` — read a caller-owned ``correlation_id`` /
  ``session_id`` / ``conversation_id``. Never mints. Never reads
  ``trace_id``. Never reads an ADK-generated ``invocation_id``. Never
  reads ``toolContext.sessionId`` or ``session.id``.

There is no ``guard_inbound`` helper and no ``guard_approval``.
``request_confirmation`` / ``require_confirmation`` are HITL, not a
policy gate. ``SecurityPlugin`` is not the Arcjet gate. Screen user text
with core :func:`~arcjet.guard.guard` / :func:`~arcjet.guard.guard_sync`
before ``runner.run_async``.

This is not the JS adapter ``@arcjet/guard/google-adk/v2`` (plugin only,
no ``guardTool``).

``protect()`` / the request path is fail-open — check
:meth:`~arcjet.guard.Decision.has_failed_open`. These helpers are
fail-closed (default ``on_guard_error="deny"``).

See https://docs.arcjet.com/guards/google-adk-py/
"""

from __future__ import annotations

from ._context import google_adk_context
from ._plugin import guard_plugin
from ._tool import guard_tool

__all__ = [
    "guard_tool",
    "guard_plugin",
    "google_adk_context",
]
