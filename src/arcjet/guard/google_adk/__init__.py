"""Optional Google ADK tool-call integration.

Install ``arcjet[google-adk]`` to use this module. Core Guard clients do
not import Google ADK, and this package does not import
:mod:`arcjet.guard.langchain`, :mod:`arcjet.guard.crewai`,
:mod:`arcjet.guard.openai_agents`, :mod:`arcjet.guard.claude_agent_sdk`,
:mod:`arcjet.guard.claude_managed_agents`, or
:mod:`arcjet.guard.strands_agents`.

This is Google ADK Python 2.x (``google-adk>=2.0.0,<3``). It is not
Google GenAI. It is not JS ``@arcjet/guard/google-adk/v2``, though the
skip-with-result contract matches that adapter.

Three names:

* :func:`guard_tool` — ``LlmAgent.before_tool_callback(tool, args,
  tool_context)``. Return ``None`` to allow; return a dict to skip the
  tool (the dict is the tool result). Empty ``{}`` also skips — never
  return ``{}`` to allow. The original tool function does not run on
  DENY. The callback does not throw.
* :func:`guard_plugin` — Runner ``BasePlugin.before_tool_callback``
  (keyword-only ``tool``, ``tool_args``, ``tool_context``). Same skip
  dict. Put it first in the plugin list; PluginManager is first-win.
* :func:`google_adk_context` — read a caller-owned ``correlationId`` /
  ``sessionId`` / ``conversationId``. Never mints. Never reads
  ``trace_id``. Never reads an ADK-generated ``invocation_id``. Never
  reads ``toolContext.session_id`` or ``session.id``.

There is no ``guard_inbound`` helper and no ``guard_approval``.
``require_confirmation`` / ``request_confirmation`` / ADK
``SecurityPlugin`` are HITL, not a policy gate. Screen user text with
core :func:`~arcjet.guard.guard` / :func:`~arcjet.guard.guard_sync`
before ``runner.run_async``.

``protect()`` / the request path is fail-open — check
:meth:`~arcjet.guard.Decision.has_failed_open`. These helpers are
fail-closed (default ``on_guard_error="deny"``). Fail-closed always
returns the deny dict; it never returns ``None`` on error.

See https://docs.arcjet.com/guards/google-adk/
"""

from __future__ import annotations

from ._callback import guard_tool
from ._context import google_adk_context
from ._plugin import guard_plugin

__all__ = [
    "guard_tool",
    "guard_plugin",
    "google_adk_context",
]
