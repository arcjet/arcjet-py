"""Optional OpenAI Agents tool-call integration.

Install ``arcjet[openai-agents]`` to use this module. Core Guard clients do
not import OpenAI Agents, and this package does not import
:mod:`arcjet.guard.langchain` or :mod:`arcjet.guard.crewai`.

Two names:

* :func:`guard_tool` — wrap an authored ``FunctionTool`` so invoke never
  runs on DENY. The gate is a prepended ``ToolInputGuardrail`` that
  ``reject_content``s a JSON ``ArcjetDenialResult``. Official: input tool
  guardrails run before invoke and can skip the call.
* :func:`openai_agents_context` — read a caller-owned
  ``correlation_id`` / ``session_id`` / ``conversation_id`` / ``group_id``
  off the run context, or the enclosing
  :func:`~arcjet.guard.arcjet_sequence`. Never mints. Never reads
  ``trace_id``. Never constructs ``OpenAIConversationsSession()``.

There is no inbound helper and no approval helper. Screen user text with
the core :func:`~arcjet.guard.guard` / :func:`~arcjet.guard.guard_sync`
call before ``Runner.run``. ``protect()`` / the request path is fail-open —
check :meth:`~arcjet.guard.Decision.has_failed_open`. ``needs_approval`` is
HITL, not a policy gate. ``pre_approval_tool_input_guardrails=True`` is an
application opt-in only; this module does not set it.

Hosted tools, MCP, Computer/Shell/ApplyPatch, handoffs, and
``Agent.as_tool()`` are not on the authored ``FunctionTool`` path.

See https://docs.arcjet.com/guards/openai-agents-py/
"""

from __future__ import annotations

from ._context import openai_agents_context
from ._tool import guard_tool

__all__ = [
    "guard_tool",
    "openai_agents_context",
]
