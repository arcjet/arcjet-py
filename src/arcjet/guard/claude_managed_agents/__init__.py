"""Optional Claude Managed Agents (hosted REST+SSE) integration.

Install ``arcjet[claude-managed-agents]`` to use this module. Core Guard
clients do not import ``anthropic``, and this package does not import
:mod:`arcjet.guard.langchain`, :mod:`arcjet.guard.crewai`,
:mod:`arcjet.guard.openai_agents`, or
:mod:`arcjet.guard.claude_agent_sdk`.

This is **not** the Claude Agent SDK extra. There is no PreToolUse,
no ``guard_tool``, and no ``guard_inbound``. Anthropic runs the tool
loop (beta ``managed-agents-2026-04-01``).

Three names:

* :func:`guard_custom_tool` — on ``agent.custom_tool_use``, run Guard
  **before** the app executes. On DENY the original does not run; the
  helper sends ``user.custom_tool_result`` with error text via the real
  events API (``is_error`` is on that schema). Pass ``tool=`` to wrap a
  self-hosted ``EnvironmentWorker`` / ``@beta_tool`` ``call`` (what
  ``SessionToolRunner`` invokes). A worker deny raises ``ToolError`` so
  the runner posts ``is_error=True``. The CLI worker cannot register
  custom tools.
* :func:`guard_events` — inbound: gate ``user.message`` /
  ``initial_events`` **before** ``sessions.events.send`` (or
  ``sessions.create(..., initial_events=)``). Always returns an async
  callable. There is no ``guard_inbound``.
* :func:`claude_managed_agents_context` — read a caller-owned
  ``correlation_id`` / ``session_id``. Never mints. Never treats
  Anthropic session / event ids as if we created them. Never reads
  ``trace_id``.

Default ``permission_policy: always_allow`` **cannot** be gated —
Anthropic-cloud bash / read / write run before any customer hook.
``web_search`` / ``web_fetch`` always run on Anthropic. MCP: Anthropic
is the client; customer-side Guard is on custom tools and MCP servers
**they** host. HITL ``always_ask`` / ``user.tool_confirmation`` is not
policy.

``protect()`` / the request path is fail-open — check
:meth:`~arcjet.guard.Decision.has_failed_open`. These helpers are
fail-closed (default ``on_guard_error="deny"``).

See https://docs.arcjet.com/guards/claude-managed-agents/
"""

from __future__ import annotations

from ._context import claude_managed_agents_context
from ._events import guard_events
from ._tool import guard_custom_tool

__all__ = [
    "guard_custom_tool",
    "guard_events",
    "claude_managed_agents_context",
]
