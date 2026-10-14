"""Optional Claude Agent SDK tool-call and inbound integration.

Install ``arcjet[claude-agent-sdk]`` to use this module. Core Guard clients
do not import the Claude Agent SDK, and this package does not import
:mod:`arcjet.guard.langchain`, :mod:`arcjet.guard.crewai`, or
:mod:`arcjet.guard.openai_agents`.

The names:

* :func:`guard_tool` — wrap an authored ``@tool`` / ``SdkMcpTool`` so the
  handler never runs on DENY, and with ``result_rules=`` screen what it
  returns. The deny is an MCP tool result
  ``{"content": [{"type": "text", "text": <json>}], "is_error": True}``.
  Do not throw (the SDK swallows into ``str(e)``). Do not set
  ``structuredContent`` (``create_sdk_mcp_server`` drops it).
* :func:`guard_hooks` — ``PreToolUse`` ``permissionDecision: "deny"`` for
  unwrapped built-ins / MCP, ``PostToolUse`` capture
  (``claude.phase: after``) and, with ``tool_results=``, a screen of every
  tool's result, and ``UserPromptSubmit`` ``{"decision": "block"}`` when
  ``inbound=`` is set. List ``guard_tool`` wrappers in ``exclude`` as
  ``{"server": ..., "name": ...}`` so they are not double-gated under the
  ``mcp__{server}__{name}`` name. ``exclude`` does not skip PostToolUse.
  ``actor=`` / ``inputs=`` do not register a tool hook by themselves; pass
  ``tools=True`` for the default ``"{tool_name}.invoked"`` gate.
* :data:`REPLACEABLE_BUILTIN_TOOLS` and :func:`can_replace_result` — the
  tools whose denied result ``tool_results=`` replaces. A denied result
  from any other tool stops the run, so keep those tools out of
  ``allowed_tools`` when that matters.
* :func:`claude_agent_context` — read a caller-owned ``session_id`` from
  hook input or a policy fallback. Never mints. Never reads ``trace_id``.
  An authored handler has no ``extra.session_id`` — use
  ``session_id=`` on the wrap.

There is no ``guard_inbound`` helper and no ``guard_can_use_tool``.
``can_use_tool`` is ask-only HITL, not a policy gate.
``permissionDecision: "ask"`` is HITL, not deny.

``protect()`` / the request path is fail-open — check
:meth:`~arcjet.guard.Decision.has_failed_open`. These helpers are
fail-closed (default ``on_guard_error="deny"``).

See https://docs.arcjet.com/guards/claude-agent-sdk-py/
"""

from __future__ import annotations

from ._context import claude_agent_context
from ._hooks import guard_hooks
from ._tool import guard_tool
from ._tool_results import REPLACEABLE_BUILTIN_TOOLS, can_replace_result

__all__ = [
    "guard_tool",
    "guard_hooks",
    "claude_agent_context",
    "REPLACEABLE_BUILTIN_TOOLS",
    "can_replace_result",
]
