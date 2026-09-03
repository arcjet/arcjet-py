"""Runner ``BasePlugin`` whose ``before_tool_callback`` is the tool-call gate.

Put Arcjet first in ``Runner(plugins=[...])``. PluginManager is first-win:
the first plugin that returns a non-``None`` value short-circuits remaining
plugins and the agent callback. If another plugin returns a dict first,
Guard never runs.

DENY is a dictionary (``ArcjetDenialResult``). ADK treats a returned dict
as skip: the original tool function does not run and the model sees the
payload. ``None`` lets the tool execute. This helper does **not** throw
from the callback — PluginManager wraps a throw as a plugin error.

On Guard error this helper fail-closes: it always returns a deny dict,
never ``None`` (unless ``on_guard_error="allow"``), and never ``{}``.

There is no inbound hook. ``on_user_message_callback`` /
``before_model_callback`` inherit the BasePlugin no-ops so a preceding
``guard()`` does not double-call. HITL is not this adapter.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from .._errors import OnGuardError
from ._callback import (
    ActionResolver,
    ActorResolver,
    InputResolver,
    MetadataResolver,
    RulesResolver,
    SessionResolver,
    _CallbackConfig,
    _validated_config,
    run_before_tool_callback,
)
from ._import import try_load_base_plugin

_plugin_seq = 0


def _plugin_name() -> str:
    """A registry key, not a secret.

    ``PluginManager`` rejects two plugins that share a name. The counter
    alone is not enough because a second copy of this module starts
    counting at one again.
    """
    global _plugin_seq
    _plugin_seq += 1
    return f"arcjet-guard-{_plugin_seq}-{uuid.uuid4().hex[:8]}"


class _DuckPlugin:
    """Structural plugin used when ``google-adk`` is not installed.

    ``PluginManager`` calls methods by name and does not require
    ``isinstance(BasePlugin)``. Unit tests call ``before_tool_callback``
    directly. When the extra is present, :func:`guard_plugin` subclasses
    ``BasePlugin`` instead so every lifecycle method exists.
    """

    def __init__(self, config: _CallbackConfig) -> None:
        self.name = _plugin_name()
        self._config = config

    async def before_tool_callback(
        self,
        *,
        tool: Any,
        tool_args: Any,
        tool_context: Any,
    ) -> Optional[dict[str, Any]]:
        return await run_before_tool_callback(
            tool, tool_args, tool_context, self._config
        )


def guard_plugin(
    *,
    guard: Any = None,
    action: ActionResolver = None,
    actor: ActorResolver = None,
    inputs: InputResolver = None,
    rules: RulesResolver = (),
    metadata: MetadataResolver = None,
    correlation_id: Optional[str] = None,
    session_id: SessionResolver = None,
    on_guard_error: OnGuardError = "deny",
) -> Any:
    """Build a Runner ``BasePlugin`` that fails closed.

    Returns a plugin for ``Runner(plugins=[...])`` or
    ``InMemoryRunner(plugins=[...])``. Put it first. Policy sits on
    ``before_tool_callback`` only.

    * A deny dict skips the tool. The original function does not run.
    * ``None`` allows the tool to run.
    * Never ``{}`` — ADK treats an empty mapping as skip too.
    * Never throws. Fail-closed always returns the deny dict on error.

    ``request_confirmation`` / ``require_confirmation`` / ADK
    ``SecurityPlugin`` are HITL, not this gate.

    Args:
        guard: The Arcjet client. An async client is preferred; a blocking
            client is accepted.
        action: Checkpoint label, or a callable of the tool-call envelope
            (``tool_name`` plus ``input``). Defaults to ``"tool.invoked"``.
        actor: Who is acting, or a callable of that envelope.
        inputs: Policy inputs, or a callable of that envelope.
        rules: Local rules, or a callable of that envelope. Empty still
            contacts Guard.
        metadata: Capture metadata, or a callable of that envelope.
        correlation_id: Caller-owned Sequence id fallback. Never minted.
        session_id: Alias fallback, or a callable of the envelope. Ignored
            as a static fallback when *correlation_id* is set. Preferred
            over durable session ``state``.
        on_guard_error: ``"deny"`` (default) or ``"allow"``.

    Raises:
        ArcjetMisconfiguration: *on_guard_error* is not ``"allow"`` or
            ``"deny"``, or the installed ``google-adk`` is below 2.0.0.
        ValueError: a fallback id is not printable ASCII within 256 bytes.
    """
    config = _validated_config(
        guard=guard,
        action=action,
        actor=actor,
        inputs=inputs,
        rules=rules,
        metadata=metadata,
        correlation_id=correlation_id,
        session_id=session_id,
        on_guard_error=on_guard_error,
    )
    base = try_load_base_plugin()
    if base is None:
        return _DuckPlugin(config)

    class ArcjetGuardPlugin(base):
        def __init__(self) -> None:
            super().__init__(name=_plugin_name())
            self._config = config

        async def before_tool_callback(
            self,
            *,
            tool: Any,
            tool_args: Any,
            tool_context: Any,
        ) -> Optional[dict[str, Any]]:
            return await run_before_tool_callback(
                tool, tool_args, tool_context, self._config
            )

    return ArcjetGuardPlugin()
