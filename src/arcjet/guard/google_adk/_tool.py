"""``LlmAgent.before_tool_callback`` — not a ``FunctionTool`` wrap.

ADK invokes ``before_tool_callback(tool, args, tool_context)`` by
keyword. Returning a dict skips ``run_async`` and that dict is the tool
result. Returning ``None`` executes the tool. Returning ``{}`` is falsy
in the callback chain and would let the tool run.

This helper returns that callback. It does not wrap ``FunctionTool``.
It does not call ``request_confirmation``. Do not also attach
:func:`~arcjet.guard.google_adk.guard_plugin` to the same tools.
"""

from __future__ import annotations

from typing import Any, Optional

from arcjet._errors import ArcjetMisconfiguration

from .._context import _validated
from .._errors import OnGuardError
from .._label import assert_valid_action
from ._callback import (
    ActionResolver,
    ActorResolver,
    BeforeToolVerdict,
    CallbackConfig,
    InputResolver,
    MetadataResolver,
    RulesResolver,
    callback_result,
    evaluate_before_tool,
)
from ._denial import payload_from_block
from ._import import _require_google_adk


def guard_tool(
    *,
    guard: Any,
    action: ActionResolver,
    actor: ActorResolver = None,
    inputs: InputResolver = None,
    rules: RulesResolver = (),
    metadata: MetadataResolver = None,
    correlation_id: Optional[str] = None,
    session_id: Optional[str] = None,
    conversation_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
) -> Any:
    """Return an ``LlmAgent.before_tool_callback`` that fails closed.

    Attach the result as ``LlmAgent(before_tool_callback=...)``. A
    ``DENY`` (or an unevaluated policy under the default
    ``on_guard_error="deny"``) returns a skip dict with
    ``arcjetDenied``. The original tool does not run. ``None`` allows
    the call. The callback never returns ``{}`` and never throws.

    Parameter names on the returned function are ``tool``, ``args``,
    ``tool_context`` — ADK passes them by keyword.

    This is not a ``FunctionTool`` wrap. ``request_confirmation`` /
    ``require_confirmation`` are HITL and are not called. Do not also
    put :func:`~arcjet.guard.google_adk.guard_plugin` on the same
    tools — the plugin runs first and a second gate double-calls Guard.

    Tool arguments are never a correlation source. Prefer putting the
    id on application-owned ``ToolContext.state``, or pass
    *session_id* / *correlation_id* here, or use
    :func:`~arcjet.guard.arcjet_sequence`. Never minted. Never read
    from ``session.id`` / ``invocation_id`` / ``trace_id``.

    *actor* and *inputs* are optional. Omit them and a remote policy
    that requires those values never fires. A resolver that throws is
    reported as degraded and fail-closes. Take *actor* from
    authenticated server context, never from a model-produced argument.

    Args:
        guard: The Arcjet client. An async client is preferred; a blocking
            client is accepted.
        action: Checkpoint label, e.g. ``"email.sent"``, or a callable of
            the tool-call envelope (arguments plus ``tool_name``).
        actor: Who is acting, or a callable of that envelope.
        inputs: Policy inputs, or a callable of that envelope.
        rules: Local rules, or a callable of that envelope. Empty
            still contacts Guard.
        metadata: Capture metadata, or a callable of that envelope.
        correlation_id: Caller-owned Sequence id. Preferred over
            *session_id* / *conversation_id*.
        session_id: Alias fallback when the application calls the id a
            session. Ignored when *correlation_id* is set.
        conversation_id: Alias fallback when the application calls the
            id a conversation. Ignored when *correlation_id* or
            *session_id* is set.
        on_guard_error: ``"deny"`` (default) or ``"allow"``.

    Raises:
        ArcjetMisconfiguration: *on_guard_error* is not ``"allow"`` or
            ``"deny"``, or the installed ``google-adk`` is below 2.0.0.
        ArcjetInvalidLabelError: *action* is a string the service cannot
            match.
        ValueError: a fallback id is not printable ASCII within 256 bytes.
    """
    if isinstance(action, str):
        assert_valid_action(action, "guard_tool")
    elif action is None or not callable(action):
        raise ArcjetMisconfiguration(
            "guard_tool() action must be a label string or a callable of "
            "the tool-call envelope."
        )
    if on_guard_error not in ("allow", "deny"):
        raise ArcjetMisconfiguration(
            f"on_guard_error must be 'allow' or 'deny', got {on_guard_error!r}. "
            f"It decides whether a call runs when policy could not be "
            f"evaluated, so there is no safe value to guess."
        )
    owned = correlation_id
    if owned is None:
        owned = session_id
    if owned is None:
        owned = conversation_id
    if owned is not None:
        _validated(owned)
    _require_google_adk()

    config = CallbackConfig(
        guard=guard,
        action=action,
        actor=actor,
        inputs=inputs,
        rules=rules,
        metadata=metadata,
        correlation_id=owned,
        on_guard_error=on_guard_error,
        exclude=frozenset(),
    )

    async def before_tool_callback(
        tool: Any,
        args: Any,
        tool_context: Any,
    ) -> Optional[dict[str, Any]]:
        try:
            verdict = await evaluate_before_tool(
                tool=tool,
                args=args,
                tool_context=tool_context,
                config=config,
            )
        except Exception:
            if config.on_guard_error == "allow":
                return None
            verdict = BeforeToolVerdict(deny=True, payload=payload_from_block(None))
        return callback_result(verdict)

    return before_tool_callback
