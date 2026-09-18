"""Runner ``BasePlugin`` — Arcjet first; do not stack with :func:`guard_tool`.

ADK runs plugin ``before_tool_callback`` before agent callbacks. The
first truthy dict wins and skips the tool. Put this plugin first on
``Runner(..., plugins=[...])``. Do not also attach
:func:`~arcjet.guard.google_adk.guard_tool` to the same tools.

Deny is a skip dict with ``arcjetDenied``. ``None`` allows. Never
``{}``. Never throw. ``request_confirmation`` is HITL and is not called.
"""

from __future__ import annotations

from collections.abc import Sequence
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
from ._import import load_base_plugin

_PLUGIN_NAME = "arcjet.guard.google_adk"


def _exclude_names(exclude: Sequence[str] | None) -> frozenset[str]:
    if exclude is None:
        return frozenset()
    names: list[str] = []
    for entry in exclude:
        if not isinstance(entry, str) or not entry:
            raise TypeError(
                "guard_plugin() exclude entries must be non-empty tool name "
                f"strings, got {type(entry).__name__}"
            )
        names.append(entry)
    return frozenset(names)


def guard_plugin(
    *,
    guard: Any,
    action: ActionResolver = None,
    actor: ActorResolver = None,
    inputs: InputResolver = None,
    rules: RulesResolver = (),
    metadata: MetadataResolver = None,
    correlation_id: Optional[str] = None,
    session_id: Optional[str] = None,
    conversation_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
    exclude: Sequence[str] | None = None,
) -> Any:
    """Return a Runner ``BasePlugin`` that fails closed.

    Put the result first on ``App(..., plugins=[...])`` (ADK 2.9+;
    ``Runner(..., plugins=[...])`` still works and is deprecated). A ``DENY`` (or an
    unevaluated policy under the default ``on_guard_error="deny"``)
    returns a skip dict with ``arcjetDenied``. The original tool does
    not run. ``None`` allows the call. The plugin never returns ``{}``
    and never throws.

    Plugin callback parameter names are ``tool``, ``tool_args``,
    ``tool_context`` — ADK passes them by keyword.

    Do not also attach :func:`~arcjet.guard.google_adk.guard_tool` to
    the same tools. Plugins run first; a second gate double-calls
    Guard. List those tool names in *exclude* only if you must stack.

    *action* defaults to ``"{tool_name}.invoked"``. *actor* and
    *inputs* are optional — omit them and a remote policy that requires
    those values never fires. A resolver that throws is reported as
    degraded and fail-closes. Take *actor* from authenticated server
    context, never from a model-produced argument.

    ``request_confirmation`` / ``require_confirmation`` are HITL and
    are not called. ``SecurityPlugin`` is not this gate.

    Args:
        guard: The Arcjet client. An async client is preferred; a blocking
            client is accepted.
        action: Checkpoint label, or a callable of the tool-call
            envelope. Defaults to ``"{tool_name}.invoked"``.
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
        exclude: Tool names already gated by ``guard_tool``. Skip those
            on the plugin path so Guard is not called twice.

    Raises:
        ArcjetMisconfiguration: *on_guard_error* is not ``"allow"`` or
            ``"deny"``, or the installed ``google-adk`` is below 2.0.0.
        ArcjetInvalidLabelError: *action* is a string the service cannot
            match.
        TypeError: an *exclude* entry is not a non-empty string.
        ValueError: a fallback id is not printable ASCII within 256 bytes.
        ImportError: the ``google-adk`` extra is not installed.
    """
    if isinstance(action, str):
        assert_valid_action(action, "guard_plugin")
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

    config = CallbackConfig(
        guard=guard,
        action=action,
        actor=actor,
        inputs=inputs,
        rules=rules,
        metadata=metadata,
        correlation_id=owned,
        on_guard_error=on_guard_error,
        exclude=_exclude_names(exclude),
    )

    base = load_base_plugin()

    class ArcjetGuardPlugin(base):
        def __init__(self) -> None:
            super().__init__(name=_PLUGIN_NAME)
            self._config = config

        async def before_tool_callback(
            self,
            *,
            tool: Any,
            tool_args: Any,
            tool_context: Any,
        ) -> Optional[dict[str, Any]]:
            try:
                verdict = await evaluate_before_tool(
                    tool=tool,
                    args=tool_args,
                    tool_context=tool_context,
                    config=self._config,
                )
            except Exception:
                if self._config.on_guard_error == "allow":
                    return None
                verdict = BeforeToolVerdict(deny=True, payload=payload_from_block(None))
            return callback_result(verdict)

    return ArcjetGuardPlugin()
