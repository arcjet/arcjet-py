"""Shared ``before_tool_callback`` evaluation for LlmAgent and plugins.

ADK skips the tool when this callback returns a dict — including ``{}``.
``None`` is the only allow. A throw is a plugin / callback error, not
skip. HITL (``request_confirmation`` / ``require_confirmation`` /
``SecurityPlugin``) is not a policy gate and is never called.

:func:`guard_tool` returns the LlmAgent callback
``(tool, args, tool_context) -> None | dict``. :func:`guard_plugin`
installs the same evaluation on ``BasePlugin.before_tool_callback``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from typing import Any, Optional, Union, cast

from arcjet._errors import ArcjetMisconfiguration
from arcjet._logging import logger
from arcjet._metadata import Metadata

from .._checkpoint import (
    ResolvedInputs,
    _classify_decision,
    _emit_capture,
    _guard_async,
    _guard_sync,
    _outcome_for_completed_action,
    _resolve_correlation_id,
)
from .._context import _validated
from .._errors import ArcjetDeniedError, ArcjetUnavailableError, OnGuardError
from .._policy_input import PolicyInputMap
from .._registry import _awaitable
from .._rules import RuleWithInput
from ._context import google_adk_context
from ._denial import ArcjetDenialResult, deny_dict, payload_from_block
from ._import import _require_google_adk

ActionResolver = Union[str, Callable[[Mapping[str, Any]], str], None]
ActorResolver = Union[str, Callable[[Mapping[str, Any]], Optional[str]], None]
InputResolver = Union[
    PolicyInputMap,
    Callable[[Mapping[str, Any]], Optional[PolicyInputMap]],
    None,
]
RulesResolver = Union[
    Sequence[RuleWithInput],
    Callable[[Mapping[str, Any]], Sequence[RuleWithInput]],
]
MetadataResolver = Union[
    Metadata, Callable[[Mapping[str, Any]], Optional[Metadata]], None
]
SessionResolver = Union[str, Callable[[Mapping[str, Any]], Optional[str]], None]

#: Attribute a sibling wrap may put on a tool so this gate does not
#: evaluate the same call twice. An attribute rather than a registry of
#: ``id()`` values: CPython reuses the id of a collected object.
_GUARD_BRAND = "_arcjet_guarded"

_DEFAULT_ACTION = "tool.invoked"


@dataclass(frozen=True, slots=True)
class _CallbackConfig:
    guard: Any
    action: ActionResolver
    actor: ActorResolver
    inputs: InputResolver
    rules: RulesResolver
    metadata: MetadataResolver
    correlation_id: Optional[str]
    session_id: SessionResolver
    on_guard_error: OnGuardError


@dataclass(frozen=True, slots=True)
class BeforeToolVerdict:
    """What ``before_tool_callback`` should return. Unit tests call this
    without constructing a real ADK tool.
    """

    deny: bool
    payload: Optional[ArcjetDenialResult] = None


def _is_already_guarded(tool: Any) -> bool:
    return tool is not None and bool(getattr(tool, _GUARD_BRAND, False))


def _tool_name(tool: Any) -> str:
    name = getattr(tool, "name", None)
    if isinstance(name, str) and name:
        return name
    alt = getattr(tool, "tool_name", None)
    return alt if isinstance(alt, str) else ""


def _arguments(args: Any) -> Mapping[str, Any]:
    if isinstance(args, Mapping):
        return dict(args)
    return {}


def _tool_call(tool: Any, args: Any) -> dict[str, Any]:
    """What ``rules`` / ``actor`` / ``inputs`` / ``metadata`` see.

    JS ``GuardPluginCall`` is ``{toolName, input}``. Python adapters also
    put ``tool_name`` on the envelope so a per-tool rate limit can key on
    the name. ``tool_name`` is applied last so a tool argument of the same
    name cannot hide it.
    """
    parsed = _arguments(args)
    call: dict[str, Any] = {"input": parsed, **parsed}
    name = _tool_name(tool)
    if name:
        call["tool_name"] = name
    return call


def _resolve(source: Any, arguments: Mapping[str, Any]) -> Any:
    if source is None or not callable(source):
        return source
    return source(arguments)


def _prepared(
    actor: ActorResolver,
    inputs: InputResolver,
    arguments: Mapping[str, Any],
) -> ResolvedInputs:
    degraded: Optional[BaseException] = None
    resolved_actor: Optional[str] = None
    resolved_inputs: Optional[PolicyInputMap] = None
    try:
        resolved_actor = _resolve(actor, arguments)
    except Exception as exc:
        degraded = exc
    try:
        resolved_inputs = _resolve(inputs, arguments)
    except Exception as exc:
        degraded = degraded or exc
    return ResolvedInputs(
        actor=resolved_actor, inputs=resolved_inputs, degraded=degraded
    )


def _resolved_rules(
    rules: RulesResolver, arguments: Mapping[str, Any]
) -> Sequence[RuleWithInput]:
    if not callable(rules):
        return rules
    return cast(
        Callable[[Mapping[str, Any]], Sequence[RuleWithInput]],
        rules,
    )(arguments)


def _resolved_metadata(
    metadata: MetadataResolver, arguments: Mapping[str, Any]
) -> Optional[Metadata]:
    if callable(metadata):
        return cast(
            Callable[[Mapping[str, Any]], Optional[Metadata]],
            metadata,
        )(arguments)
    return metadata


def _resolved_session_id(
    session_id: SessionResolver, arguments: Mapping[str, Any]
) -> Optional[str]:
    if callable(session_id):
        return cast(
            Callable[[Mapping[str, Any]], Optional[str]],
            session_id,
        )(arguments)
    return session_id


def _resolve_action(config: _CallbackConfig, arguments: Mapping[str, Any]) -> str:
    action = config.action
    if action is None:
        return _DEFAULT_ACTION
    if callable(action):
        return cast(Callable[[Mapping[str, Any]], str], action)(arguments)
    if isinstance(action, str) and action:
        return action
    return _DEFAULT_ACTION


def _correlation(
    config: _CallbackConfig,
    tool_context: Any,
    arguments: Mapping[str, Any],
) -> Optional[str]:
    owned = _resolved_session_id(config.session_id, arguments)
    derived = google_adk_context(
        tool_context,
        correlation_id=config.correlation_id,
        session_id=owned,
    )
    return _resolve_correlation_id(derived.correlation_id)


def _merged_metadata(
    config: _CallbackConfig,
    tool: Any,
    tool_context: Any,
    arguments: Mapping[str, Any],
    extra: Optional[Metadata],
) -> Optional[Metadata]:
    owned = _resolved_session_id(config.session_id, arguments)
    derived = google_adk_context(
        tool_context,
        correlation_id=config.correlation_id,
        session_id=owned,
    )
    merged: dict[str, Any] = {}
    if derived.metadata:
        merged.update(derived.metadata)
    name = _tool_name(tool)
    if name and "google-adk.tool" not in merged:
        merged["google-adk.tool"] = name
    if extra:
        merged.update(extra)
    return merged or None


def _unavailable(action: str, cause: Optional[BaseException]) -> BaseException:
    return ArcjetUnavailableError(action, cause=cause)


async def _decide(
    guard: Any,
    *,
    action: str,
    correlation_id: Optional[str],
    metadata: Optional[Metadata],
    prepared: ResolvedInputs,
    rules: Sequence[RuleWithInput],
) -> Any:
    kwargs = {
        "rules": rules,
        "label": action,
        "metadata": metadata,
        "correlation_id": correlation_id,
        "actor": prepared.actor,
        "inputs": prepared.inputs,
    }
    if _awaitable(guard, "guard") is not None or guard is None:
        return await _guard_async(guard, **kwargs)
    return await asyncio.to_thread(partial(_guard_sync, guard, **kwargs))


def _looks_like_tool(tool: Any) -> bool:
    if tool is None:
        return False
    return bool(_tool_name(tool)) or hasattr(tool, "name") or hasattr(tool, "tool_name")


async def evaluate_before_tool(
    tool: Any,
    args: Any,
    tool_context: Any,
    config: _CallbackConfig,
) -> BeforeToolVerdict:
    """Evaluate policy for one tool call. Never raises an Arcjet error.

    A raise would leave the callback; PluginManager wraps it as a plugin
    error, which is a different path than skip. ``None`` allows. A dict
    skips. HITL APIs are never called.
    """
    if _is_already_guarded(tool):
        return BeforeToolVerdict(deny=False)
    if not _looks_like_tool(tool):
        return BeforeToolVerdict(deny=False)

    action = _DEFAULT_ACTION
    correlation_id = _resolve_correlation_id(None)
    metadata: Optional[Metadata] = None

    try:
        arguments = _tool_call(tool, args)
        action = _resolve_action(config, arguments)
        correlation_id = _correlation(config, tool_context, arguments)
        extra = _resolved_metadata(config.metadata, arguments)
        metadata = _merged_metadata(config, tool, tool_context, arguments, extra)
        prepared = _prepared(config.actor, config.inputs, arguments)
        rules = _resolved_rules(config.rules, arguments)
        decision = await _decide(
            config.guard,
            action=action,
            correlation_id=correlation_id,
            metadata=metadata,
            prepared=prepared,
            rules=rules,
        )
        failure = _classify_decision(
            decision,
            action=action,
            on_guard_error=config.on_guard_error,
            denied_error=ArcjetDeniedError,
            unavailable_error=_unavailable,
            degraded=prepared.degraded,
        )
    except Exception:
        if config.on_guard_error == "allow":
            logger.warning(
                "arcjet: policy for action %r could not be evaluated; proceeding "
                "because on_guard_error is 'allow'",
                action,
            )
            return BeforeToolVerdict(deny=False)
        _emit_capture(
            client=config.guard,
            action=action,
            outcome="unavailable",
            correlation_id=correlation_id,
            decision=None,
            metadata=metadata,
        )
        return BeforeToolVerdict(deny=True, payload=payload_from_block(None))

    if failure is not None:
        denied = getattr(decision, "conclusion", None) == "DENY"
        _emit_capture(
            client=config.guard,
            action=action,
            outcome="denied" if denied else "unavailable",
            correlation_id=correlation_id,
            decision=decision,
            metadata=metadata,
        )
        return BeforeToolVerdict(deny=True, payload=payload_from_block(decision))

    _emit_capture(
        client=config.guard,
        action=action,
        outcome=_outcome_for_completed_action(decision, degraded=prepared.degraded),
        correlation_id=correlation_id,
        decision=decision,
        metadata=metadata,
    )
    return BeforeToolVerdict(deny=False)


def verdict_result(verdict: BeforeToolVerdict) -> Optional[dict[str, Any]]:
    """``None`` to allow; a non-empty deny dict to skip. Never ``{}``."""
    if not verdict.deny:
        return None
    payload = (
        verdict.payload if verdict.payload is not None else payload_from_block(None)
    )
    return deny_dict(payload)


async def run_before_tool_callback(
    tool: Any,
    args: Any,
    tool_context: Any,
    config: _CallbackConfig,
) -> Optional[dict[str, Any]]:
    """Evaluate and map to the ADK skip-with-result contract. Never raises."""
    try:
        verdict = await evaluate_before_tool(tool, args, tool_context, config)
    except Exception:
        if config.on_guard_error == "allow":
            logger.warning(
                "arcjet: before_tool_callback for a Google ADK tool threw; "
                "the tool proceeds because on_guard_error is 'allow'"
            )
            return None
        return deny_dict(payload_from_block(None))
    return verdict_result(verdict)


def _owned_fallback(
    correlation_id: Optional[str],
    session_id: SessionResolver,
) -> Optional[str]:
    if correlation_id is not None:
        return correlation_id
    if isinstance(session_id, str):
        return session_id
    return None


def _validated_config(
    *,
    guard: Any,
    action: ActionResolver,
    actor: ActorResolver,
    inputs: InputResolver,
    rules: RulesResolver,
    metadata: MetadataResolver,
    correlation_id: Optional[str],
    session_id: SessionResolver,
    on_guard_error: OnGuardError,
) -> _CallbackConfig:
    if on_guard_error not in ("allow", "deny"):
        raise ArcjetMisconfiguration(
            f"on_guard_error must be 'allow' or 'deny', got {on_guard_error!r}. "
            f"It decides whether a call runs when policy could not be "
            f"evaluated, so there is no safe value to guess."
        )
    owned = _owned_fallback(correlation_id, session_id)
    if owned is not None:
        _validated(owned)
    _require_google_adk()
    return _CallbackConfig(
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


def guard_tool(
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
    """Build an ``LlmAgent.before_tool_callback`` that fails closed.

    Returns ``async (tool, args, tool_context) -> None | dict``. Assign it
    to ``LlmAgent(before_tool_callback=...)``.

    * ``None`` — allow; the original tool function runs.
    * a dict — skip; ADK uses the dict as the tool result. The original
      function does not run. The dict is the ``ArcjetDenialResult``
      envelope. Never ``{}``: ADK treats an empty mapping as skip too.

    The callback does not throw. A throw is a callback error, not skip.
    ``request_confirmation`` / ``require_confirmation`` / ADK
    ``SecurityPlugin`` are HITL, not this gate.

    Already-branded tools (``_arcjet_guarded``) are skipped so Guard is
    not double-called when a plugin is also installed.

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

    async def before_tool_callback(
        tool: Any,
        args: Any,
        tool_context: Any,
    ) -> Optional[dict[str, Any]]:
        return await run_before_tool_callback(tool, args, tool_context, config)

    return before_tool_callback
