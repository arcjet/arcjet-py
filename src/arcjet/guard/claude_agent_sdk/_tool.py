"""Authored ``@tool`` / ``SdkMcpTool`` wrap via a replaced ``.handler``.

The SDK invokes ``SdkMcpTool.handler`` from ``create_sdk_mcp_server``. On
DENY the original handler must not run. The deny is a returned MCP tool
result — ``create_sdk_mcp_server`` copies ``content`` and ``is_error`` and
drops ``structuredContent``, and an exception is swallowed into ``str(e)``.

This module therefore does **not** wrap ``can_use_tool`` as a policy gate.
An authored handler has no ``extra.session_id`` — pass ``session_id=``.
"""

from __future__ import annotations

import asyncio
import copy
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
from ._context import claude_agent_context
from ._denial import (
    ArcjetDenialResult,
    denial_tool_result,
    payload_from_block,
)
from ._import import load_sdk_mcp_tool

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

#: Attribute :func:`guard_tool` puts on the copy it returns, so a second wrap
#: of the same object does not evaluate the same call twice. An attribute
#: rather than a registry of ``id()`` values: CPython reuses the id of a
#: collected object, so an id-keyed registry starts skipping unrelated tools
#: once the wrapped tool is garbage collected.
_GUARD_BRAND = "_arcjet_guarded"


@dataclass(frozen=True, slots=True)
class _ToolConfig:
    guard: Any
    action: str
    actor: ActorResolver
    inputs: InputResolver
    rules: RulesResolver
    metadata: MetadataResolver
    session_id: Optional[str]
    on_guard_error: OnGuardError
    tool_name: str


@dataclass(frozen=True, slots=True)
class HandlerVerdict:
    """What the wrapped handler should return. Unit tests call this without
    constructing a real ``SdkMcpTool``.
    """

    deny: bool
    payload: Optional[ArcjetDenialResult] = None


def _arguments_from_handler(arguments: Any) -> Mapping[str, Any]:
    """The model-produced arguments, as the SDK handed the handler.

    The SDK validates against the tool schema and passes a dict. A
    non-mapping is an empty mapping — the same shape a policy with no
    resolver sees for a call with no args — rather than an exception that
    would skip Guard.
    """
    if isinstance(arguments, Mapping):
        return dict(arguments)
    return {}


def _resolve(source: Any, arguments: Mapping[str, Any]) -> Any:
    if source is None or not callable(source):
        return source
    return source(arguments)


def _prepared(config: _ToolConfig, arguments: Mapping[str, Any]) -> ResolvedInputs:
    """What the decision is made from; a failed resolver is reported."""
    degraded: Optional[BaseException] = None
    resolved_actor: Optional[str] = None
    resolved_inputs: Optional[PolicyInputMap] = None
    try:
        resolved_actor = _resolve(config.actor, arguments)
    except Exception as exc:
        degraded = exc
    try:
        resolved_inputs = _resolve(config.inputs, arguments)
    except Exception as exc:
        degraded = degraded or exc
    return ResolvedInputs(
        actor=resolved_actor, inputs=resolved_inputs, degraded=degraded
    )


def _resolved_rules(
    config: _ToolConfig, arguments: Mapping[str, Any]
) -> Sequence[RuleWithInput]:
    rules = config.rules
    if not callable(rules):
        return rules
    return cast(
        Callable[[Mapping[str, Any]], Sequence[RuleWithInput]],
        rules,
    )(arguments)


def _resolved_metadata(
    config: _ToolConfig, arguments: Mapping[str, Any]
) -> Optional[Metadata]:
    metadata = config.metadata
    if callable(metadata):
        return cast(
            Callable[[Mapping[str, Any]], Optional[Metadata]],
            metadata,
        )(arguments)
    return metadata


def _correlation(config: _ToolConfig) -> Optional[str]:
    """Caller-owned UUID from the wrap, then the enclosing sequence."""
    derived = claude_agent_context(session_id=config.session_id)
    return _resolve_correlation_id(derived.correlation_id)


def _merged_metadata(
    config: _ToolConfig, extra: Optional[Metadata]
) -> Optional[Metadata]:
    derived = claude_agent_context(session_id=config.session_id)
    merged: dict[str, Any] = {}
    if derived.metadata:
        merged.update(derived.metadata)
    if config.tool_name and "claude.tool" not in merged:
        merged["claude.tool"] = config.tool_name
    if extra:
        merged.update(extra)
    return merged or None


def _unavailable(action: str, cause: Optional[BaseException]) -> BaseException:
    return ArcjetUnavailableError(action, cause=cause)


async def _decide(
    config: _ToolConfig,
    *,
    action: str,
    correlation_id: Optional[str],
    metadata: Optional[Metadata],
    prepared: ResolvedInputs,
    rules: Sequence[RuleWithInput],
) -> Any:
    """Evaluate through the async client when there is one, else the sync one.

    Authored handlers are async. A blocking ``guard_sync()`` client is
    offloaded with ``asyncio.to_thread`` so the event loop is not wedged
    for the Guard round trip.
    """
    kwargs = {
        "rules": rules,
        "label": action,
        "metadata": metadata,
        "correlation_id": correlation_id,
        "actor": prepared.actor,
        "inputs": prepared.inputs,
    }
    if _awaitable(config.guard, "guard") is not None or config.guard is None:
        return await _guard_async(config.guard, **kwargs)
    return await asyncio.to_thread(partial(_guard_sync, config.guard, **kwargs))


async def evaluate_handler(arguments: Any, config: _ToolConfig) -> HandlerVerdict:
    """Evaluate policy for one authored tool call. Never raises an Arcjet error.

    A raise from this function would leave the handler, and the SDK would
    swallow it into ``str(e)``. The deny envelope is the only shape the
    model can read as a structured ``ArcjetDenialResult``.
    """
    action = config.action
    correlation_id = _resolve_correlation_id(None)
    metadata: Optional[Metadata] = None

    try:
        parsed = _arguments_from_handler(arguments)
        correlation_id = _correlation(config)
        extra = _resolved_metadata(config, parsed)
        metadata = _merged_metadata(config, extra)
        prepared = _prepared(config, parsed)
        rules = _resolved_rules(config, parsed)
        decision = await _decide(
            config,
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
            return HandlerVerdict(deny=False)
        _emit_capture(
            client=config.guard,
            action=action,
            outcome="unavailable",
            correlation_id=correlation_id,
            decision=None,
            metadata=metadata,
        )
        return HandlerVerdict(deny=True, payload=payload_from_block(action, None))

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
        return HandlerVerdict(deny=True, payload=payload_from_block(action, decision))

    _emit_capture(
        client=config.guard,
        action=action,
        outcome=_outcome_for_completed_action(decision, degraded=prepared.degraded),
        correlation_id=correlation_id,
        decision=decision,
        metadata=metadata,
    )
    return HandlerVerdict(deny=False)


def handler_denial_result(verdict: HandlerVerdict) -> dict[str, Any]:
    """The exact MCP tool result a DENY handler must return."""
    payload = (
        verdict.payload if verdict.payload is not None else payload_from_block("", None)
    )
    return denial_tool_result(payload)


def _is_already_guarded(tool: Any) -> bool:
    return bool(getattr(tool, _GUARD_BRAND, False))


def _copy_tool(tool: Any) -> Any:
    return copy.copy(tool)


def _wrap_handler(config: _ToolConfig, original: Any) -> Any:
    async def guarded_handler(arguments: Any) -> dict[str, Any]:
        # Never throw: the SDK reports ``str(e)`` and drops the envelope.
        try:
            verdict = await evaluate_handler(arguments, config)
        except Exception:
            if config.on_guard_error == "allow":
                logger.warning(
                    "arcjet: policy for action %r could not be evaluated; "
                    "proceeding because on_guard_error is 'allow'",
                    config.action,
                )
                return await original(arguments)
            return denial_tool_result(payload_from_block(config.action, None))
        if verdict.deny:
            return handler_denial_result(verdict)
        return await original(arguments)

    return guarded_handler


def guard_tool(
    *,
    guard: Any,
    tool: Any,
    action: str,
    actor: ActorResolver = None,
    inputs: InputResolver = None,
    rules: RulesResolver = (),
    metadata: MetadataResolver = None,
    session_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
) -> Any:
    """Wrap an authored ``SdkMcpTool`` so the handler never runs on DENY.

    Returns a copy of *tool* whose ``handler`` evaluates policy first. A
    ``DENY`` (or an unevaluated policy under the default
    ``on_guard_error="deny"``) returns exactly::

        {
            "content": [{"type": "text", "text": <json.dumps(ArcjetDenialResult)>}],
            "is_error": True,
        }

    The tool body does not run. Already-branded tools are returned unchanged
    so a second wrap cannot double-call Guard. ``structuredContent`` is not
    set: ``create_sdk_mcp_server`` drops it.

    ``can_use_tool`` is not a policy gate and is not wrapped.
    ``permissionDecision: "ask"`` is HITL, not deny.

    The authored handler has no ``extra.session_id``. Pass the same
    caller-owned UUID you give ``ClaudeAgentOptions.session_id`` as
    *session_id* (or *correlation_id*). Never minted.

    Args:
        guard: The Arcjet client. An async client is preferred; a blocking
            client is accepted.
        tool: A Claude Agent SDK ``SdkMcpTool`` from ``@tool``.
        action: Checkpoint label, e.g. ``"email.sent"``.
        actor: Who is acting, or a callable of the call's arguments.
        inputs: Policy inputs, or a callable of the call's arguments.
        rules: Local rules, or a callable of the call's arguments. Empty
            still contacts Guard.
        metadata: Capture metadata, or a callable of the call's arguments.
        session_id: Caller-owned UUID Sequence id. Preferred over
            *correlation_id*. Falls back to
            :func:`~arcjet.guard.arcjet_sequence`. Never minted.
        correlation_id: Alias of *session_id* for the same caller-owned
            id. Ignored when *session_id* is set.
        on_guard_error: ``"deny"`` (default) or ``"allow"``.

    Raises:
        ArcjetMisconfiguration: *on_guard_error* is not ``"allow"`` or
            ``"deny"``, or the installed ``claude-agent-sdk`` is below
            0.2.127.
        TypeError: *tool* is not an ``SdkMcpTool``.
        ValueError: *session_id* / *correlation_id* is not printable ASCII
            within 256 bytes.
        ImportError: the ``claude-agent-sdk`` extra is not installed.
    """
    if on_guard_error not in ("allow", "deny"):
        raise ArcjetMisconfiguration(
            f"on_guard_error must be 'allow' or 'deny', got {on_guard_error!r}. "
            f"It decides whether a call runs when policy could not be "
            f"evaluated, so there is no safe value to guess."
        )
    owned = session_id if session_id is not None else correlation_id
    if owned is not None:
        _validated(owned)
    sdk_mcp_tool = load_sdk_mcp_tool()
    if not isinstance(tool, sdk_mcp_tool):
        raise TypeError(
            f"guard_tool() wraps a Claude Agent SDK SdkMcpTool, got "
            f"{type(tool).__name__}"
        )
    if _is_already_guarded(tool):
        return tool

    guarded = _copy_tool(tool)
    config = _ToolConfig(
        guard=guard,
        action=action,
        actor=actor,
        inputs=inputs,
        rules=rules,
        metadata=metadata,
        session_id=owned,
        on_guard_error=on_guard_error,
        tool_name=getattr(tool, "name", "") or "",
    )
    original = getattr(tool, "handler", None)
    if not callable(original):
        raise TypeError(
            "guard_tool() wraps an SdkMcpTool with a callable handler, got "
            f"{type(original).__name__}"
        )
    guarded.handler = _wrap_handler(config, original)
    # Only the copy is branded. Branding the original as well would make a
    # later wrap of the unwrapped tool skip it, which is a fail-open.
    object.__setattr__(guarded, _GUARD_BRAND, True)
    return guarded
