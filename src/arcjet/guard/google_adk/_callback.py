"""Shared before-tool evaluation for :func:`guard_tool` and :func:`guard_plugin`.

Both surfaces return the same skip dict on DENY and ``None`` on allow.
They never return ``{}``. They never throw to signal a denial.
``request_confirmation`` is HITL and is not called.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from typing import Any, Optional, Union, cast

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
from .._errors import ArcjetDeniedError, ArcjetUnavailableError, OnGuardError
from .._policy_input import PolicyInputMap
from .._registry import _awaitable
from .._rules import RuleWithInput
from ._context import google_adk_context
from ._denial import ArcjetDenialResult, payload_from_block, skip_dict

ActorResolver = Union[str, Callable[[Mapping[str, Any]], Optional[str]], None]
InputResolver = Union[
    PolicyInputMap,
    Callable[[Mapping[str, Any]], Optional[PolicyInputMap]],
    None,
]
ActionResolver = Union[str, Callable[[Mapping[str, Any]], str], None]
RulesResolver = Union[
    Sequence[RuleWithInput],
    Callable[[Mapping[str, Any]], Sequence[RuleWithInput]],
]
MetadataResolver = Union[
    Metadata, Callable[[Mapping[str, Any]], Optional[Metadata]], None
]


@dataclass(frozen=True, slots=True)
class CallbackConfig:
    """What one before-tool evaluation is made from."""

    guard: Any
    action: ActionResolver
    actor: ActorResolver
    inputs: InputResolver
    rules: RulesResolver
    metadata: MetadataResolver
    correlation_id: Optional[str]
    on_guard_error: OnGuardError
    exclude: frozenset[str]


@dataclass(frozen=True, slots=True)
class BeforeToolVerdict:
    """What the callback / plugin should return. Unit tests call this
    without constructing a real ADK callback.
    """

    deny: bool
    payload: Optional[ArcjetDenialResult] = None


def tool_name(tool: Any) -> str:
    name = getattr(tool, "name", None)
    return name if isinstance(name, str) and name else ""


def arguments_from_tool(args: Any) -> Mapping[str, Any]:
    """The model-produced arguments, as ADK handed the callback.

    A non-mapping is an empty mapping — the same shape a policy with no
    resolver sees for a call with no args — rather than an exception that
    would skip Guard.
    """
    if isinstance(args, Mapping):
        return dict(args)
    return {}


def tool_call(tool: Any, args: Any) -> dict[str, Any]:
    """What ``rules`` / ``actor`` / ``inputs`` / ``metadata`` / ``action`` see.

    The model-produced arguments plus ``tool_name``, so a per-tool rate
    limit can key on the name. ``tool_name`` is applied last so a tool
    argument of the same name cannot hide the callback's name.
    """
    call = dict(arguments_from_tool(args))
    name = tool_name(tool)
    if name:
        call["tool_name"] = name
    return call


def default_action(call: Mapping[str, Any]) -> str:
    """``"{tool_name}.invoked"``, or ``"tool.invoked"`` when the name is empty."""
    name = call.get("tool_name")
    if isinstance(name, str) and name:
        return f"{name}.invoked"
    return "tool.invoked"


def _resolve(source: Any, arguments: Mapping[str, Any]) -> Any:
    if source is None or not callable(source):
        return source
    return source(arguments)


def prepared_inputs(
    actor: ActorResolver, inputs: InputResolver, arguments: Mapping[str, Any]
) -> ResolvedInputs:
    """What the decision is made from; a failed resolver is reported.

    Reported rather than raised so Guard still sees the call and
    ``on_guard_error`` decides whether a partly-judged call may run.
    Omitting both leaves ``actor`` / ``inputs`` unset — a remote policy
    that requires them then never fires.
    """
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


def _resolved_action(config: CallbackConfig, arguments: Mapping[str, Any]) -> str:
    action = config.action
    if action is None:
        return default_action(arguments)
    if not callable(action):
        return action
    return cast(Callable[[Mapping[str, Any]], str], action)(arguments)


def _resolved_rules(
    config: CallbackConfig, arguments: Mapping[str, Any]
) -> Sequence[RuleWithInput]:
    rules = config.rules
    if not callable(rules):
        return rules
    return cast(
        Callable[[Mapping[str, Any]], Sequence[RuleWithInput]],
        rules,
    )(arguments)


def _resolved_metadata(
    config: CallbackConfig, arguments: Mapping[str, Any]
) -> Optional[Metadata]:
    metadata = config.metadata
    if callable(metadata):
        return cast(
            Callable[[Mapping[str, Any]], Optional[Metadata]],
            metadata,
        )(arguments)
    return metadata


def _caller_owned_source(tool_context: Any) -> Any:
    """What :func:`google_adk_context` may read.

    Application-owned ``state`` is a source. ``session.id`` /
    ``toolContext.sessionId`` / ``invocation_id`` are not — the helper
    refuses those even if *tool_context* itself is passed.
    """
    if tool_context is None:
        return None
    state = getattr(tool_context, "state", None)
    if isinstance(state, Mapping):
        return state
    if isinstance(tool_context, Mapping):
        return tool_context
    return tool_context


def _correlation(config: CallbackConfig, tool_context: Any) -> Optional[str]:
    """Caller-owned id from state / wrap-time fallback / the sequence.

    Tool arguments are never a correlation source — the model controls
    those. ADK-generated session / invocation ids are never a source.
    """
    derived = google_adk_context(
        _caller_owned_source(tool_context),
        correlation_id=config.correlation_id,
    )
    return _resolve_correlation_id(derived.correlation_id)


def _merged_metadata(
    config: CallbackConfig,
    *,
    tool: Any,
    tool_context: Any,
    extra: Optional[Metadata],
) -> Optional[Metadata]:
    derived = google_adk_context(
        _caller_owned_source(tool_context),
        correlation_id=config.correlation_id,
    )
    merged: dict[str, Any] = {}
    if derived.metadata:
        merged.update(derived.metadata)
    name = tool_name(tool)
    if name and "google-adk.tool" not in merged:
        merged["google-adk.tool"] = name
    if extra:
        merged.update(extra)
    return merged or None


def _unavailable(action: str, cause: Optional[BaseException]) -> BaseException:
    return ArcjetUnavailableError(action, cause=cause)


async def _decide(
    config: CallbackConfig,
    *,
    action: str,
    correlation_id: Optional[str],
    metadata: Optional[Metadata],
    prepared: ResolvedInputs,
    rules: Sequence[RuleWithInput],
) -> Any:
    """Evaluate through the async client when there is one, else the sync one.

    ADK callbacks are async. A blocking ``guard_sync()`` client is
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


async def evaluate_before_tool(
    *,
    tool: Any,
    args: Any,
    tool_context: Any,
    config: CallbackConfig,
) -> BeforeToolVerdict:
    """Evaluate policy for one tool call. Never raises an Arcjet error.

    A raise from this function would leave the ADK callback, which is the
    wrong envelope. A deny is a skip dict; allow is ``None``.
    """
    name = tool_name(tool)
    if name and name in config.exclude:
        return BeforeToolVerdict(deny=False)

    action = "tool.invoked"
    correlation_id = _resolve_correlation_id(None)
    metadata: Optional[Metadata] = None

    try:
        call = tool_call(tool, args)
        action = _resolved_action(config, call)
        correlation_id = _correlation(config, tool_context)
        extra = _resolved_metadata(config, call)
        metadata = _merged_metadata(
            config, tool=tool, tool_context=tool_context, extra=extra
        )
        prepared = prepared_inputs(config.actor, config.inputs, call)
        rules = _resolved_rules(config, call)
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


def callback_result(verdict: BeforeToolVerdict) -> Optional[dict[str, Any]]:
    """``None`` allows the tool. A truthy skip dict skips it. Never ``{}``."""
    if not verdict.deny:
        return None
    payload = (
        verdict.payload if verdict.payload is not None else payload_from_block(None)
    )
    return skip_dict(payload)
