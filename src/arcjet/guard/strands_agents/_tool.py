"""Authored ``@tool`` / ``DecoratedFunctionTool`` wrap via a replaced ``_tool_func``.

The SDK invokes ``DecoratedFunctionTool._tool_func`` from ``stream()`` and
from ``__call__``. On DENY the original handler must not run. The deny is a
returned ``ArcjetDenialResult`` dict — ``_wrap_tool_result`` JSON-serializes
any other mapping into a success tool-result text block, and an exception
is swallowed into ``Error: {Type} - {message}``.

This module therefore does **not** wrap ``event.interrupt()`` as a policy
gate. HITL is not the Arcjet gate.
"""

from __future__ import annotations

import asyncio
import copy
import inspect
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
from ._context import strands_agent_context
from ._denial import (
    ArcjetDenialResult,
    payload_from_block,
)
from ._import import load_decorated_function_tool

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
#: of the same object does not evaluate the same call twice, and
#: :func:`guard_hooks` can skip the branded tool. An attribute rather than a
#: registry of ``id()`` values: CPython reuses the id of a collected object,
#: so an id-keyed registry starts skipping unrelated tools once the wrapped
#: tool is garbage collected.
_GUARD_BRAND = "_arcjet_guarded"


@dataclass(frozen=True, slots=True)
class _ToolConfig:
    guard: Any
    action: str
    actor: ActorResolver
    inputs: InputResolver
    rules: RulesResolver
    metadata: MetadataResolver
    correlation_id: Optional[str]
    on_guard_error: OnGuardError
    tool_name: str


@dataclass(frozen=True, slots=True)
class HandlerVerdict:
    """What the wrapped handler should return. Unit tests call this without
    constructing a real ``DecoratedFunctionTool``.
    """

    deny: bool
    payload: Optional[ArcjetDenialResult] = None


def _arguments_from_handler(arguments: Any) -> Mapping[str, Any]:
    """The model-produced arguments, as the SDK handed the handler.

    ``stream()`` validates against the tool schema and passes kwargs. A
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


def _correlation(config: _ToolConfig, arguments: Mapping[str, Any]) -> Optional[str]:
    """Caller-owned id from the wrap / tool kwargs, then the enclosing sequence."""
    derived = strands_agent_context(arguments, correlation_id=config.correlation_id)
    return _resolve_correlation_id(derived.correlation_id)


def _merged_metadata(
    config: _ToolConfig, arguments: Mapping[str, Any], extra: Optional[Metadata]
) -> Optional[Metadata]:
    derived = strands_agent_context(arguments, correlation_id=config.correlation_id)
    merged: dict[str, Any] = {}
    if derived.metadata:
        merged.update(derived.metadata)
    if config.tool_name and "strands.tool" not in merged:
        merged["strands.tool"] = config.tool_name
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

    Authored handlers may be sync or async. A blocking ``guard_sync()``
    client is offloaded with ``asyncio.to_thread`` so the event loop is not
    wedged for the Guard round trip.
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
    swallow it into ``Error: {Type} - {message}``. The deny envelope is the
    only shape the model can read as a structured ``ArcjetDenialResult``.
    """
    action = config.action
    correlation_id = _resolve_correlation_id(None)
    metadata: Optional[Metadata] = None

    try:
        parsed = _arguments_from_handler(arguments)
        correlation_id = _correlation(config, parsed)
        extra = _resolved_metadata(config, parsed)
        metadata = _merged_metadata(config, parsed, extra)
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
        return HandlerVerdict(deny=True, payload=payload_from_block(None))

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
        return HandlerVerdict(deny=True, payload=payload_from_block(decision))

    _emit_capture(
        client=config.guard,
        action=action,
        outcome=_outcome_for_completed_action(decision, degraded=prepared.degraded),
        correlation_id=correlation_id,
        decision=decision,
        metadata=metadata,
    )
    return HandlerVerdict(deny=False)


def handler_denial_result(verdict: HandlerVerdict) -> ArcjetDenialResult:
    """The exact payload a DENY handler must return."""
    if verdict.payload is not None:
        return verdict.payload
    return payload_from_block(None)


def _is_already_guarded(tool: Any) -> bool:
    return bool(getattr(tool, _GUARD_BRAND, False))


def _brand(tool: Any) -> None:
    """Mark the wrapped *copy* so a second wrap does not double-call Guard.

    An attribute rather than a WeakSet of ``id()`` values: CPython reuses
    the id of a collected object, so an id-keyed registry starts skipping
    unrelated tools — a silent fail-open. ``object.__setattr__`` works on
    a frozen dataclass. If ``DecoratedFunctionTool`` grows ``__slots__``
    without room for this name, fail loudly at wrap time rather than
    shipping an unbranded copy.
    """
    try:
        object.__setattr__(tool, _GUARD_BRAND, True)
    except AttributeError as exc:
        raise TypeError(
            "guard_tool() could not brand the DecoratedFunctionTool copy with "
            f"{_GUARD_BRAND!r}; the SDK type likely uses __slots__ "
            "without space for this attribute. The wrap cannot proceed "
            "without the brand — a second wrap would double-call Guard, "
            "and guard_hooks would not skip this tool."
        ) from exc


def _copy_tool(tool: Any) -> Any:
    return copy.copy(tool)


def _wrap_tool_func(config: _ToolConfig, original: Any) -> Any:
    """A replacement ``_tool_func`` that evaluates policy first and never throws.

    The wrapper is async (or an async generator when *original* is one) so
    ``stream()`` awaits it. A raise would be swallowed into
    ``Error: {Type} - {message}``.
    """

    async def _verdict_or_none(
        arguments: Mapping[str, Any],
    ) -> Optional[HandlerVerdict]:
        try:
            verdict = await evaluate_handler(arguments, config)
        except Exception:
            if config.on_guard_error == "allow":
                logger.warning(
                    "arcjet: policy for action %r could not be evaluated; "
                    "proceeding because on_guard_error is 'allow'",
                    config.action,
                )
                return None
            return HandlerVerdict(deny=True, payload=payload_from_block(None))
        if verdict.deny:
            return verdict
        return None

    if inspect.isasyncgenfunction(original):

        async def guarded_gen(**kwargs: Any) -> Any:
            denied = await _verdict_or_none(kwargs)
            if denied is not None:
                yield handler_denial_result(denied)
                return
            async for item in original(**kwargs):
                yield item

        return guarded_gen

    async def guarded(**kwargs: Any) -> Any:
        denied = await _verdict_or_none(kwargs)
        if denied is not None:
            return handler_denial_result(denied)
        if inspect.iscoroutinefunction(original):
            return await original(**kwargs)
        return original(**kwargs)

    return guarded


def guard_tool(
    *,
    guard: Any,
    tool: Any,
    action: str,
    actor: ActorResolver = None,
    inputs: InputResolver = None,
    rules: RulesResolver = (),
    metadata: MetadataResolver = None,
    correlation_id: Optional[str] = None,
    session_id: Optional[str] = None,
    request_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
) -> Any:
    """Wrap an authored ``@tool`` so the handler never runs on DENY.

    Returns a copy of *tool* whose ``_tool_func`` evaluates policy first. A
    ``DENY`` (or an unevaluated policy under the default
    ``on_guard_error="deny"``) returns the plain ``ArcjetDenialResult``
    dict. The tool body does not run. Already-branded tools are returned
    unchanged so a second wrap cannot double-call Guard.

    Do not throw: the SDK reports ``Error: {Type} - {message}`` and drops
    the envelope. ``event.interrupt()`` is HITL, not a policy gate.

    Args:
        guard: The Arcjet client. An async client is preferred; a blocking
            client is accepted.
        tool: A Strands ``DecoratedFunctionTool`` from ``@tool``.
        action: Checkpoint label, e.g. ``"email.sent"``.
        actor: Who is acting, or a callable of the call's arguments.
        inputs: Policy inputs, or a callable of the call's arguments.
        rules: Local rules, or a callable of the call's arguments. Empty
            still contacts Guard.
        metadata: Capture metadata, or a callable of the call's arguments.
        correlation_id: Caller-owned Sequence id. Preferred over
            *session_id* / *request_id*. Falls back to
            :func:`~arcjet.guard.arcjet_sequence`. Never minted.
        session_id: Alias fallback when the application calls the id a
            session. Ignored when *correlation_id* is set.
        request_id: Alias fallback when the application calls the id a
            request. Ignored when *correlation_id* or *session_id* is set.
        on_guard_error: ``"deny"`` (default) or ``"allow"``.

    Raises:
        ArcjetMisconfiguration: *on_guard_error* is not ``"allow"`` or
            ``"deny"``, or the installed ``strands-agents`` is below 1.11.0.
        TypeError: *tool* is not a ``DecoratedFunctionTool``.
        ValueError: a fallback id is not printable ASCII within 256 bytes.
        ImportError: the ``strands-agents`` extra is not installed.
    """
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
        owned = request_id
    if owned is not None:
        _validated(owned)
    decorated = load_decorated_function_tool()
    if not isinstance(tool, decorated):
        raise TypeError(
            f"guard_tool() wraps a Strands Agents DecoratedFunctionTool "
            f"from @tool, got {type(tool).__name__}"
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
        correlation_id=owned,
        on_guard_error=on_guard_error,
        tool_name=getattr(tool, "tool_name", "") or "",
    )
    original = getattr(tool, "_tool_func", None)
    if not callable(original):
        raise TypeError(
            "guard_tool() wraps a DecoratedFunctionTool with a callable "
            f"_tool_func, got {type(original).__name__}"
        )
    guarded._tool_func = _wrap_tool_func(config, original)
    _brand(guarded)
    return guarded
