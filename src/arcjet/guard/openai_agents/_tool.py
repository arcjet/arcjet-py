"""Authored ``FunctionTool`` wrap via a prepended ``ToolInputGuardrail``.

The runner runs ``FunctionTool.tool_input_guardrails`` before
``on_invoke_tool`` and can skip the call. ``reject_content(message)`` is the
honest deny: the message is what the model sees, and invoke never runs.
``raise_exception()`` would halt the run. Raising an Arcjet error from
``on_invoke_tool`` would be swallowed by the SDK
``default_tool_error_function`` into a generic string.

This module therefore does **not** wrap ``on_invoke_tool`` as the policy
gate, does not wrap ``needs_approval``, and does not mutate ``RunConfig``.
``pre_approval_tool_input_guardrails=True`` is an application opt-in only.

Hosted tools, MCP, Computer/Shell/ApplyPatch, handoffs, and
``Agent.as_tool()`` are not on this path.
"""

from __future__ import annotations

import asyncio
import copy
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import partial
from typing import Any, Literal, Optional, Union, cast

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
from ._context import openai_agents_context
from ._denial import dumps_denial, payload_from_block
from ._import import load_agents_tool_guardrails, load_function_tool

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

_GUARDRAIL_NAME = "arcjet.guard.openai_agents"


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
class ToolInputVerdict:
    """What the guardrail should tell the SDK. Unit tests call this without
    constructing a real ``ToolGuardrailFunctionOutput``.
    """

    behavior: Literal["allow", "reject_content"]
    message: Optional[str] = None


def _arguments_from_tool_context(ctx: Any) -> Mapping[str, Any]:
    """The model-produced arguments, parsed from ``tool_arguments``.

    The runner hands a JSON string. A parse failure is an empty mapping —
    the same shape a policy with no resolver sees for a call with no args —
    rather than an exception that would skip Guard.
    """
    raw = getattr(ctx, "tool_arguments", None)
    if raw is None:
        raw = getattr(ctx, "tool_input", None)
    if isinstance(raw, Mapping):
        return dict(raw)
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
        except ValueError:
            return {}
        return dict(parsed) if isinstance(parsed, Mapping) else {}
    return {}


def _resolve(source: Any, arguments: Mapping[str, Any]) -> Any:
    if source is None or not callable(source):
        return source
    return source(arguments)


def _prepared(config: _ToolConfig, arguments: Mapping[str, Any]) -> ResolvedInputs:
    """What the decision is made from; a failed resolver is reported.

    Reported rather than raised so Guard still sees the call and
    ``on_guard_error`` decides whether a partly-judged call may run.
    """
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


def _correlation(config: _ToolConfig, data: Any) -> Optional[str]:
    """Caller-owned id from the run context, then the wrap, then the sequence."""
    ctx = getattr(data, "context", data)
    derived = openai_agents_context(ctx, correlation_id=config.correlation_id)
    return _resolve_correlation_id(derived.correlation_id)


def _merged_metadata(
    config: _ToolConfig, data: Any, extra: Optional[Metadata]
) -> Optional[Metadata]:
    ctx = getattr(data, "context", data)
    derived = openai_agents_context(ctx, correlation_id=config.correlation_id)
    merged: dict[str, Any] = {}
    if derived.metadata:
        merged.update(derived.metadata)
    tool_name = config.tool_name or getattr(ctx, "tool_name", None)
    if isinstance(tool_name, str) and tool_name and "openai-agents.tool" not in merged:
        merged["openai-agents.tool"] = tool_name
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

    The runner is async. A blocking ``guard_sync()`` client is offloaded with
    ``asyncio.to_thread`` so the event loop is not wedged for the Guard round
    trip.
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


async def evaluate_tool_input(data: Any, config: _ToolConfig) -> ToolInputVerdict:
    """Evaluate policy for one tool call. Never raises an Arcjet error.

    A raise from this function would leave the runner, which is either a
    tripwire (``raise_exception``) or an unhandled exception — both halt or
    swallow. ``reject_content`` is the only deny that skips invoke and still
    reaches the model.
    """
    action = config.action
    correlation_id = _resolve_correlation_id(None)
    metadata: Optional[Metadata] = None

    try:
        arguments = _arguments_from_tool_context(getattr(data, "context", data))
        correlation_id = _correlation(config, data)
        extra = _resolved_metadata(config, arguments)
        metadata = _merged_metadata(config, data, extra)
        prepared = _prepared(config, arguments)
        rules = _resolved_rules(config, arguments)
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
            return ToolInputVerdict("allow")
        _emit_capture(
            client=config.guard,
            action=action,
            outcome="unavailable",
            correlation_id=correlation_id,
            decision=None,
            metadata=metadata,
        )
        return ToolInputVerdict(
            "reject_content",
            dumps_denial(payload_from_block(action, None)),
        )

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
        return ToolInputVerdict(
            "reject_content",
            dumps_denial(payload_from_block(action, decision)),
        )

    _emit_capture(
        client=config.guard,
        action=action,
        outcome=_outcome_for_completed_action(decision, degraded=prepared.degraded),
        correlation_id=correlation_id,
        decision=decision,
        metadata=metadata,
    )
    return ToolInputVerdict("allow")


def _is_already_guarded(tool: Any) -> bool:
    return bool(getattr(tool, _GUARD_BRAND, False))


def _copy_tool(tool: Any) -> Any:
    return copy.copy(tool)


def _prepend_guardrail(tool: Any, guardrail: Any) -> None:
    existing = list(getattr(tool, "tool_input_guardrails", None) or [])
    tool.tool_input_guardrails = [guardrail, *existing]


def _make_guardrail(config: _ToolConfig) -> Any:
    modules = load_agents_tool_guardrails()
    tool_input_guardrail = modules.ToolInputGuardrail
    output = modules.ToolGuardrailFunctionOutput

    async def arcjet_tool_input(data: Any) -> Any:
        verdict = await evaluate_tool_input(data, config)
        if verdict.behavior == "reject_content":
            return output.reject_content(verdict.message or "")
        return output.allow()

    return tool_input_guardrail(
        guardrail_function=arcjet_tool_input,
        name=_GUARDRAIL_NAME,
    )


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
    on_guard_error: OnGuardError = "deny",
) -> Any:
    """Wrap an authored ``FunctionTool`` so invoke never runs on DENY.

    Returns a copy of *tool* whose ``tool_input_guardrails`` start with an
    Arcjet ``ToolInputGuardrail``. A ``DENY`` (or an unevaluated policy under
    the default ``on_guard_error="deny"``) is
    ``ToolGuardrailFunctionOutput.reject_content`` of a JSON
    ``ArcjetDenialResult``. The tool body does not run. Already-branded tools
    are returned unchanged so a second wrap cannot double-call Guard.

    ``needs_approval`` is not a policy gate and is not wrapped. Input
    guardrails normally run after approval; set
    ``RunConfig.tool_execution.pre_approval_tool_input_guardrails=True``
    yourself if you want the check before the HITL pause. This helper does
    not set that flag.

    Args:
        guard: The Arcjet client. An async client is preferred; a blocking
            client is accepted.
        tool: An OpenAI Agents ``FunctionTool`` from ``function_tool`` /
            ``@function_tool``.
        action: Checkpoint label, e.g. ``"email.sent"``.
        actor: Who is acting, or a callable of the call's arguments.
        inputs: Policy inputs, or a callable of the call's arguments.
        rules: Local rules, or a callable of the call's arguments. Empty
            still contacts Guard.
        metadata: Capture metadata, or a callable of the call's arguments.
        correlation_id: Caller-owned fallback Sequence id. The run context
            is preferred; then this; then :func:`~arcjet.guard.arcjet_sequence`.
            Never minted.
        on_guard_error: ``"deny"`` (default) or ``"allow"``.

    Raises:
        ArcjetMisconfiguration: *on_guard_error* is not ``"allow"`` or
            ``"deny"``, or the installed ``openai-agents`` is below 0.19.0.
        TypeError: *tool* is not a ``FunctionTool``.
        ValueError: *correlation_id* is not printable ASCII within 256 bytes.
        ImportError: the ``openai-agents`` extra is not installed.
    """
    if on_guard_error not in ("allow", "deny"):
        raise ArcjetMisconfiguration(
            f"on_guard_error must be 'allow' or 'deny', got {on_guard_error!r}. "
            f"It decides whether a call runs when policy could not be "
            f"evaluated, so there is no safe value to guess."
        )
    if correlation_id is not None:
        _validated(correlation_id)
    function_tool = load_function_tool()
    if not isinstance(tool, function_tool):
        raise TypeError(
            f"guard_tool() wraps an OpenAI Agents FunctionTool, got "
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
        correlation_id=correlation_id,
        on_guard_error=on_guard_error,
        tool_name=getattr(tool, "name", "") or "",
    )
    _prepend_guardrail(guarded, _make_guardrail(config))
    # Only the copy is branded. Branding the original as well would make a
    # later wrap of the unwrapped tool skip it, which is a fail-open.
    object.__setattr__(guarded, _GUARD_BRAND, True)
    return guarded
