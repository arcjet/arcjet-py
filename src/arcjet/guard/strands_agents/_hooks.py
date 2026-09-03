"""Strands Agents ``BeforeToolCallEvent`` / ``AfterToolCallEvent`` hooks.

Unwrapped MCP, vended, and built-in tools have no authored handler to wrap.
``BeforeToolCallEvent.cancel_tool`` (a ``True`` or a str) is the deny that
skips the handler. A string is placed in an error-status tool result; this
adapter sets the JSON ``ArcjetDenialResult`` so the model can still read
the envelope.

``BeforeToolsEvent.cancel`` is deliberately **not** set. Official Strands
docs: setting the batch ``cancel`` produces an error result for every tool
and skips execution entirely, so no per-tool ``BeforeToolCallEvent`` fires.
The JS adapter avoided ``BeforeToolsEvent.cancel`` for that reason; Python
is the same, so the primary gate is per-tool ``cancel_tool``. That is also
the only path that can brand-skip a ``guard_tool`` wrapper.

There is no dedicated prompt / inbound hook on this bus. ``MessageAddedEvent``
is observe-only. ``BeforeInvocationEvent.cancel`` aborts the whole run, not
a prompt screen, and is not used. There is no ``guard_inbound``. Screen
user text with core :func:`~arcjet.guard.guard` / ``guard_sync`` before
``agent()``.

``event.interrupt()`` is HITL, not a policy gate, and is never called.

``AfterToolCallEvent`` is capture only (``strands.phase: after``). Brand-skip
does not skip it. ``retry`` is never set.
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
from ._context import strands_agent_context
from ._denial import (
    cancel_tool_value,
    payload_from_block,
)
from ._import import load_strands_hooks
from ._tool import _GUARD_BRAND

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


@dataclass(frozen=True, slots=True)
class _HookConfig:
    guard: Any
    action: ActionResolver
    actor: ActorResolver
    inputs: InputResolver
    rules: RulesResolver
    metadata: MetadataResolver
    correlation_id: Optional[str]
    on_guard_error: OnGuardError


@dataclass(frozen=True, slots=True)
class BeforeToolCallVerdict:
    """What BeforeToolCallEvent should tell the SDK. Unit tests call this
    without constructing a real event.
    """

    cancel: bool
    message: Optional[str] = None


def _is_already_guarded(tool: Any) -> bool:
    """Whether :func:`guard_tool` already evaluates this tool's calls."""
    return tool is not None and bool(getattr(tool, _GUARD_BRAND, False))


def _tool_use(source: Any) -> Mapping[str, Any]:
    raw = getattr(source, "tool_use", None)
    if raw is None:
        raw = getattr(source, "toolUse", None)
    return raw if isinstance(raw, Mapping) else {}


def _tool_name(source: Any) -> str:
    use = _tool_use(source)
    name = use.get("name")
    if isinstance(name, str) and name:
        return name
    selected = getattr(source, "selected_tool", None)
    if selected is None:
        selected = getattr(source, "selectedTool", None)
    selected_name = getattr(selected, "tool_name", None)
    return selected_name if isinstance(selected_name, str) else ""


def _tool_arguments(source: Any) -> Mapping[str, Any]:
    raw = _tool_use(source).get("input")
    return dict(raw) if isinstance(raw, Mapping) else {}


def _tool_call(source: Any) -> dict[str, Any]:
    """What ``rules`` / ``actor`` / ``inputs`` / ``metadata`` see for a tool hook.

    The model-produced ``input`` fields plus ``tool_name``, so a per-tool
    rate limit can key on the name. ``tool_name`` is applied last so a tool
    argument of the same name cannot hide the hook's name.
    """
    call = dict(_tool_arguments(source))
    name = _tool_name(source)
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


def _correlation(correlation_id: Optional[str], source: Any) -> Optional[str]:
    derived = strands_agent_context(source, correlation_id=correlation_id)
    return _resolve_correlation_id(derived.correlation_id)


def _merged_metadata(
    correlation_id: Optional[str],
    source: Any,
    extra: Optional[Metadata],
    *,
    phase: str,
) -> Optional[Metadata]:
    derived = strands_agent_context(source, correlation_id=correlation_id)
    merged: dict[str, Any] = {}
    if derived.metadata:
        merged.update(derived.metadata)
    merged["strands.phase"] = phase
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


def _resolve_tool_action(config: _HookConfig, source: Any) -> str:
    action = config.action
    if action is None:
        name = _tool_name(source) or "tool"
        return f"{name}.invoked"
    if callable(action):
        return cast(Callable[[Mapping[str, Any]], str], action)(_tool_call(source))
    return action


async def evaluate_before_tool_call(
    source: Any, config: _HookConfig
) -> BeforeToolCallVerdict:
    """Evaluate BeforeToolCallEvent policy. Never raises an Arcjet error.

    A raise would leave the hook; the SDK propagates callback exceptions.
    ``cancel_tool`` is the only deny. ``event.interrupt()`` is never called.
    """
    selected = getattr(source, "selected_tool", None)
    if selected is None:
        selected = getattr(source, "selectedTool", None)
    if _is_already_guarded(selected):
        return BeforeToolCallVerdict(cancel=False)

    name = _tool_name(source)
    action = f"{name or 'tool'}.invoked"
    correlation_id = _resolve_correlation_id(None)
    metadata: Optional[Metadata] = None

    try:
        action = _resolve_tool_action(config, source)
        arguments = _tool_call(source)
        correlation_id = _correlation(config.correlation_id, source)
        extra = _resolved_metadata(config.metadata, arguments)
        metadata = _merged_metadata(
            config.correlation_id, source, extra, phase="before"
        )
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
            return BeforeToolCallVerdict(cancel=False)
        _emit_capture(
            client=config.guard,
            action=action,
            outcome="unavailable",
            correlation_id=correlation_id,
            decision=None,
            metadata=metadata,
        )
        return BeforeToolCallVerdict(
            cancel=True, message=cancel_tool_value(payload_from_block(None))
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
        return BeforeToolCallVerdict(
            cancel=True, message=cancel_tool_value(payload_from_block(decision))
        )

    _emit_capture(
        client=config.guard,
        action=action,
        outcome=_outcome_for_completed_action(decision, degraded=prepared.degraded),
        correlation_id=correlation_id,
        decision=decision,
        metadata=metadata,
    )
    return BeforeToolCallVerdict(cancel=False)


def apply_cancel_tool(event: Any, verdict: BeforeToolCallVerdict) -> None:
    """Set ``event.cancel_tool`` when *verdict* says the handler must not run.

    ``True`` or a str both skip the handler. This sets the JSON envelope
    string so the error tool result still carries ``ArcjetDenialResult``.
    """
    if not verdict.cancel:
        return
    event.cancel_tool = verdict.message if verdict.message else True


def capture_after_tool_call(source: Any, config: _HookConfig) -> None:
    """Observe-only AfterToolCallEvent. Never blocks. Brand-skip does not apply.

    ``guard_tool`` already captured the gate; this is the JS adapter's
    after-call audit trail (``strands.phase: after``). Outcome is
    ``success`` because AfterToolCallEvent cannot distinguish a tool error
    from a result the model is meant to read. ``retry`` is never set.
    """
    try:
        action = _resolve_tool_action(config, source)
        arguments = _tool_call(source)
        extra = _resolved_metadata(config.metadata, arguments)
        metadata = _merged_metadata(config.correlation_id, source, extra, phase="after")
        _emit_capture(
            client=config.guard,
            action=action,
            outcome="success",
            correlation_id=_correlation(config.correlation_id, source),
            decision=None,
            metadata=metadata,
        )
    except Exception:
        logger.warning(
            "arcjet: the Strands Agents AfterToolCallEvent hook failed; "
            "the tool result is unchanged"
        )


class _ArcjetStrandsHooks:
    """HookProvider passed to ``Agent(hooks=[...])``.

    Not a policy API. Registers ``BeforeToolCallEvent`` (deny via
    ``cancel_tool``) and ``AfterToolCallEvent`` (capture only). Does not
    register ``BeforeToolsEvent``.
    """

    def __init__(self, config: _HookConfig) -> None:
        self._config = config

    def register_hooks(self, registry: Any, **_kwargs: Any) -> None:
        hooks = load_strands_hooks()
        registry.add_callback(hooks.BeforeToolCallEvent, self._before_tool_call)
        registry.add_callback(hooks.AfterToolCallEvent, self._after_tool_call)

    async def _before_tool_call(self, event: Any) -> None:
        try:
            verdict = await evaluate_before_tool_call(event, self._config)
        except Exception:
            if self._config.on_guard_error == "allow":
                logger.warning(
                    "arcjet: the Strands Agents BeforeToolCallEvent hook "
                    "failed; the tool proceeds because on_guard_error is "
                    "'allow'"
                )
                return
            apply_cancel_tool(
                event,
                BeforeToolCallVerdict(
                    cancel=True, message=cancel_tool_value(payload_from_block(None))
                ),
            )
            return
        apply_cancel_tool(event, verdict)

    def _after_tool_call(self, event: Any) -> None:
        capture_after_tool_call(event, self._config)


def guard_hooks(
    *,
    guard: Any = None,
    action: ActionResolver = None,
    actor: ActorResolver = None,
    inputs: InputResolver = None,
    rules: RulesResolver = (),
    metadata: MetadataResolver = None,
    correlation_id: Optional[str] = None,
    session_id: Optional[str] = None,
    request_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
) -> _ArcjetStrandsHooks:
    """Build Strands Agents hooks that fail closed.

    Returns a HookProvider for ``Agent(hooks=[...])``.

    * ``BeforeToolCallEvent`` — deny unwrapped MCP / vended / built-in
      tools with ``cancel_tool`` set to the JSON ``ArcjetDenialResult``.
      Tools already wrapped by
      :func:`~arcjet.guard.strands_agents.guard_tool` are skipped via the
      ``_arcjet_guarded`` brand so Guard is not called twice.
    * ``AfterToolCallEvent`` — capture only (``strands.phase: after``).
      Never blocks. Brand-skip does not skip this. ``retry`` is never set.

    ``BeforeToolsEvent.cancel`` is not set. Official docs: a batch cancel
    skips per-tool ``BeforeToolCallEvent`` hooks, so a branded
    ``guard_tool`` wrapper would not be the only gate and every tool in
    the batch would share one deny. The JS adapter made the same choice.

    There is no inbound helper. ``event.interrupt()`` is HITL and is not
    called.

    Tool-hook ``rules`` / ``actor`` / ``inputs`` / ``metadata`` callables
    receive ``tool_use.input`` plus ``tool_name``. ``action`` still
    receives that envelope when it is a callable.

    Args:
        guard: The Arcjet client. An async client is preferred; a blocking
            client is accepted.
        action: Checkpoint label, or a callable of the tool-call envelope.
            Defaults to ``"{tool_name}.invoked"``.
        actor: Who is acting, or a callable of that envelope.
        inputs: Policy inputs, or a callable of that envelope.
        rules: Local rules, or a callable of that envelope. Empty still
            contacts Guard.
        metadata: Capture metadata, or a callable of that envelope.
        correlation_id: Caller-owned Sequence id fallback. Invocation
            state is preferred. Never minted.
        session_id: Alias of *correlation_id* when the application calls
            the id a session. Ignored when *correlation_id* is set.
        request_id: Alias of *correlation_id* when the application calls
            the id a request. Ignored when *correlation_id* or
            *session_id* is set.
        on_guard_error: ``"deny"`` (default) or ``"allow"``.

    Raises:
        ArcjetMisconfiguration: *on_guard_error* is not ``"allow"`` or
            ``"deny"``, or the installed ``strands-agents`` is below
            1.11.0.
        ValueError: a fallback id is not printable ASCII within 256 bytes.
        ImportError: the ``strands-agents`` extra is not installed. Raised
            when the returned provider is registered on an agent (the
            first call that loads ``strands.hooks``).
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

    # Load now so a missing extra is reported at build time, not later
    # inside an agent callback the SDK would propagate.
    load_strands_hooks()

    return _ArcjetStrandsHooks(
        _HookConfig(
            guard=guard,
            action=action,
            actor=actor,
            inputs=inputs,
            rules=rules,
            metadata=metadata,
            correlation_id=owned,
            on_guard_error=on_guard_error,
        )
    )
