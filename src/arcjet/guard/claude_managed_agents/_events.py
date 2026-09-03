"""Inbound gate for ``sessions.events.send`` / ``initial_events``.

``guard_events`` wraps a send callable (the real
``client.beta.sessions.events.send``, or ``sessions.create`` when the
caller is seeding ``initial_events``). ``user.message`` events are
evaluated **before** the original send runs. On DENY the original is
not called.

This is not ``guard_inbound``. There is no PreToolUse. Built-in tools
under default ``always_allow`` cannot be gated here.
"""

from __future__ import annotations

import asyncio
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
from .._types import Decision
from ._context import claude_managed_agents_context
from ._denial import payload_from_block, unavailable_message
from ._import import _require_anthropic

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

_USER_MESSAGE = "user.message"


@dataclass(frozen=True, slots=True)
class _EventsConfig:
    guard: Any
    action: str
    actor: ActorResolver
    inputs: InputResolver
    rules: RulesResolver
    metadata: MetadataResolver
    correlation_id: Optional[str]
    session_id: Optional[str]
    on_guard_error: OnGuardError


@dataclass(frozen=True, slots=True)
class InboundVerdict:
    """What the send wrapper should do. Unit tests call this without a client."""

    deny: bool
    reason: Optional[str] = None
    decision: Optional[Decision] = None


def _read(source: Any, name: str) -> Any:
    if source is None:
        return None
    if isinstance(source, Mapping):
        return source.get(name)
    return getattr(source, name, None)


def _event_type(event: Any) -> str:
    value = _read(event, "type")
    return value if isinstance(value, str) else ""


def _is_user_message(event: Any) -> bool:
    return _event_type(event) == _USER_MESSAGE


def _as_event_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (str, bytes, bytearray, Mapping)):
        return [value]
    if isinstance(value, Sequence):
        return list(value)
    return [value]


def inbound_events(*groups: Any) -> list[Any]:
    """``user.message`` events from ``events`` / ``initial_events`` groups."""
    found: list[Any] = []
    for group in groups:
        for event in _as_event_list(group):
            if _is_user_message(event):
                found.append(event)
    return found


def _content_text(content: Any) -> str:
    """Flatten Managed Agents message content to a single prompt string."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, Mapping):
        text = content.get("text")
        return text if isinstance(text, str) else ""
    if isinstance(content, Sequence) and not isinstance(
        content, (str, bytes, bytearray)
    ):
        parts: list[str] = []
        for block in content:
            piece = _content_text(block)
            if piece:
                parts.append(piece)
        return "\n".join(parts)
    text = getattr(content, "text", None)
    return text if isinstance(text, str) else ""


def message_arguments(event: Any) -> dict[str, Any]:
    """What inbound resolvers see for one ``user.message``."""
    content = _read(event, "content")
    prompt = _content_text(content)
    return {"prompt": prompt, "content": content, "type": _USER_MESSAGE}


def _resolve(source: Any, arguments: Mapping[str, Any]) -> Any:
    if source is None or not callable(source):
        return source
    return source(arguments)


def _prepared(config: _EventsConfig, arguments: Mapping[str, Any]) -> ResolvedInputs:
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
    config: _EventsConfig, arguments: Mapping[str, Any]
) -> Sequence[RuleWithInput]:
    rules = config.rules
    if not callable(rules):
        return rules
    return cast(
        Callable[[Mapping[str, Any]], Sequence[RuleWithInput]],
        rules,
    )(arguments)


def _resolved_metadata(
    config: _EventsConfig, arguments: Mapping[str, Any]
) -> Optional[Metadata]:
    metadata = config.metadata
    if callable(metadata):
        return cast(
            Callable[[Mapping[str, Any]], Optional[Metadata]],
            metadata,
        )(arguments)
    return metadata


def _correlation(config: _EventsConfig) -> Optional[str]:
    derived = claude_managed_agents_context(
        correlation_id=config.correlation_id,
        session_id=config.session_id,
    )
    return _resolve_correlation_id(derived.correlation_id)


def _merged_metadata(
    config: _EventsConfig, extra: Optional[Metadata]
) -> Optional[Metadata]:
    derived = claude_managed_agents_context(
        correlation_id=config.correlation_id,
        session_id=config.session_id,
    )
    merged: dict[str, Any] = {}
    if derived.metadata:
        merged.update(derived.metadata)
    merged["claude-managed-agents.phase"] = "inbound"
    if extra:
        merged.update(extra)
    return merged or None


def _unavailable(action: str, cause: Optional[BaseException]) -> BaseException:
    return ArcjetUnavailableError(action, cause=cause)


async def _decide(
    config: _EventsConfig,
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
    if _awaitable(config.guard, "guard") is not None or config.guard is None:
        return await _guard_async(config.guard, **kwargs)
    return await asyncio.to_thread(partial(_guard_sync, config.guard, **kwargs))


async def evaluate_user_message(event: Any, config: _EventsConfig) -> InboundVerdict:
    """Evaluate policy for one inbound ``user.message``. Never raises Arcjet."""
    action = config.action
    correlation_id = _resolve_correlation_id(None)
    metadata: Optional[Metadata] = None
    decision: Any = None

    try:
        arguments = message_arguments(event)
        correlation_id = _correlation(config)
        extra = _resolved_metadata(config, arguments)
        metadata = _merged_metadata(config, extra)
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
            return InboundVerdict(deny=False)
        _emit_capture(
            client=config.guard,
            action=action,
            outcome="unavailable",
            correlation_id=correlation_id,
            decision=None,
            metadata=metadata,
        )
        return InboundVerdict(deny=True, reason=unavailable_message())

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
        payload = payload_from_block(decision)
        return InboundVerdict(deny=True, reason=payload["message"], decision=decision)

    _emit_capture(
        client=config.guard,
        action=action,
        outcome=_outcome_for_completed_action(decision, degraded=prepared.degraded),
        correlation_id=correlation_id,
        decision=decision,
        metadata=metadata,
    )
    return InboundVerdict(deny=False)


def _extract_inbound(args: tuple[Any, ...], kwargs: dict[str, Any]) -> list[Any]:
    """``user.message`` values from a send / create call.

    Real SDK shapes:

    * ``sessions.events.send(session_id, events=[...])``
    * ``sessions.create(..., initial_events=[...])``
    """
    events = kwargs.get("events")
    initial = kwargs.get("initial_events")
    if events is None and args:
        # Positional ``events`` after session_id on some call styles.
        if len(args) >= 2 and not isinstance(args[1], (str, bytes, bytearray)):
            events = args[1]
    return inbound_events(events, initial)


async def _gate_inbound(
    config: _EventsConfig, inbound: Sequence[Any]
) -> InboundVerdict:
    for event in inbound:
        verdict = await evaluate_user_message(event, config)
        if verdict.deny:
            return verdict
    return InboundVerdict(deny=False)


def _looks_async(fn: Any) -> bool:
    """True when *fn* should be awaited.

    Covers ``async def`` functions, bound coroutine methods (the real
    ``AsyncAnthropic`` ``sessions.events.send``), and instances whose
    ``__call__`` is async.
    """
    if inspect.iscoroutinefunction(fn):
        return True
    call = getattr(fn, "__call__", None)
    if inspect.iscoroutinefunction(call):
        return True
    unwrapped = inspect.unwrap(fn)
    if inspect.iscoroutinefunction(unwrapped):
        return True
    unwrapped_call = getattr(unwrapped, "__call__", None)
    return inspect.iscoroutinefunction(unwrapped_call)


def guard_events(
    *,
    guard: Any,
    send: Any,
    action: str,
    actor: ActorResolver = None,
    inputs: InputResolver = None,
    rules: RulesResolver = (),
    metadata: MetadataResolver = None,
    correlation_id: Optional[str] = None,
    session_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
) -> Callable[..., Any]:
    """Wrap ``sessions.events.send`` so inbound ``user.message`` is gated first.

    Also gates ``initial_events`` when the wrapped callable is
    ``sessions.create`` (or any send-shaped function that takes that
    kwarg). Non-``user.message`` events (``user.custom_tool_result``,
    ``user.interrupt``, ``user.tool_confirmation``, …) pass through
    without an inbound check.

    On DENY (or unevaluated policy under the default
    ``on_guard_error="deny"``) the original *send* is not called and
    :class:`~arcjet.guard.ArcjetDeniedError` /
    :class:`~arcjet.guard.ArcjetUnavailableError` is raised. The
    Anthropic session id passed to *send* is never used as correlation.

    There is no ``guard_inbound``. ``permission_policy: always_allow``
    (the default) cannot be gated. HITL ``always_ask`` is not policy.

    Args:
        guard: The Arcjet client. An async client is preferred; a blocking
            client is accepted.
        send: ``client.beta.sessions.events.send``, or another callable
            with the same ``events=`` / ``initial_events=`` kwargs.
        action: Checkpoint label, e.g. ``"message.received"``.
        actor: Who is acting, or a callable of the message arguments.
        inputs: Policy inputs, or a callable of the message arguments.
        rules: Local rules, or a callable of the message arguments.
        metadata: Capture metadata, or a callable of the message arguments.
        correlation_id: Caller-owned Sequence id. Never minted. Never an
            Anthropic session / event id we treated as ours.
        session_id: Same, for an id the application calls a session.
        on_guard_error: ``"deny"`` (default) or ``"allow"``.

    Raises:
        ArcjetMisconfiguration: *on_guard_error* is not ``"allow"`` or
            ``"deny"``, or the installed ``anthropic`` is below 0.92.0.
        TypeError: *send* is not callable.
        ValueError: *correlation_id* / *session_id* is not printable ASCII
            within 256 bytes.
    """
    _require_anthropic()
    if on_guard_error not in ("allow", "deny"):
        raise ArcjetMisconfiguration(
            f"on_guard_error must be 'allow' or 'deny', got {on_guard_error!r}. "
            f"It decides whether a call runs when policy could not be "
            f"evaluated, so there is no safe value to guess."
        )
    if not callable(send):
        raise TypeError(
            f"guard_events() wraps a send callable "
            f"(client.beta.sessions.events.send), got {type(send).__name__}"
        )
    if correlation_id is not None:
        _validated(correlation_id)
    if session_id is not None:
        _validated(session_id)
    if not isinstance(action, str) or not action:
        raise ArcjetMisconfiguration(
            "guard_events() needs a non-empty action string "
            "(there is no guard_inbound helper; user.message is this path)"
        )

    config = _EventsConfig(
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

    def _raise_for(verdict: InboundVerdict) -> None:
        if not verdict.deny:
            return
        if (
            verdict.decision is not None
            and getattr(verdict.decision, "conclusion", None) == "DENY"
        ):
            raise ArcjetDeniedError(config.action, verdict.decision)
        raise ArcjetUnavailableError(config.action)

    if _looks_async(send):

        async def wrapped_async(*args: Any, **kwargs: Any) -> Any:
            inbound = _extract_inbound(args, kwargs)
            if inbound:
                verdict = await _gate_inbound(config, inbound)
                _raise_for(verdict)
            result = send(*args, **kwargs)
            if inspect.isawaitable(result):
                return await result
            return result

        return wrapped_async

    def wrapped_sync(*args: Any, **kwargs: Any) -> Any:
        inbound = _extract_inbound(args, kwargs)
        if inbound:
            verdict = asyncio.run(_gate_inbound(config, inbound))
            _raise_for(verdict)
        return send(*args, **kwargs)

    return wrapped_sync
