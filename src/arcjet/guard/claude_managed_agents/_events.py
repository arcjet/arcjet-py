"""Inbound gate for ``sessions.events.send`` / ``initial_events``.

``guard_events`` wraps a send callable (the real
``client.beta.sessions.events.send``, or ``sessions.create`` when the
caller is seeding ``initial_events``). ``user.message`` events are
evaluated **before** the original send runs. On DENY the original is
not called.

The wrapper is always async so it is safe to ``await`` from an already
running loop (``AsyncAnthropic``, FastAPI). A sync ``send`` is invoked
directly after the gate; its return value is returned as-is.

This is not ``guard_inbound``. There is no PreToolUse. Built-in tools
under default ``always_allow`` cannot be gated here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Optional

from arcjet._errors import ArcjetMisconfiguration

from .._context import _validated
from .._errors import ArcjetDeniedError, ArcjetUnavailableError, OnGuardError
from ._common import (
    PHASE_METADATA_KEY,
    ActorResolver,
    InputResolver,
    MetadataResolver,
    RulesResolver,
    _read,
    adopt_wrapper,
    brand,
    evaluate_checkpoint,
    is_already_guarded,
    maybe_await,
)
from ._denial import payload_from_block
from ._import import _require_anthropic

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
    decision: Optional[Any] = None


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


async def evaluate_user_message(event: Any, config: _EventsConfig) -> InboundVerdict:
    """Evaluate policy for one inbound ``user.message``. Never raises Arcjet."""
    outcome = await evaluate_checkpoint(
        guard=config.guard,
        action=config.action,
        actor=config.actor,
        inputs=config.inputs,
        rules=config.rules,
        metadata=config.metadata,
        correlation_id=config.correlation_id,
        session_id=config.session_id,
        on_guard_error=config.on_guard_error,
        arguments=message_arguments(event),
        reserved_metadata={PHASE_METADATA_KEY: "inbound"},
    )
    if outcome.proceeded_open:
        return InboundVerdict(deny=False)
    if outcome.failure is not None:
        payload = payload_from_block(outcome.decision)
        return InboundVerdict(
            deny=True, reason=payload["message"], decision=outcome.decision
        )
    return InboundVerdict(deny=False)


def _extract_inbound(_args: tuple[Any, ...], kwargs: dict[str, Any]) -> list[Any]:
    """``user.message`` values from a send / create call.

    Matches the real SDK: ``events=`` / ``initial_events=`` are
    keyword-only. A positional second argument is not treated as events
    — ``send(session_id, *, events=...)`` would reject that shape.
    """
    return inbound_events(kwargs.get("events"), kwargs.get("initial_events"))


async def _gate_inbound(
    config: _EventsConfig, inbound: Sequence[Any]
) -> InboundVerdict:
    for event in inbound:
        verdict = await evaluate_user_message(event, config)
        if verdict.deny:
            return verdict
    return InboundVerdict(deny=False)


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

    Always returns an async callable. ``await`` it — including when *send*
    itself is the sync ``Anthropic`` client method. On DENY (or unevaluated
    policy under the default ``on_guard_error="deny"``) the original *send*
    is not called and :class:`~arcjet.guard.ArcjetDeniedError` /
    :class:`~arcjet.guard.ArcjetUnavailableError` is raised.

    Also gates ``initial_events`` when the wrapped callable is
    ``sessions.create`` (or any send-shaped function that takes that
    kwarg). Non-``user.message`` events (``user.custom_tool_result``,
    ``user.interrupt``, ``user.tool_confirmation``, …) pass through
    without an inbound check.

    The Anthropic session id passed to *send* is never used as
    correlation. Already-branded wrappers are returned unchanged.

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
    if is_already_guarded(send):
        return send
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

    async def wrapped(*args: Any, **kwargs: Any) -> Any:
        inbound = _extract_inbound(args, kwargs)
        if inbound:
            verdict = await _gate_inbound(config, inbound)
            _raise_for(verdict)
        return await maybe_await(send(*args, **kwargs))

    adopt_wrapper(wrapped, send)
    brand(wrapped)
    return wrapped
