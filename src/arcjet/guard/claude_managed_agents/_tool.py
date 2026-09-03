"""Custom-tool gate for Claude Managed Agents.

On ``agent.custom_tool_use`` Guard runs **before** the app ``run``. On
DENY the original does not run and the wrapper sends a real
``user.custom_tool_result`` via ``sessions.events.send``. There is no
PreToolUse.

A ``tool=`` object with ``run`` (the ``@beta_tool`` /
``@beta_async_tool`` / ``betaTool({ run })`` shape) is wrapped the same
way for a self-hosted ``EnvironmentWorker``. The CLI worker cannot
register custom tools.
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
from ._context import claude_managed_agents_context
from ._denial import (
    ArcjetDenialResult,
    custom_tool_result_event,
    dumps_denial,
    payload_from_block,
)
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

#: Attribute :func:`guard_custom_tool` puts on the copy it returns, so a
#: second wrap of the same object does not evaluate the same call twice.
_GUARD_BRAND = "_arcjet_guarded"

#: Built-in toolset names. ``web_search`` / ``web_fetch`` always run on
#: Anthropic. Cloud bash/read/write under default ``always_allow`` cannot
#: be gated. A self-hosted worker *does* execute bash/read/write locally;
#: wrapping those is the caller's choice via ``tool=``, not an automatic
#: factory rewrite of the stock toolset.
_ANTHROPIC_CLOUD_ONLY = frozenset({"web_search", "web_fetch"})


@dataclass(frozen=True, slots=True)
class _ToolConfig:
    guard: Any
    action: str
    actor: ActorResolver
    inputs: InputResolver
    rules: RulesResolver
    metadata: MetadataResolver
    correlation_id: Optional[str]
    session_id: Optional[str]
    on_guard_error: OnGuardError
    tool_name: str


@dataclass(frozen=True, slots=True)
class CustomToolVerdict:
    """What the custom-tool wrapper should do. Unit tests call this
    without constructing a real Anthropic client.
    """

    deny: bool
    payload: Optional[ArcjetDenialResult] = None


def _read(source: Any, name: str) -> Any:
    if source is None:
        return None
    if isinstance(source, Mapping):
        return source.get(name)
    return getattr(source, name, None)


def _event_id(event: Any) -> str:
    """Anthropic's event id — used only as ``custom_tool_use_id``, never
    as a Sequence correlation we minted.
    """
    for name in ("id", "event_id", "eventId"):
        value = _read(event, name)
        if isinstance(value, str) and value:
            return value
    return ""


def _session_thread_id(event: Any) -> Optional[str]:
    value = _read(event, "session_thread_id")
    if value is None:
        value = _read(event, "sessionThreadId")
    return value if isinstance(value, str) and value else None


def _tool_name(event: Any, fallback: str = "") -> str:
    value = _read(event, "name")
    if value is None:
        value = _read(event, "tool_name")
    if value is None:
        value = _read(event, "toolName")
    if isinstance(value, str) and value:
        return value
    return fallback


def _arguments_from_event(event: Any) -> Mapping[str, Any]:
    """Model-produced input from ``agent.custom_tool_use``."""
    raw = _read(event, "input")
    if raw is None:
        raw = _read(event, "arguments")
    if isinstance(raw, Mapping):
        return dict(raw)
    return {}


def _resolve(source: Any, arguments: Mapping[str, Any]) -> Any:
    if source is None or not callable(source):
        return source
    return source(arguments)


def _prepared(config: _ToolConfig, arguments: Mapping[str, Any]) -> ResolvedInputs:
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
    derived = claude_managed_agents_context(
        correlation_id=config.correlation_id,
        session_id=config.session_id,
    )
    return _resolve_correlation_id(derived.correlation_id)


def _merged_metadata(
    config: _ToolConfig,
    extra: Optional[Metadata],
    *,
    event: Any = None,
) -> Optional[Metadata]:
    derived = claude_managed_agents_context(
        correlation_id=config.correlation_id,
        session_id=config.session_id,
    )
    merged: dict[str, Any] = {}
    if derived.metadata:
        merged.update(derived.metadata)
    name = _tool_name(event, config.tool_name)
    if name:
        merged["claude-managed-agents.tool"] = name
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


async def evaluate_custom_tool(event: Any, config: _ToolConfig) -> CustomToolVerdict:
    """Evaluate policy for one ``agent.custom_tool_use``. Never raises Arcjet.

    A raise from this function would skip the ``user.custom_tool_result``
    the session is waiting on. The deny envelope is the only shape the
    model can read as a structured ``ArcjetDenialResult``.
    """
    action = config.action
    correlation_id = _resolve_correlation_id(None)
    metadata: Optional[Metadata] = None
    decision: Any = None

    try:
        arguments = _arguments_from_event(event)
        correlation_id = _correlation(config)
        extra = _resolved_metadata(config, arguments)
        metadata = _merged_metadata(config, extra, event=event)
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
            return CustomToolVerdict(deny=False)
        _emit_capture(
            client=config.guard,
            action=action,
            outcome="unavailable",
            correlation_id=correlation_id,
            decision=None,
            metadata=metadata,
        )
        return CustomToolVerdict(deny=True, payload=payload_from_block(None))

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
        return CustomToolVerdict(deny=True, payload=payload_from_block(decision))

    _emit_capture(
        client=config.guard,
        action=action,
        outcome=_outcome_for_completed_action(decision, degraded=prepared.degraded),
        correlation_id=correlation_id,
        decision=decision,
        metadata=metadata,
    )
    return CustomToolVerdict(deny=False)


def denial_event(event: Any, verdict: CustomToolVerdict) -> dict[str, Any]:
    """The real ``user.custom_tool_result`` a DENY must send."""
    payload = (
        verdict.payload if verdict.payload is not None else payload_from_block(None)
    )
    return custom_tool_result_event(
        custom_tool_use_id=_event_id(event),
        payload=payload,
        session_thread_id=_session_thread_id(event),
    )


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def _send_denial(
    *,
    send: Any,
    session_id: Any,
    event: Any,
    verdict: CustomToolVerdict,
) -> Any:
    body = denial_event(event, verdict)
    # Real SDK: ``send(session_id, events=[...])``.
    result = send(session_id, events=[body])
    return await _maybe_await(result)


def _is_already_guarded(tool: Any) -> bool:
    return bool(getattr(tool, _GUARD_BRAND, False))


def _brand(tool: Any) -> None:
    try:
        object.__setattr__(tool, _GUARD_BRAND, True)
    except AttributeError as exc:
        raise TypeError(
            "guard_custom_tool() could not brand the tool copy with "
            f"{_GUARD_BRAND!r}; the SDK type likely uses __slots__ "
            "without space for this attribute. The wrap cannot proceed "
            "without the brand — a second wrap would double-call Guard."
        ) from exc


def _invoke_run(run: Any, event: Any) -> Any:
    """Call a user ``run`` with the custom-tool event or its input.

    Hosted handlers typically take ``(name, input)`` or the event. A
    worker ``@beta_tool`` ``run`` takes the validated input mapping.
    Try the event first; if that TypeError-s on arity, pass input.
    """
    try:
        return run(event)
    except TypeError:
        return run(_arguments_from_event(event))


def _wrap_run_handler(config: _ToolConfig, run: Any) -> Callable[..., Any]:
    async def handle(
        event: Any,
        *,
        send: Any,
        session_id: Any,
    ) -> Any:
        try:
            verdict = await evaluate_custom_tool(event, config)
        except Exception:
            if config.on_guard_error == "allow":
                logger.warning(
                    "arcjet: policy for action %r could not be evaluated; "
                    "proceeding because on_guard_error is 'allow'",
                    config.action,
                )
                return await _maybe_await(_invoke_run(run, event))
            await _send_denial(
                send=send,
                session_id=session_id,
                event=event,
                verdict=CustomToolVerdict(deny=True, payload=payload_from_block(None)),
            )
            return None
        if verdict.deny:
            await _send_denial(
                send=send, session_id=session_id, event=event, verdict=verdict
            )
            return None
        return await _maybe_await(_invoke_run(run, event))

    return handle


def _wrap_tool_run(config: _ToolConfig, original: Any) -> Any:
    """Wrap a worker tool ``run`` so DENY never executes the body.

    The EnvironmentWorker / SessionToolRunner posts
    ``user.custom_tool_result`` from the return value. Returning the
    denial JSON is the same gate; we do not invent a second send.
    """

    async def guarded_run(*args: Any, **kwargs: Any) -> Any:
        event = _event_from_run_args(config.tool_name, args, kwargs)
        try:
            verdict = await evaluate_custom_tool(event, config)
        except Exception:
            if config.on_guard_error == "allow":
                return await _maybe_await(original(*args, **kwargs))
            return dumps_denial(payload_from_block(None))
        if verdict.deny:
            payload = (
                verdict.payload
                if verdict.payload is not None
                else payload_from_block(None)
            )
            return dumps_denial(payload)
        return await _maybe_await(original(*args, **kwargs))

    if inspect.iscoroutinefunction(inspect.unwrap(original)):
        return guarded_run

    def guarded_run_sync(*args: Any, **kwargs: Any) -> Any:
        return asyncio.run(guarded_run(*args, **kwargs))

    return guarded_run_sync


def _event_from_run_args(
    tool_name: str, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Rebuild an ``agent.custom_tool_use``-shaped mapping from ``run`` args."""
    if args and isinstance(args[0], Mapping) and "input" in args[0]:
        source = args[0]
        return {
            "type": "agent.custom_tool_use",
            "id": _event_id(source),
            "name": _tool_name(source, tool_name),
            "input": _arguments_from_event(source),
        }
    input_map: dict[str, Any] = {}
    if args and isinstance(args[0], Mapping):
        input_map = dict(args[0])
    elif kwargs:
        input_map = dict(kwargs)
    return {
        "type": "agent.custom_tool_use",
        "id": "",
        "name": tool_name,
        "input": input_map,
    }


def _has_run(tool: Any) -> bool:
    return callable(getattr(tool, "run", None))


def _wrap_tool_object(tool: Any, config: _ToolConfig) -> Any:
    if _is_already_guarded(tool):
        return tool
    if not _has_run(tool):
        raise TypeError(
            "guard_custom_tool(tool=) wraps an object with a callable run "
            f"(beta_tool / beta_async_tool), got {type(tool).__name__}"
        )
    guarded = copy.copy(tool)
    original = getattr(tool, "run")
    wrapped = _wrap_tool_run(config, original)
    try:
        object.__setattr__(guarded, "run", wrapped)
    except AttributeError:
        guarded.run = wrapped
    _brand(guarded)
    return guarded


def _validate_common(
    *,
    on_guard_error: OnGuardError,
    correlation_id: Optional[str],
    session_id: Optional[str],
    action: str,
) -> None:
    _require_anthropic()
    if on_guard_error not in ("allow", "deny"):
        raise ArcjetMisconfiguration(
            f"on_guard_error must be 'allow' or 'deny', got {on_guard_error!r}. "
            f"It decides whether a call runs when policy could not be "
            f"evaluated, so there is no safe value to guess."
        )
    if correlation_id is not None:
        _validated(correlation_id)
    if session_id is not None:
        _validated(session_id)
    if not isinstance(action, str) or not action:
        raise ArcjetMisconfiguration(
            "guard_custom_tool() needs a non-empty action string"
        )


def guard_custom_tool(
    *,
    guard: Any,
    action: str,
    run: Any = None,
    tool: Any = None,
    actor: ActorResolver = None,
    inputs: InputResolver = None,
    rules: RulesResolver = (),
    metadata: MetadataResolver = None,
    correlation_id: Optional[str] = None,
    session_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
) -> Any:
    """Gate an ``agent.custom_tool_use`` **before** the app executes.

    Pass ``run=`` for the hosted REST+SSE path. The returned handler is::

        await handler(event, send=client.beta.sessions.events.send, session_id=...)

    On DENY (or unevaluated policy under the default
    ``on_guard_error="deny"``) the original ``run`` is not called and
    ``user.custom_tool_result`` is sent with error text (schema field
    ``is_error`` is set). On ALLOW, ``run`` executes and the caller
    sends the success result.

    Pass ``tool=`` for a self-hosted ``EnvironmentWorker`` /
    ``@beta_tool`` object. The returned copy has ``run`` wrapped the
    same way; the worker posts the denial JSON as the tool result.
    Already-branded tools are returned unchanged. The ``ant`` CLI
    worker cannot register custom tools.

    Default ``permission_policy: always_allow`` for built-in / MCP
    tools on Anthropic's cloud **cannot** be gated. ``web_search`` /
    ``web_fetch`` always run on Anthropic. HITL ``always_ask`` is not
    policy.

    Args:
        guard: The Arcjet client. An async client is preferred; a blocking
            client is accepted.
        action: Checkpoint label, e.g. ``"email.sent"``.
        run: Hosted custom-tool body. Called with the
            ``agent.custom_tool_use`` event (or its ``input`` mapping).
        tool: A worker tool with ``run`` (``@beta_tool`` /
            ``@beta_async_tool``).
        actor: Who is acting, or a callable of the tool arguments.
        inputs: Policy inputs, or a callable of the tool arguments.
        rules: Local rules, or a callable of the tool arguments.
        metadata: Capture metadata, or a callable of the tool arguments.
        correlation_id: Caller-owned Sequence id. Never minted. Never an
            Anthropic session / event id we treated as ours.
        session_id: Same, for an id the application calls a session.
        on_guard_error: ``"deny"`` (default) or ``"allow"``.

    Raises:
        ArcjetMisconfiguration: *on_guard_error* is not ``"allow"`` or
            ``"deny"``, or the installed ``anthropic`` is below 0.92.0.
        TypeError: neither ``run`` nor ``tool`` was provided, or *tool*
            has no callable ``run``.
        ValueError: *correlation_id* / *session_id* is not printable ASCII
            within 256 bytes.
    """
    _validate_common(
        on_guard_error=on_guard_error,
        correlation_id=correlation_id,
        session_id=session_id,
        action=action,
    )
    if run is None and tool is None:
        raise TypeError("guard_custom_tool() needs run= or tool=")
    if run is not None and tool is not None:
        raise TypeError("guard_custom_tool() takes run= or tool=, not both")

    tool_name = ""
    if tool is not None:
        raw_name = getattr(tool, "name", None)
        if isinstance(raw_name, str):
            tool_name = raw_name
        if tool_name in _ANTHROPIC_CLOUD_ONLY:
            logger.warning(
                "arcjet: %s always runs on Anthropic; wrapping its local "
                "run does not gate the cloud tool",
                tool_name,
            )

    config = _ToolConfig(
        guard=guard,
        action=action,
        actor=actor,
        inputs=inputs,
        rules=rules,
        metadata=metadata,
        correlation_id=correlation_id,
        session_id=session_id,
        on_guard_error=on_guard_error,
        tool_name=tool_name,
    )

    if tool is not None:
        return _wrap_tool_object(tool, config)

    if not callable(run):
        raise TypeError(
            f"guard_custom_tool(run=) needs a callable, got {type(run).__name__}"
        )
    return _wrap_run_handler(config, run)
