"""Custom-tool gate for Claude Managed Agents.

On ``agent.custom_tool_use`` Guard runs **before** the app handler. On
DENY the original does not run and the wrapper sends a real
``user.custom_tool_result`` via ``sessions.events.send``. There is no
PreToolUse.

A ``tool=`` object with ``call`` (the Python ``@beta_tool`` /
``@beta_async_tool`` / ``BetaFunctionTool.call`` shape that
``SessionToolRunner`` invokes) is wrapped the same way for a
self-hosted ``EnvironmentWorker``. The CLI worker cannot register
custom tools.
"""

from __future__ import annotations

import asyncio
import copy
import inspect
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Optional

from arcjet._errors import ArcjetMisconfiguration
from arcjet._logging import logger

from .._context import _validated
from .._errors import OnGuardError
from ._common import (
    TOOL_METADATA_KEY,
    ActorResolver,
    InputResolver,
    MetadataResolver,
    RulesResolver,
    _read,
    adopt_wrapper,
    brand,
    evaluate_checkpoint,
    is_already_guarded,
    looks_async,
    maybe_await,
    run_coroutine_sync,
)
from ._denial import (
    ArcjetDenialResult,
    custom_tool_result_event,
    payload_from_block,
    raise_worker_denial,
)
from ._import import _require_anthropic

#: How many times a hosted deny ``send`` is attempted before giving up.
DENIAL_SEND_ATTEMPTS = 3
#: Backoff between deny-send retries. Tests monkeypatch this to zeros.
DENIAL_SEND_BACKOFF_SECONDS: tuple[float, ...] = (0.05, 0.15)


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


#: Built-in toolset names. ``web_search`` / ``web_fetch`` always run on
#: Anthropic. Cloud bash/read/write under default ``always_allow`` cannot
#: be gated. A self-hosted worker *does* execute bash/read/write locally;
#: wrapping those is the caller's choice via ``tool=``, not an automatic
#: factory rewrite of the stock toolset.
_ANTHROPIC_CLOUD_ONLY = frozenset({"web_search", "web_fetch"})


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


def _reserved_tool_metadata(event: Any, config: _ToolConfig) -> dict[str, Any]:
    reserved: dict[str, Any] = {}
    name = _tool_name(event, config.tool_name)
    if name:
        reserved[TOOL_METADATA_KEY] = name
    return reserved


async def evaluate_custom_tool(event: Any, config: _ToolConfig) -> CustomToolVerdict:
    """Evaluate policy for one ``agent.custom_tool_use``. Never raises Arcjet.

    A raise from this function would skip the ``user.custom_tool_result``
    the session is waiting on. The deny envelope is the only shape the
    model can read as a structured ``ArcjetDenialResult``.
    """
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
        arguments=_arguments_from_event(event),
        reserved_metadata=_reserved_tool_metadata(event, config),
    )
    if outcome.proceeded_open:
        return CustomToolVerdict(deny=False)
    if outcome.failure is not None:
        return CustomToolVerdict(
            deny=True, payload=payload_from_block(outcome.decision)
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


async def _send_denial(
    *,
    send: Any,
    anthropic_session_id: Any,
    event: Any,
    verdict: CustomToolVerdict,
) -> Any:
    """Post the deny result, retrying transient send failures.

    ``SessionToolRunner`` retries result posts; the hosted path must too,
    or the session stays idle on ``agent.custom_tool_use``.
    """
    body = denial_event(event, verdict)
    last_error: Optional[BaseException] = None
    attempts = max(1, DENIAL_SEND_ATTEMPTS)
    for attempt in range(attempts):
        try:
            return await maybe_await(
                send(anthropic_session_id, events=[body])
            )
        except Exception as exc:
            last_error = exc
            if attempt + 1 >= attempts:
                raise
            delay_index = min(attempt, len(DENIAL_SEND_BACKOFF_SECONDS) - 1)
            if delay_index >= 0 and DENIAL_SEND_BACKOFF_SECONDS:
                await asyncio.sleep(DENIAL_SEND_BACKOFF_SECONDS[delay_index])
    if last_error is not None:  # pragma: no cover - loop always raises
        raise last_error
    return None


def _positional_param_names(fn: Any) -> Optional[list[str]]:
    """Positional / named-positional parameter names, or ``None`` if unknown."""
    try:
        signature = inspect.signature(fn)
    except (TypeError, ValueError):
        return None
    names: list[str] = []
    for param in signature.parameters.values():
        if param.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
        if param.name in {"self", "cls"}:
            continue
        if param.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            names.append(param.name)
    return names


def _invoke_run(run: Any, event: Any) -> Any:
    """Call a hosted ``run`` from its signature. Never catches a body error.

    Contracts, in order:

    * ``(name, input)`` / ``(tool_name, arguments)``
    * a single ``input`` / ``arguments`` mapping
    * the ``agent.custom_tool_use`` event (the default)
    """
    names = _positional_param_names(run)
    if names is not None and len(names) >= 2:
        first, second = names[0], names[1]
        if first in {"name", "tool_name"} and second in {"input", "arguments"}:
            return run(_tool_name(event), _arguments_from_event(event))
    if names is not None and len(names) == 1 and names[0] in {"input", "arguments"}:
        return run(_arguments_from_event(event))
    return run(event)


def _wrap_run_handler(config: _ToolConfig, run: Any) -> Callable[..., Any]:
    async def handle(
        event: Any,
        *,
        send: Any,
        anthropic_session_id: Any,
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
                return await maybe_await(_invoke_run(run, event))
            await _send_denial(
                send=send,
                anthropic_session_id=anthropic_session_id,
                event=event,
                verdict=CustomToolVerdict(deny=True, payload=payload_from_block(None)),
            )
            return None
        if verdict.deny:
            await _send_denial(
                send=send,
                anthropic_session_id=anthropic_session_id,
                event=event,
                verdict=verdict,
            )
            return None
        return await maybe_await(_invoke_run(run, event))

    adopt_wrapper(handle, run)
    return handle


def _event_from_call_args(
    tool_name: str, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Rebuild an ``agent.custom_tool_use``-shaped mapping from ``call`` args.

    ``SessionToolRunner`` invokes ``tool.call(input)`` with the model input
    mapping. A mapping is treated as a full event only when it *is* one
    (``type == agent.custom_tool_use``), not merely because it has an
    ``input`` key — that is a legal tool-schema field.
    """
    if (
        args
        and isinstance(args[0], Mapping)
        and args[0].get("type") == "agent.custom_tool_use"
    ):
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
    elif "input" in kwargs and isinstance(kwargs["input"], Mapping):
        input_map = dict(kwargs["input"])
    elif kwargs:
        input_map = dict(kwargs)
    return {
        "type": "agent.custom_tool_use",
        "id": "",
        "name": tool_name,
        "input": input_map,
    }


def _wrap_tool_call(config: _ToolConfig, original: Any) -> Any:
    """Wrap a worker tool ``call`` so DENY never executes the body.

    ``SessionToolRunner`` posts ``user.custom_tool_result`` from the
    return value and sets ``is_error`` only when ``call`` raises.
    Returning denial JSON would look like success. Raising
    ``ToolError`` (or :class:`~._denial.WorkerToolDenied` without the
    extra) is the honest deny.
    """

    async def guarded_call(*args: Any, **kwargs: Any) -> Any:
        event = _event_from_call_args(config.tool_name, args, kwargs)
        try:
            verdict = await evaluate_custom_tool(event, config)
        except Exception:
            if config.on_guard_error == "allow":
                return await maybe_await(original(*args, **kwargs))
            raise_worker_denial(payload_from_block(None))
        if verdict.deny:
            payload = (
                verdict.payload
                if verdict.payload is not None
                else payload_from_block(None)
            )
            raise_worker_denial(payload)
        return await maybe_await(original(*args, **kwargs))

    if looks_async(original):
        adopt_wrapper(guarded_call, original)
        return guarded_call

    def guarded_call_sync(*args: Any, **kwargs: Any) -> Any:
        return run_coroutine_sync(guarded_call(*args, **kwargs))

    adopt_wrapper(guarded_call_sync, original)
    return guarded_call_sync


def _has_call(tool: Any) -> bool:
    return callable(getattr(tool, "call", None))


def _wrap_tool_object(tool: Any, config: _ToolConfig) -> Any:
    if is_already_guarded(tool):
        return tool
    if not _has_call(tool):
        raise TypeError(
            "guard_custom_tool(tool=) wraps an object with a callable call "
            f"(BetaFunctionTool / @beta_tool / @beta_async_tool), got "
            f"{type(tool).__name__}"
        )
    guarded = copy.copy(tool)
    original = getattr(tool, "call")
    wrapped = _wrap_tool_call(config, original)
    try:
        object.__setattr__(guarded, "call", wrapped)
    except AttributeError:
        guarded.call = wrapped
    brand(guarded)
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

        await handler(
            event,
            send=client.beta.sessions.events.send,
            anthropic_session_id=session.id,
        )

    ``anthropic_session_id`` is Anthropic's ``ses_...``, used only to post
    ``user.custom_tool_result``. Wrap-time ``session_id=`` is a
    caller-owned correlation id and is never read off that value.

    On DENY (or unevaluated policy under the default
    ``on_guard_error="deny"``) the original ``run`` is not called and
    ``user.custom_tool_result`` is sent with error text (schema field
    ``is_error`` is set). Transient send failures are retried. On ALLOW,
    ``run`` executes and the caller sends the success result.

    Pass ``tool=`` for a self-hosted ``EnvironmentWorker`` /
    ``@beta_tool`` object. The returned copy has ``call`` wrapped — that
    is what ``SessionToolRunner`` invokes, not ``run``. On DENY the
    wrapper raises ``ToolError`` so the runner posts ``is_error=True``.
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
            ``agent.custom_tool_use`` event, its ``input`` mapping, or
            ``(name, input)`` — chosen from the callable's signature.
        tool: A worker tool with ``call`` (``@beta_tool`` /
            ``@beta_async_tool`` / ``BetaFunctionTool``).
        actor: Who is acting, or a callable of the tool arguments.
        inputs: Policy inputs, or a callable of the tool arguments.
        rules: Local rules, or a callable of the tool arguments.
        metadata: Capture metadata, or a callable of the tool arguments.
        correlation_id: Caller-owned Sequence id. Never minted. Never an
            Anthropic session / event id we treated as ours.
        session_id: Same, for an id the application calls a session.
            Not Anthropic's ``ses_...``.
        on_guard_error: ``"deny"`` (default) or ``"allow"``.

    Raises:
        ArcjetMisconfiguration: *on_guard_error* is not ``"allow"`` or
            ``"deny"``, or the installed ``anthropic`` is below 0.92.0.
        TypeError: neither ``run`` nor ``tool`` was provided, or *tool*
            has no callable ``call``.
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
                "call does not gate the cloud tool",
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
