"""Standalone CrewAI ``BaseTool`` wrap for tools you call yourself.

``BaseTool.run`` / ``_run`` do not dispatch ``PRE_TOOL_CALL``. A tool invoked
outside a crew — a worker, a test, an MCP handler you call directly — never
hits the registrar. This wrap is the authored-tool checkpoint for that path,
and it is the only CrewAI surface that raises
:class:`~arcjet.guard.ArcjetDeniedError` /
:class:`~arcjet.guard.ArcjetUnavailableError`. The hook path cannot: CrewAI
swallows those and the tool would run.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextvars import ContextVar
from typing import Any, Optional

from arcjet._errors import ArcjetMisconfiguration
from arcjet._metadata import Metadata

from .._checkpoint import ResolvedInputs, run_checkpoint, run_checkpoint_sync
from .._context import _validated
from .._errors import ArcjetDeniedError, ArcjetUnavailableError, OnGuardError
from .._policy_input import PolicyInputMap
from .._registry import _awaitable, _blocking
from .._rules import RuleWithInput
from ._hooks import mark_guarded_tool
from ._import import load_crewai_base_tool
from ._names import free_text_arguments

_in_checkpoint: ContextVar[bool] = ContextVar(
    "arcjet_crewai_tool_checkpoint", default=False
)

ActorResolver = str | Callable[[Mapping[str, Any]], Optional[str]] | None
InputResolver = (
    PolicyInputMap | Callable[[Mapping[str, Any]], Optional[PolicyInputMap]] | None
)


def _arguments_from_call(
    args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Mapping[str, Any]:
    if kwargs:
        return free_text_arguments(kwargs)
    if len(args) == 1 and isinstance(args[0], dict):
        return free_text_arguments(args[0])
    if len(args) == 1 and isinstance(args[0], str):
        return {"input": args[0]}
    return {}


def _resolve(source: Any, arguments: Mapping[str, Any]) -> Any:
    if source is None or not callable(source):
        return source
    return source(arguments)


def guard_tool(
    *,
    guard: Any,
    tool: Any,
    action: str,
    actor: ActorResolver = None,
    inputs: InputResolver = None,
    rules: Sequence[RuleWithInput] = (),
    metadata: Optional[Metadata] = None,
    correlation_id: Optional[str] = None,
    on_guard_error: OnGuardError = "deny",
) -> Any:
    """Wrap a CrewAI ``BaseTool`` you call yourself with a fail-closed checkpoint.

    The wrapped tool evaluates policy and then hands the call to *tool*. A
    ``DENY`` raises :class:`~arcjet.guard.ArcjetDeniedError`; an unevaluated
    policy under the default ``on_guard_error="deny"`` raises
    :class:`~arcjet.guard.ArcjetUnavailableError`. The tool body does not run
    in either case.

    Use this when you invoke the tool directly. Tools a crew executes are
    gated by :func:`register_arcjet_hooks` instead — ``BaseTool.run`` never
    sees ``PRE_TOOL_CALL``. A tool that is both wrapped and executed by a
    crew whose hooks are registered is evaluated once: the hook skips a
    branded wrap.

    Args:
        guard: The Arcjet client. A sync call needs a blocking client; an
            async call needs an awaitable one.
        tool: A CrewAI ``BaseTool`` (or ``Tool``).
        action: Checkpoint label, e.g. ``"email.sent"``.
        actor: Who is acting, or a callable of the free-text arguments.
        inputs: Policy inputs, or a callable of the free-text arguments.
        rules: Local rules. Empty still contacts Guard.
        metadata: Capture metadata.
        correlation_id: Caller-owned Sequence id. Falls back to
            :func:`~arcjet.guard.arcjet_sequence`. Never minted.
        on_guard_error: ``"deny"`` (default) or ``"allow"``.
    """
    if on_guard_error not in ("allow", "deny"):
        raise ArcjetMisconfiguration(
            f"on_guard_error must be 'allow' or 'deny', got {on_guard_error!r}. "
            f"It decides whether a call runs when policy could not be "
            f"evaluated, so there is no safe value to guess."
        )
    base_tool = load_crewai_base_tool()
    if not isinstance(tool, base_tool):
        raise TypeError(
            f"guard_tool() wraps a CrewAI BaseTool, got {type(tool).__name__}"
        )
    if correlation_id is not None:
        _validated(correlation_id)

    blocking = _blocking(guard, "guard_sync", "guard")
    awaitable = _awaitable(guard, "guard")

    def prepare(args: tuple[Any, ...], kwargs: dict[str, Any]) -> ResolvedInputs:
        arguments = _arguments_from_call(args, kwargs)
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

    def checkpoint_sync(
        fn: Callable[[], Any], args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> Any:
        if _in_checkpoint.get():
            return fn()
        if blocking is None:
            raise TypeError(
                "A synchronous CrewAI tool call requires a guard client with a "
                "blocking guard(), such as ArcjetGuardSync"
            )
        token = _in_checkpoint.set(True)
        try:
            return run_checkpoint_sync(
                fn,
                action=action,
                guard=guard,
                prepare=lambda: prepare(args, kwargs),
                rules=rules,
                metadata=metadata,
                correlation_id=correlation_id,
                on_guard_error=on_guard_error,
                denied_error=ArcjetDeniedError,
                unavailable_error=lambda act, cause: ArcjetUnavailableError(
                    act, cause=cause
                ),
            )
        finally:
            _in_checkpoint.reset(token)

    async def checkpoint_async(
        fn: Callable[[], Awaitable[Any]], args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> Any:
        if _in_checkpoint.get():
            return await fn()
        if awaitable is None:
            raise TypeError(
                "An asynchronous CrewAI tool call requires a guard client with an "
                "awaitable guard(), such as ArcjetGuard"
            )
        token = _in_checkpoint.set(True)
        try:
            return await run_checkpoint(
                fn,
                action=action,
                guard=guard,
                prepare=lambda: _async_prepare(prepare, args, kwargs),
                rules=rules,
                metadata=metadata,
                correlation_id=correlation_id,
                on_guard_error=on_guard_error,
                denied_error=ArcjetDeniedError,
                unavailable_error=lambda act, cause: ArcjetUnavailableError(
                    act, cause=cause
                ),
            )
        finally:
            _in_checkpoint.reset(token)

    guarded = _copy_tool(tool)
    _install_checkpoints(guarded, checkpoint_sync, checkpoint_async)
    object.__setattr__(guarded, "_arcjet_guarded", True)
    mark_guarded_tool(guarded)
    mark_guarded_tool(tool)
    return guarded


async def _async_prepare(
    prepare: Callable[[tuple[Any, ...], dict[str, Any]], ResolvedInputs],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> ResolvedInputs:
    return prepare(args, kwargs)


def _copy_tool(tool: Any) -> Any:
    copy = getattr(tool, "model_copy", None)
    if callable(copy):
        return copy()
    return tool


def _bound(instance: Any, name: str) -> Any:
    method = getattr(type(instance), name, None)
    if method is None:
        return getattr(instance, name, None)
    descriptor = getattr(method, "__get__", None)
    if callable(descriptor):
        return descriptor(instance, type(instance))
    return method


def _install_checkpoints(
    tool: Any,
    checkpoint_sync: Callable[..., Any],
    checkpoint_async: Callable[..., Any],
) -> None:
    original_run = _bound(tool, "run")
    original_arun = _bound(tool, "arun")
    original_run_impl = _bound(tool, "_run")
    original_arun_impl = _bound(tool, "_arun")
    original_func = getattr(tool, "func", None)

    def run(*args: Any, **kwargs: Any) -> Any:
        return checkpoint_sync(lambda: original_run(*args, **kwargs), args, kwargs)

    async def arun(*args: Any, **kwargs: Any) -> Any:
        return await checkpoint_async(
            lambda: original_arun(*args, **kwargs), args, kwargs
        )

    object.__setattr__(tool, "run", run)
    object.__setattr__(tool, "arun", arun)

    if callable(original_run_impl):

        def _run(*args: Any, **kwargs: Any) -> Any:
            return checkpoint_sync(
                lambda: original_run_impl(*args, **kwargs), args, kwargs
            )

        object.__setattr__(tool, "_run", _run)

    if callable(original_arun_impl):

        async def _arun(*args: Any, **kwargs: Any) -> Any:
            return await checkpoint_async(
                lambda: original_arun_impl(*args, **kwargs), args, kwargs
            )

        object.__setattr__(tool, "_arun", _arun)

    if callable(original_func):

        def func(*args: Any, **kwargs: Any) -> Any:
            return checkpoint_sync(lambda: original_func(*args, **kwargs), args, kwargs)

        object.__setattr__(tool, "func", func)
