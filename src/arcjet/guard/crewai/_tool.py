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
from ._hooks import _GUARD_BRAND
from ._import import load_crewai_base_tool

#: The guarded tools whose checkpoint is already running on this call stack.
#: A guarded tool advertises several entrypoints that call one another —
#: ``run`` calls ``_run``, which for a ``Tool`` calls ``func`` — and each one
#: is guarded, so a single call would otherwise evaluate policy several times.
#:
#: Holds the tool objects rather than a bare flag, because a tool body may
#: legitimately call *another* guarded tool (or start a crew that does), and
#: that inner call is a separate effect that must be evaluated. A flag skipped
#: it, which was a fail-open.
_active: ContextVar[tuple[Any, ...]] = ContextVar(
    "arcjet_crewai_active_tools", default=()
)

ActorResolver = str | Callable[[Mapping[str, Any]], Optional[str]] | None
InputResolver = (
    PolicyInputMap | Callable[[Mapping[str, Any]], Optional[PolicyInputMap]] | None
)


def _arguments_from_call(
    args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Mapping[str, Any]:
    """The call's arguments as a mapping, for a resolver to read.

    Keyword arguments describe themselves, and so does a single mapping
    argument. A single positional value cannot be named from here — the tool's
    own schema is what names it — so it is offered under ``"input"``.
    """
    if kwargs:
        return dict(kwargs)
    if len(args) == 1 and isinstance(args[0], Mapping):
        return dict(args[0])
    if len(args) == 1:
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

    Returns a copy of *tool* whose entrypoints evaluate policy first. A
    ``DENY`` raises :class:`~arcjet.guard.ArcjetDeniedError`; an unevaluated
    policy under the default ``on_guard_error="deny"`` raises
    :class:`~arcjet.guard.ArcjetUnavailableError`. The tool body does not run
    in either case. One call evaluates once, however deep the tool's own
    entrypoints delegate.

    Use this when you invoke the tool directly. Tools a crew executes are
    gated by :func:`register_arcjet_hooks` instead — ``BaseTool.run`` never
    sees ``PRE_TOOL_CALL``.

    Give the crew the tool this returns, not the one you passed in: the copy
    carries the brand the hook reads to avoid evaluating the same call twice,
    and the original stays unguarded on purpose so that handing it to a crew
    is still covered by the hook.

    Args:
        guard: The Arcjet client. A sync call needs a blocking client; an
            async call needs an awaitable one.
        tool: A CrewAI ``BaseTool`` (or ``Tool``).
        action: Checkpoint label, e.g. ``"email.sent"``.
        actor: Who is acting, or a callable of the call's arguments.
        inputs: Policy inputs, or a callable of the call's arguments.
        rules: Local rules. Empty still contacts Guard.
        metadata: Capture metadata.
        correlation_id: Caller-owned Sequence id. Falls back to
            :func:`~arcjet.guard.arcjet_sequence`. Never minted.
        on_guard_error: ``"deny"`` (default) or ``"allow"``.

    Raises:
        ArcjetMisconfiguration: *on_guard_error* is not ``"allow"`` or
            ``"deny"``.
        TypeError: *tool* is not a CrewAI ``BaseTool``.
        ValueError: *correlation_id* is not printable ASCII within 256 bytes.
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
    guarded = _copy_tool(tool)

    def prepare(args: tuple[Any, ...], kwargs: dict[str, Any]) -> ResolvedInputs:
        """What the decision is made from; a failed resolver is reported.

        Reported rather than raised for the same reason as every other Arcjet
        checkpoint: Guard still sees the call, so it stays on the record, and
        ``on_guard_error`` decides whether a partly-judged call may run.
        """
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
        if _is_active(guarded):
            return fn()
        if blocking is None:
            raise TypeError(
                "A synchronous CrewAI tool call requires a guard client with a "
                "blocking guard(), such as ArcjetGuardSync"
            )
        token = _activate(guarded)
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
            _active.reset(token)

    async def checkpoint_async(
        fn: Callable[[], Awaitable[Any]], args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> Any:
        if _is_active(guarded):
            return await fn()
        if awaitable is None:
            raise TypeError(
                "An asynchronous CrewAI tool call requires a guard client with an "
                "awaitable guard(), such as ArcjetGuard"
            )
        token = _activate(guarded)
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
            _active.reset(token)

    _install_checkpoints(guarded, checkpoint_sync, checkpoint_async)
    # Only the copy is branded. Branding the original as well would make the
    # PRE_TOOL_CALL hook skip a crew that was handed the unwrapped tool, which
    # is a fail-open.
    object.__setattr__(guarded, _GUARD_BRAND, True)
    return guarded


def _is_active(tool: Any) -> bool:
    return any(active is tool for active in _active.get())


def _activate(tool: Any) -> Any:
    return _active.set((*_active.get(), tool))


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
    """*name* bound to *instance*, taken from its class.

    Read off the class so that installing the checkpoints does not capture a
    callable this function already replaced — otherwise wrapping twice would
    nest the checkpoint inside itself.
    """
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
    """Put the checkpoint in front of every entrypoint the tool advertises.

    ``run``/``arun`` are what a caller uses, ``_run``/``_arun`` are what a
    subclass overrides and what ``to_structured_tool()`` hands CrewAI as
    ``func``, and ``func`` is what a ``Tool`` executes. All of them are
    guarded, and the re-entrancy record keeps one call to one evaluation.
    """
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
