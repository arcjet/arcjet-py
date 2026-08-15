"""Optional LangChain tool checkpoint integration.

Install ``arcjet[langchain]`` to use this module. Core Guard clients do not
import LangChain.

A guarded tool is an instance of the wrapped tool's own class — a generated
subclass — that evaluates policy and then hands the call to the tool it wraps.
Everything the framework derives from a tool — its schema, its arguments — is
asked of the wrapped tool rather than recomputed here, so a guarded tool
advertises and executes exactly what the unguarded one did.
"""

from __future__ import annotations

import functools
import inspect
import threading
from collections.abc import (
    Awaitable,
    Callable,
    Iterator,
    Mapping,
    MutableMapping,
    Sequence,
)
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Literal, cast
from weakref import ReferenceType, WeakKeyDictionary, ref

from langchain_core.callbacks import (
    AsyncCallbackManager,
    CallbackManager,
)
from langchain_core.messages import ToolMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.runnables.config import ensure_config
from langchain_core.tools import BaseTool, ToolException
from langchain_core.tools.base import FILTERED_ARGS
from langchain_core.tools.simple import Tool as SimpleTool
from pydantic import BaseModel, PrivateAttr, ValidationError
from pydantic.v1 import ValidationError as ValidationErrorV1

from arcjet._errors import ArcjetMisconfiguration
from arcjet._logging import logger

from ._client import GuardClient
from ._policy_input import PolicyInputMap
from ._registry import _awaitable, _blocking, registered_client
from ._rules import RuleWithInput
from ._types import Decision

OnGuardError = Literal["allow", "deny"]
ActorResolver = str | Callable[[RunnableConfig], str]
InputResolver = (
    PolicyInputMap | Callable[[Mapping[str, Any], RunnableConfig], PolicyInputMap]
)
AsyncActorResolver = str | Callable[[RunnableConfig], str | Awaitable[str]]
AsyncInputResolver = (
    PolicyInputMap
    | Callable[
        [Mapping[str, Any], RunnableConfig], PolicyInputMap | Awaitable[PolicyInputMap]
    ]
)

# The callable halves of the aliases above. `callable()` narrows a union
# containing a Mapping to something no type checker will call, so the call
# sites name the shape they already know.
_ActorFn = Callable[[RunnableConfig], "str | Awaitable[str]"]
_InputsFn = Callable[
    [Mapping[str, Any], RunnableConfig], "PolicyInputMap | Awaitable[PolicyInputMap]"
]


class ArcjetToolDeniedError(ToolException):
    """Raised when Arcjet policy denies a LangChain tool call."""

    def __init__(self, action: str, decision: Decision) -> None:
        super().__init__(f'Arcjet denied action "{action}" ({decision.reason})')
        self.action = action
        self.decision = decision


class ArcjetToolUnavailableError(ToolException):
    """Raised when a required Arcjet policy cannot be evaluated."""

    def __init__(self, action: str, *, cause: BaseException | None = None) -> None:
        super().__init__(f'Arcjet policy for "{action}" could not be evaluated')
        self.action = action
        # Only when there is one. Assigning `None` sets `__suppress_context__`,
        # which hides the context Python would otherwise have chained on and
        # leaves the traceback saying nothing about why evaluation failed.
        if cause is not None:
            self.__cause__ = cause


# What the checkpoint raises to stop a call, as one except clause.
_BLOCKED = (ArcjetToolDeniedError, ArcjetToolUnavailableError)

# What a tool's own schema raises when it rejects a call's arguments. Both
# flavours, because langchain-core accepts a pydantic v1 `args_schema` and
# `BaseTool.run` catches both before running `handle_validation_error`; seeing
# only one of them turns a routine, model-recoverable mistake into an outage.
_SCHEMA_REJECTED = (ValidationError, ValidationErrorV1)


@contextmanager
def _reporting(action: str) -> Iterator[None]:
    """Swallow and log a failure to report on the callbacks.

    A trace is observational: a callback handler that fails must not turn a
    denial into some other error.
    """
    try:
        yield
    except Exception:
        logger.warning(
            "arcjet: could not report a blocked call to %r on its callbacks",
            action,
            exc_info=True,
        )


@contextmanager
def _fail_closed(action: str, on_guard_error: OnGuardError) -> Iterator[None]:
    """Turn a failure to evaluate policy into the outcome ``on_guard_error`` asks for.

    Anything the checkpoint raises to stop a call passes through: it is the
    evaluation's result, not a failure to reach one. Anything else means policy
    was not evaluated, which is what ``on_guard_error`` governs.

    Shared by both evaluators because the rule is the same for each, and one
    that drifted would have the two flavours raise differently-shaped errors
    for the same failure.
    """
    try:
        yield
    except _BLOCKED:
        raise
    except Exception as exc:
        if on_guard_error == "deny":
            raise ArcjetToolUnavailableError(action, cause=exc) from exc
        # Allowing the call is not the same as there being nothing to report.
        # A resolver that raises on every call leaves policy permanently
        # unevaluated, and without this the tool looks guarded while no
        # decision is being made — the one failure mode with no other symptom.
        logger.warning(
            "arcjet: could not evaluate policy for a call to %r; "
            "the call proceeds because on_guard_error is 'allow'",
            action,
            exc_info=exc,
        )


@dataclass(frozen=True, slots=True)
class _Report:
    """What the caller told ``run`` about the run it expected to open.

    ``BaseTool.run`` reports a call from these, so a blocked call is reported
    from the same values — including the caller's own ``run_id``, which is how
    a trace is correlated back to the call that asked for it.
    """

    callbacks: Any
    tags: list[str] | None
    metadata: dict[str, Any] | None
    run_name: str | None
    run_id: Any
    tool_call_id: str | None

    @classmethod
    def of(cls, config: RunnableConfig, tool_call_id: str | None) -> "_Report":
        """The same values ``BaseTool.invoke`` would hand its own ``run``."""
        return cls(
            config.get("callbacks"),
            config.get("tags"),
            config.get("metadata"),
            config.get("run_name"),
            config.get("run_id"),
            tool_call_id,
        )


def _unwrap_tool_call(value: Any) -> tuple[Any, str | None]:
    """A ToolCall-shaped input split into its arguments and its id.

    The arguments are copied for the same reason ``_prep_run_args`` copies
    them: they are usually the ``args`` of a ``ToolCall`` living in message
    history, and the tool's own parsing writes into the mapping it is given.
    """
    if isinstance(value, dict) and value.get("type") == "tool_call":
        args = value.get("args", {})
        return (dict(args) if isinstance(args, Mapping) else args), value.get("id")
    return value, None


def _has_derivable_schema(tool: BaseTool) -> bool:
    """Whether ``tool_call_schema`` describes this tool's actual arguments.

    A ``Tool`` built from a bare function declares no schema, so the property
    falls back to introspecting ``Tool._run(*args, config, **kwargs)`` and
    reports that signature instead. LangChain works around this with the same
    concrete-class check when it advertises such a tool.
    """
    return not (isinstance(tool, SimpleTool) and not tool.args_schema)


def _arguments(tool: BaseTool, raw: Any, tool_call_id: str | None) -> Mapping[str, Any]:
    """The arguments the tool is about to receive, as the tool itself reads them.

    Delegates to the tool's own ``_parse_input`` rather than re-deriving the
    rule from ``tool_call_schema``: that schema is not the parsing contract for
    every tool, and regenerating it drops the author's field validators, which
    would show a resolver a different value than the tool runs with.

    The input is copied first, because ``_parse_input`` writes into the mapping
    it is given and that mapping is usually the ``args`` of a ``ToolCall``
    living in message history.

    Raises whatever the tool's own validation raises. Callers treat resolving
    arguments as best-effort and evaluate policy regardless — a call whose
    arguments cannot be read is still a call.
    """
    if isinstance(raw, Mapping):
        raw = dict(raw)

    parsed = tool._parse_input(raw, tool_call_id)
    if not isinstance(parsed, dict):
        # A bare string comes back unchanged. LangChain binds it to the
        # schema's first field whatever the field count, so key it the same way
        # rather than inventing a name the tool will never use.
        names = list(tool.args)
        return {names[0]: parsed} if names else {"input": parsed}

    # `_parse_input` re-adds arguments the framework injects — credentials,
    # graph state, the tool call id — that `tool_call_schema` hides from the
    # model. A policy resolver must not be handed those. Only that schema
    # identifies them, so filtering happens only when it can say so; the
    # alternative, `tool.args`, names a different key-space for a tool whose
    # arguments the model supplies positionally.
    schema = tool.tool_call_schema
    if (
        _has_derivable_schema(tool)
        and isinstance(schema, type)
        and issubclass(schema, BaseModel)
    ):
        visible = set(schema.model_fields)
        parsed = {key: value for key, value in parsed.items() if key in visible}

    # Nested models come back as instances. Resolvers are documented to take a
    # `Mapping[str, Any]`, so hand them data rather than model objects.
    return {
        key: value.model_dump() if isinstance(value, BaseModel) else value
        for key, value in parsed.items()
    }


def _check_decision(
    decision: Decision, action: str, on_guard_error: OnGuardError
) -> None:
    if decision.conclusion == "DENY":
        raise ArcjetToolDeniedError(action, decision)
    if decision.has_failed_open() and on_guard_error == "deny":
        raise ArcjetToolUnavailableError(action)


def _handles_tool_errors(tool: BaseTool) -> bool:
    """Whether *tool* converts a ``ToolException`` rather than raising it.

    Asked before the handler runs, so that a handler which raises is not
    mistaken for there being no handler at all: its exception is the tool
    author's, and it belongs to the caller.
    """
    handler = tool.handle_tool_error
    return isinstance(handler, str) or handler is True or callable(handler)


def _handle_tool_exception(
    tool: BaseTool, error: ToolException, tool_call_id: str | None
) -> Any:
    handler = tool.handle_tool_error
    if isinstance(handler, str):
        content = handler
    elif handler is True:
        content = error.args[0] if error.args else "Tool execution error"
    elif callable(handler):
        content = cast(Callable[[ToolException], str], handler)(error)
    else:
        raise error
    if tool_call_id is not None:
        return ToolMessage(
            content=cast(Any, content),
            tool_call_id=tool_call_id,
            name=tool.name,
            status="error",
        )
    return content


# ``repr=False`` because this holds the Arcjet client, whose own repr renders
# the API key. A dataclass repr would put that key in any traceback captured
# with locals, which is what pytest --showlocals and most error reporters do.
@dataclass(frozen=True, slots=True, repr=False)
class _Policy:
    """What guarding one tool needs, held apart from the tool's own fields."""

    guard: GuardClient
    action: str
    actor: ActorResolver | AsyncActorResolver | None
    inputs: InputResolver | AsyncInputResolver | None
    rules: tuple[RuleWithInput, ...]
    on_guard_error: OnGuardError
    # Which of the client's two spellings answers each flavour, resolved once.
    # The client cannot change flavour for the life of a guarded tool, so
    # asking it on every call is introspection with one possible answer.
    blocking: Callable[..., Any] | None
    awaitable: Callable[..., Awaitable[Any]] | None


class _UnreadableArguments(Exception):
    """The call's arguments could not be read, and the tool may still run.

    Distinct from arguments the tool's own schema rejects: those stop the tool
    before its body, so an input rule has no effect to protect. This means the
    rule was configured, could not see what it was meant to evaluate, and the
    call would otherwise proceed — an unevaluated policy, which is what
    ``on_guard_error`` governs.
    """


class _GuardMixin:
    """The checkpoint, in front of a tool this wrapper delegates to.

    Never used as a base class.  Its members are copied into the namespace of
    each generated wrapper (see :func:`_guarded_class`), because a wrapper that
    inherited this as well as the tool's own class could not be guarded a
    second time: the second wrapper would need this ahead of a class that
    already has it behind, which is not a linearizable MRO.  A namespace entry
    has no such constraint and still beats every base.

    It follows that nothing here may use a zero-argument ``super()``, whose
    ``__class__`` cell would still name this class after the copy and no longer
    match the instance.
    """

    _arcjet: _Policy
    _arcjet_tool: BaseTool

    def get_input_schema(self, config: RunnableConfig | None = None) -> Any:
        # The one schema override: everything else that reports a schema —
        # `tool_call_schema`, `args`, the provider conversions — derives from
        # this on the base class, so forwarding here forwards them all.
        if self._arcjet_owns_schema():
            return BaseTool.get_input_schema(cast(BaseTool, self), config)
        return self._arcjet_tool.get_input_schema(config)

    def _arcjet_owns_schema(self) -> bool:
        """Whether this wrapper's own ``args_schema`` should be believed.

        The wrapper is handed a copy of the wrapped tool's ``args_schema`` and
        normally has nothing to add, so the derivation is forwarded to the tool
        that owns it — which is the only way a tool declaring no schema gets
        one, since it is derived from a ``_run`` this wrapper does not have.
        Reassigning it is how an application narrows what a model may send, so
        a schema that is no longer the wrapped tool's wins instead.
        """
        return cast(BaseTool, self).args_schema is not self._arcjet_tool.args_schema

    def invoke(
        self, input: Any, config: RunnableConfig | None = None, **kwargs: Any
    ) -> Any:
        """Guard a call in the flavour it was made in, then hand it on.

        Overridden rather than left to ``BaseTool.invoke`` because that would
        reduce every call to ``run``, and a tool with no async body sends an
        awaited call there too — so an application with an async client would
        reach the blocking checkpoint and be refused a client it correctly
        supplied. The flavour of the checkpoint follows the entrypoint; how the
        tool then executes is the tool's own business.

        The config is resolved here so the checkpoint reads what the tool will
        run with, including one a chain passed down without the caller
        re-threading it.
        """
        resolved = ensure_config(config)
        raw, tool_call_id = _unwrap_tool_call(input)
        report = _Report.of(resolved, tool_call_id)
        try:
            self._arcjet_evaluate(raw, tool_call_id, resolved)
        except _BLOCKED as exc:
            return self._arcjet_blocked(exc, raw, report)
        return self._arcjet_tool.invoke(input, resolved, **kwargs)

    async def ainvoke(
        self, input: Any, config: RunnableConfig | None = None, **kwargs: Any
    ) -> Any:
        """The awaitable counterpart of :meth:`invoke`."""
        resolved = ensure_config(config)
        raw, tool_call_id = _unwrap_tool_call(input)
        report = _Report.of(resolved, tool_call_id)
        try:
            await self._arcjet_evaluate_async(raw, tool_call_id, resolved)
        except _BLOCKED as exc:
            return await self._arcjet_blocked_async(exc, raw, report)
        return await self._arcjet_tool.ainvoke(input, resolved, **kwargs)

    def run(
        self,
        tool_input: str | dict[str, Any],
        verbose: bool | None = None,
        start_color: str | None = "green",
        color: str | None = "green",
        callbacks: Any = None,
        *,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        run_name: str | None = None,
        run_id: Any = None,
        config: RunnableConfig | None = None,
        tool_call_id: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """The checkpoint for a call made through ``run`` rather than ``invoke``.

        Mirroring ``BaseTool.run``'s signature rather than taking ``*args`` is
        what lets a caller pass ``callbacks`` positionally, as that signature
        allows, without the value arriving twice — and what puts the values a
        blocked call is reported from in named parameters.

        The config is resolved for the same reason it is in :meth:`invoke`: a
        resolver should read what the tool runs with.
        """
        resolved = ensure_config(config)
        report = _Report(callbacks, tags, metadata, run_name, run_id, tool_call_id)
        try:
            self._arcjet_evaluate(tool_input, tool_call_id, resolved)
        except _BLOCKED as exc:
            return self._arcjet_blocked(exc, tool_input, report)
        return self._arcjet_tool.run(
            tool_input,
            verbose,
            start_color,
            color,
            callbacks,
            tags=tags,
            metadata=metadata,
            run_name=run_name,
            run_id=run_id,
            config=config,
            tool_call_id=tool_call_id,
            **kwargs,
        )

    async def arun(
        self,
        tool_input: str | dict[str, Any],
        verbose: bool | None = None,
        start_color: str | None = "green",
        color: str | None = "green",
        callbacks: Any = None,
        *,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        run_name: str | None = None,
        run_id: Any = None,
        config: RunnableConfig | None = None,
        tool_call_id: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """The awaitable counterpart of :meth:`run`."""
        resolved = ensure_config(config)
        report = _Report(callbacks, tags, metadata, run_name, run_id, tool_call_id)
        try:
            await self._arcjet_evaluate_async(tool_input, tool_call_id, resolved)
        except _BLOCKED as exc:
            return await self._arcjet_blocked_async(exc, tool_input, report)
        return await self._arcjet_tool.arun(
            tool_input,
            verbose,
            start_color,
            color,
            callbacks,
            tags=tags,
            metadata=metadata,
            run_name=run_name,
            run_id=run_id,
            config=config,
            tool_call_id=tool_call_id,
            **kwargs,
        )

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Evaluate, then hand the body to the tool that owns it.

        The four entrypoints above delegate before this depth, so this is
        reached only by a direct call or by a tool-class helper built on
        ``self._run`` — a preview or dry-run method, say. Those keep working
        on the guarded handle, and the checkpoint still runs first, so there
        is no unguarded path through here.
        """
        delegate = self._arcjet_tool
        raw = _call_arguments(_signature_of(delegate._run), args, kwargs)
        self._arcjet_evaluate(raw, None, None, validated=False)
        return delegate._run(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """The awaitable counterpart of :meth:`_run`."""
        delegate = self._arcjet_tool
        raw = _call_arguments(_signature_of(delegate._arun), args, kwargs)
        await self._arcjet_evaluate_async(raw, None, None, validated=False)
        return await delegate._arun(*args, **kwargs)

    def _arcjet_evaluate(
        self,
        raw: Any,
        tool_call_id: str | None,
        config: RunnableConfig | None,
        *,
        validated: bool = True,
    ) -> None:
        guard = self._arcjet.blocking
        if guard is None:
            raise TypeError(
                "A synchronous LangChain invocation requires a guard client with a "
                "blocking guard(), such as ArcjetGuardSync"
            )
        resolved = config if config is not None else cast(RunnableConfig, {})
        with _fail_closed(self._arcjet.action, self._arcjet.on_guard_error):
            actor = self._arcjet_actor(resolved)
            readable = True
            unreadable_cause: BaseException | None = None
            try:
                inputs = self._arcjet_inputs(
                    raw, tool_call_id, resolved, validated=validated
                )
            except _UnreadableArguments as unreadable:
                inputs, readable = None, False
                unreadable_cause = unreadable.__cause__
            decision = guard(
                self._arcjet.rules,
                label=self._arcjet.action,
                actor=actor,
                inputs=inputs,
            )
            self._arcjet_after_decision(decision, readable, unreadable_cause)

    async def _arcjet_evaluate_async(
        self,
        raw: Any,
        tool_call_id: str | None,
        config: RunnableConfig | None,
        *,
        validated: bool = True,
    ) -> None:
        guard = self._arcjet.awaitable
        if guard is None:
            raise TypeError(
                "An asynchronous LangChain invocation requires a guard client with an "
                "awaitable guard(), such as ArcjetGuard"
            )
        resolved = config if config is not None else cast(RunnableConfig, {})
        with _fail_closed(self._arcjet.action, self._arcjet.on_guard_error):
            actor = await self._arcjet_actor_async(resolved)
            readable = True
            unreadable_cause: BaseException | None = None
            try:
                inputs = await self._arcjet_inputs_async(
                    raw, tool_call_id, resolved, validated=validated
                )
            except _UnreadableArguments as unreadable:
                inputs, readable = None, False
                unreadable_cause = unreadable.__cause__
            decision = await guard(
                self._arcjet.rules,
                label=self._arcjet.action,
                actor=actor,
                inputs=inputs,
            )
            self._arcjet_after_decision(decision, readable, unreadable_cause)

    def _arcjet_after_decision(
        self,
        decision: Decision,
        readable: bool,
        unreadable_cause: BaseException | None = None,
    ) -> None:
        """The fail-closed rules, applied once for both flavours.

        Pure sync code: it raises or returns, so the async evaluator calls it
        without crossing the boundary.
        """
        _check_decision(decision, self._arcjet.action, self._arcjet.on_guard_error)
        if readable:
            return
        if self._arcjet.on_guard_error == "deny":
            # Guard still saw the call, so the decision is on the record.
            # The input rule was not evaluated, so the call does not run. The
            # cause travels with it: without it the operator is told only that
            # policy could not be evaluated, not what stopped it being read.
            raise ArcjetToolUnavailableError(
                self._arcjet.action, cause=unreadable_cause
            )
        logger.warning(
            "arcjet: could not read the arguments of a call to %r; "
            "policy ran without them because on_guard_error is 'allow'",
            self._arcjet.action,
            exc_info=unreadable_cause,
        )

    def __reduce__(self) -> tuple[Any, ...]:
        """Pickle as the tool plus its policy, and never as the client.

        The generated class cannot be looked up by name, so the wrapper is
        rebuilt by guarding the wrapped tool again rather than restored field
        by field. The wrapped tool pickles by its own machinery, so a tool that
        could be pickled before it was guarded still can be.

        The client is deliberately not part of this. It holds a transport that
        cannot cross a process boundary, and it holds the site key — which
        pickling would write into whatever the pickle is sent to or stored in.
        The receiving process supplies its own through ``register_arcjet``,
        which is how a client is shared with code that did not construct it.

        The handle's own field values ride along and are reapplied after the
        rebuild, so a ``handle_tool_error`` or a tag set on the guarded handle
        survives the boundary — a denial that returned a handled message in
        the parent process must not raise in the worker. ``func`` and
        ``coroutine`` stay out: they are this module's guarded closures, and
        the rebuild derives fresh ones.
        """
        policy = self._arcjet
        own = {
            name: value
            for name, value in self.__dict__.items()
            if name not in ("func", "coroutine")
        }
        return (
            _rebuild_guarded_tool,
            (
                self._arcjet_tool,
                policy.action,
                policy.actor,
                policy.inputs,
                policy.rules,
                policy.on_guard_error,
                own,
            ),
        )

    def _arcjet_blocked(self, error: ToolException, raw: Any, report: _Report) -> Any:
        """Report a blocked call to the tool's callbacks and produce its outcome.

        The wrapped tool never runs, so it never opens a run of its own and a
        trace would otherwise hold no record at all of a blocked call — the one
        kind of call an operator most wants to find. The report takes the shape
        LangChain itself gives the outcome: a denial the tool's
        ``handle_tool_error`` converts is a run that *ends*, with the handled
        content, exactly as ``BaseTool.run`` closes a handled ``ToolException``;
        anything else is a start then an error, and re-raises.

        Only the blocked path reports. An allowed call is delegated to the
        tool, which opens its own run, and reporting here as well would double
        every span. The report reads exactly what an allowed call's own run
        reads — what the caller passed, and the delegate's fields as the tool's
        own — so the two paths land on the same handlers, under the same run
        id, with the same labels and the same error handling.
        """
        run_manager = self._arcjet_open_run(raw, report)
        if isinstance(error, ArcjetToolDeniedError) and _handles_tool_errors(
            self._arcjet_tool
        ):
            content = _handle_tool_exception(
                self._arcjet_tool, error, report.tool_call_id
            )
            if run_manager is not None:
                with _reporting(self._arcjet.action):
                    run_manager.on_tool_end(content)
            return content
        if run_manager is not None:
            with _reporting(self._arcjet.action):
                run_manager.on_tool_error(error)
        raise error

    async def _arcjet_blocked_async(
        self, error: ToolException, raw: Any, report: _Report
    ) -> Any:
        """The awaitable counterpart of :meth:`_arcjet_blocked`."""
        run_manager = await self._arcjet_open_run_async(raw, report)
        if isinstance(error, ArcjetToolDeniedError) and _handles_tool_errors(
            self._arcjet_tool
        ):
            content = _handle_tool_exception(
                self._arcjet_tool, error, report.tool_call_id
            )
            if run_manager is not None:
                with _reporting(self._arcjet.action):
                    await run_manager.on_tool_end(content)
            return content
        if run_manager is not None:
            with _reporting(self._arcjet.action):
                await run_manager.on_tool_error(error)
        raise error

    def _arcjet_open_run(self, raw: Any, report: _Report) -> Any:
        """Open the blocked call's run on the callbacks, or ``None``.

        ``None`` on any failure: a trace is observational, and a callback
        handler that fails must not turn a denial into something else.
        """
        with _reporting(self._arcjet.action):
            manager = CallbackManager.configure(*self._arcjet_configure_args(report))
            serialized, input_str, start_kwargs = self._arcjet_start_args(raw, report)
            return manager.on_tool_start(serialized, input_str, **start_kwargs)
        return None

    async def _arcjet_open_run_async(self, raw: Any, report: _Report) -> Any:
        """The awaitable counterpart of :meth:`_arcjet_open_run`."""
        with _reporting(self._arcjet.action):
            manager = AsyncCallbackManager.configure(
                *self._arcjet_configure_args(report)
            )
            serialized, input_str, start_kwargs = self._arcjet_start_args(raw, report)
            return await manager.on_tool_start(serialized, input_str, **start_kwargs)
        return None

    def _arcjet_configure_args(self, report: _Report) -> tuple[Any, ...]:
        """The seven ``configure`` arguments, once, for both manager flavours.

        The tool-level values come from the delegate, because the delegate is
        what an allowed call's own run reads; the call-level values come from
        what the caller passed, which is what ``BaseTool.run`` was given.
        """
        tool = self._arcjet_tool
        return (
            report.callbacks,
            tool.callbacks,
            tool.verbose,
            report.tags,
            tool.tags,
            report.metadata,
            tool.metadata,
        )

    def _arcjet_start_args(
        self, raw: Any, report: _Report
    ) -> tuple[dict[str, Any], str, dict[str, Any]]:
        """What ``on_tool_start`` is given, matching what the tool would send.

        Injected arguments are filtered the way ``BaseTool.run`` filters them
        before it reports: they carry credentials and framework state, and an
        allowed call's trace never shows them, so a blocked call's must not
        either.
        """
        tool = self._arcjet_tool
        filtered = tool._filter_injected_args(raw) if isinstance(raw, dict) else None
        input_str = (
            raw
            if isinstance(raw, str)
            else str(filtered if filtered is not None else raw)
        )
        return (
            {"name": tool.name, "description": tool.description},
            input_str,
            {
                "inputs": filtered,
                "tool_call_id": report.tool_call_id,
                "name": report.run_name,
                "run_id": report.run_id,
            },
        )

    def _arcjet_resolve_actor(
        self, config: RunnableConfig
    ) -> str | None | Awaitable[str | None]:
        actor = self._arcjet.actor
        if not callable(actor):
            return actor
        return cast(_ActorFn, actor)(config)

    def _arcjet_resolve_inputs(
        self,
        raw: Any,
        tool_call_id: str | None,
        config: RunnableConfig,
        *,
        validated: bool,
    ) -> PolicyInputMap | None | Awaitable[PolicyInputMap | None]:
        resolver = self._arcjet.inputs
        if not callable(resolver):
            return resolver
        # Parsed only here, because a resolver is the only thing that reads the
        # arguments: a tool with no resolver configured is never parsed at all.
        try:
            arguments = _arguments(self._arcjet_tool, raw, tool_call_id)
        except _SCHEMA_REJECTED as exc:
            if not validated:
                # This surface runs the tool's body with the arguments as
                # given, so nothing downstream will reject them. The rule was
                # configured, could not see the effect it protects, and the
                # call would otherwise proceed — an unevaluated policy.
                raise _UnreadableArguments from exc
            # The tool's own schema rejected these arguments, so the tool
            # rejects the call too and its body never runs. Policy still gets a
            # decision, without inputs — there is no effect for an input rule
            # to protect, and the tool keeps its own `handle_validation_error`.
            logger.warning(
                "arcjet: the arguments of a call to %r did not validate; "
                "evaluating policy without them",
                self._arcjet.action,
            )
            return None
        except Exception as exc:
            raise _UnreadableArguments from exc
        return cast(_InputsFn, resolver)(arguments, config)

    def _arcjet_actor(self, config: RunnableConfig) -> str | None:
        value = self._arcjet_resolve_actor(config)
        if inspect.isawaitable(value):
            _discard(value)
            raise TypeError("A synchronous actor resolver must not return an awaitable")
        return cast("str | None", value)

    def _arcjet_inputs(
        self,
        raw: Any,
        tool_call_id: str | None,
        config: RunnableConfig,
        *,
        validated: bool,
    ) -> PolicyInputMap | None:
        value = self._arcjet_resolve_inputs(
            raw, tool_call_id, config, validated=validated
        )
        if inspect.isawaitable(value):
            _discard(value)
            raise TypeError("A synchronous input resolver must not return an awaitable")
        return cast("PolicyInputMap | None", value)

    async def _arcjet_actor_async(self, config: RunnableConfig) -> str | None:
        value = self._arcjet_resolve_actor(config)
        if inspect.isawaitable(value):
            return cast("str | None", await value)
        return cast("str | None", value)

    async def _arcjet_inputs_async(
        self,
        raw: Any,
        tool_call_id: str | None,
        config: RunnableConfig,
        *,
        validated: bool,
    ) -> PolicyInputMap | None:
        value = self._arcjet_resolve_inputs(
            raw, tool_call_id, config, validated=validated
        )
        if inspect.isawaitable(value):
            return cast("PolicyInputMap | None", await value)
        return cast("PolicyInputMap | None", value)


def _discard(value: Any) -> None:
    """Close a coroutine that will never be awaited.

    Dropping it instead leaves a ``RuntimeWarning`` to surface at an arbitrary
    later garbage collection, which is a hard failure under ``-W error``.
    """
    close = getattr(value, "close", None)
    if callable(close):
        close()


def _rebuild_guarded_tool(
    tool: BaseTool,
    action: str,
    actor: ActorResolver | AsyncActorResolver | None,
    inputs: InputResolver | AsyncInputResolver | None,
    rules: tuple[RuleWithInput, ...],
    on_guard_error: OnGuardError,
    fields: dict[str, Any],
) -> BaseTool:
    """Guard *tool* again, with the client the receiving process registered.

    Named at module level because :meth:`_GuardMixin.__reduce__` names it, and
    pickle resolves that by import. *fields* are the pickled handle's own
    field values, reapplied so the rebuilt handle behaves as the one that was
    pickled rather than as a freshly guarded *tool*.
    """
    guard = registered_client()
    if guard is None:
        raise ArcjetMisconfiguration(
            "Unpickling a guarded tool needs an Arcjet client registered in "
            "this process: a guarded tool is pickled without one, because a "
            "client cannot cross a process boundary and carries the site key. "
            "Call register_arcjet() before loading it."
        )
    guarded = guard_tool(
        guard=guard,
        tool=tool,
        action=action,
        actor=actor,
        inputs=inputs,
        rules=rules,
        on_guard_error=on_guard_error,
    )
    for name, value in fields.items():
        setattr(guarded, name, value)
    return guarded


def _signature_of(fn: Callable[..., Any]) -> inspect.Signature | None:
    """*fn*'s signature, or ``None`` when it does not have one to report.

    A C or extension callable — a numpy ufunc, a pybind11 function,
    ``time.time`` — has no introspectable signature, and LangChain accepts one
    as a tool's ``func`` regardless. Guarding such a tool must not be the thing
    that fails; the call's keyword arguments stand in as the resolver's view.
    """
    try:
        return inspect.signature(fn)
    except (TypeError, ValueError):
        return None


def _call_arguments(
    signature: inspect.Signature | None,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> Any:
    """A direct call's arguments, shaped the way the tool reads its input.

    Binding to the signature is what turns a positional call into the mapping a
    policy resolver is documented to receive, so a resolver sees the same thing
    whether the model called the tool or the application called its function.

    The bound mapping is flattened before it is handed on, because a tool's
    ``_run`` collects the real arguments in ``**kwargs`` behind the framework's
    own ``config`` and ``run_manager`` parameters: binding
    ``_run(x="secret", config={})`` yields ``{"args": (), "config": {},
    "run_manager": None, "kwargs": {"x": "secret"}}``, and it is ``x`` the
    policy is meant to see.  A tool taking its input positionally has nothing
    left after the flattening, so the single value is handed on as the tool's
    own ``_parse_input`` expects it.

    An unbindable call is handed on untouched: the tool is about to raise over
    it anyway, and the checkpoint should not be the thing that reports it.
    """
    if signature is None:
        return kwargs or (args[0] if len(args) == 1 else {})
    try:
        bound = signature.bind(*args, **kwargs)
    except TypeError:
        return kwargs or (args[0] if len(args) == 1 else {})
    bound.apply_defaults()

    positional: list[Any] = []
    flattened: dict[str, Any] = {}
    for name, value in bound.arguments.items():
        kind = signature.parameters[name].kind
        if kind is inspect.Parameter.VAR_KEYWORD:
            flattened.update(value)
        elif kind is inspect.Parameter.VAR_POSITIONAL:
            positional = list(value)
        else:
            flattened[name] = value

    # What the framework supplies rather than the caller. `tool_call_schema`
    # hides these from the model, so a resolver must not be handed them either.
    for name in (*FILTERED_ARGS, "config"):
        flattened.pop(name, None)

    if not flattened and len(positional) == 1:
        return positional[0]
    return flattened


def _guarded_callables(guarded: BaseTool) -> None:
    """Put the checkpoint in front of the tool's own callables.

    ``func`` and ``coroutine`` are ordinary fields, so they are copied from the
    wrapped tool with everything else — and they are the two callables
    LangChain itself reads off a tool. Copied verbatim they would run the
    tool's body with no checkpoint, so the guarded handle would offer an
    unguarded call through its own advertised surface. This is fidelity of
    the handle, not a security boundary: a caller that still holds the
    unguarded tool can always call it directly.

    The replacements keep the wrapped function's signature, because that is
    what ``render_text_description`` reports and what makes a guarded tool
    render as the unguarded one did. The signature is computed here, once,
    because the wrapped callable never changes for the wrapper's lifetime.
    """
    func = getattr(guarded, "func", None)
    if callable(func):
        inner_func = cast(Callable[..., Any], func)
        func_signature = _signature_of(inner_func)

        @functools.wraps(inner_func)
        def guarded_func(*args: Any, **kwargs: Any) -> Any:
            evaluate = cast(Any, guarded)._arcjet_evaluate
            evaluate(
                _call_arguments(func_signature, args, kwargs),
                None,
                None,
                validated=False,
            )
            return inner_func(*args, **kwargs)

        cast(Any, guarded).func = guarded_func

    coroutine = getattr(guarded, "coroutine", None)
    if callable(coroutine):
        inner_coroutine = cast(Callable[..., Awaitable[Any]], coroutine)
        coroutine_signature = _signature_of(inner_coroutine)

        @functools.wraps(inner_coroutine)
        async def guarded_coroutine(*args: Any, **kwargs: Any) -> Any:
            evaluate = cast(Any, guarded)._arcjet_evaluate_async
            await evaluate(
                _call_arguments(coroutine_signature, args, kwargs),
                None,
                None,
                validated=False,
            )
            return await inner_coroutine(*args, **kwargs)

        cast(Any, guarded).coroutine = guarded_coroutine


# Copied wholesale into each generated namespace. `__dict__` and `__weakref__`
# are descriptors bound to _GuardMixin and break the copy's instances if they
# come along; `__doc__` describes the mixin, not the generated class; and
# pydantic collects the two PrivateAttr assignments below without needing
# `__annotations__`.
_NAMESPACE_SKIP = frozenset({"__dict__", "__weakref__", "__doc__", "__annotations__"})

# Keyed weakly so guarding a tool cannot keep its class alive, and *valued*
# weakly for the same reason: a generated class holds its base in `__bases__`,
# so a strong value would make every entry immortal. A guarded tool keeps its
# own class alive, which is exactly as long as the entry is worth having.
_guarded_classes: MutableMapping[type[BaseTool], ReferenceType[type[BaseTool]]] = (
    WeakKeyDictionary()
)
_guarded_classes_lock = threading.Lock()


def _guarded_class(base: type[BaseTool]) -> type[BaseTool]:
    """A subclass of *base* that guards before delegating, made once per class.

    A guarded tool has to *be* the tool it wraps: applications and parts of
    LangChain itself branch on a tool's concrete class, and a wrapper of some
    other class silently changes what they decide.  Subclassing is the only
    thing ``isinstance`` accepts, so the wrapper is generated from whatever
    class it was handed.

    Generated once per class and reused, so a tool class that registers its
    subclasses sees one registration rather than one per guarded tool.  The
    guard's own members go in the namespace, which beats every base, so the
    tool's fields and methods are inherited untouched.
    """
    with _guarded_classes_lock:
        cached = _guarded_classes.get(base)
        existing = cached() if cached is not None else None
        if existing is not None:
            return existing

        name = f"ArcjetGuarded{base.__name__}"
        namespace: dict[str, Any] = {
            member_name: member
            for member_name, member in _GuardMixin.__dict__.items()
            if member_name not in _NAMESPACE_SKIP
        }
        namespace.update(
            _arcjet=PrivateAttr(),
            _arcjet_tool=PrivateAttr(),
            # Named for this module rather than for the caller's, so a repr or
            # a traceback points at the code that made the class.
            __module__=__name__,
            __qualname__=name,
        )

        generated = cast("type[BaseTool]", type(name, (base,), namespace))
        _guarded_classes[base] = ref(generated)
        return generated


def _copy_of(tool: BaseTool, wrapper: type[BaseTool]) -> BaseTool:
    """*tool*'s state, in an instance of *wrapper*.

    The state is copied across rather than replayed through the class's own
    constructor. Re-running ``__init__`` re-validates by *alias*, so a field
    the tool declares one for is silently reset to its default; it also drops
    whatever an ``extra="allow"`` tool holds outside its declared fields, and
    it cannot construct a class whose ``__init__`` requires something that is
    not a field at all. None of that is a copy of the tool.

    Containers are copied one level down. Sharing them would let a tag or a
    callback attached to either tool show up on the other, so an audit trail
    could record executions that never passed the checkpoint.
    """
    guarded = wrapper.__new__(wrapper)
    fields = {
        name: list(value)
        if isinstance(value, list)
        else dict(value)
        if isinstance(value, dict)
        else value
        for name, value in (tool.__dict__ or {}).items()
    }
    object.__setattr__(guarded, "__dict__", fields)
    object.__setattr__(
        guarded, "__pydantic_fields_set__", set(tool.__pydantic_fields_set__)
    )
    extra = tool.__pydantic_extra__
    object.__setattr__(
        guarded, "__pydantic_extra__", dict(extra) if extra is not None else None
    )
    private = tool.__pydantic_private__
    object.__setattr__(
        guarded, "__pydantic_private__", dict(private) if private else {}
    )
    return guarded


def guard_tool(
    *,
    guard: GuardClient,
    tool: BaseTool,
    action: str,
    actor: ActorResolver | AsyncActorResolver | None = None,
    inputs: InputResolver | AsyncInputResolver | None = None,
    rules: Sequence[RuleWithInput] = (),
    on_guard_error: OnGuardError = "deny",
) -> BaseTool:
    """Wrap a LangChain tool with an Arcjet pre-execution checkpoint.

    The guarded tool evaluates policy and then hands the call to *tool*, which
    is left untouched and keeps running its own code — so anything the tool's
    class overrides still applies, and the model is told what the unguarded
    tool advertised.

    The result is an instance of *tool*'s own class, so ``isinstance`` and the
    concrete-class gates LangChain uses to decide what to advertise keep
    answering as they did.  It is a generated subclass, made once per tool
    class: a class that registers or validates its subclasses sees one such
    subclass, at the first ``guard_tool`` call for it.

    Unlike the core Guard client, which returns a fail-open ``ALLOW`` decision
    when evaluation is degraded, this helper fails closed by default. With
    ``on_guard_error="deny"``, an exception from the pre-execution checkpoint
    (actor or input resolution, or Guard itself) or a decision whose
    ``has_failed_open()`` is true raises :class:`ArcjetToolUnavailableError`
    without executing the tool. Set ``on_guard_error="allow"`` to execute the
    tool in either case.

    A real ``DENY`` decision blocks execution regardless of ``on_guard_error``
    and is represented by :class:`ArcjetToolDeniedError`; the wrapped tool's
    ``handle_tool_error`` may convert it into a LangChain error result. It is
    distinct from an unavailable evaluation.

    A guarded tool pickles if the tool it wraps does *and* its resolvers do,
    carrying the policy but not *guard*: a client cannot cross a process
    boundary, and pickling one would write the site key into whatever the
    pickle is stored in. The receiving process supplies its own with
    :func:`~arcjet.guard.register_arcjet` before loading the tool. Resolvers
    are pickled as given, so a lambda or a closure — fine everywhere else —
    makes a guarded tool unpicklable; a module-level function does not.

    Fields reassigned on the guarded tool after this returns do not reach the
    call. The wrapped tool executes with what it had, and both the call and
    the report of a blocked one read the wrapped tool, so the two agree.
    Configure the tool before guarding it.

    *guard* is recognised by the shape of its ``guard()`` rather than by its
    class, matching the free guard calls, so an
    :class:`~arcjet.guard.testing.ArcjetTestClient` or a hand-rolled double
    drives a guarded tool without subclassing anything. A recorder answers a
    fail-open decision, so pair one with ``on_guard_error="allow"`` unless the
    test is asserting the denial. A client that cannot answer the flavour a
    call takes still raises ``TypeError``: that is a wiring mistake, not a
    degraded evaluation, and ``on_guard_error`` deliberately does not govern
    it.
    """
    guarded = _copy_of(tool, _guarded_class(type(tool)))
    guarded._arcjet_tool = tool
    guarded._arcjet = _Policy(
        guard=guard,
        action=action,
        actor=actor,
        inputs=inputs,
        rules=tuple(rules),
        on_guard_error=on_guard_error,
        blocking=_blocking(guard, "guard_sync", "guard"),
        awaitable=_awaitable(guard, "guard"),
    )
    _guarded_callables(guarded)
    return guarded


__all__ = [
    "ArcjetToolDeniedError",
    "ArcjetToolUnavailableError",
    "guard_tool",
]
