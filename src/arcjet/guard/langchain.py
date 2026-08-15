"""Optional LangChain tool checkpoint integration.

Install ``arcjet[langchain]`` to use this module. Core Guard clients do not
import LangChain.

A guarded tool is a thin wrapper that evaluates policy and then hands the call
to the tool it wraps.  It deliberately does **not** try to *be* the wrapped
tool: everything the framework derives from a tool — its schema, its arguments
— is asked of the wrapped tool rather than recomputed here, so a guarded tool
advertises and executes exactly what the unguarded one did.
"""

from __future__ import annotations

import functools
import inspect
import threading
from collections.abc import Awaitable, Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast
from weakref import ReferenceType, WeakKeyDictionary, ref

from langchain_core.callbacks import AsyncCallbackManager, CallbackManager
from langchain_core.messages import ToolMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import BaseTool, ToolException
from langchain_core.tools.simple import Tool as SimpleTool
from pydantic import BaseModel, PrivateAttr, ValidationError

from arcjet._logging import logger

from ._client import ArcjetGuard, ArcjetGuardSync
from ._policy_input import PolicyInputMap
from ._registry import _awaitable, _blocking
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
        self.__cause__ = cause


def _unwrap_tool_call(value: Any) -> tuple[Any, str | None]:
    """A ToolCall-shaped input split into its arguments and its id."""
    if isinstance(value, dict) and value.get("type") == "tool_call":
        return value.get("args", {}), value.get("id")
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

    guard: ArcjetGuard | ArcjetGuardSync
    action: str
    actor: ActorResolver | AsyncActorResolver | None
    inputs: InputResolver | AsyncInputResolver | None
    rules: tuple[RuleWithInput, ...]
    on_guard_error: OnGuardError


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
        if self._arcjet_owns_schema():
            return BaseTool.get_input_schema(cast(BaseTool, self), config)
        return self._arcjet_tool.get_input_schema(config)

    @property
    def tool_call_schema(self) -> Any:
        if self._arcjet_owns_schema():
            return cast(Any, BaseTool.tool_call_schema).fget(self)
        return self._arcjet_tool.tool_call_schema

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
        raw, tool_call_id = _unwrap_tool_call(input)
        try:
            self._arcjet_evaluate(raw, tool_call_id, config)
        except ArcjetToolDeniedError as exc:
            return _handle_tool_exception(cast(BaseTool, self), exc, tool_call_id)
        return self._arcjet_tool.invoke(input, config, **kwargs)

    async def ainvoke(
        self, input: Any, config: RunnableConfig | None = None, **kwargs: Any
    ) -> Any:
        raw, tool_call_id = _unwrap_tool_call(input)
        try:
            await self._arcjet_evaluate_async(raw, tool_call_id, config)
        except ArcjetToolDeniedError as exc:
            return _handle_tool_exception(cast(BaseTool, self), exc, tool_call_id)
        return await self._arcjet_tool.ainvoke(input, config, **kwargs)

    def run(self, tool_input: Any, *args: Any, **kwargs: Any) -> Any:
        tool_call_id = kwargs.get("tool_call_id")
        try:
            self._arcjet_evaluate(tool_input, tool_call_id, kwargs.get("config"))
        except ArcjetToolDeniedError as exc:
            return _handle_tool_exception(cast(BaseTool, self), exc, tool_call_id)
        return self._arcjet_tool.run(tool_input, *args, **kwargs)

    async def arun(self, tool_input: Any, *args: Any, **kwargs: Any) -> Any:
        tool_call_id = kwargs.get("tool_call_id")
        try:
            await self._arcjet_evaluate_async(
                tool_input, tool_call_id, kwargs.get("config")
            )
        except ArcjetToolDeniedError as exc:
            return _handle_tool_exception(cast(BaseTool, self), exc, tool_call_id)
        return await self._arcjet_tool.arun(tool_input, *args, **kwargs)

    def _arcjet_evaluate(
        self, raw: Any, tool_call_id: str | None, config: RunnableConfig | None
    ) -> None:
        guard = _blocking(self._arcjet.guard, "guard_sync", "guard")
        if guard is None:
            raise TypeError(
                "A synchronous LangChain invocation requires a guard client with a "
                "blocking guard(), such as ArcjetGuardSync"
            )
        resolved = config if config is not None else cast(RunnableConfig, {})
        try:
            actor = self._arcjet_actor(resolved)
            readable = True
            try:
                inputs = self._arcjet_inputs(raw, tool_call_id, resolved)
            except _UnreadableArguments:
                inputs, readable = None, False
            decision = guard(
                self._arcjet.rules,
                label=self._arcjet.action,
                actor=actor,
                inputs=inputs,
            )
            _check_decision(decision, self._arcjet.action, self._arcjet.on_guard_error)
            if not readable and self._arcjet.on_guard_error == "deny":
                # Guard still saw the call, so the decision is on the record.
                # The input rule was not evaluated, so the call does not run.
                raise ArcjetToolUnavailableError(self._arcjet.action)
            if not readable:
                logger.warning(
                    "arcjet: could not read the arguments of a call to %r; "
                    "policy ran without them because on_guard_error is 'allow'",
                    self._arcjet.action,
                )
        except (ArcjetToolDeniedError, ArcjetToolUnavailableError) as exc:
            self._arcjet_report_blocked(exc, raw, tool_call_id, resolved)
            raise
        except Exception as exc:
            if self._arcjet.on_guard_error == "deny":
                blocked = ArcjetToolUnavailableError(self._arcjet.action, cause=exc)
                self._arcjet_report_blocked(blocked, raw, tool_call_id, resolved)
                raise blocked from exc

    async def _arcjet_evaluate_async(
        self, raw: Any, tool_call_id: str | None, config: RunnableConfig | None
    ) -> None:
        guard = _awaitable(self._arcjet.guard, "guard")
        if guard is None:
            raise TypeError(
                "An asynchronous LangChain invocation requires a guard client with an "
                "awaitable guard(), such as ArcjetGuard"
            )
        resolved = config if config is not None else cast(RunnableConfig, {})
        try:
            actor = await self._arcjet_actor_async(resolved)
            readable = True
            try:
                inputs = await self._arcjet_inputs_async(raw, tool_call_id, resolved)
            except _UnreadableArguments:
                inputs, readable = None, False
            decision = await guard(
                self._arcjet.rules,
                label=self._arcjet.action,
                actor=actor,
                inputs=inputs,
            )
            _check_decision(decision, self._arcjet.action, self._arcjet.on_guard_error)
            if not readable and self._arcjet.on_guard_error == "deny":
                # Guard still saw the call, so the decision is on the record.
                # The input rule was not evaluated, so the call does not run.
                raise ArcjetToolUnavailableError(self._arcjet.action)
            if not readable:
                logger.warning(
                    "arcjet: could not read the arguments of a call to %r; "
                    "policy ran without them because on_guard_error is 'allow'",
                    self._arcjet.action,
                )
        except (ArcjetToolDeniedError, ArcjetToolUnavailableError) as exc:
            await self._arcjet_report_blocked_async(exc, raw, tool_call_id, resolved)
            raise
        except Exception as exc:
            if self._arcjet.on_guard_error == "deny":
                blocked = ArcjetToolUnavailableError(self._arcjet.action, cause=exc)
                await self._arcjet_report_blocked_async(
                    blocked, raw, tool_call_id, resolved
                )
                raise blocked from exc

    def _arcjet_start_fields(
        self, raw: Any, config: RunnableConfig
    ) -> tuple[dict[str, Any], str, Any]:
        """What ``on_tool_start`` is given, matching what the tool would send."""
        tool = cast(BaseTool, self)
        inputs = raw if isinstance(raw, dict) else None
        return (
            {"name": tool.name, "description": tool.description},
            raw if isinstance(raw, str) else str(raw),
            inputs,
        )

    def _arcjet_report_blocked(
        self,
        error: ToolException,
        raw: Any,
        tool_call_id: str | None,
        config: RunnableConfig,
    ) -> None:
        """Put a call the checkpoint stopped onto the trace.

        The wrapped tool never runs, so it never opens a run of its own and a
        trace would otherwise hold no record at all of a blocked call — the one
        kind of call an operator most wants to find. It is reported as the
        wrapped tool would have reported a failure: a start, then an error.

        Only the blocked path reports. An allowed call is delegated to the tool,
        which opens its own run, and reporting here as well would double every
        span. Nothing here may raise: a trace is observational, and a callback
        handler that fails must not turn a denial into something else.
        """
        serialized, input_str, inputs = self._arcjet_start_fields(raw, config)
        try:
            manager = CallbackManager.configure(
                config.get("callbacks"),
                cast(BaseTool, self).callbacks,
                cast(BaseTool, self).verbose,
                config.get("tags"),
                cast(BaseTool, self).tags,
                config.get("metadata"),
                cast(BaseTool, self).metadata,
            )
            run_manager = manager.on_tool_start(
                serialized, input_str, inputs=inputs, tool_call_id=tool_call_id
            )
            run_manager.on_tool_error(error)
        except Exception:
            logger.warning(
                "arcjet: could not report a blocked call to %r on its callbacks",
                self._arcjet.action,
                exc_info=True,
            )

    async def _arcjet_report_blocked_async(
        self,
        error: ToolException,
        raw: Any,
        tool_call_id: str | None,
        config: RunnableConfig,
    ) -> None:
        """The awaitable counterpart of :meth:`_arcjet_report_blocked`."""
        serialized, input_str, inputs = self._arcjet_start_fields(raw, config)
        try:
            manager = AsyncCallbackManager.configure(
                config.get("callbacks"),
                cast(BaseTool, self).callbacks,
                cast(BaseTool, self).verbose,
                config.get("tags"),
                cast(BaseTool, self).tags,
                config.get("metadata"),
                cast(BaseTool, self).metadata,
            )
            run_manager = await manager.on_tool_start(
                serialized, input_str, inputs=inputs, tool_call_id=tool_call_id
            )
            await run_manager.on_tool_error(error)
        except Exception:
            logger.warning(
                "arcjet: could not report a blocked call to %r on its callbacks",
                self._arcjet.action,
                exc_info=True,
            )

    def _arcjet_resolve_actor(
        self, config: RunnableConfig
    ) -> str | None | Awaitable[str | None]:
        actor = self._arcjet.actor
        if not callable(actor):
            return actor
        return cast(_ActorFn, actor)(config)

    def _arcjet_resolve_inputs(
        self, raw: Any, tool_call_id: str | None, config: RunnableConfig
    ) -> PolicyInputMap | None | Awaitable[PolicyInputMap | None]:
        resolver = self._arcjet.inputs
        if not callable(resolver):
            return resolver
        # Parsed only here, because a resolver is the only thing that reads the
        # arguments: a tool with no resolver configured is never parsed at all.
        try:
            arguments = _arguments(self._arcjet_tool, raw, tool_call_id)
        except ValidationError:
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
        self, raw: Any, tool_call_id: str | None, config: RunnableConfig
    ) -> PolicyInputMap | None:
        value = self._arcjet_resolve_inputs(raw, tool_call_id, config)
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
        self, raw: Any, tool_call_id: str | None, config: RunnableConfig
    ) -> PolicyInputMap | None:
        value = self._arcjet_resolve_inputs(raw, tool_call_id, config)
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


def _call_arguments(
    fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    """A direct call's arguments, keyed the way the tool's own schema keys them.

    Binding to the signature is what turns a positional call into the mapping a
    policy resolver is documented to receive, so a resolver sees the same thing
    whether the model called the tool or the application called its function.
    An unbindable call is handed on untouched: the tool is about to raise over
    it anyway, and the checkpoint should not be the thing that reports it.
    """
    try:
        bound = inspect.signature(fn).bind(*args, **kwargs)
    except TypeError:
        return kwargs if kwargs else args[0] if len(args) == 1 else dict(kwargs)
    bound.apply_defaults()
    return dict(bound.arguments)


def _guarded_callables(guarded: BaseTool) -> None:
    """Put the checkpoint in front of the tool's own callables.

    ``func`` and ``coroutine`` are ordinary fields, so they are copied from the
    wrapped tool with everything else — and they are public. LangChain reads
    ``func`` to render a tool's signature, and application code calls it
    directly. Copied verbatim they would run the tool's body with no
    checkpoint, which is a way past a ``DENY`` on the guarded tool itself.

    The replacements keep the wrapped function's signature, because that is
    what ``render_text_description`` reports and what makes a guarded tool
    render as the unguarded one did.
    """
    func = getattr(guarded, "func", None)
    if callable(func):
        inner_func = cast(Callable[..., Any], func)

        @functools.wraps(inner_func)
        def guarded_func(*args: Any, **kwargs: Any) -> Any:
            evaluate = cast(Any, guarded)._arcjet_evaluate
            evaluate(_call_arguments(inner_func, args, kwargs), None, None)
            return inner_func(*args, **kwargs)

        cast(Any, guarded).func = guarded_func

    coroutine = getattr(guarded, "coroutine", None)
    if callable(coroutine):
        inner_coroutine = cast(Callable[..., Awaitable[Any]], coroutine)

        @functools.wraps(inner_coroutine)
        async def guarded_coroutine(*args: Any, **kwargs: Any) -> Any:
            evaluate = cast(Any, guarded)._arcjet_evaluate_async
            await evaluate(_call_arguments(inner_coroutine, args, kwargs), None, None)
            return await inner_coroutine(*args, **kwargs)

        cast(Any, guarded).coroutine = guarded_coroutine


def _refuse_direct_run(self: Any, *args: Any, **kwargs: Any) -> Any:
    raise RuntimeError("Guarded tools delegate to the tool they wrap")


async def _refuse_direct_arun(self: Any, *args: Any, **kwargs: Any) -> Any:
    raise RuntimeError("Guarded tools delegate to the tool they wrap")


# Copied wholesale into each generated namespace, minus the entries that
# describe where a class was written rather than what it does.
_NAMESPACE_SKIP = frozenset(
    {"__dict__", "__weakref__", "__module__", "__doc__", "__qualname__"}
)

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

        namespace: dict[str, Any] = {
            name: member
            for name, member in _GuardMixin.__dict__.items()
            if name not in _NAMESPACE_SKIP
        }
        namespace["__annotations__"] = dict(
            _GuardMixin.__dict__.get("__annotations__", {})
        )
        namespace["_arcjet"] = PrivateAttr()
        namespace["_arcjet_tool"] = PrivateAttr()
        # The tool's own body is never reached through the wrapper — every
        # entrypoint delegates to the inner tool — so these refuse rather than
        # offer a way past the checkpoint.
        namespace["_run"] = _refuse_direct_run
        namespace["_arun"] = _refuse_direct_arun
        name = f"ArcjetGuarded{base.__name__}"
        # Named for this module rather than for the caller's, so a repr or a
        # traceback points at the code that made the class.
        namespace["__module__"] = __name__
        namespace["__qualname__"] = name

        generated = cast("type[BaseTool]", type(name, (base,), namespace))
        _guarded_classes[base] = ref(generated)
        return generated


def guard_tool(
    *,
    guard: ArcjetGuard | ArcjetGuardSync,
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

    *guard* is recognised by the shape of its ``guard()`` rather than by its
    class, matching the free guard calls, so an
    :class:`~arcjet.guard.testing.ArcjetTestClient` or a hand-rolled double
    drives a guarded tool without subclassing anything. A recorder answers a
    fail-open decision, so pair one with ``on_guard_error="allow"`` unless the
    test is asserting the denial. A client of the wrong flavour still raises
    ``TypeError``: that is a wiring mistake, not a degraded evaluation, and
    ``on_guard_error`` deliberately does not govern it.
    """
    wrapper = _guarded_class(type(tool))

    values: dict[str, Any] = {}
    for name in type(tool).model_fields:
        if name not in wrapper.model_fields:
            continue
        value = getattr(tool, name)
        # One level of copy on the containers. Sharing them would let a tag or
        # a callback attached to either tool show up on the other, so an audit
        # trail could record executions that never passed the checkpoint.
        if isinstance(value, list):
            value = list(value)
        elif isinstance(value, dict):
            value = dict(value)
        values[name] = value

    guarded = wrapper(**values)
    guarded._arcjet_tool = tool
    guarded._arcjet = _Policy(
        guard=guard,
        action=action,
        actor=actor,
        inputs=inputs,
        rules=tuple(rules),
        on_guard_error=on_guard_error,
    )
    _guarded_callables(guarded)
    return guarded


__all__ = [
    "ArcjetToolDeniedError",
    "ArcjetToolUnavailableError",
    "guard_tool",
]
