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
    BaseCallbackHandler,
    CallbackManager,
)
from langchain_core.messages import ToolMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.runnables.config import merge_configs
from langchain_core.tools import BaseTool, ToolException
from langchain_core.tools.simple import Tool as SimpleTool
from pydantic import BaseModel, PrivateAttr, ValidationError

from arcjet._errors import ArcjetMisconfiguration
from arcjet._logging import logger

from ._client import ArcjetGuard, ArcjetGuardSync
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
        self.__cause__ = cause


# What the checkpoint raises to stop a call, as one except clause.
_BLOCKED = (ArcjetToolDeniedError, ArcjetToolUnavailableError)


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
        raw, tool_call_id = _unwrap_tool_call(input)
        try:
            self._arcjet_evaluate(raw, tool_call_id, config)
        except _BLOCKED as exc:
            return self._arcjet_blocked(exc, raw, tool_call_id, config)
        return self._arcjet_tool.invoke(
            input, self._arcjet_child_config(config), **kwargs
        )

    async def ainvoke(
        self, input: Any, config: RunnableConfig | None = None, **kwargs: Any
    ) -> Any:
        raw, tool_call_id = _unwrap_tool_call(input)
        try:
            await self._arcjet_evaluate_async(raw, tool_call_id, config)
        except _BLOCKED as exc:
            return await self._arcjet_blocked_async(exc, raw, tool_call_id, config)
        return await self._arcjet_tool.ainvoke(
            input, self._arcjet_child_config(config), **kwargs
        )

    def run(self, tool_input: Any, *args: Any, **kwargs: Any) -> Any:
        tool_call_id = kwargs.get("tool_call_id")
        config = kwargs.get("config")
        try:
            self._arcjet_evaluate(tool_input, tool_call_id, config)
        except _BLOCKED as exc:
            return self._arcjet_blocked(exc, tool_input, tool_call_id, config)
        return self._arcjet_tool.run(
            tool_input, *args, **self._arcjet_run_kwargs(kwargs)
        )

    async def arun(self, tool_input: Any, *args: Any, **kwargs: Any) -> Any:
        tool_call_id = kwargs.get("tool_call_id")
        config = kwargs.get("config")
        try:
            await self._arcjet_evaluate_async(tool_input, tool_call_id, config)
        except _BLOCKED as exc:
            return await self._arcjet_blocked_async(
                exc, tool_input, tool_call_id, config
            )
        return await self._arcjet_tool.arun(
            tool_input, *args, **self._arcjet_run_kwargs(kwargs)
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
        raw = _call_arguments(inspect.signature(delegate._run), args, kwargs)
        self._arcjet_evaluate(raw, None, None)
        return delegate._run(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """The awaitable counterpart of :meth:`_run`."""
        delegate = self._arcjet_tool
        raw = _call_arguments(inspect.signature(delegate._arun), args, kwargs)
        await self._arcjet_evaluate_async(raw, None, None)
        return await delegate._arun(*args, **kwargs)

    def _arcjet_child_config(self, config: RunnableConfig | None) -> RunnableConfig:
        """The delegated call's config, carrying this handle's own fields.

        The delegate executes with the copies of ``callbacks``, ``tags`` and
        ``metadata`` it had when ``guard_tool`` ran, so anything attached to
        the guarded handle afterwards would never fire on an allowed call —
        while a blocked call, which this handle reports, would show it. That
        asymmetry reads as a tool that only ever denies. Folding the handle's
        fields into the config is the one channel the delegate accepts them
        on; a handler the delegate already has is not doubled, because the
        callback manager refuses a handler it already holds.
        """
        tool = cast(BaseTool, self)
        own: RunnableConfig = {}
        own_callbacks = tool.callbacks
        if own_callbacks is not None:
            supplied = (config or {}).get("callbacks")
            if isinstance(own_callbacks, list) and isinstance(supplied, list):
                # merge_configs concatenates two lists blindly, and configure
                # does not deduplicate within one, so a handler the call
                # already carries is dropped here rather than fired twice. A
                # manager on either side deduplicates itself via add_handler.
                handlers = cast("list[BaseCallbackHandler]", own_callbacks)
                fresh = [handler for handler in handlers if handler not in supplied]
                if fresh:
                    own["callbacks"] = fresh
            else:
                own["callbacks"] = own_callbacks
        if tool.tags:
            own["tags"] = list(tool.tags)
        if tool.metadata:
            own["metadata"] = dict(tool.metadata)
        if not own:
            return config if config is not None else cast(RunnableConfig, {})
        return merge_configs(config, own)

    def _arcjet_run_kwargs(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        """``run``/``arun``'s keyword view of :meth:`_arcjet_child_config`.

        Those entrypoints take ``callbacks``, ``tags`` and ``metadata`` as
        keywords rather than in a config, so the handle's fields fold into the
        keywords. The handle's metadata wins a key both supply, matching how
        the callback manager applies a tool's own metadata after the call's.
        A callback manager instance in the keywords is passed through: merging
        into a caller's manager would mutate it.
        """
        tool = cast(BaseTool, self)
        merged = dict(kwargs)
        callbacks = merged.get("callbacks")
        if isinstance(tool.callbacks, list) and tool.callbacks:
            if callbacks is None:
                merged["callbacks"] = list(tool.callbacks)
            elif isinstance(callbacks, list):
                merged["callbacks"] = callbacks + [
                    handler for handler in tool.callbacks if handler not in callbacks
                ]
        if tool.tags:
            tags = merged.get("tags")
            merged["tags"] = (tags or []) + [
                tag for tag in tool.tags if tag not in (tags or [])
            ]
        if tool.metadata:
            merged["metadata"] = {**(merged.get("metadata") or {}), **tool.metadata}
        return merged

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
            self._arcjet_after_decision(decision, readable)
        except _BLOCKED:
            raise
        except Exception as exc:
            if self._arcjet.on_guard_error == "deny":
                raise ArcjetToolUnavailableError(
                    self._arcjet.action, cause=exc
                ) from exc

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
            self._arcjet_after_decision(decision, readable)
        except _BLOCKED:
            raise
        except Exception as exc:
            if self._arcjet.on_guard_error == "deny":
                raise ArcjetToolUnavailableError(
                    self._arcjet.action, cause=exc
                ) from exc

    def _arcjet_after_decision(self, decision: Decision, readable: bool) -> None:
        """The fail-closed rules, applied once for both flavours.

        Pure sync code: it raises or returns, so the async evaluator calls it
        without crossing the boundary.
        """
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

    def _arcjet_blocked(
        self,
        error: ToolException,
        raw: Any,
        tool_call_id: str | None,
        config: RunnableConfig | None,
    ) -> Any:
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
        every span. The report reads the same sources an allowed call's run
        would — this handle's fields folded into the config, the delegate's
        fields as the tool's own — so blocked and allowed calls land on the
        same handlers with the same labels.
        """
        run_manager = self._arcjet_open_run(
            raw, tool_call_id, self._arcjet_child_config(config)
        )
        if isinstance(error, ArcjetToolDeniedError):
            try:
                content = _handle_tool_exception(
                    cast(BaseTool, self), error, tool_call_id
                )
            except ToolException:
                pass  # No handler took it; report the error below and re-raise.
            else:
                if run_manager is not None:
                    with _reporting(self._arcjet.action):
                        run_manager.on_tool_end(content)
                return content
        if run_manager is not None:
            with _reporting(self._arcjet.action):
                run_manager.on_tool_error(error)
        raise error

    async def _arcjet_blocked_async(
        self,
        error: ToolException,
        raw: Any,
        tool_call_id: str | None,
        config: RunnableConfig | None,
    ) -> Any:
        """The awaitable counterpart of :meth:`_arcjet_blocked`."""
        run_manager = await self._arcjet_open_run_async(
            raw, tool_call_id, self._arcjet_child_config(config)
        )
        if isinstance(error, ArcjetToolDeniedError):
            try:
                content = _handle_tool_exception(
                    cast(BaseTool, self), error, tool_call_id
                )
            except ToolException:
                pass  # No handler took it; report the error below and re-raise.
            else:
                if run_manager is not None:
                    with _reporting(self._arcjet.action):
                        await run_manager.on_tool_end(content)
                return content
        if run_manager is not None:
            with _reporting(self._arcjet.action):
                await run_manager.on_tool_error(error)
        raise error

    def _arcjet_open_run(
        self, raw: Any, tool_call_id: str | None, config: RunnableConfig
    ) -> Any:
        """Open the blocked call's run on the callbacks, or ``None``.

        ``None`` on any failure: a trace is observational, and a callback
        handler that fails must not turn a denial into something else.
        """
        try:
            manager = CallbackManager.configure(*self._arcjet_configure_args(config))
            serialized, input_str, start_kwargs = self._arcjet_start_args(
                raw, tool_call_id
            )
            return manager.on_tool_start(serialized, input_str, **start_kwargs)
        except Exception:
            logger.warning(
                "arcjet: could not report a blocked call to %r on its callbacks",
                self._arcjet.action,
                exc_info=True,
            )
            return None

    async def _arcjet_open_run_async(
        self, raw: Any, tool_call_id: str | None, config: RunnableConfig
    ) -> Any:
        """The awaitable counterpart of :meth:`_arcjet_open_run`."""
        try:
            manager = AsyncCallbackManager.configure(
                *self._arcjet_configure_args(config)
            )
            serialized, input_str, start_kwargs = self._arcjet_start_args(
                raw, tool_call_id
            )
            return await manager.on_tool_start(serialized, input_str, **start_kwargs)
        except Exception:
            logger.warning(
                "arcjet: could not report a blocked call to %r on its callbacks",
                self._arcjet.action,
                exc_info=True,
            )
            return None

    def _arcjet_configure_args(self, config: RunnableConfig) -> tuple[Any, ...]:
        """The seven ``configure`` arguments, once, for both manager flavours.

        The tool-level values come from the delegate, because the delegate is
        what an allowed call's own run reads; this handle's fields reach the
        report through the merged config instead.
        """
        tool = self._arcjet_tool
        return (
            config.get("callbacks"),
            tool.callbacks,
            tool.verbose,
            config.get("tags"),
            tool.tags,
            config.get("metadata"),
            tool.metadata,
        )

    def _arcjet_start_args(
        self, raw: Any, tool_call_id: str | None
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
            {"inputs": filtered, "tool_call_id": tool_call_id},
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


def _call_arguments(
    signature: inspect.Signature, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> Any:
    """A direct call's arguments, keyed the way the tool's own schema keys them.

    Binding to the signature is what turns a positional call into the mapping a
    policy resolver is documented to receive, so a resolver sees the same thing
    whether the model called the tool or the application called its function.
    An unbindable call is handed on untouched: the tool is about to raise over
    it anyway, and the checkpoint should not be the thing that reports it.
    """
    try:
        bound = signature.bind(*args, **kwargs)
    except TypeError:
        return kwargs or (args[0] if len(args) == 1 else {})
    bound.apply_defaults()
    return dict(bound.arguments)


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
        func_signature = inspect.signature(inner_func)

        @functools.wraps(inner_func)
        def guarded_func(*args: Any, **kwargs: Any) -> Any:
            evaluate = cast(Any, guarded)._arcjet_evaluate
            evaluate(_call_arguments(func_signature, args, kwargs), None, None)
            return inner_func(*args, **kwargs)

        cast(Any, guarded).func = guarded_func

    coroutine = getattr(guarded, "coroutine", None)
    if callable(coroutine):
        inner_coroutine = cast(Callable[..., Awaitable[Any]], coroutine)
        coroutine_signature = inspect.signature(inner_coroutine)

        @functools.wraps(inner_coroutine)
        async def guarded_coroutine(*args: Any, **kwargs: Any) -> Any:
            evaluate = cast(Any, guarded)._arcjet_evaluate_async
            await evaluate(
                _call_arguments(coroutine_signature, args, kwargs), None, None
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

    A guarded tool pickles if the tool it wraps does, carrying the policy but
    not *guard*: a client cannot cross a process boundary, and pickling one
    would write the site key into whatever the pickle is stored in. The
    receiving process supplies its own with
    :func:`~arcjet.guard.register_arcjet` before loading the tool.

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
    # The wrapper subclasses the tool's class, so it has every field the tool
    # has; no membership check is needed.
    for name in type(tool).model_fields:
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
