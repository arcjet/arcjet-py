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

import inspect
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

from langchain_core.messages import ToolMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import BaseTool, ToolException
from langchain_core.tools.simple import Tool as SimpleTool
from pydantic import BaseModel, PrivateAttr

from ._client import ArcjetGuard, ArcjetGuardSync
from ._policy_input import PolicyInputMap
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


class _InvalidArguments(Exception):
    """The wrapped tool's own validation rejected this call's arguments.

    Not an Arcjet failure, and never surfaced to the caller: the tool is handed
    the call so it raises, or applies ``handle_validation_error``, exactly as
    it would have without a checkpoint in front of it.  No effect can run
    either way, because the tool rejects the call before reaching its body.
    """


def _unwrap_tool_call(value: Any) -> tuple[Any, str | None]:
    """A ToolCall-shaped input split into its arguments and its id."""
    if isinstance(value, dict) and value.get("type") == "tool_call":
        return value.get("args", {}), value.get("id")
    return value, None


def _arguments(tool: BaseTool, raw: Any, tool_call_id: str | None) -> Mapping[str, Any]:
    """The arguments the tool is about to receive, as the tool itself reads them.

    Delegates to the tool's own ``_parse_input`` rather than re-deriving the
    rule from ``tool_call_schema``: that schema is not the parsing contract for
    every tool, and regenerating it drops the author's field validators, which
    would show a resolver a different value than the tool runs with.

    Two things are then corrected.  The input is copied first, because
    ``_parse_input`` writes into the mapping it is given and that mapping is
    usually the ``args`` of a ``ToolCall`` living in message history.  And the
    result is narrowed to what the model can actually supply: ``_parse_input``
    re-adds arguments the framework injects — credentials, graph state, the
    tool call id — that ``tool_call_schema`` deliberately hides, and a policy
    resolver must not be handed those.
    """
    if isinstance(raw, Mapping):
        raw = dict(raw)

    try:
        parsed = tool._parse_input(raw, tool_call_id)
    except Exception as exc:
        raise _InvalidArguments from exc

    visible = tool.args
    if isinstance(parsed, dict):
        return {key: value for key, value in parsed.items() if key in visible}

    # A bare string comes back out of _parse_input unchanged. LangChain binds
    # it to the schema's first field whatever the field count, so key it the
    # same way rather than inventing a name the tool will never use.
    names = list(visible)
    return {names[0]: parsed} if names else {"input": parsed}


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


class _GuardMixin:
    """The checkpoint, in front of a tool this wrapper delegates to.

    Both wrapper classes below mix this in.  It holds no pydantic state of its
    own — the concrete classes declare the private attributes — so it cannot
    disturb the field definitions of the model it is mixed into.
    """

    _arcjet: _Policy
    _arcjet_tool: BaseTool

    def invoke(
        self, input: Any, config: RunnableConfig | None = None, **kwargs: Any
    ) -> Any:
        raw, tool_call_id = _unwrap_tool_call(input)
        try:
            self._arcjet_evaluate(raw, tool_call_id, config)
        except _InvalidArguments:
            pass
        except ArcjetToolDeniedError as exc:
            return _handle_tool_exception(cast(BaseTool, self), exc, tool_call_id)
        return self._arcjet_tool.invoke(input, config, **kwargs)

    async def ainvoke(
        self, input: Any, config: RunnableConfig | None = None, **kwargs: Any
    ) -> Any:
        raw, tool_call_id = _unwrap_tool_call(input)
        try:
            await self._arcjet_evaluate_async(raw, tool_call_id, config)
        except _InvalidArguments:
            pass
        except ArcjetToolDeniedError as exc:
            return _handle_tool_exception(cast(BaseTool, self), exc, tool_call_id)
        return await self._arcjet_tool.ainvoke(input, config, **kwargs)

    def run(self, tool_input: Any, *args: Any, **kwargs: Any) -> Any:
        tool_call_id = kwargs.get("tool_call_id")
        try:
            self._arcjet_evaluate(tool_input, tool_call_id, kwargs.get("config"))
        except _InvalidArguments:
            pass
        except ArcjetToolDeniedError as exc:
            return _handle_tool_exception(cast(BaseTool, self), exc, tool_call_id)
        return self._arcjet_tool.run(tool_input, *args, **kwargs)

    async def arun(self, tool_input: Any, *args: Any, **kwargs: Any) -> Any:
        tool_call_id = kwargs.get("tool_call_id")
        try:
            await self._arcjet_evaluate_async(
                tool_input, tool_call_id, kwargs.get("config")
            )
        except _InvalidArguments:
            pass
        except ArcjetToolDeniedError as exc:
            return _handle_tool_exception(cast(BaseTool, self), exc, tool_call_id)
        return await self._arcjet_tool.arun(tool_input, *args, **kwargs)

    def _arcjet_evaluate(
        self, raw: Any, tool_call_id: str | None, config: RunnableConfig | None
    ) -> None:
        if not isinstance(self._arcjet.guard, ArcjetGuardSync):
            raise TypeError(
                "A synchronous LangChain invocation requires ArcjetGuardSync"
            )
        resolved = config if config is not None else cast(RunnableConfig, {})
        try:
            decision = self._arcjet.guard.guard(
                self._arcjet.rules,
                label=self._arcjet.action,
                actor=self._arcjet_actor(resolved),
                inputs=self._arcjet_inputs(raw, tool_call_id, resolved),
            )
            _check_decision(decision, self._arcjet.action, self._arcjet.on_guard_error)
        except (ArcjetToolDeniedError, ArcjetToolUnavailableError, _InvalidArguments):
            raise
        except Exception as exc:
            if self._arcjet.on_guard_error == "deny":
                raise ArcjetToolUnavailableError(
                    self._arcjet.action, cause=exc
                ) from exc

    async def _arcjet_evaluate_async(
        self, raw: Any, tool_call_id: str | None, config: RunnableConfig | None
    ) -> None:
        if not isinstance(self._arcjet.guard, ArcjetGuard):
            raise TypeError("An asynchronous LangChain invocation requires ArcjetGuard")
        resolved = config if config is not None else cast(RunnableConfig, {})
        try:
            decision = await self._arcjet.guard.guard(
                self._arcjet.rules,
                label=self._arcjet.action,
                actor=await self._arcjet_actor_async(resolved),
                inputs=await self._arcjet_inputs_async(raw, tool_call_id, resolved),
            )
            _check_decision(decision, self._arcjet.action, self._arcjet.on_guard_error)
        except (ArcjetToolDeniedError, ArcjetToolUnavailableError, _InvalidArguments):
            raise
        except Exception as exc:
            if self._arcjet.on_guard_error == "deny":
                raise ArcjetToolUnavailableError(
                    self._arcjet.action, cause=exc
                ) from exc

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
        arguments = _arguments(self._arcjet_tool, raw, tool_call_id)
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

    def __deepcopy__(self, memo: dict[int, Any]) -> Any:
        # The Arcjet client owns a connection pool and a lock, so it is shared
        # with the copy rather than duplicated: copying a client is not
        # meaningful, and `copy.deepcopy` cannot do it at all.
        guard = self._arcjet.guard
        memo[id(guard)] = guard
        return BaseModel.__deepcopy__(cast(BaseModel, self), memo)


def _discard(value: Any) -> None:
    """Close a coroutine that will never be awaited.

    Dropping it instead leaves a ``RuntimeWarning`` to surface at an arbitrary
    later garbage collection, which is a hard failure under ``-W error``.
    """
    close = getattr(value, "close", None)
    if callable(close):
        close()


class _GuardedTool(_GuardMixin, BaseTool):
    """Guards any tool, and asks that tool what its schema is.

    ``args_schema`` is a cache of an answer, not the answer: a tool that
    declares none has its schema derived from its own ``_run``, which this
    wrapper does not have.  Forwarding the derivation keeps ``args``, the
    provider conversions and ``bind_tools`` reading the tool that knows.
    """

    _arcjet: _Policy = PrivateAttr()
    _arcjet_tool: BaseTool = PrivateAttr()

    def get_input_schema(self, config: RunnableConfig | None = None) -> Any:
        return self._arcjet_tool.get_input_schema(config)

    @property
    def tool_call_schema(self) -> Any:
        return self._arcjet_tool.tool_call_schema

    @property
    def args(self) -> dict[str, Any]:
        return self._arcjet_tool.args

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("Guarded tools delegate to the tool they wrap")


class _GuardedSimpleTool(_GuardMixin, SimpleTool):
    """Guards a ``Tool`` built from a bare function.

    Such a tool has no schema to forward: LangChain advertises it through an
    escape hatch in ``_format_tool_to_openai_function`` gated on the concrete
    ``Tool`` class, so the wrapper has to be one for the model to be told the
    same thing.  Leaving ``args_schema`` unset is the other half of that gate.
    """

    _arcjet: _Policy = PrivateAttr()
    _arcjet_tool: BaseTool = PrivateAttr()

    @property
    def args(self) -> dict[str, Any]:
        return self._arcjet_tool.args


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
    class overrides still applies, and the model is told exactly what the
    unguarded tool advertised.

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
    """
    wrapper: type[BaseTool]
    if isinstance(tool, SimpleTool) and not tool.args_schema:
        wrapper = _GuardedSimpleTool
    else:
        wrapper = _GuardedTool

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
    return guarded


__all__ = [
    "ArcjetToolDeniedError",
    "ArcjetToolUnavailableError",
    "guard_tool",
]
