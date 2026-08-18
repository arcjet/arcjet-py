"""The guarded tool itself: :func:`guard_tool` and the checkpoint it installs.

A guarded tool is an instance of the wrapped tool's own class — a generated
subclass — that evaluates policy and then hands the call to the tool it wraps.
Everything the framework derives from a tool — its schema, its arguments — is
asked of the wrapped tool rather than recomputed here, so a guarded tool
advertises and executes exactly what the unguarded one did.

Imported through :mod:`arcjet.guard.langchain`, which is the public name.
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
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal, cast
from weakref import WeakKeyDictionary

from langchain_core.callbacks import (
    AsyncCallbackManager,
    CallbackManager,
)
from langchain_core.runnables import RunnableConfig
from langchain_core.runnables.config import ensure_config
from langchain_core.tools import BaseTool, ToolException
from langchain_core.tools.base import FILTERED_ARGS
from langchain_core.tools.base import _format_output as _lc_format_output
from langchain_core.tools.base import (
    _get_runnable_config_param as _lc_config_param,
)
from langchain_core.tools.base import (
    _handle_tool_error as _lc_handle_tool_error,
)
from pydantic import BaseModel, PrivateAttr, ValidationError
from pydantic.v1 import BaseModel as BaseModelV1
from pydantic.v1 import ValidationError as ValidationErrorV1

from arcjet._errors import ArcjetMisconfiguration
from arcjet._logging import logger

from .._client import _GuardClient
from .._policy_input import PolicyInputMap
from .._registry import _awaitable, _blocking, registered_client
from .._rules import RuleWithInput
from .._types import Decision

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

#: Stands for "there is no content to answer with, so re-raise". A sentinel
#: rather than ``None``, because a handler returning ``None`` is answering.
_RERAISE: Any = object()

#: The tool fields the guard replaces with checkpointed copies rather than
#: carrying across. They are derived from the wrapped tool every time the
#: handle is built, so a copy and a pickle both leave them out.
_DERIVED_FIELDS = frozenset({"func", "coroutine"})

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


def _resolved(
    resolve: Callable[..., Any],
    *args: Any,
    so_far: BaseException | None = None,
    **kwargs: Any,
) -> tuple[Any, BaseException | None]:
    """Run one resolver, returning its failure alongside rather than raising it.

    A resolver that fails degrades what the decision is made *from*; it is not
    a failure to reach a decision, so Guard is still called and still holds a
    record that the call happened. The first failure is the one returned: a
    later one is usually the same wiring mistake seen twice.
    """
    try:
        return resolve(*args, **kwargs), so_far
    except _UnreadableArguments as unreadable:
        return None, so_far or unreadable.__cause__ or unreadable
    except Exception as exc:
        return None, so_far or exc


async def _resolved_async(
    resolve: Callable[..., Awaitable[Any]],
    *args: Any,
    so_far: BaseException | None = None,
    **kwargs: Any,
) -> tuple[Any, BaseException | None]:
    """The awaitable counterpart of :func:`_resolved`."""
    try:
        return await resolve(*args, **kwargs), so_far
    except _UnreadableArguments as unreadable:
        return None, so_far or unreadable.__cause__ or unreadable
    except Exception as exc:
        return None, so_far or exc


@contextmanager
def _fail_closed(action: str, on_guard_error: OnGuardError) -> Iterator[None]:
    """Turn a failure to evaluate policy into the outcome ``on_guard_error`` asks for.

    Anything the checkpoint raises to stop a call passes through: it is the
    evaluation's result, not a failure to reach one. Anything else means policy
    was not evaluated, which is what ``on_guard_error`` governs.

    Shared by both evaluators so the two flavours cannot raise
    differently-shaped errors for the same failure.
    """
    try:
        yield
    except _BLOCKED:
        raise
    except Exception as exc:
        if on_guard_error != "allow":
            raise ArcjetToolUnavailableError(action, cause=exc) from exc
        # Allowing the call is not the same as there being nothing to report: a
        # resolver that raises on every call leaves policy permanently
        # unevaluated, which has no other symptom.
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
    verbose: bool = False
    start_color: str | None = "green"
    #: What `BaseTool.run` hands `on_tool_end`, as distinct from `start_color`
    #: which it hands `on_tool_start`.
    color: str | None = "green"
    # A default_factory rather than a bare default: Python 3.11's dataclasses
    # rejects any default whose type defines `__hash__ = None`, and mappingproxy
    # only gained `__hash__` in 3.12. A literal default makes this module
    # unimportable on 3.11, which is inside the supported range.
    extra: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

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

    @classmethod
    def of_run(
        cls,
        callbacks: Any,
        tags: list[str] | None,
        metadata: dict[str, Any] | None,
        run_name: str | None,
        run_id: Any,
        tool_call_id: str | None,
        verbose: bool | None,
        start_color: str | None,
        color: str | None,
        extra: Mapping[str, Any],
    ) -> "_Report":
        """The values a caller handed ``run`` or ``arun`` directly."""
        return cls(
            callbacks,
            tags,
            metadata,
            run_name,
            run_id,
            tool_call_id,
            bool(verbose),
            start_color,
            color,
            MappingProxyType(dict(extra)),
        )


def _checkpoint_config(given: RunnableConfig | None) -> RunnableConfig:
    """The config a policy resolver reads.

    ``ensure_config`` is what lets a resolver see a config a chain passed down
    without the caller re-threading it, and it normalizes the known keys. But
    it also *relocates* every unrecognized top-level key into ``configurable``,
    so a resolver written as ``lambda config: config["user_id"]`` — reading the
    config exactly as it was handed to ``invoke`` — stopped finding it and
    raised. Under the fail-closed default that denied every call to the tool.

    Both readings are made to work, from both directions. ``configurable`` is
    surfaced at the top level, because by the time a tool inside a chain is
    reached the *chain's* own ``ensure_config`` has already relocated the key
    and there is nothing left for this to restore — a resolver reading the top
    level then worked on a direct call and denied every call once the tool was
    placed in a chain. The caller's own keys go on last for the direct case.

    Nothing already present is displaced, so a genuine ``RunnableConfig`` key
    always wins over a same-named ``configurable`` entry.
    """
    resolved = ensure_config(given)
    merged: dict[str, Any] = {**cast("dict[str, Any]", resolved)}
    for key, value in (resolved.get("configurable") or {}).items():
        merged.setdefault(key, value)
    for key, value in (given or {}).items():
        merged.setdefault(key, value)
    return cast(RunnableConfig, merged)


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


#: Parameter names that describe how a tool is *called* rather than what it
#: takes. The framework supplies them, ``tool_call_schema`` hides them from the
#: model, and a resolver must not be handed them.
#:
#: One home for a question this module asks in two places: which of a derived
#: schema's names are real arguments, and which of a direct call's bound
#: parameters came from the framework. ``_filter_injected_args`` answers the
#: same question for a *parsed* mapping, where the tool's own key-space applies.
_FRAMEWORK_ARGS = frozenset({"args", "kwargs", "config", *FILTERED_ARGS})


@dataclass(frozen=True, slots=True)
class _Call:
    """One tool call, as the checkpoint reads it.

    Built by each entrypoint and passed whole, so the evaluators and the
    resolvers take one argument rather than four that must stay in step.

    *validated* is false on the surfaces that run the tool's body with the
    arguments as given — a direct ``_run``, or the tool's own ``func``. Nothing
    downstream will reject those, so arguments a resolver cannot read there
    mean an unevaluated policy rather than a call the tool refuses anyway.
    """

    raw: Any
    tool_call_id: str | None
    config: RunnableConfig
    validated: bool = True


def _as_data(value: Any) -> Any:
    """A nested model as plain data, in whichever pydantic flavour it is.

    Both, because langchain-core accepts a pydantic v1 ``args_schema`` and this
    module already recognizes both flavours when one rejects a call. Handling
    only v2 handed a v1 tool's resolver a live model where the documented type
    is a ``Mapping``, so a resolver reading ``arguments["addr"]["city"]``
    raised — and under the fail-closed default denied every call to that tool.
    """
    if isinstance(value, BaseModel):
        return value.model_dump()
    if isinstance(value, BaseModelV1):
        return value.dict()
    # Through containers as well: `list[Model]` and `dict[str, Model]` are
    # ordinary schema shapes — recipients, batch items, chat messages — and a
    # model one level down is as unreadable to a resolver as one at the top.
    if isinstance(value, Mapping):
        return {key: _as_data(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return type(value)(_as_data(item) for item in value)
    return value


def _resolver_view(tool: BaseTool, call: _Call) -> Mapping[str, Any]:
    """The arguments the tool is about to receive, as the tool itself reads them.

    The one place that builds what a policy resolver sees, whichever entrypoint
    the call arrived through.

    Delegates to the tool's own ``_parse_input`` rather than re-deriving the
    rule from ``tool_call_schema``: that schema is not the parsing contract for
    every tool, and regenerating it drops the author's field validators, which
    would show a resolver a different value than the tool runs with.

    The input is copied first, because ``_parse_input`` writes into the mapping
    it is given and that mapping is usually the ``args`` of a ``ToolCall``
    living in message history.

    Raises whatever the tool's own validation raises. Callers treat resolving
    arguments as best-effort and evaluate policy regardless.
    """
    if call.raw is _UNREADABLE:
        raise _UnreadableArguments(
            "the call's arguments could not be matched to the tool's callable, "
            "which reports no signature to bind them to"
        )
    raw = dict(call.raw) if isinstance(call.raw, Mapping) else call.raw

    parsed = tool._parse_input(raw, call.tool_call_id)
    if not isinstance(parsed, dict):
        # A bare value comes back unchanged, so it needs a key. The tool's own
        # `args` supplies one — unless every name there is framework
        # scaffolding, which is what a tool with no schema and a variadic
        # `_run` reports. Naming the value after that tells a resolver nothing.
        names = [name for name in tool.args if name not in _FRAMEWORK_ARGS]
        return {names[0]: parsed} if names else {"input": parsed}

    # `_parse_input` re-adds arguments the framework injects — credentials,
    # graph state, the tool call id — that the model never sent. A policy
    # resolver must not be handed those, and the tool's own filter is what
    # identifies them, against the key-space the arguments are actually in.
    parsed = tool._filter_injected_args(parsed)

    # Nested models come back as instances. Resolvers are documented to take a
    # `Mapping[str, Any]`, so hand them data rather than model objects.
    return {key: _as_data(value) for key, value in parsed.items()}


def _handles_tool_errors(tool: BaseTool) -> bool:
    """Whether *tool* converts a ``ToolException`` rather than raising it.

    Gated on truthiness, as ``BaseTool.run`` gates it: an empty string is a
    handler that produces nothing, and the tool raises rather than answering
    with it.

    Asked before the handler runs, so that a handler which raises is not
    mistaken for there being no handler at all: its exception is the tool
    author's, and it belongs to the caller.
    """
    return bool(tool.handle_tool_error)


def _handle_tool_exception(
    tool: BaseTool, error: ToolException, tool_call_id: str | None
) -> Any:
    """The outcome LangChain would give this error, from LangChain's own code.

    Using LangChain's helpers rather than re-deriving the formatting is what
    makes a denial reach the model shaped exactly as the tool's own error
    would have been — a handler returning a ``ToolMessage`` or a mapping
    included.
    """
    # Only reached when `_handles_tool_errors` said there is one, so the
    # falsy half of the field's type — which LangChain's own helper does not
    # accept — cannot arrive here.
    content = _lc_handle_tool_error(error, flag=cast(Any, tool.handle_tool_error))
    return _lc_format_output(content, None, tool_call_id, tool.name, "error")


@dataclass(frozen=True, slots=True)
class _Guarded:
    """Everything the guard keeps about one guarded tool.

    One object, under one name, because the handle is an instance of the tool's
    own class: every name the guard puts there is a name the tool may not use,
    and the guard reserves exactly this one.
    """

    #: The tool this handle wraps. Asked for anything the framework derives
    #: from a tool, and run once the checkpoint allows the call.
    delegate: BaseTool
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
    # The delegate's own `_run`/`_arun` signatures, for the same reason: they
    # cannot change for the life of a guarded tool, and taking a signature is
    # the most expensive thing on that path by some way.
    run_signature: inspect.Signature | None
    arun_signature: inspect.Signature | None
    # Which parameter, if any, is the RunnableConfig — by annotation, as
    # LangChain identifies it, rather than by the name `config`.
    run_config_param: str | None
    arun_config_param: str | None

    # The checkpoint itself lives here rather than on the handle. It reads
    # nothing else off one, and the guarded `func`/`coroutine` are stored *on*
    # the handle — so a closure over the handle would make the two refer to
    # each other, and no guarded tool carrying a callable could be reclaimed by
    # reference counting. Closing over this state leaves no cycle, and a
    # callable detached from its handle still evaluates.

    def evaluate(self, call: _Call) -> None:
        guard = self.blocking
        if guard is None:
            raise TypeError(
                "A synchronous LangChain invocation requires a guard client with a "
                "blocking guard(), such as ArcjetGuardSync"
            )
        with _fail_closed(self.action, self.on_guard_error):
            actor, degraded = _resolved(self._actor, call.config)
            inputs, degraded = _resolved(self._inputs, call, so_far=degraded)
            decision = guard(self.rules, label=self.action, actor=actor, inputs=inputs)
            self._after_decision(decision, degraded)

    async def evaluate_async(self, call: _Call) -> None:
        guard = self.awaitable
        if guard is None:
            raise TypeError(
                "An asynchronous LangChain invocation requires a guard client with an "
                "awaitable guard(), such as ArcjetGuard"
            )
        with _fail_closed(self.action, self.on_guard_error):
            actor, degraded = await _resolved_async(self._actor_async, call.config)
            inputs, degraded = await _resolved_async(
                self._inputs_async, call, so_far=degraded
            )
            decision = await guard(
                self.rules, label=self.action, actor=actor, inputs=inputs
            )
            self._after_decision(decision, degraded)

    def _after_decision(
        self, decision: Decision, degraded: BaseException | None
    ) -> None:
        """The fail-closed rules, applied once for both flavours.

        *degraded* is whatever stopped one of the decision's inputs being
        resolved, or ``None``. Guard has seen the call either way, so the
        decision is on the record; what ``on_guard_error`` governs is whether a
        call the policy could not fully judge is allowed to run.

        Pure sync code: it raises or returns, so the async evaluator calls it
        without crossing the boundary.
        """
        if decision.conclusion == "DENY":
            raise ArcjetToolDeniedError(self.action, decision)
        # The cause travels with either refusal: without it the operator is
        # told only that policy could not be evaluated, not what stopped it.
        # The two conditions co-occur during a transport outage, which is when
        # a resolver failure is most likely a symptom of the same fault.
        if decision.has_failed_open() and self.on_guard_error != "allow":
            raise ArcjetToolUnavailableError(self.action, cause=degraded)
        if degraded is None:
            return
        if self.on_guard_error != "allow":
            raise ArcjetToolUnavailableError(self.action, cause=degraded)
        logger.warning(
            "arcjet: could not resolve everything policy needed for a call to %r; "
            "it was evaluated without that, and the call proceeds because "
            "on_guard_error is 'allow'",
            self.action,
            exc_info=degraded,
        )

    def _resolve_actor(
        self, config: RunnableConfig
    ) -> str | None | Awaitable[str | None]:
        actor = self.actor
        if not callable(actor):
            return actor
        return cast(_ActorFn, actor)(config)

    def _resolve_inputs(
        self, call: _Call
    ) -> PolicyInputMap | None | Awaitable[PolicyInputMap | None]:
        resolver = self.inputs
        if not callable(resolver):
            return resolver
        # Parsed only here, because a resolver is the only thing that reads the
        # arguments: a tool with no resolver configured is never parsed at all.
        try:
            arguments = _resolver_view(self.delegate, call)
        except _SCHEMA_REJECTED as exc:
            if not call.validated:
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
                self.action,
            )
            return None
        except Exception as exc:
            raise _UnreadableArguments from exc
        return cast(_InputsFn, resolver)(arguments, call.config)

    def _actor(self, config: RunnableConfig) -> str | None:
        return _not_awaited(self._resolve_actor(config), "actor")

    def _inputs(self, call: _Call) -> PolicyInputMap | None:
        return _not_awaited(self._resolve_inputs(call), "input")

    async def _actor_async(self, config: RunnableConfig) -> str | None:
        return await _awaited(self._resolve_actor(config))

    async def _inputs_async(self, call: _Call) -> PolicyInputMap | None:
        return await _awaited(self._resolve_inputs(call))


def _state_of(handle: Any) -> "_Guarded":
    """The guard's state on *handle*, or a diagnosis of how it went missing.

    LangChain rebuilds a runnable through its own class in a few places:
    ``configurable_fields`` and ``configurable_alternatives`` construct
    ``self.default.__class__(**init_params)`` once a configurable value is
    actually supplied. Only declared fields survive that, and the guard's state
    is a private attribute, so the rebuilt handle has none.

    A module-level function rather than another attribute on the handle,
    because every name the guard puts there is a name the tool may not use and
    ``_arcjet_state`` is the one this reserves.
    """
    state = handle._arcjet_state
    if state is None:
        raise ArcjetMisconfiguration(
            "This guarded tool has no Arcjet state, which happens when "
            "LangChain rebuilds a tool through its own class — "
            "configurable_fields() and configurable_alternatives() do that "
            "once a configurable value is supplied, and the rebuilt tool keeps "
            "only its declared fields. Apply those to the tool before guarding "
            "it."
        )
    return state


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

    _arcjet_state: _Guarded

    def get_input_schema(self, config: RunnableConfig | None = None) -> Any:
        """The wrapped tool's schema, always.

        The one schema override: everything else that reports a schema —
        ``tool_call_schema``, ``args``, the provider conversions — derives from
        this on the base class, so forwarding here forwards them all. It is
        also the only way a tool declaring no schema gets one, since that is
        derived from a ``_run`` this wrapper does not have.

        Forwarded unconditionally, so a schema assigned to the handle after
        ``guard_tool`` does not change what the model is told. It never changed
        what the tool *accepted* — the wrapped tool parses and executes against
        its own schema either way — so honouring it advertised a narrowing that
        was not enforced. Narrow the wrapped tool before guarding it instead,
        which both hides the argument and stops it.
        """
        return self._arcjet_state.delegate.get_input_schema(config)

    @property
    def tool_call_schema(self) -> Any:
        """The wrapped tool's tool-call schema, always.

        Forwarded as well as :meth:`get_input_schema`, because for a JSON
        schema — an ``args_schema`` that is a ``dict`` — ``BaseTool`` reads
        ``self.args_schema`` here directly and never reaches the derivation
        above. This is what the provider conversions read, so without it a
        schema assigned to the handle after ``guard_tool`` still changed what
        the model was told, for exactly the tools the forwarding was meant to
        cover.
        """
        return self._arcjet_state.delegate.tool_call_schema

    @property
    def args(self) -> dict[str, Any]:
        """The wrapped tool's arguments, always.

        The third derivation, and the last one that can disagree: for a JSON
        schema ``BaseTool.args`` reads ``self.args_schema`` directly, bypassing
        even ``tool_call_schema``. Forwarding all three is what makes the rule
        hold without exception — the handle advertises what the wrapped tool
        advertises, whichever kind of schema it has.
        """
        return self._arcjet_state.delegate.args

    def invoke(
        self, input: Any, config: RunnableConfig | None = None, **kwargs: Any
    ) -> Any:
        """Guard a call in the flavour it was made in, then hand it on.

        Overridden rather than left to ``BaseTool.invoke`` because that reduces
        every call to ``run``, including an awaited call to a tool with no
        async body — so an application with an async client would reach the
        blocking checkpoint and be refused a client it correctly supplied. The
        flavour of the checkpoint follows the entrypoint; how the tool then
        executes is the tool's own business.

        The config is resolved here so the checkpoint reads what the tool will
        run with, including one a chain passed down without the caller
        re-threading it.
        """
        resolved = ensure_config(config)
        raw, tool_call_id = _unwrap_tool_call(input)
        try:
            self._arcjet_evaluate(_Call(raw, tool_call_id, _checkpoint_config(config)))
        except _BLOCKED as exc:
            return self._arcjet_blocked(exc, raw, _Report.of(resolved, tool_call_id))
        return self._arcjet_state.delegate.invoke(input, resolved, **kwargs)

    async def ainvoke(
        self, input: Any, config: RunnableConfig | None = None, **kwargs: Any
    ) -> Any:
        """The awaitable counterpart of :meth:`invoke`."""
        resolved = ensure_config(config)
        raw, tool_call_id = _unwrap_tool_call(input)
        try:
            await self._arcjet_evaluate_async(
                _Call(raw, tool_call_id, _checkpoint_config(config))
            )
        except _BLOCKED as exc:
            return await self._arcjet_blocked_async(
                exc, raw, _Report.of(resolved, tool_call_id)
            )
        return await self._arcjet_state.delegate.ainvoke(input, resolved, **kwargs)

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

        The config a resolver reads is derived by ``_checkpoint_config``, for
        the same reason it is in :meth:`invoke`. What the delegate runs with is
        the caller's own config, forwarded untouched.
        """
        try:
            self._arcjet_evaluate(
                _Call(tool_input, tool_call_id, _checkpoint_config(config))
            )
        except _BLOCKED as exc:
            return self._arcjet_blocked(
                exc,
                tool_input,
                _Report.of_run(
                    callbacks,
                    tags,
                    metadata,
                    run_name,
                    run_id,
                    tool_call_id,
                    verbose,
                    start_color,
                    color,
                    kwargs,
                ),
            )
        return self._arcjet_state.delegate.run(
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
        try:
            await self._arcjet_evaluate_async(
                _Call(tool_input, tool_call_id, _checkpoint_config(config))
            )
        except _BLOCKED as exc:
            return await self._arcjet_blocked_async(
                exc,
                tool_input,
                _Report.of_run(
                    callbacks,
                    tags,
                    metadata,
                    run_name,
                    run_id,
                    tool_call_id,
                    verbose,
                    start_color,
                    color,
                    kwargs,
                ),
            )
        return await self._arcjet_state.delegate.arun(
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
        ``self._run`` — a preview or dry-run method, say. The checkpoint still
        runs first, so there is no unguarded path through here.

        Such a helper *reads* the handle's own copy of the tool's state, which
        is the state the tool was guarded with. One that writes is a different
        matter: the write lands on the handle, and the body runs on the wrapped
        tool, so it does not reach the call. That is the same rule as a
        reassigned field — configure the tool before guarding it.
        """
        delegate = self._arcjet_state.delegate
        raw, config, rejected = _call_arguments(
            self._arcjet_state.run_signature,
            args,
            kwargs,
            self._arcjet_state.run_config_param,
        )
        self._arcjet_evaluate(
            _Call(raw, None, _checkpoint_config(config), validated=rejected)
        )
        return delegate._run(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """The awaitable counterpart of :meth:`_run`."""
        delegate = self._arcjet_state.delegate
        raw, config, rejected = _call_arguments(
            self._arcjet_state.arun_signature,
            args,
            kwargs,
            self._arcjet_state.arun_config_param,
        )
        await self._arcjet_evaluate_async(
            _Call(raw, None, _checkpoint_config(config), validated=rejected)
        )
        return await delegate._arun(*args, **kwargs)

    def _arcjet_evaluate(self, call: _Call) -> None:
        _state_of(self).evaluate(call)

    async def _arcjet_evaluate_async(self, call: _Call) -> None:
        await _state_of(self).evaluate_async(call)

    def __deepcopy__(self, memo: dict[int, Any] | None = None) -> Any:
        """Copy the handle, sharing the client and rebinding the callables.

        The three Arcjet clients answer a copy with themselves, so a copy of a
        handle holding one keeps it. A hand-rolled double does not, and a copy
        of a recorder records where the test that made it cannot see — so the
        policy is shared here, whatever kind of client it holds.

        The guarded callables close over the handle they were made for, and a
        copy of a function is that same function, so without rebinding them the
        copy would evaluate the original's policy and call the original's tool.

        The client is pinned through the two bound methods that hold it, rather
        than by pinning the whole policy. Pinning the policy shared the wrapped
        tool as well, so a copy delegated to the very object the caller deep
        copied it to stop sharing — and a tool that caches, or holds a
        per-request handle, then crossed between them.
        """
        memo = {} if memo is None else memo
        policy = self._arcjet_state
        for bound in (policy.blocking, policy.awaitable):
            if bound is not None:
                memo[id(bound)] = bound
        copied = BaseModel.__deepcopy__(cast(BaseModel, self), memo)
        _guarded_callables(cast(BaseTool, copied))
        return copied

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

        The handle's own state rides along and is reapplied after the rebuild,
        so a tag or a narrowed schema set on the guarded handle survives the
        boundary. It travels as pydantic's own state rather than as a bag of
        fields, because replaying fields through assignment cannot restore a
        frozen model, drops whatever an ``extra="allow"`` tool holds outside
        its declared fields, and marks every field as explicitly set.

        The guard's own private attributes and the guarded callables stay out:
        the first hold the client, and the second are closures over this
        handle. The rebuild derives all of them fresh.
        """
        policy = self._arcjet_state
        state = cast(Any, self).__getstate__()
        fields = {
            name: value
            for name, value in (state.get("__dict__") or {}).items()
            if name not in _DERIVED_FIELDS
        }
        private = {
            name: value
            for name, value in (state.get("__pydantic_private__") or {}).items()
            if name != _GUARD_STATE
        }
        return (
            _rebuild_guarded_tool,
            (
                self._arcjet_state.delegate,
                policy.action,
                policy.actor,
                policy.inputs,
                policy.rules,
                policy.on_guard_error,
                {
                    "__dict__": fields,
                    "__pydantic_extra__": state.get("__pydantic_extra__"),
                    "__pydantic_fields_set__": set(
                        state.get("__pydantic_fields_set__") or ()
                    ),
                    "__pydantic_private__": private,
                },
            ),
        )

    def _arcjet_blocked(self, error: ToolException, raw: Any, report: _Report) -> Any:
        """Report a blocked call to the tool's callbacks and produce its outcome.

        The wrapped tool never runs, so it never opens a run of its own and a
        trace would otherwise hold no record of a blocked call.

        Only the blocked path reports: an allowed call is delegated to the
        tool, which opens its own run, and reporting here too would double
        every span. The report reads what an allowed call's own run reads —
        what the caller passed, and the delegate's fields as the tool's own —
        so both paths land on the same handlers, under the same run id, with
        the same labels and the same error handling.
        """
        # The run is opened first, as `BaseTool.run` opens it before it calls
        # `_handle_tool_error`. Computing the outcome first runs the tool
        # author's handler first, and a handler that raises then left the
        # blocked call with no trace at all — the gap this method exists to
        # close, missing exactly when something went wrong.
        run_manager = self._arcjet_open_run(raw, report)
        event, kwargs, content = self._arcjet_blocked_outcome(error, report)
        if run_manager is not None:
            with _reporting(self._arcjet_state.action):
                getattr(run_manager, event)(**kwargs)
        if content is _RERAISE:
            raise error
        return content

    async def _arcjet_blocked_async(
        self, error: ToolException, raw: Any, report: _Report
    ) -> Any:
        """The awaitable counterpart of :meth:`_arcjet_blocked`."""
        run_manager = await self._arcjet_open_run_async(raw, report)
        event, kwargs, content = self._arcjet_blocked_outcome(error, report)
        if run_manager is not None:
            with _reporting(self._arcjet_state.action):
                await getattr(run_manager, event)(**kwargs)
        if content is _RERAISE:
            raise error
        return content

    def _arcjet_blocked_outcome(
        self, error: ToolException, report: _Report
    ) -> tuple[str, dict[str, Any], Any]:
        """The callback event a blocked call closes with, and what it answers.

        A denial the tool's ``handle_tool_error`` converts ends the run with the
        handled content; anything else closes it as an error and re-raises,
        which :data:`_RERAISE` asks the caller to do.
        """
        if isinstance(error, ArcjetToolDeniedError) and _handles_tool_errors(
            self._arcjet_state.delegate
        ):
            content = _handle_tool_exception(
                self._arcjet_state.delegate, error, report.tool_call_id
            )
            # `BaseTool.run` closes a handled ToolException with
            # `on_tool_end(output, color=color, name=self.name, **kwargs)`, so
            # a handler reading `kwargs["name"]` to attribute a span finds it.
            return (
                "on_tool_end",
                {
                    **report.extra,
                    "output": content,
                    "color": report.color,
                    "name": self._arcjet_state.delegate.name,
                },
                content,
            )
        return (
            "on_tool_error",
            {"error": error, "tool_call_id": report.tool_call_id},
            _RERAISE,
        )

    def _arcjet_open_run(self, raw: Any, report: _Report) -> Any:
        """Open the blocked call's run on the callbacks, or ``None``.

        ``None`` on any failure: a trace is observational, and a callback
        handler that fails must not turn a denial into something else.
        """
        with _reporting(self._arcjet_state.action):
            manager = CallbackManager.configure(*self._arcjet_configure_args(report))
            serialized, input_str, start_kwargs = self._arcjet_start_args(raw, report)
            return manager.on_tool_start(serialized, input_str, **start_kwargs)
        return None

    async def _arcjet_open_run_async(self, raw: Any, report: _Report) -> Any:
        """The awaitable counterpart of :meth:`_arcjet_open_run`."""
        with _reporting(self._arcjet_state.action):
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
        tool = self._arcjet_state.delegate
        return (
            report.callbacks,
            tool.callbacks,
            tool.verbose or report.verbose,
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
        tool = self._arcjet_state.delegate
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
                # The caller's extras go first, so a stray `inputs=` cannot
                # displace the filtered arguments and corrupt the trace.
                # Unguarded, LangChain splats these at a call site and such a
                # collision raises; here it would be swallowed by `_reporting`
                # and cost the blocked call its trace, so it is dropped.
                **report.extra,
                "inputs": filtered,
                "tool_call_id": report.tool_call_id,
                "name": report.run_name,
                "run_id": report.run_id,
                "color": report.start_color,
            },
        )


def _not_awaited(value: Any, kind: str) -> Any:
    """*value*, refusing an awaitable a blocking checkpoint cannot wait on.

    The unawaited coroutine is closed rather than dropped: dropping it leaves a
    ``RuntimeWarning`` to surface at an arbitrary later garbage collection,
    which is a hard failure under ``-W error``.
    """
    if inspect.isawaitable(value):
        close = getattr(value, "close", None)
        if callable(close):
            close()
        raise TypeError(f"A synchronous {kind} resolver must not return an awaitable")
    return value


async def _awaited(value: Any) -> Any:
    """*value*, awaited when the resolver returned something awaitable."""
    return await value if inspect.isawaitable(value) else value


def _rebuild_guarded_tool(
    tool: BaseTool,
    action: str,
    actor: ActorResolver | AsyncActorResolver | None,
    inputs: InputResolver | AsyncInputResolver | None,
    rules: tuple[RuleWithInput, ...],
    on_guard_error: OnGuardError,
    state: dict[str, Any],
) -> BaseTool:
    """Guard *tool* again, with the client the receiving process registered.

    Named at module level because :meth:`_GuardMixin.__reduce__` names it, and
    pickle resolves that by import. *state* is the pickled handle's own
    pydantic state, reapplied so the rebuilt handle behaves as the one that was
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
    if not state:
        return guarded

    # Merge rather than replace: the rebuild has just derived the guard's own
    # private attributes and the guarded callables, and those are the parts the
    # pickle deliberately left out.
    fresh = guarded.__getstate__()
    fresh_fields = fresh.get("__dict__") or {}
    merged_fields = {
        **state["__dict__"],
        **{n: v for n, v in fresh_fields.items() if n in _DERIVED_FIELDS},
    }
    guarded.__setstate__(
        {
            "__dict__": merged_fields,
            "__pydantic_extra__": state["__pydantic_extra__"],
            "__pydantic_fields_set__": state["__pydantic_fields_set__"],
            "__pydantic_private__": {
                **state["__pydantic_private__"],
                **{
                    name: value
                    for name, value in (fresh.get("__pydantic_private__") or {}).items()
                    if name == _GUARD_STATE
                },
            },
        }
    )
    return guarded


def _config_param_of(fn: Callable[..., Any]) -> str | None:
    """The name of *fn*'s ``RunnableConfig`` parameter, or ``None``.

    Asked of LangChain, which identifies this parameter by its annotation and
    never by its name. Matching on the literal name ``config`` instead did two
    things wrong: a tool with a genuine ``config`` argument of its own had it
    taken away and fed to ``ensure_config``, which crashed on a call that works
    unguarded, and a tool whose config parameter is named anything else kept it
    among the arguments while resolvers saw no config at all.

    Resolved once per guarded tool, beside the signature it belongs to.
    """
    try:
        return _lc_config_param(fn)
    except Exception:
        return None


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


#: Stands in for a call whose arguments the checkpoint could not reconstruct.
#: A sentinel rather than an empty mapping, because the two mean opposite
#: things to a rule: no arguments, or arguments it could not see.
_UNREADABLE: Any = object()


def _unbound_arguments(
    args: tuple[Any, ...], kwargs: dict[str, Any], config_param: str | None
) -> tuple[Any, RunnableConfig | None]:
    """A call that could not be bound to a signature, handed on as it came.

    Keyword arguments describe themselves, and a single positional one is what
    a tool taking one input receives, so both are handed on. Anything else —
    several positional arguments to a callable with no signature to bind them
    to — cannot be named, and an empty mapping would tell an input rule the
    call had no arguments rather than that it could not read them. A rule
    would inspect nothing, conclude ALLOW, and the body would run: the one
    place in this module that reported a clean evaluation while evaluating
    nothing. The sentinel routes it through ``on_guard_error`` instead.
    """
    if kwargs:
        return kwargs, (kwargs.get(config_param) if config_param else None)
    if len(args) == 1:
        return args[0], None
    return _UNREADABLE, None


def _call_arguments(
    signature: inspect.Signature | None,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    config_param: str | None = None,
) -> tuple[Any, RunnableConfig | None, bool]:
    """A direct call's arguments, shaped the way the tool reads its input, and
    the ``config`` it was given.

    Binding to the signature turns a positional call into the mapping a policy
    resolver is documented to receive, so a resolver sees the same thing whether
    the model called the tool or the application called its function. The bound
    mapping is flattened, because a tool's ``_run`` collects the real arguments
    in ``**kwargs`` behind the framework's own parameters; a tool taking its
    input positionally has nothing left after that, so the single value is
    handed on as the tool's own ``_parse_input`` expects it.

    The ``config`` comes back rather than being dropped with the rest of what
    the framework supplies: it is the config the tool is about to run with.

    A signature-less or unbindable call is handed on untouched: the tool is
    about to raise over it anyway, and the checkpoint should not be the thing
    that reports it.
    """
    if signature is None:
        raw, config = _unbound_arguments(args, kwargs, config_param)
        return raw, config, False
    try:
        bound = signature.bind(*args, **kwargs)
    except TypeError:
        # The call does not fit the callable, so the callable is about to
        # reject it. That makes this the validated case: whatever a resolver
        # cannot read here has no effect to protect, exactly as when a schema
        # rejects a call arriving through `invoke`.
        raw, config = _unbound_arguments(args, kwargs, config_param)
        return raw, config, True
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
    config = flattened.pop(config_param, None) if config_param else None
    for name in FILTERED_ARGS:
        flattened.pop(name, None)

    if not flattened and len(positional) == 1:
        return positional[0], config, False
    return flattened, config, False


def _guarded_callables(guarded: BaseTool) -> None:
    """Put the checkpoint in front of the tool's own callables.

    ``func`` and ``coroutine`` are the two callables LangChain reads off a
    tool, and they are ordinary fields, so a verbatim copy would offer an
    unguarded call through the handle's own advertised surface. This is
    fidelity of the handle, not a security boundary: a caller that still holds
    the unguarded tool can always call it directly.

    The replacements keep the wrapped function's signature, which is what
    ``render_text_description`` reports. Written past validation, because a
    tool class may be frozen and guarding one must not be the thing that fails.
    Sourced from the wrapped tool rather than from the handle, so running this
    again on a copy derives a fresh pair from the same original instead of
    wrapping the wrapper.
    """
    state = _state_of(guarded)
    delegate = state.delegate
    func = getattr(delegate, "func", None)
    if callable(func):
        inner_func = cast(Callable[..., Any], func)
        func_signature = _signature_of(inner_func)
        func_config_param = _config_param_of(inner_func)

        @functools.wraps(inner_func)
        def guarded_func(*args: Any, **kwargs: Any) -> Any:
            raw, config, rejected = _call_arguments(
                func_signature, args, kwargs, func_config_param
            )
            state.evaluate(
                _Call(raw, None, _checkpoint_config(config), validated=rejected)
            )
            return inner_func(*args, **kwargs)

        object.__setattr__(guarded, "func", guarded_func)

    coroutine = getattr(delegate, "coroutine", None)
    if callable(coroutine):
        inner_coroutine = cast(Callable[..., Awaitable[Any]], coroutine)
        coroutine_signature = _signature_of(inner_coroutine)
        coroutine_config_param = _config_param_of(inner_coroutine)

        @functools.wraps(inner_coroutine)
        async def guarded_coroutine(*args: Any, **kwargs: Any) -> Any:
            raw, config, rejected = _call_arguments(
                coroutine_signature, args, kwargs, coroutine_config_param
            )
            await state.evaluate_async(
                _Call(raw, None, _checkpoint_config(config), validated=rejected)
            )
            return await inner_coroutine(*args, **kwargs)

        object.__setattr__(guarded, "coroutine", guarded_coroutine)


# Copied wholesale into each generated namespace. `__dict__` and `__weakref__`
# are descriptors bound to _GuardMixin and break the copy's instances if they
# come along; `__doc__` describes the mixin, not the generated class; and
# pydantic collects the two PrivateAttr assignments below without needing
# `__annotations__`.
_NAMESPACE_SKIP = frozenset({"__dict__", "__weakref__", "__doc__", "__annotations__"})

# Keyed weakly so guarding a tool cannot keep its class alive. The value keeps
# its own key alive through `__bases__`, so an entry lasts as long as the
# process — the intended lifetime, because the generated class must outlive
# every instance of it: regenerating it would fire the tool class's
# `__init_subclass__` a second time, against the once-per-class this promises.
# The number of distinct tool *classes* is small and fixed by the code.
_guarded_classes: MutableMapping[type[BaseTool], type[BaseTool]] = WeakKeyDictionary()
# Reentrant because the lock is held across the class creation below, which
# runs the tool class's `__init_subclass__` and pydantic's metaclass — code
# this module does not own and cannot stop from guarding a tool of its own. A
# plain lock would deadlock the thread against itself on that re-entry.
_guarded_classes_lock = threading.RLock()


def _ignore_schema_assignment(base: type[BaseTool]) -> Callable[..., None]:
    """A ``__setattr__`` that drops a write to ``args_schema``.

    Every field on the handle is already ignored in the sense that matters —
    the wrapped tool answers every schema question — but this one has to be
    dropped rather than merely unread. ``convert_to_openai_function`` decides
    whether a tool is a "simple" one with ``isinstance(tool, Tool) and not
    tool.args_schema``, reading the raw field and bypassing the three forwarded
    derivations. A handle that accepted the write therefore advertised a
    different schema to the model than the tool it wraps: for a schema-less
    ``Tool`` it exposed the whole ``RunnableConfig``, ``config`` included.

    Bound to *base* at class creation rather than looked up from the instance,
    because guarding an already-guarded tool nests these classes and any
    lookup relative to ``type(self)`` would recurse forever.
    """

    def __setattr__(self: Any, name: str, value: Any) -> None:
        if name == "args_schema":
            return
        base.__setattr__(self, name, value)

    return __setattr__


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
        existing = _guarded_classes.get(base)
        if existing is not None:
            return existing

        name = f"ArcjetGuarded{base.__name__}"
        namespace: dict[str, Any] = {
            member_name: member
            for member_name, member in _GuardMixin.__dict__.items()
            if member_name not in _NAMESPACE_SKIP
        }
        namespace.update(
            __setattr__=_ignore_schema_assignment(base),
            _arcjet_state=PrivateAttr(default=None),
            # Named for this module rather than for the caller's, so a repr or
            # a traceback points at the code that made the class.
            __module__=__name__,
            __qualname__=name,
            # A class a tool's own `__init_subclass__` may inspect. Given one
            # because requiring a docstring is a common thing for such a hook
            # to check, and there is no reason for this class not to have one.
            __doc__=f"{base.__name__} with an Arcjet checkpoint in front of it.",
        )

        try:
            generated = cast("type[BaseTool]", type(name, (base,), namespace))
        except Exception as exc:
            # Creating the subclass runs the tool class's own
            # `__init_subclass__`. A hook that validates its subclasses can
            # refuse this one, and the failure reads as coming from the tool's
            # own code with no hint that guarding is what triggered it.
            raise ArcjetMisconfiguration(
                f"Could not guard a {base.__name__}: guarding makes a subclass "
                f"of the tool's own class, and {base.__name__} refused it. "
                f"A tool class that validates its subclasses has to accept "
                f"one it did not write."
            ) from exc
        _guarded_classes[base] = generated
        return generated


#: The one name the guard keeps its own state under on the handle. Namespaced
#: because the handle is an instance of the tool's own class, so anything the
#: tool keeps under the same name is in the same place.
_GUARD_STATE = "_arcjet_state"


def _refuse_colliding_state(tool: BaseTool) -> None:
    """Refuse a tool that keeps its own state where the guard keeps the guard's.

    The handle carries the tool's state and the guard's together, so whichever
    is written second wins and the loser fails silently or fails later with an
    error that names the value rather than the collision.

    An already-guarded tool is not a collision: guarding one again is
    supported, and what it holds under this name is the guard's own.
    """
    for holder in (tool.__dict__ or {}, tool.__pydantic_private__ or {}):
        if _GUARD_STATE in holder and not isinstance(holder[_GUARD_STATE], _Guarded):
            raise ArcjetMisconfiguration(
                f"Cannot guard a tool that keeps its own {_GUARD_STATE!r}: a "
                f"guarded tool is an instance of the tool's own class, so "
                f"that name is where the guard keeps its state. Rename the "
                f"tool's attribute."
            )


def _copied_state(values: Mapping[str, Any] | None) -> dict[str, Any]:
    """A state mapping with each value copied one level down."""
    return {name: _copied_container(value) for name, value in (values or {}).items()}


def _copied_container(value: Any) -> Any:
    """One level of copy, so a tag or a callback cannot show up on both tools."""
    if isinstance(value, list):
        return list(value)
    if isinstance(value, dict):
        return dict(value)
    return value


def _copy_of(tool: BaseTool, wrapper: type[BaseTool]) -> BaseTool:
    """*tool*'s state, in an instance of *wrapper*.

    The state is copied across rather than replayed through the class's own
    constructor, because re-running ``__init__`` re-validates by *alias* (so a
    field the tool declares one for resets to its default), drops whatever an
    ``extra="allow"`` tool holds outside its declared fields, and cannot
    construct a class whose ``__init__`` requires something that is not a field.

    Containers are copied one level down, so a tag or a callback attached to
    either tool cannot show up on the other. That covers what a tool holds in
    a private attribute as well as in a declared field: copying only the
    private *dict* left its values shared, so a tool with a mutable
    ``PrivateAttr`` wrote through the handle into the tool and back.

    ``__pydantic_extra__`` is the same case, for whatever an ``extra="allow"``
    tool holds outside its declared fields.
    """
    guarded = wrapper.__new__(wrapper)
    fields = {
        name: _copied_container(value) for name, value in (tool.__dict__ or {}).items()
    }
    object.__setattr__(guarded, "__dict__", fields)
    object.__setattr__(
        guarded, "__pydantic_fields_set__", set(tool.__pydantic_fields_set__)
    )
    extra = tool.__pydantic_extra__
    object.__setattr__(
        guarded,
        "__pydantic_extra__",
        _copied_state(extra) if extra is not None else None,
    )
    object.__setattr__(
        guarded, "__pydantic_private__", _copied_state(tool.__pydantic_private__)
    )
    return guarded


def guard_tool(
    *,
    guard: _GuardClient,
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
    carrying the policy but not *guard*; the receiving process supplies its own
    with :func:`~arcjet.guard.register_arcjet` before loading the tool.

    Fields reassigned on the guarded tool after this returns do not reach the
    call — configure the tool before guarding it.

    *guard* is recognised by the shape of its ``guard()`` rather than by its
    class, matching the free guard calls, so an
    :class:`~arcjet.guard.testing.ArcjetTestClient` or a hand-rolled double
    drives a guarded tool without subclassing anything. A client that cannot
    answer the flavour a call takes raises ``TypeError``: that is a wiring
    mistake, not a degraded evaluation, and ``on_guard_error`` deliberately
    does not govern it.
    """
    if on_guard_error not in ("allow", "deny"):
        raise ArcjetMisconfiguration(
            f"on_guard_error must be 'allow' or 'deny', got {on_guard_error!r}. "
            f"It decides whether a call runs when policy could not be "
            f"evaluated, so there is no safe value to guess."
        )
    _refuse_colliding_state(tool)
    guarded = _copy_of(tool, _guarded_class(type(tool)))
    guarded._arcjet_state = _Guarded(
        delegate=tool,
        action=action,
        actor=actor,
        inputs=inputs,
        rules=tuple(rules),
        on_guard_error=on_guard_error,
        blocking=_blocking(guard, "guard_sync", "guard"),
        awaitable=_awaitable(guard, "guard"),
        run_signature=_signature_of(tool._run),
        arun_signature=_signature_of(tool._arun),
        run_config_param=_config_param_of(tool._run),
        arun_config_param=_config_param_of(tool._arun),
    )
    _guarded_callables(guarded)
    return guarded


__all__ = [
    "ArcjetToolDeniedError",
    "ArcjetToolUnavailableError",
    "guard_tool",
]
