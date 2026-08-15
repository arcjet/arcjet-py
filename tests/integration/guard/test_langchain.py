from __future__ import annotations

import asyncio
import copy
import pickle
import threading
import uuid
from typing import Annotated, Any, cast

import pytest
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.runnables import RunnableLambda
from langchain_core.runnables.config import ensure_config, set_config_context
from langchain_core.tools import (
    BaseTool,
    InjectedToolArg,
    StructuredTool,
    Tool,
    ToolException,
    tool,
)
from langchain_core.tools.render import render_text_description
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import BaseModel, Field, PrivateAttr

from arcjet._errors import ArcjetMisconfiguration
from arcjet.guard import (
    ArcjetGuard,
    ArcjetGuardSync,
    ModerateContent,
    register_arcjet,
    server_input,
    unregister_arcjet,
)
from arcjet.guard.langchain import (
    ArcjetToolDeniedError,
    ArcjetToolUnavailableError,
    guard_tool,
)
from arcjet.guard.proto.decide.v2 import decide_pb2 as pb
from arcjet.guard.testing import ArcjetTestClient


class _Transport:
    def __init__(
        self, conclusion: pb.GuardConclusion = pb.GUARD_CONCLUSION_ALLOW
    ) -> None:
        self.conclusion = conclusion
        self.request: pb.GuardRequest | None = None
        self.calls = 0

    def guard(self, request: pb.GuardRequest, **_kwargs: Any) -> pb.GuardResponse:
        self.request = request
        self.calls += 1
        return pb.GuardResponse(
            decision=pb.GuardDecision(
                id="gdec_test",
                conclusion=self.conclusion,
                reason=(
                    pb.GUARD_REASON_INPUT_CONSTRAINT
                    if self.conclusion == pb.GUARD_CONCLUSION_DENY
                    else pb.GUARD_REASON_UNSPECIFIED
                ),
            )
        )

    def capture(
        self, _request: pb.CaptureRequest, **_kwargs: Any
    ) -> pb.CaptureResponse:
        return pb.CaptureResponse()


def _guard(transport: _Transport) -> ArcjetGuardSync:
    return ArcjetGuardSync("key", transport, 1000, "test-agent")  # type: ignore[arg-type]


def test_guard_tool_maps_parsed_arguments_and_trusted_config_before_delegating() -> (
    None
):
    transport = _Transport()
    calls: list[tuple[str, str]] = []

    def send_email(to: str, body: str) -> str:
        calls.append((to, body))
        return "sent"

    tool = StructuredTool.from_function(
        send_email, name="send_email", description="Send email"
    )
    wrapped = guard_tool(
        guard=_guard(transport),
        tool=tool,
        action="email.sent",
        actor=lambda config: str((config.get("configurable") or {})["user_id"]),
        inputs=lambda arguments, _config: {
            "recipient": server_input.string(str(arguments["to"]))
        },
    )

    result = wrapped.invoke(
        cast(Any, {"to": "person@example.com", "body": "hello"}),
        config={"configurable": {"user_id": "user-1"}},
    )

    assert result == "sent"
    assert calls == [("person@example.com", "hello")]
    assert wrapped.name == tool.name
    assert wrapped.description == tool.description
    assert wrapped.args_schema is tool.args_schema
    assert transport.request is not None
    assert transport.request.actor == "user-1"
    assert (
        transport.request.policy_inputs["recipient"].server.string_value
        == "person@example.com"
    )


def test_guard_tool_uses_public_schema_validation_and_defaults() -> None:
    transport = _Transport()

    def greet(name: str, punctuation: str = "!") -> str:
        return f"Hello {name}{punctuation}"

    seen: list[dict[str, Any]] = []
    wrapped = guard_tool(
        guard=_guard(transport),
        tool=StructuredTool.from_function(greet, description="Greet someone"),
        action="greet.called",
        inputs=lambda arguments, _config: seen.append(dict(arguments)) or {},
    )

    assert wrapped.invoke(cast(Any, {"name": "Ada"})) == "Hello Ada!"
    assert seen == [{"name": "Ada", "punctuation": "!"}]


def test_guard_tool_does_not_invoke_wrapped_tool_after_denial() -> None:
    calls = 0

    def dangerous(value: str) -> str:
        nonlocal calls
        calls += 1
        return value

    wrapped = guard_tool(
        guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
        tool=StructuredTool.from_function(
            dangerous, name="dangerous", description="Dangerous action"
        ),
        action="dangerous.called",
    )

    with pytest.raises(ArcjetToolDeniedError):
        wrapped.invoke(cast(Any, {"value": "no"}))
    assert calls == 0


class _ModerationErrorTransport(_Transport):
    def guard(self, request: pb.GuardRequest, **_kwargs: Any) -> pb.GuardResponse:
        sub = request.rule_submissions[0]
        return pb.GuardResponse(
            decision=pb.GuardDecision(
                id="gdec_moderation_error",
                conclusion=pb.GUARD_CONCLUSION_ALLOW,
                rule_results=[
                    pb.GuardRuleResult(
                        result_id="gres_err",
                        config_id=sub.config_id,
                        input_id=sub.input_id,
                        type=pb.GUARD_RULE_TYPE_MODERATE_CONTENT,
                        error=pb.ResultError(
                            message="moderation model failed",
                            code="MODEL_ERROR",
                        ),
                    )
                ],
            )
        )


def test_guard_tool_fails_closed_when_moderation_rule_errors() -> None:
    calls = 0

    def dangerous(value: str) -> str:
        nonlocal calls
        calls += 1
        return value

    wrapped = guard_tool(
        guard=_guard(_ModerationErrorTransport()),
        tool=StructuredTool.from_function(
            dangerous, name="dangerous", description="Dangerous action"
        ),
        action="chat.moderated",
        rules=[ModerateContent()("user text")],
    )

    with pytest.raises(ArcjetToolUnavailableError):
        wrapped.invoke(cast(Any, {"value": "no"}))
    assert calls == 0


def test_guard_tool_uses_wrapped_tool_error_handler_after_denial() -> None:
    calls = 0

    def dangerous(value: str) -> str:
        nonlocal calls
        calls += 1
        return value

    tool = StructuredTool.from_function(
        dangerous, name="dangerous", description="Dangerous action"
    )
    tool.handle_tool_error = lambda error: f"blocked: {type(error).__name__}"
    wrapped = guard_tool(
        guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
        tool=tool,
        action="dangerous.called",
    )

    assert wrapped.invoke(cast(Any, {"value": "no"})) == (
        "blocked: ArcjetToolDeniedError"
    )
    assert calls == 0


class _AsyncTransport:
    def __init__(
        self, conclusion: pb.GuardConclusion = pb.GUARD_CONCLUSION_ALLOW
    ) -> None:
        self.conclusion = conclusion
        self.request: pb.GuardRequest | None = None
        self.calls = 0

    async def guard(self, request: pb.GuardRequest, **_kwargs: Any) -> pb.GuardResponse:
        self.request = request
        self.calls += 1
        return pb.GuardResponse(
            decision=pb.GuardDecision(
                id="gdec_async",
                conclusion=self.conclusion,
                reason=(
                    pb.GUARD_REASON_INPUT_CONSTRAINT
                    if self.conclusion == pb.GUARD_CONCLUSION_DENY
                    else pb.GUARD_REASON_UNSPECIFIED
                ),
            )
        )

    async def capture(
        self, _request: pb.CaptureRequest, **_kwargs: Any
    ) -> pb.CaptureResponse:
        return pb.CaptureResponse()


def test_guard_tool_uses_native_async_guard_and_tool_paths() -> None:
    transport = _AsyncTransport()

    async def lookup(value: str) -> str:
        return f"found:{value}"

    async def actor(_config: Any) -> str:
        return "user-async"

    async def inputs(arguments: Any, _config: Any) -> Any:
        return {"query": server_input.string(str(arguments["value"]))}

    tool = StructuredTool.from_function(
        coroutine=lookup, name="lookup", description="Lookup value"
    )
    guard = ArcjetGuard("key", transport, 1000, "test-agent")  # type: ignore[arg-type]
    wrapped = guard_tool(
        guard=guard,
        tool=tool,
        action="lookup.called",
        actor=actor,
        inputs=inputs,
    )

    assert asyncio.run(wrapped.ainvoke(cast(Any, {"value": "one"}))) == "found:one"
    assert transport.request is not None
    assert transport.request.actor == "user-async"


# --- Guarding must not change what the application already did ---------------
#
# guard_tool is an instrumentation layer, so the bar for each of these is that
# the guarded tool behaves as the unguarded one did. Every case below compares
# against that baseline rather than against a value written down by hand.


class _SubclassTool(BaseTool):
    """A BaseTool subclass declaring no args_schema, so _run's signature is it."""

    name: str = "search"
    description: str = "Search the index"

    def _run(self, query: str, limit: int = 5) -> str:
        return f"search({query},{limit})"


@tool
def _decorated(location: str, units: str = "c") -> str:
    """Get the weather.

    Args:
        location: Where to look.
        units: c or f.
    """
    return f"weather({location},{units})"


class _LegacyArgs(BaseModel):
    """A schema declared on a ``Tool``, which the bare-function gate ignores."""

    q: str


def _authored_tools() -> dict[str, BaseTool]:
    return {
        "decorator": _decorated,
        "structured": StructuredTool.from_function(
            lambda value: f"st({value})", name="st", description="Structured"
        ),
        "subclass": _SubclassTool(),
        "simple": Tool(name="legacy", description="Legacy", func=lambda v: f"lg({v})"),
        "simple_with_schema": Tool(
            name="legacy_schema",
            description="Legacy with a schema",
            func=lambda q: f"lg({q})",
            args_schema=_LegacyArgs,
        ),
        # LangChain reads this metadata off the concrete Tool class to decide
        # the tool is a "custom" one, which is a different tool type to the
        # model rather than a different schema.
        "custom_tool": Tool(
            name="custom",
            description="Marked custom",
            func=lambda q: f"ct({q})",
            args_schema=_LegacyArgs,
            metadata={"type": "custom_tool"},
        ),
        "json_schema": StructuredTool.from_function(
            lambda **kwargs: "js",
            name="js",
            description="JSON schema",
            args_schema={
                "type": "object",
                "properties": {"q": {"type": "string"}},
                "required": ["q"],
            },
        ),
    }


@pytest.mark.parametrize("style", sorted(_authored_tools()))
def test_guarding_does_not_change_what_the_model_is_told(style: str) -> None:
    """A guarded tool that advertises a different schema is a broken tool.

    It still gets called, with whatever arguments the changed schema implies,
    so this fails silently rather than loudly.
    """
    original = _authored_tools()[style]
    wrapped = guard_tool(
        guard=_guard(_Transport()), tool=original, action="schema.checked"
    )

    assert convert_to_openai_tool(wrapped) == convert_to_openai_tool(original)
    assert wrapped.args == original.args


def test_guarding_does_not_change_a_single_input_tools_result() -> None:
    transport = _Transport()
    original = Tool(name="lookup", description="d", func=lambda v: f"found({v})")
    wrapped = guard_tool(guard=_guard(transport), tool=original, action="lookup.called")

    assert wrapped.invoke(cast(Any, "widget")) == original.invoke(cast(Any, "widget"))
    assert transport.calls == 1


def test_injected_arguments_are_hidden_from_a_policy_resolver() -> None:
    """Injected arguments are credentials and graph state, not model input.

    `tool_call_schema` hides them from the model; `_parse_input` puts them back.
    A resolver that forwards its argument map to Guard would ship them off-box.
    """

    class Args(BaseModel):
        query: str
        api_token: Annotated[str, InjectedToolArg] = "sk-SECRET"

    seen: list[dict[str, Any]] = []
    wrapped = guard_tool(
        guard=_guard(_Transport()),
        tool=StructuredTool.from_function(
            lambda query, api_token="sk-SECRET": "ok",
            name="search",
            description="d",
            args_schema=Args,
        ),
        action="search.called",
        inputs=lambda arguments, _config: seen.append(dict(arguments)) or {},
    )

    wrapped.invoke(cast(Any, {"query": "q"}))

    assert seen == [{"query": "q"}]


@pytest.mark.parametrize("with_resolver", [False, True])
def test_bad_model_arguments_reach_the_tools_own_validation_handler(
    with_resolver: bool,
) -> None:
    """Malformed model output is the agent's problem, not an Arcjet outage.

    Reporting it as ArcjetToolUnavailableError would page an operator and kill
    the agent's retry loop over a routine, permanent error.
    """

    class Amount(BaseModel):
        amount: int = Field(ge=0)

    def build() -> BaseTool:
        t = StructuredTool.from_function(
            lambda amount: f"charged({amount})",
            name="charge",
            description="d",
            args_schema=Amount,
        )
        t.handle_validation_error = "the model sent bad arguments"
        return t

    original = build()
    wrapped = guard_tool(
        guard=_guard(_Transport()),
        tool=build(),
        action="charge.made",
        inputs=(lambda arguments, _config: {}) if with_resolver else None,
    )

    assert wrapped.invoke(cast(Any, {"amount": -5})) == original.invoke(
        cast(Any, {"amount": -5})
    )


def test_a_guarded_tool_can_be_copied() -> None:
    """LangGraph and several tracing paths clone the objects they hold.

    The Arcjet client cannot be copied — it owns a lock — so it answers a copy
    of itself with itself, and a guarded tool copies like any other object.
    """
    wrapped = guard_tool(
        guard=_guard(_Transport()), tool=_SubclassTool(), action="search.called"
    )

    assert copy.deepcopy(wrapped).invoke(cast(Any, {"query": "q"})) == "search(q,5)"
    assert wrapped.model_copy(deep=True).invoke(cast(Any, {"query": "q"})) == (
        "search(q,5)"
    )


def test_a_client_held_beside_its_tools_can_be_copied() -> None:
    """Sharing the client must not depend on the order of the traversal.

    An application that holds its client next to the tools it guards — a
    settings object, a module namespace, an agent's state — offers the copy an
    edge to the client that does not pass through any guarded tool. Nothing on
    the tool can memoise a client the copy reaches first, so the client is what
    answers.
    """
    guard = _guard(_Transport())
    wrapped = guard_tool(guard=guard, tool=_SubclassTool(), action="search.called")
    # Insertion order decides which edge deepcopy walks first, so the client
    # deliberately goes in ahead of the tool that refers to it.
    bundle = {"client": guard, "tool": wrapped}

    copied = copy.deepcopy(bundle)

    assert copied["client"] is guard
    assert cast(Any, copied["tool"]).invoke(cast(Any, {"query": "q"})) == "search(q,5)"


def test_every_execution_is_guarded_including_a_tools_own_recursion() -> None:
    """A tool that re-enters itself must not amortise one decision over many runs.

    The recursive arguments are the model-derived ones, so they are exactly
    what a prompt-injection or rate-limit rule needs to see.
    """
    transport = _Transport()
    bodies = 0

    def recurse(depth: int) -> str:
        nonlocal bodies
        bodies += 1
        if depth > 0:
            return wrapped.invoke(cast(Any, {"depth": depth - 1}))
        return "done"

    wrapped = guard_tool(
        guard=_guard(transport),
        tool=StructuredTool.from_function(recurse, name="recurse", description="d"),
        action="recurse.called",
    )

    wrapped.invoke(cast(Any, {"depth": 4}))

    assert bodies == 5
    assert transport.calls == bodies


def test_guarding_an_already_guarded_tool_evaluates_both_policies() -> None:
    inner_transport, outer_transport = _Transport(), _Transport()
    tool = StructuredTool.from_function(
        lambda value: f"ok({value})", name="echo", description="d"
    )

    inner = guard_tool(guard=_guard(inner_transport), tool=tool, action="echo.inner")
    outer = guard_tool(guard=_guard(outer_transport), tool=inner, action="echo.outer")

    assert outer.invoke(cast(Any, {"value": "x"})) == "ok(x)"
    assert (inner_transport.calls, outer_transport.calls) == (1, 1)


def test_run_is_a_guarded_entrypoint() -> None:
    transport = _Transport(pb.GUARD_CONCLUSION_DENY)
    calls = 0

    def dangerous(value: str) -> str:
        nonlocal calls
        calls += 1
        return value

    wrapped = guard_tool(
        guard=_guard(transport),
        tool=StructuredTool.from_function(dangerous, name="dangerous", description="d"),
        action="dangerous.called",
    )

    with pytest.raises(ArcjetToolDeniedError):
        wrapped.run({"value": "no"})
    assert calls == 0


def test_arun_is_a_guarded_entrypoint() -> None:
    transport = _AsyncTransport(pb.GUARD_CONCLUSION_DENY)
    calls = 0

    async def dangerous(value: str) -> str:
        nonlocal calls
        calls += 1
        return value

    wrapped = guard_tool(
        guard=ArcjetGuard("key", transport, 1000, "test-agent"),  # type: ignore[arg-type]
        tool=StructuredTool.from_function(
            coroutine=dangerous, name="dangerous", description="d"
        ),
        action="dangerous.called",
    )

    with pytest.raises(ArcjetToolDeniedError):
        asyncio.run(wrapped.arun({"value": "no"}))
    assert calls == 0


def test_guarding_leaves_the_tool_it_was_given_untouched() -> None:
    """Applications keep the unguarded tool for trusted internal call sites.

    Shared containers would let a tag or callback attached to one appear on the
    other, so an audit trail could record executions that never passed a check.
    """
    original = _SubclassTool(tags=["billing"], metadata={"team": "payments"})
    wrapped = guard_tool(
        guard=_guard(_Transport()), tool=original, action="search.called"
    )

    assert wrapped.tags is not None and wrapped.metadata is not None
    wrapped.tags.append("added")
    wrapped.metadata["added"] = True

    assert original.tags == ["billing"]
    assert original.metadata == {"team": "payments"}


def test_guarding_does_not_edit_the_callers_tool_call() -> None:
    """A ToolCall's args live in an AIMessage in conversation state.

    Editing them re-serializes to the provider next turn and is replayed by a
    checkpointer on resume.
    """
    call = {
        "type": "tool_call",
        "name": "search",
        "id": "call_1",
        "args": {"query": "q"},
    }
    wrapped = guard_tool(
        guard=_guard(_Transport()),
        tool=_SubclassTool(),
        action="search.called",
        inputs=lambda arguments, _config: {},
    )

    wrapped.invoke(cast(Any, call))

    assert call["args"] == {"query": "q"}


def test_a_resolver_reads_the_config_the_tool_runs_with() -> None:
    """A resolver sees the config LangChain normalized, not the raw argument.

    `ensure_config` relocates a key it does not know into `configurable`, and
    that normalized config is what the tool itself runs with — so it is what
    the resolver is shown, rather than a view only the checkpoint would have.
    """
    transport = _Transport()
    wrapped = guard_tool(
        guard=_guard(transport),
        tool=StructuredTool.from_function(
            lambda value: "ok", name="echo", description="d"
        ),
        action="echo.called",
        actor=lambda config: str((config.get("configurable") or {})["user_id"]),
    )

    wrapped.invoke(cast(Any, {"value": "x"}), cast(Any, {"user_id": "user-1"}))

    assert transport.request is not None
    assert transport.request.actor == "user-1"


def test_guarding_preserves_a_tools_own_private_state() -> None:
    """The handle is the tool's own class, so the tool's state lives on it too.

    Asserted on the handle rather than only through the call: delegating means
    a call reaches the untouched original whatever the handle lost, so a test
    that only invokes cannot see the handle's own state being clobbered.
    """

    class Stateful(BaseTool):
        name: str = "stateful"
        description: str = "d"
        _arcjet: str = PrivateAttr(default="the tool's own state")

        def _run(self, query: str) -> str:
            return f"got:{self._arcjet}"

    original = Stateful()
    wrapped = guard_tool(
        guard=_guard(_Transport()), tool=original, action="stateful.called"
    )

    assert cast(Any, wrapped)._arcjet == "the tool's own state"
    assert wrapped.invoke(cast(Any, {"query": "q"})) == original.invoke(
        cast(Any, {"query": "q"})
    )


def test_a_tool_keeping_an_undeclared_arcjet_attribute_still_works() -> None:
    """Pydantic keeps an undeclared underscore attribute in the instance dict.

    That is the same place the handle's own state would be, so a tool setting
    one used to win the name and leave the guard reading the tool's value —
    failing on the next call with an error about that value, not the clash.
    """

    class Undeclared(BaseTool):
        name: str = "undeclared"
        description: str = "d"

        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            object.__setattr__(self, "_arcjet", "the tool's own state")

        def _run(self, query: str) -> str:
            return "ran"

    wrapped = guard_tool(
        guard=_guard(_Transport()), tool=Undeclared(), action="undeclared.called"
    )

    assert cast(Any, wrapped)._arcjet == "the tool's own state"
    assert wrapped.invoke(cast(Any, {"query": "q"})) == "ran"


def test_a_tool_colliding_with_the_guards_own_state_is_refused() -> None:
    """Where a collision is unavoidable, name it rather than pick a loser."""

    class Colliding(BaseTool):
        name: str = "colliding"
        description: str = "d"

        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            object.__setattr__(self, "_arcjet_policy", "not a policy")

        def _run(self, query: str) -> str:
            return "ran"

    with pytest.raises(ArcjetMisconfiguration, match="_arcjet_policy"):
        guard_tool(
            guard=_guard(_Transport()), tool=Colliding(), action="colliding.called"
        )


def test_guarding_registers_one_subclass_per_tool_class() -> None:
    """Being the tool's own class means being a subclass of it, which registers.

    A tool class that hooks its own subclassing therefore sees the guard's
    subclass. It sees it once, however many tools of that class are guarded,
    because the class is generated once and reused — so the cost is a fixed
    entry per tool class rather than one per guarded tool.
    """
    registered: list[str] = []

    class Registering(BaseTool):
        name: str = "reg"
        description: str = "d"

        def __init_subclass__(cls, **kwargs: Any) -> None:
            super().__init_subclass__(**kwargs)
            registered.append(cls.__name__)

        def _run(self, query: str) -> str:
            return "r"

    guard = _guard(_Transport())
    first = guard_tool(guard=guard, tool=Registering(), action="reg.called")
    second = guard_tool(guard=guard, tool=Registering(), action="reg.called")

    assert registered == ["ArcjetGuardedRegistering"]
    assert type(first) is type(second)


def test_guarding_keeps_a_field_the_tool_declares_an_alias_for() -> None:
    """Replaying the tool through its own constructor validates by alias.

    A field the tool declares an alias for is then silently reset to its
    default, because the class ignores the field-name keyword — so the handle
    reports a value the tool never had.
    """

    class Aliased(BaseTool):
        name: str = "aliased"
        description: str = "d"
        max_hits: int = Field(default=3, alias="maxHits")

        def _run(self, query: str) -> str:
            return "r"

    original = cast(Any, Aliased)(maxHits=5)
    wrapped = guard_tool(
        guard=_guard(_Transport()), tool=original, action="aliased.called"
    )

    assert cast(Any, wrapped).max_hits == 5


def test_guarding_keeps_what_an_extra_allowing_tool_holds() -> None:
    """A tool that accepts extras carries state outside its declared fields."""

    class Extras(BaseTool):
        model_config = {"extra": "allow"}
        name: str = "extras"
        description: str = "d"

        def _run(self, query: str) -> str:
            return "r"

    original = cast(Any, Extras)(api_base="https://example.test")
    wrapped = guard_tool(
        guard=_guard(_Transport()), tool=original, action="extras.called"
    )

    assert cast(Any, wrapped).api_base == "https://example.test"


def test_a_tool_whose_constructor_takes_more_than_fields_can_be_guarded() -> None:
    """A tool class may take a collaborator its fields do not describe.

    Rebuilding through such a constructor cannot work — the argument is not a
    field to copy — so the tool's state is copied rather than replayed.
    """

    class WithClient(BaseTool):
        name: str = "withclient"
        description: str = "d"

        def __init__(self, client: Any, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            self._client = client

        def _run(self, query: str) -> str:
            return "r"

    client = object()
    wrapped = guard_tool(
        guard=_guard(_Transport()),
        tool=WithClient(client=client),
        action="withclient.called",
    )

    assert wrapped.name == "withclient"


def test_guarding_from_inside_a_subclass_hook_does_not_deadlock() -> None:
    """Generating the class runs code this module does not own.

    A tool class's `__init_subclass__` can do anything, including guard a tool
    of its own — a plugin base registering a guarded variant of each subclass.
    Holding a non-reentrant lock across the class creation makes that re-entry
    block the thread on itself, with no traceback and no timeout.

    Driven from a worker thread so a regression fails this test rather than
    hanging the whole suite: a deadlocked thread never returns to report.
    """
    guard = _guard(_Transport())

    class Inner(BaseTool):
        name: str = "inner"
        description: str = "d"

        def _run(self, query: str) -> str:
            return "r"

    class Reentrant(BaseTool):
        name: str = "reentrant"
        description: str = "d"

        def __init_subclass__(cls, **kwargs: Any) -> None:
            super().__init_subclass__(**kwargs)
            guard_tool(guard=guard, tool=Inner(), action="inner.called")

        def _run(self, query: str) -> str:
            return "r"

    done: list[Any] = []
    worker = threading.Thread(
        target=lambda: done.append(
            guard_tool(guard=guard, tool=Reentrant(), action="reentrant.called")
        ),
        daemon=True,
    )
    worker.start()
    worker.join(timeout=20)

    assert not worker.is_alive(), "guard_tool deadlocked inside the subclass hook"
    assert isinstance(done[0], Reentrant)


def test_a_guarded_tool_is_an_instance_of_the_tool_it_wraps() -> None:
    """Application code and LangChain both branch on a tool's concrete class.

    A wrapper of some other class does not fail loudly there; it silently
    takes the other branch.
    """
    for original in (
        _SubclassTool(),
        StructuredTool.from_function(lambda q: "ok", name="st", description="d"),
        Tool(name="legacy", description="d", func=lambda v: "ok"),
    ):
        wrapped = guard_tool(
            guard=_guard(_Transport()), tool=original, action="a.called"
        )
        assert isinstance(wrapped, type(original))


def test_a_guarded_tools_own_function_runs_the_checkpoint() -> None:
    """`func` is public, and a copied one would run the body with no checkpoint.

    LangChain reads it to render a signature and applications call it, so it
    stays callable — but it is the guarded tool's function, not a way round the
    guarded tool.
    """
    executed: list[str] = []

    def dangerous(value: str) -> str:
        executed.append(value)
        return "EXECUTED"

    for original in (
        Tool(name="legacy", description="d", func=dangerous),
        StructuredTool.from_function(dangerous, name="st", description="d"),
    ):
        wrapped = guard_tool(
            guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
            tool=original,
            action="a.called",
        )

        with pytest.raises(ArcjetToolDeniedError):
            cast(Any, wrapped).func("secret")
        assert executed == []


def test_guarding_preserves_a_rendered_tool_signature() -> None:
    """`render_text_description` reads `func` and reports its signature.

    A guarded tool that carries no `func`, or one whose `func` does not keep
    the wrapped signature, renders less than the unguarded tool did and the
    model is told less about it.
    """
    for original in (
        StructuredTool.from_function(
            lambda q: "ok", name="st", description="Structured"
        ),
        Tool(name="legacy", description="Legacy", func=lambda v: "ok"),
    ):
        wrapped = guard_tool(
            guard=_guard(_Transport()), tool=original, action="a.called"
        )
        assert render_text_description([wrapped]) == render_text_description([original])


def _in_ambient_config(config: dict[str, Any], call: Any) -> Any:
    """Run *call* where LangChain's ambient config is *config*.

    `set_config_context` installs the config in a copied context, so the call
    has to be run through that context to see it — which is how a chain hands
    its config to the steps inside it without threading it explicitly.
    """
    with set_config_context(ensure_config(cast(Any, config))) as ctx:
        return ctx.run(call)


def test_a_resolver_sees_the_ambient_config() -> None:
    """A chain hands its config down without the caller re-threading it.

    The tool runs with that config, so the checkpoint must resolve the actor
    from it too, rather than from an empty mapping only it can see.
    """
    seen: list[dict[str, Any]] = []
    wrapped = guard_tool(
        guard=_guard(_Transport()),
        tool=StructuredTool.from_function(
            lambda value: "ok", name="t", description="d"
        ),
        action="t.called",
        actor=lambda config: seen.append(dict(config)) or "u",
    )

    _in_ambient_config(
        {"metadata": {"uid": "user-1"}},
        lambda: wrapped.invoke(cast(Any, {"value": "x"})),
    )

    assert seen and seen[0].get("metadata", {}).get("uid") == "user-1"


def test_a_blocked_call_reaches_an_ambient_tracer() -> None:
    """The denials an operator most needs are the ones a chain must not lose."""
    recorder = _Recorder()
    wrapped = guard_tool(
        guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
        tool=StructuredTool.from_function(
            lambda value: "ok", name="t", description="d"
        ),
        action="t.called",
    )

    def call() -> None:
        with pytest.raises(ArcjetToolDeniedError):
            wrapped.invoke(cast(Any, {"value": "x"}))

    _in_ambient_config({"callbacks": [recorder]}, call)

    assert [kind for kind, _ in recorder.events] == ["start", "error"]


def test_a_blocked_call_is_reported_under_the_callers_run_id() -> None:
    """A caller that assigned a run id must be able to find the blocked run."""
    recorder = _RunIdRecorder()
    run_id = uuid.uuid4()
    wrapped = guard_tool(
        guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
        tool=StructuredTool.from_function(
            lambda value: "ok", name="t", description="d"
        ),
        action="t.called",
    )

    with pytest.raises(ArcjetToolDeniedError):
        wrapped.invoke(
            cast(Any, {"value": "x"}),
            config=cast(Any, {"callbacks": [recorder], "run_id": run_id}),
        )

    assert recorder.run_ids == [run_id]


def test_callbacks_passed_positionally_to_run_are_accepted() -> None:
    """`BaseTool.run` takes callbacks as its fifth positional parameter.

    A guarded tool mirrors the signature, so a legacy caller using the
    positional form is not turned into a TypeError by the checkpoint.
    """
    recorder = _Recorder()
    wrapped = guard_tool(
        guard=_guard(_Transport()),
        tool=StructuredTool.from_function(
            lambda value: "ok", name="t", description="d"
        ),
        action="t.called",
    )

    assert wrapped.run({"value": "x"}, False, "green", "green", [recorder]) == "ok"
    assert [kind for kind, _ in recorder.events] == ["start", "end"]


def test_a_denial_reaches_callbacks_passed_as_run_keywords() -> None:
    """AgentExecutor calls `tool.run(..., callbacks=run_manager.get_child())`.

    Reporting only from a config would leave every denial in that stack
    invisible, which reads as a tool that never denies.
    """
    recorder = _Recorder()
    wrapped = guard_tool(
        guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
        tool=StructuredTool.from_function(
            lambda value: "ok", name="t", description="d"
        ),
        action="t.called",
    )

    with pytest.raises(ArcjetToolDeniedError):
        wrapped.run({"value": "x"}, callbacks=[recorder])

    assert [kind for kind, _ in recorder.events] == ["start", "error"]


# --- Crossing a process boundary ---------------------------------------------


def test_a_guarded_tool_pickles_and_still_guards() -> None:
    """Sending tools to a worker process pickles them, tools included.

    The generated class cannot be looked up by name, so the tool is rebuilt by
    guarding the wrapped tool again with the client the receiving process
    registered.
    """
    guard = _guard(_Transport(pb.GUARD_CONCLUSION_DENY))
    wrapped = guard_tool(guard=guard, tool=_SubclassTool(), action="search.called")

    blob = pickle.dumps(wrapped)
    register_arcjet(guard)
    try:
        restored = pickle.loads(blob)
    finally:
        unregister_arcjet()

    assert isinstance(restored, _SubclassTool)
    with pytest.raises(ArcjetToolDeniedError):
        restored.invoke(cast(Any, {"query": "q"}))


def test_a_guarded_tool_never_renders_the_site_key() -> None:
    """A client reaches everything that renders objects on a failing call.

    A traceback captured with frame locals — `pytest --showlocals`, an error
    reporter, a debugger — renders whatever the frame held, including a bound
    method, whose repr renders the client it is bound to.
    """
    secret = "ajkey_live_NOTAREALKEY"
    guard = ArcjetGuardSync(secret, cast(Any, _Transport()), 1000, "ua")
    wrapped = guard_tool(
        guard=guard,
        tool=StructuredTool.from_function(
            lambda value: "ok", name="t", description="d"
        ),
        action="t.called",
    )

    policy = cast(Any, wrapped)._arcjet_policy
    assert secret not in repr(guard)
    assert secret not in repr(policy)
    assert secret not in repr(policy.blocking)


def test_pickling_a_guarded_tool_does_not_serialize_the_site_key() -> None:
    """A pickle is written somewhere — a broker, a checkpoint, a disk.

    The client is left out of it entirely, so nothing that stores or forwards
    a pickled tool ends up holding the key that authenticates as this site.
    """
    guard = ArcjetGuardSync("ajkey_notasecret", cast(Any, _Transport()), 1000, "ua")
    wrapped = guard_tool(guard=guard, tool=_SubclassTool(), action="search.called")

    assert b"ajkey_notasecret" not in pickle.dumps(wrapped)


def test_pickling_preserves_fields_set_on_the_guarded_handle() -> None:
    """The worker must hold the tool the parent had, not a freshly guarded one.

    Rebuilding from the delegate and the policy alone would drop every field
    the application set on the handle, so a tool tagged for one team arrives
    untagged and a narrowed schema arrives widened.
    """
    guard = _guard(_Transport(pb.GUARD_CONCLUSION_DENY))
    original = _SubclassTool()
    original.handle_tool_error = "policy said no"
    wrapped = guard_tool(guard=guard, tool=original, action="search.called")
    wrapped.tags = ["team-a"]

    blob = pickle.dumps(wrapped)
    register_arcjet(guard)
    try:
        restored = pickle.loads(blob)
    finally:
        unregister_arcjet()

    assert restored.handle_tool_error == "policy said no"
    assert restored.tags == ["team-a"]
    assert restored.invoke(cast(Any, {"query": "q"})) == "policy said no"


def test_unpickling_without_a_registered_client_says_so() -> None:
    """The failure names what is missing, rather than surfacing as an attribute
    error deep in a worker."""
    wrapped = guard_tool(
        guard=_guard(_Transport()), tool=_SubclassTool(), action="search.called"
    )
    blob = pickle.dumps(wrapped)

    unregister_arcjet()
    with pytest.raises(ArcjetMisconfiguration, match="register_arcjet"):
        pickle.loads(blob)


# --- A blocked call is still a call, and belongs on the trace ----------------


class _Recorder(BaseCallbackHandler):
    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []
        self.starts: list[tuple[str, Any]] = []
        """Each start's ``input_str`` and ``inputs``, for asserting on content."""

    def on_tool_start(
        self, serialized: dict[str, Any], input_str: str, **kwargs: Any
    ) -> None:
        self.events.append(("start", serialized.get("name", "")))
        self.starts.append((input_str, kwargs.get("inputs")))

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        self.events.append(("end", str(output)))

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        self.events.append(("error", type(error).__name__))

    # Recorded so a handler that has been promoted to inheritable — and so
    # follows the tool's body into whatever it invokes — is visible as extra
    # events rather than silently absent.
    def on_chain_start(
        self, serialized: dict[str, Any], inputs: Any, **kwargs: Any
    ) -> None:
        self.events.append(("chain_start", ""))

    def on_chain_end(self, outputs: Any, **kwargs: Any) -> None:
        self.events.append(("chain_end", ""))


class _RunIdRecorder(BaseCallbackHandler):
    """Records the run id each tool run was opened under."""

    def __init__(self) -> None:
        self.run_ids: list[Any] = []

    def on_tool_start(
        self, serialized: dict[str, Any], input_str: str, **kwargs: Any
    ) -> None:
        self.run_ids.append(kwargs.get("run_id"))


def test_a_denied_call_is_reported_to_the_callbacks() -> None:
    """A trace with no record of a blocked call hides the interesting ones."""
    recorder = _Recorder()
    original = StructuredTool.from_function(
        lambda value: "ok", name="dangerous", description="d"
    )
    wrapped = guard_tool(
        guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
        tool=original,
        action="dangerous.called",
    )

    with pytest.raises(ArcjetToolDeniedError):
        wrapped.invoke(cast(Any, {"value": "no"}), config={"callbacks": [recorder]})

    assert recorder.events == [
        ("start", "dangerous"),
        ("error", "ArcjetToolDeniedError"),
    ]


def test_an_unavailable_policy_is_reported_to_the_callbacks() -> None:
    """Failing closed stops the call too, so it is reported the same way."""
    recorder = _Recorder()

    def explode(_config: Any) -> str:
        raise RuntimeError("resolver down")

    original = StructuredTool.from_function(
        lambda value: "ok", name="dangerous", description="d"
    )
    wrapped = guard_tool(
        guard=_guard(_Transport()),
        tool=original,
        action="dangerous.called",
        actor=explode,
    )

    with pytest.raises(ArcjetToolUnavailableError):
        wrapped.invoke(cast(Any, {"value": "no"}), config={"callbacks": [recorder]})

    assert recorder.events == [
        ("start", "dangerous"),
        ("error", "ArcjetToolUnavailableError"),
    ]


def test_an_allowed_call_is_reported_once() -> None:
    """The tool opens its own run, so the checkpoint must not open a second."""
    recorder = _Recorder()
    original = StructuredTool.from_function(
        lambda value: "ok", name="safe", description="d"
    )
    wrapped = guard_tool(
        guard=_guard(_Transport()), tool=original, action="safe.called"
    )

    assert (
        wrapped.invoke(cast(Any, {"value": "yes"}), config={"callbacks": [recorder]})
        == "ok"
    )

    assert [name for kind, name in recorder.events if kind == "start"] == ["safe"]
    assert [kind for kind, _ in recorder.events] == ["start", "end"]


def test_a_denied_async_call_is_reported_to_the_callbacks() -> None:
    recorder = _Recorder()

    async def lookup(value: str) -> str:
        return "ok"

    original = StructuredTool.from_function(
        coroutine=lookup, name="dangerous", description="d"
    )
    wrapped = guard_tool(
        guard=ArcjetGuard(
            "key", cast(Any, _AsyncTransport(pb.GUARD_CONCLUSION_DENY)), 1000, "ua"
        ),
        tool=original,
        action="dangerous.called",
    )

    with pytest.raises(ArcjetToolDeniedError):
        asyncio.run(
            wrapped.ainvoke(
                cast(Any, {"value": "no"}), config={"callbacks": [recorder]}
            )
        )

    assert recorder.events == [
        ("start", "dangerous"),
        ("error", "ArcjetToolDeniedError"),
    ]


def test_a_handled_denial_is_a_run_that_ends() -> None:
    """LangChain closes a handled ToolException with on_tool_end, not error.

    The caller got a normal result back, so the run did not fail; reporting an
    error would mark it failed in a trace and over-count hard failures.
    """
    recorder = _Recorder()
    original = StructuredTool.from_function(
        lambda value: "ok", name="dangerous", description="d"
    )
    original.handle_tool_error = "policy said no"
    wrapped = guard_tool(
        guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
        tool=original,
        action="dangerous.called",
    )

    result = wrapped.invoke(
        cast(Any, {"value": "no"}), config={"callbacks": [recorder]}
    )

    assert result == "policy said no"
    assert recorder.events == [
        ("start", "dangerous"),
        ("end", "policy said no"),
    ]


def test_a_handled_async_denial_is_a_run_that_ends() -> None:
    recorder = _Recorder()

    async def lookup(value: str) -> str:
        return "ok"

    original = StructuredTool.from_function(
        coroutine=lookup, name="dangerous", description="d"
    )
    original.handle_tool_error = "policy said no"
    wrapped = guard_tool(
        guard=ArcjetGuard(
            "key", cast(Any, _AsyncTransport(pb.GUARD_CONCLUSION_DENY)), 1000, "ua"
        ),
        tool=original,
        action="dangerous.called",
    )

    result = asyncio.run(
        wrapped.ainvoke(cast(Any, {"value": "no"}), config={"callbacks": [recorder]})
    )

    assert result == "policy said no"
    assert recorder.events == [
        ("start", "dangerous"),
        ("end", "policy said no"),
    ]


def test_a_direct_function_call_is_not_a_tool_run() -> None:
    """Calling a tool's own function opens no run on the unguarded tool.

    The guarded one must not fabricate a span for it either — the checkpoint
    still evaluates and denies, but a trace only records tool runs.
    """
    recorder = _Recorder()
    original = StructuredTool.from_function(
        lambda value: "ok", name="dangerous", description="d"
    )
    wrapped = guard_tool(
        guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
        tool=original,
        action="dangerous.called",
    )
    wrapped.callbacks = [recorder]

    with pytest.raises(ArcjetToolDeniedError):
        cast(Any, wrapped).func("no")

    assert recorder.events == []


def test_a_blocked_calls_report_hides_injected_arguments() -> None:
    """An allowed call's trace never shows an injected credential.

    ``BaseTool.run`` filters them before reporting, so a blocked call's report
    filters the same way — otherwise denials would be the one place secrets
    land on a trace.
    """
    recorder = _Recorder()

    def send(query: str, api_token: Annotated[str, InjectedToolArg]) -> str:
        return "sent"

    original = StructuredTool.from_function(send, name="send", description="d")
    wrapped = guard_tool(
        guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
        tool=original,
        action="send.called",
    )

    with pytest.raises(ArcjetToolDeniedError):
        wrapped.invoke(
            cast(Any, {"query": "q", "api_token": "sk-SECRET"}),
            config={"callbacks": [recorder]},
        )

    assert recorder.events[0] == ("start", "send")
    input_str, inputs = recorder.starts[0]
    assert "sk-SECRET" not in input_str
    assert inputs == {"query": "q"}


def test_a_handler_on_the_call_fires_once_per_event() -> None:
    """The delegate opens the run, so nothing the checkpoint does may double it.

    A handler reaching the tool through the call's own config is the supported
    way to trace a guarded tool, and it must see one start and one end.
    """
    recorder = _Recorder()
    original = StructuredTool.from_function(
        lambda value: "ok", name="tool", description="d"
    )
    wrapped = guard_tool(
        guard=_guard(_Transport()), tool=original, action="tool.called"
    )

    result = wrapped.invoke(
        cast(Any, {"value": "yes"}), config={"callbacks": [recorder]}
    )

    assert result == "ok"
    assert [kind for kind, _ in recorder.events] == ["start", "end"]


def test_a_tools_own_handler_does_not_follow_its_body_into_child_runs() -> None:
    """A tool-local handler is local: the unguarded tool never inherits it down.

    Folding the handle's handlers into the delegated config would promote them
    to inheritable and fire them for whatever the tool's body invokes, which is
    a per-tool audit handler counting runs the unguarded tool never reported.
    """
    inner = RunnableLambda(lambda value: value)

    def body(value: str) -> str:
        return cast(Any, inner.invoke(value))

    recorder = _Recorder()
    original = StructuredTool.from_function(body, name="tool", description="d")
    original.callbacks = [recorder]
    original.invoke(cast(Any, {"value": "x"}))
    unguarded = list(recorder.events)

    recorder.events.clear()
    guarded_original = StructuredTool.from_function(body, name="tool", description="d")
    guarded_original.callbacks = [recorder]
    wrapped = guard_tool(
        guard=_guard(_Transport()), tool=guarded_original, action="tool.called"
    )
    wrapped.invoke(cast(Any, {"value": "x"}))

    assert recorder.events == unguarded


def test_a_tool_built_on_a_signature_less_callable_can_be_guarded() -> None:
    """LangChain accepts a C callable as a tool's func; guarding must too.

    `inspect.signature` has nothing to report for one, and that is not a
    reason for the tool to become unguardable.
    """
    import time

    original = Tool(name="clock", description="d", func=time.time)
    wrapped = guard_tool(
        guard=_guard(_Transport()), tool=original, action="clock.called"
    )

    assert isinstance(cast(Any, wrapped).func(), float)


def test_a_v1_schemas_rejection_reaches_the_tools_own_handler() -> None:
    """langchain-core accepts a pydantic v1 args_schema, and `run` catches both.

    Seeing only the v2 flavour turns a routine, model-recoverable mistake into
    an Arcjet outage that kills the retry loop.
    """
    from pydantic.v1 import BaseModel as V1BaseModel

    class QueryV1(V1BaseModel):
        q: str

    original = StructuredTool.from_function(
        lambda **kwargs: "ok",
        name="v1",
        description="d",
        args_schema=cast(Any, QueryV1),
    )
    original.handle_validation_error = "the model sent bad arguments"
    wrapped = guard_tool(
        guard=_guard(_Transport()),
        tool=original,
        action="v1.called",
        inputs=lambda arguments, _config: {},
    )

    assert wrapped.invoke(cast(Any, {"wrong": "x"})) == original.invoke(
        cast(Any, {"wrong": "x"})
    )


def test_allowing_a_failed_evaluation_still_reports_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A permanently broken resolver has no other symptom.

    Under `allow` the call proceeds, so nothing raises and nothing is denied;
    without a log line the tool looks guarded while no decision is being made.
    """

    def broken_actor(config: Any) -> str:
        raise KeyError("user_id")

    wrapped = guard_tool(
        guard=_guard(_Transport()),
        tool=StructuredTool.from_function(
            lambda value: "ok", name="t", description="d"
        ),
        action="t.called",
        actor=broken_actor,
        on_guard_error="allow",
    )

    with caplog.at_level("WARNING", logger="arcjet"):
        assert wrapped.invoke(cast(Any, {"value": "x"})) == "ok"

    assert any(
        "could not resolve everything policy needed" in record.message
        for record in caplog.records
    )


def test_a_failed_resolver_still_puts_the_call_on_the_record() -> None:
    """A resolver failing degrades the decision's inputs, not the decision.

    Letting it stop the Guard call meant that under `allow` the tool ran and
    Guard held no record the call happened — so a rate limit or a remote policy
    on the label silently stopped counting exactly the calls whose actor could
    not be resolved, with nothing but a log line to say so.
    """

    def broken_actor(config: Any) -> str:
        raise KeyError("user_id")

    def broken_inputs(arguments: Any, config: Any) -> Any:
        raise KeyError("boom")

    for policy in ({"actor": broken_actor}, {"inputs": broken_inputs}):
        transport = _Transport()
        wrapped = guard_tool(
            guard=_guard(transport),
            tool=StructuredTool.from_function(
                lambda value: "ok", name="t", description="d"
            ),
            action="t.called",
            on_guard_error="allow",
            **cast(Any, policy),
        )

        assert wrapped.invoke(cast(Any, {"value": "x"})) == "ok"
        assert transport.calls == 1


def test_a_failed_resolver_denies_but_still_records_under_deny() -> None:
    """Failing closed stops the call; it does not stop the decision."""
    transport = _Transport()

    def broken_actor(config: Any) -> str:
        raise KeyError("user_id")

    wrapped = guard_tool(
        guard=_guard(transport),
        tool=StructuredTool.from_function(
            lambda value: "ok", name="t", description="d"
        ),
        action="t.called",
        actor=broken_actor,
    )

    with pytest.raises(ArcjetToolUnavailableError) as raised:
        wrapped.invoke(cast(Any, {"value": "x"}))

    assert transport.calls == 1
    assert isinstance(raised.value.__cause__, KeyError)


def test_an_unreadable_arguments_failure_carries_its_cause() -> None:
    """`could not be evaluated` alone does not say what stopped the read."""

    class Broken(BaseTool):
        name: str = "broken"
        description: str = "d"

        def _parse_input(self, *args: Any, **kwargs: Any) -> Any:
            raise RecursionError("schema is self-referential")

        def _run(self, query: str) -> str:
            return "r"

    wrapped = guard_tool(
        guard=_guard(_Transport()),
        tool=Broken(),
        action="broken.called",
        inputs=lambda arguments, _config: {},
    )

    with pytest.raises(ArcjetToolUnavailableError) as raised:
        wrapped.invoke(cast(Any, {"query": "q"}))
    assert isinstance(raised.value.__cause__, RecursionError)


def test_an_error_handler_that_raises_reaches_the_caller() -> None:
    """A handler's own exception is the tool author's, and it belongs to the caller.

    LangChain lets a raising `handle_tool_error` propagate, so an agent
    branching on the handler's error type must see it rather than the denial
    that triggered it.
    """
    original = StructuredTool.from_function(
        lambda value: "ok", name="tool", description="d"
    )

    def handler(error: ToolException) -> str:
        raise ToolException("quota exhausted - retry tomorrow")

    original.handle_tool_error = handler
    wrapped = guard_tool(
        guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
        tool=original,
        action="tool.called",
    )

    with pytest.raises(ToolException, match="quota exhausted") as raised:
        wrapped.invoke(cast(Any, {"value": "no"}))
    assert not isinstance(raised.value, ArcjetToolDeniedError)


def test_the_delegates_error_handler_governs_a_denial() -> None:
    """One rule for both error sources, so an agent loop sees one behaviour.

    The wrapped tool's `handle_tool_error` is what converts its own
    ToolExceptions, so it is what converts a denial too — rather than the
    denial following the handle and the tool's own errors following the
    delegate.
    """
    original = StructuredTool.from_function(
        lambda value: "ok", name="tool", description="d"
    )
    original.handle_tool_error = "handled by the tool"
    wrapped = guard_tool(
        guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
        tool=original,
        action="tool.called",
    )

    assert wrapped.invoke(cast(Any, {"value": "no"})) == "handled by the tool"

    # Set on the handle rather than the tool, it does not govern either path.
    plain = StructuredTool.from_function(
        lambda value: "ok", name="tool", description="d"
    )
    handle_only = guard_tool(
        guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
        tool=plain,
        action="tool.called",
    )
    handle_only.handle_tool_error = "handled by the handle"

    with pytest.raises(ArcjetToolDeniedError):
        handle_only.invoke(cast(Any, {"value": "no"}))


def test_guarding_preserves_an_artifact_result() -> None:
    original = StructuredTool.from_function(
        lambda value: ("content", {"rows": 2}),
        name="report",
        description="d",
        response_format="content_and_artifact",
        return_direct=True,
    )
    wrapped = guard_tool(
        guard=_guard(_Transport()), tool=original, action="report.built"
    )
    call = {"type": "tool_call", "name": "report", "id": "c1", "args": {"value": "x"}}

    assert (
        wrapped.invoke(cast(Any, call)).artifact
        == original.invoke(cast(Any, call)).artifact
    )
    assert wrapped.return_direct == original.return_direct


# --- The checkpoint must run, whatever the arguments look like ---------------


def test_a_zero_argument_tool_is_still_guarded() -> None:
    """The checkpoint cannot be conditional on reading the arguments.

    A tool taking no arguments accepts a bare string that no schema validates,
    so treating an unreadable argument list as "the tool will reject this
    anyway" lets the call through with policy never consulted.
    """
    transport = _Transport(pb.GUARD_CONCLUSION_DENY)
    ran = 0

    @tool
    def list_secrets() -> str:
        """List every secret."""
        nonlocal ran
        ran += 1
        return "secret1,secret2"

    wrapped = guard_tool(
        guard=_guard(transport),
        tool=list_secrets,
        action="secrets.listed",
        inputs=lambda arguments, _config: {},
    )

    for probe in ("", "N/A"):
        with pytest.raises((ArcjetToolDeniedError, ArcjetToolUnavailableError)):
            wrapped.invoke(cast(Any, probe))
    assert ran == 0
    # Guard saw both calls, so a blocked call is on the record rather than
    # looking like a call that never happened.
    assert transport.calls == 2


def test_unreadable_arguments_still_reach_the_checkpoint() -> None:
    """Arguments this cannot read must not become an Arcjet outage under allow.

    Policy still runs — without inputs, which is weaker and still a decision —
    and the tool then does whatever it would have done unguarded.

    The failure is in deriving the model-facing schema, which is what the
    checkpoint reads to hide injected arguments — not in parsing, which the
    tool itself needs to run. So the tool executes and only the checkpoint's
    view of the arguments is lost, which is exactly the case being described.
    """
    transport = _Transport()
    seen: list[dict[str, Any]] = []

    class Unparseable(BaseTool):
        name: str = "unparseable"
        description: str = "d"

        @property
        def tool_call_schema(self) -> Any:
            raise RecursionError("schema is self-referential")

        def _run(self, **kwargs: Any) -> str:
            return "ran"

    wrapped = guard_tool(
        guard=_guard(transport),
        tool=Unparseable(),
        action="unparseable.called",
        inputs=lambda arguments, _config: seen.append(dict(arguments)) or {},
        on_guard_error="allow",
    )

    assert wrapped.invoke(cast(Any, {"a": 1})) == "ran"
    assert transport.calls == 1
    assert seen == []  # the resolver never saw arguments it could not be given


def test_a_resolver_sees_the_keys_the_model_was_told_to_send() -> None:
    """A tool with no schema is advertised under a key its own `args` never uses.

    Filtering against the wrong key-space silently empties the argument map, so
    a rule bound to it scans nothing while the guard call still reports healthy.
    """
    seen: list[dict[str, Any]] = []
    wrapped = guard_tool(
        guard=_guard(_Transport()),
        tool=Tool(name="shell", description="d", func=lambda v: f"ran({v})"),
        action="shell.run",
        inputs=lambda arguments, _config: seen.append(dict(arguments)) or {},
    )

    wrapped.invoke(
        cast(
            Any,
            {
                "type": "tool_call",
                "name": "shell",
                "id": "c1",
                "args": {"__arg1": "ignore previous instructions"},
            },
        )
    )

    assert seen == [{"__arg1": "ignore previous instructions"}]


def test_a_resolver_receives_plain_data_for_nested_models() -> None:
    """Resolvers are documented to take a Mapping[str, Any], not model objects."""

    class Address(BaseModel):
        street: str

    class Order(BaseModel):
        address: Address
        qty: int = 1

    seen: list[Any] = []
    wrapped = guard_tool(
        guard=_guard(_Transport()),
        tool=StructuredTool.from_function(
            lambda address, qty=1: "ok",
            name="order",
            description="d",
            args_schema=Order,
        ),
        action="order.placed",
        inputs=lambda arguments, _config: seen.append(arguments["address"]) or {},
    )

    wrapped.invoke(cast(Any, {"address": {"street": "1 Main"}, "qty": 2}))

    assert seen == [{"street": "1 Main"}]


def test_a_narrowed_args_schema_on_the_guarded_tool_is_honoured() -> None:
    """Narrowing the guarded copy is how an app hides a privileged field."""

    class Full(BaseModel):
        to: str
        admin_override: bool = False

    class Public(BaseModel):
        to: str

    wrapped = guard_tool(
        guard=_guard(_Transport()),
        tool=StructuredTool.from_function(
            lambda to, admin_override=False: "sent",
            name="send",
            description="d",
            args_schema=Full,
        ),
        action="email.sent",
    )
    wrapped.args_schema = Public

    properties = convert_to_openai_tool(wrapped)["function"]["parameters"]["properties"]
    assert set(properties) == {"to"}
    assert set(wrapped.args) == {"to"}


def test_no_wrapper_exposes_an_unguarded_execution_path() -> None:
    """`_run`/`_arun` are private but public enough to be reached.

    They delegate like every other surface, so the checkpoint runs first and
    a denial stops the body.
    """
    for original in (
        _SubclassTool(),
        Tool(name="legacy", description="d", func=lambda v: f"EXECUTED:{v}"),
    ):
        wrapped = guard_tool(
            guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
            tool=original,
            action="a",
        )
        with pytest.raises(ArcjetToolDeniedError):
            cast(Any, wrapped)._run("secret", config={})


def test_a_tool_class_helper_built_on_run_still_works() -> None:
    """A tool class may offer a preview or dry-run helper built on self._run.

    The guarded handle is an instance of that class, so the helper is
    callable on it; it runs the checkpoint and then the real body, rather
    than failing on a stub.
    """

    class Previewing(BaseTool):
        name: str = "p"
        description: str = "d"

        def _run(self, query: str) -> str:
            return f"ran:{query}"

        def preview(self) -> str:
            return self._run("probe")

    allowed = guard_tool(
        guard=_guard(_Transport()), tool=Previewing(), action="p.called"
    )
    assert cast(Any, allowed).preview() == "ran:probe"

    denied = guard_tool(
        guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
        tool=Previewing(),
        action="p.called",
    )
    with pytest.raises(ArcjetToolDeniedError):
        cast(Any, denied).preview()


def test_a_direct_run_call_shows_a_resolver_the_real_arguments() -> None:
    """`_run` collects the caller's arguments behind the framework's own.

    A tool's `_run` is `(*args, config, run_manager, **kwargs)`, so binding the
    call yields the real arguments nested under `kwargs` next to `config` and
    `run_manager`. A resolver handed that shape sees scaffolding instead of the
    call, and an input rule protects nothing.
    """
    seen: list[dict[str, Any]] = []
    original = StructuredTool.from_function(
        lambda x: f"ran:{x}", name="s", description="d"
    )
    wrapped = guard_tool(
        guard=_guard(_Transport()),
        tool=original,
        action="s.called",
        inputs=lambda arguments, _config: seen.append(dict(arguments)) or {},
    )

    assert cast(Any, wrapped)._run(x="secret", config={}) == "ran:secret"
    assert seen == [{"x": "secret"}]


def test_a_single_input_tools_direct_run_keeps_its_shape() -> None:
    """A tool taking its input positionally has nothing left after flattening.

    The single value is handed on as the tool's own `_parse_input` reads it,
    rather than as an empty mapping.
    """
    seen: list[dict[str, Any]] = []
    original = Tool(name="t", description="d", func=lambda v: f"ran:{v}")
    wrapped = guard_tool(
        guard=_guard(_Transport()),
        tool=original,
        action="t.called",
        inputs=lambda arguments, _config: seen.append(dict(arguments)) or {},
    )

    assert cast(Any, wrapped)._run("hello", config={}) == "ran:hello"
    assert seen == [{"tool_input": "hello"}]


def test_arguments_a_direct_call_will_not_have_validated_are_unevaluated() -> None:
    """Only a call the tool parses has its bad arguments stopped by the tool.

    `invoke` hands schema-rejected arguments to the tool's own validation
    handler, so an input rule has no effect left to protect. A direct call runs
    the body with whatever it was given, so the same rejection means the rule
    could not see what it protects — an unevaluated policy, which
    `on_guard_error` governs.
    """
    executed: list[int] = []

    class Amount(BaseModel):
        amount: int = Field(ge=0)

    def charge(amount: int) -> str:
        executed.append(amount)
        return "charged"

    def build(on_guard_error: str) -> Any:
        return guard_tool(
            guard=_guard(_Transport()),
            tool=StructuredTool.from_function(
                charge, name="charge", description="d", args_schema=Amount
            ),
            action="charge.made",
            inputs=lambda arguments, _config: {},
            on_guard_error=cast(Any, on_guard_error),
        )

    with pytest.raises(ArcjetToolUnavailableError):
        build("deny").func(amount=-5)
    assert executed == []

    assert build("allow").func(amount=-5) == "charged"
    assert executed == [-5]


def test_a_direct_arun_call_is_still_guarded() -> None:
    async def lookup(value: str) -> str:
        return f"found:{value}"

    original = StructuredTool.from_function(
        coroutine=lookup, name="lookup", description="d"
    )
    denied = guard_tool(
        guard=ArcjetGuard(
            "key", cast(Any, _AsyncTransport(pb.GUARD_CONCLUSION_DENY)), 1000, "ua"
        ),
        tool=original,
        action="lookup.called",
    )

    with pytest.raises(ArcjetToolDeniedError):
        asyncio.run(cast(Any, denied)._arun(value="x"))


@pytest.mark.parametrize("on_guard_error", ["deny", "allow"])
def test_an_unevaluated_policy_is_governed_by_on_guard_error(
    on_guard_error: str,
) -> None:
    """The fail-closed default is the property this helper exists for."""
    ran = 0

    def effect(value: str) -> str:
        nonlocal ran
        ran += 1
        return "done"

    class _Failing:
        def guard(self, _request: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("transport down")

        def capture(self, _request: Any, **_kwargs: Any) -> pb.CaptureResponse:
            return pb.CaptureResponse()

    wrapped = guard_tool(
        guard=ArcjetGuardSync("key", _Failing(), 1000, "test-agent"),  # type: ignore[arg-type]
        tool=StructuredTool.from_function(effect, name="effect", description="d"),
        action="effect.done",
        on_guard_error=cast(Any, on_guard_error),
    )

    if on_guard_error == "deny":
        with pytest.raises(ArcjetToolUnavailableError):
            wrapped.invoke(cast(Any, {"value": "x"}))
        assert ran == 0
    else:
        assert wrapped.invoke(cast(Any, {"value": "x"})) == "done"
        assert ran == 1


def test_arguments_a_resolver_cannot_read_are_an_unevaluated_policy() -> None:
    """An input rule that sees nothing has not run, whatever Guard replied.

    A tool taking no arguments accepts input no schema validates, so the rule
    is configured, sees nothing, and the call would otherwise proceed.
    """
    transport = _Transport()
    ran = 0

    @tool
    def zero() -> str:
        """Take no arguments."""
        nonlocal ran
        ran += 1
        return "done"

    denied = guard_tool(
        guard=_guard(transport),
        tool=zero,
        action="zero.called",
        inputs=lambda arguments, _config: {},
    )
    with pytest.raises(ArcjetToolUnavailableError):
        denied.invoke(cast(Any, ""))
    assert ran == 0
    assert transport.calls == 1

    allowed = guard_tool(
        guard=_guard(transport),
        tool=zero,
        action="zero.called",
        inputs=lambda arguments, _config: {},
        on_guard_error="allow",
    )
    assert allowed.invoke(cast(Any, "")) == "done"


def test_arguments_the_tool_itself_rejects_are_not_an_arcjet_failure() -> None:
    """A schema rejection stops the tool, so there is no effect to protect."""
    transport = _Transport()

    class Amount(BaseModel):
        amount: int = Field(ge=0)

    original = StructuredTool.from_function(
        lambda amount: "charged", name="charge", description="d", args_schema=Amount
    )
    original.handle_validation_error = "the model sent bad arguments"
    wrapped = guard_tool(
        guard=_guard(transport),
        tool=original,
        action="charge.made",
        inputs=lambda arguments, _config: {},
    )

    assert wrapped.invoke(cast(Any, {"amount": -5})) == "the model sent bad arguments"
    assert transport.calls == 1


# --- The guard client is identified by shape, not by class -------------------


def test_the_in_memory_test_client_can_drive_a_guarded_tool() -> None:
    """A double is dispatched on structurally, as the free guard calls are.

    ``on_guard_error="allow"`` because the recorder answers a fail-open
    decision, which a checkpoint left on its fail-closed default would deny —
    the client records calls, it does not decide them.
    """
    client = ArcjetTestClient()
    original = StructuredTool.from_function(
        lambda value: f"found:{value}", name="lookup", description="d"
    )
    wrapped = guard_tool(
        guard=client,
        tool=original,
        action="lookup.called",
        actor="user-1",
        inputs=lambda arguments, _config: {
            "query": server_input.string(str(arguments["value"]))
        },
        on_guard_error="allow",
    )

    assert wrapped.invoke(cast(Any, {"value": "one"})) == "found:one"
    assert len(client.guards) == 1
    assert client.guards[0].label == "lookup.called"
    assert client.guards[0].actor == "user-1"
    assert client.guards[0].inputs is not None


def test_the_in_memory_test_client_drives_the_async_path_too() -> None:
    """The recorder offers both flavours, so either entrypoint reaches it."""
    client = ArcjetTestClient()

    async def lookup(value: str) -> str:
        return f"found:{value}"

    original = StructuredTool.from_function(
        coroutine=lookup, name="lookup", description="d"
    )
    wrapped = guard_tool(
        guard=client,
        tool=original,
        action="lookup.called",
        actor="user-2",
        on_guard_error="allow",
    )

    assert asyncio.run(wrapped.ainvoke(cast(Any, {"value": "one"}))) == "found:one"
    assert len(client.guards) == 1
    assert client.guards[0].actor == "user-2"


def test_the_test_client_records_calls_made_through_a_copy() -> None:
    """A graph that clones its tools must not fork the recorder with them.

    The test asserts against the client it created, so a copy that records
    somewhere else makes the assertion silently pass against an empty list.
    """
    client = ArcjetTestClient()
    wrapped = guard_tool(
        guard=client,
        tool=StructuredTool.from_function(
            lambda value: "ok", name="t", description="d"
        ),
        action="t.called",
        on_guard_error="allow",
    )

    clone = copy.deepcopy(wrapped)
    clone.invoke(cast(Any, {"value": "x"}))

    assert len(client.guards) == 1


def test_a_client_of_the_wrong_flavour_is_still_rejected() -> None:
    """Structural dispatch widens what is accepted; it does not stop checking.

    The mismatch raises rather than being converted into an unavailable
    policy: it is a wiring mistake in the application, not a degraded
    evaluation, so ``on_guard_error`` deliberately does not govern it.

    The flavour that matters is the one the call actually takes. A tool with
    no coroutine runs its sync body even under `ainvoke`, so the async half
    uses a tool that genuinely awaits.
    """
    original = StructuredTool.from_function(
        lambda value: "ok", name="lookup", description="d"
    )
    async_only = guard_tool(
        guard=ArcjetGuard("key", cast(Any, _AsyncTransport()), 1000, "test-agent"),
        tool=original,
        action="lookup.called",
        on_guard_error="allow",
    )

    with pytest.raises(TypeError, match="blocking guard"):
        async_only.invoke(cast(Any, {"value": "one"}))

    async def lookup(value: str) -> str:
        return "ok"

    sync_only = guard_tool(
        guard=_guard(_Transport()),
        tool=StructuredTool.from_function(
            coroutine=lookup, name="lookup", description="d"
        ),
        action="lookup.called",
        on_guard_error="allow",
    )

    with pytest.raises(TypeError, match="awaitable guard"):
        asyncio.run(sync_only.ainvoke(cast(Any, {"value": "one"})))


def test_the_decorated_tool_shape_the_examples_use_is_guarded_when_awaited() -> None:
    """The exact wiring in examples/fastapi-guard-policy: async client, sync
    `@tool`, awaited through an agent.

    Reducing every call to `run` would send this to the blocking checkpoint,
    where the async client the application correctly supplied is refused.
    """
    transport = _AsyncTransport()

    @tool
    def send_email(recipient: str) -> str:
        """Send an email."""
        return f"sent:{recipient}"

    wrapped = guard_tool(
        guard=ArcjetGuard("key", cast(Any, transport), 1000, "test-agent"),
        tool=send_email,
        action="email.sent",
    )

    assert (
        asyncio.run(wrapped.ainvoke(cast(Any, {"recipient": "a@b.c"}))) == "sent:a@b.c"
    )
    assert transport.calls == 1


def test_an_async_client_guards_a_tool_with_no_async_body() -> None:
    """The commonest wiring there is: an async app holding sync tools.

    An async application supplies the async client and writes ordinary sync
    tools; LangChain runs their bodies in an executor. The checkpoint follows
    the entrypoint, so an awaited call is evaluated by the async client the
    application correctly supplied — being refused one here would make the
    guard unusable in exactly the shape the examples use.
    """
    transport = _AsyncTransport()
    wrapped = guard_tool(
        guard=ArcjetGuard("key", cast(Any, transport), 1000, "test-agent"),
        tool=StructuredTool.from_function(
            lambda value: "ok", name="lookup", description="d"
        ),
        action="lookup.called",
    )

    assert asyncio.run(wrapped.ainvoke(cast(Any, {"value": "one"}))) == "ok"
    assert transport.calls == 1
