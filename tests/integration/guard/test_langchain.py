from __future__ import annotations

import asyncio
import copy
from typing import Annotated, Any, cast

import pytest
from langchain_core.tools import (
    BaseTool,
    InjectedToolArg,
    StructuredTool,
    Tool,
    tool,
)
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import BaseModel, Field, PrivateAttr

from arcjet.guard import ArcjetGuard, ArcjetGuardSync, ModerateContent, server_input
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


def _authored_tools() -> dict[str, BaseTool]:
    return {
        "decorator": _decorated,
        "structured": StructuredTool.from_function(
            lambda value: f"st({value})", name="st", description="Structured"
        ),
        "subclass": _SubclassTool(),
        "simple": Tool(name="legacy", description="Legacy", func=lambda v: f"lg({v})"),
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

    The Arcjet client cannot be copied — it owns a lock — so it is shared with
    the copy. That only holds while the copy reaches the guarded tool before it
    reaches the client by some other edge, which a caller cannot control; an
    application holding its client alongside its tools can still fail, and
    fixing that needs the client itself to be copy-aware.
    """
    wrapped = guard_tool(
        guard=_guard(_Transport()), tool=_SubclassTool(), action="search.called"
    )

    assert copy.deepcopy(wrapped).invoke(cast(Any, {"query": "q"})) == "search(q,5)"
    assert wrapped.model_copy(deep=True).invoke(cast(Any, {"query": "q"})) == (
        "search(q,5)"
    )


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


def test_a_resolver_can_read_a_top_level_config_key() -> None:
    """`Callable[[RunnableConfig], str]` permits reading the config as passed."""
    transport = _Transport()
    wrapped = guard_tool(
        guard=_guard(transport),
        tool=StructuredTool.from_function(
            lambda value: "ok", name="echo", description="d"
        ),
        action="echo.called",
        actor=lambda config: str(cast(Any, config)["user_id"]),
    )

    wrapped.invoke(cast(Any, {"value": "x"}), cast(Any, {"user_id": "user-1"}))

    assert transport.request is not None
    assert transport.request.actor == "user-1"


def test_guarding_preserves_a_tools_own_private_state() -> None:
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

    assert wrapped.invoke(cast(Any, {"query": "q"})) == original.invoke(
        cast(Any, {"query": "q"})
    )


def test_guarding_fires_no_subclass_registration_hook() -> None:
    registered: list[str] = []

    class Registering(BaseTool):
        name: str = "reg"
        description: str = "d"

        def __init_subclass__(cls, **kwargs: Any) -> None:
            super().__init_subclass__(**kwargs)
            registered.append(cls.__name__)

        def _run(self, query: str) -> str:
            return "r"

    guard_tool(guard=_guard(_Transport()), tool=Registering(), action="reg.called")

    assert registered == []


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
    """A schema shape this cannot parse must not become an Arcjet outage.

    Policy still runs — without inputs, which is weaker and still a decision —
    and the tool then does whatever it would have done unguarded.
    """
    transport = _Transport()
    original = StructuredTool.from_function(
        lambda **kwargs: "ran",
        name="permissive",
        description="d",
        args_schema={"type": "object", "additionalProperties": True},
    )
    wrapped = guard_tool(
        guard=_guard(transport),
        tool=original,
        action="permissive.called",
        inputs=lambda arguments, _config: {},
    )

    assert wrapped.invoke(cast(Any, {"a": 1})) == original.invoke(cast(Any, {"a": 1}))
    assert transport.calls == 1


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
    """`_run`/`_arun` are private but public enough to be reached."""
    for original in (
        _SubclassTool(),
        Tool(name="legacy", description="d", func=lambda v: f"EXECUTED:{v}"),
    ):
        wrapped = guard_tool(
            guard=_guard(_Transport(pb.GUARD_CONCLUSION_DENY)),
            tool=original,
            action="a",
        )
        with pytest.raises(RuntimeError):
            cast(Any, wrapped)._run("secret", config={})


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
        guard=cast(Any, client),
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
        guard=cast(Any, client),
        tool=original,
        action="lookup.called",
        actor="user-2",
        on_guard_error="allow",
    )

    assert asyncio.run(wrapped.ainvoke(cast(Any, {"value": "one"}))) == "found:one"
    assert len(client.guards) == 1
    assert client.guards[0].actor == "user-2"


def test_a_client_of_the_wrong_flavour_is_still_rejected() -> None:
    """Structural dispatch widens what is accepted; it does not stop checking.

    The mismatch raises rather than being converted into an unavailable
    policy: it is a wiring mistake in the application, not a degraded
    evaluation, so ``on_guard_error`` deliberately does not govern it.
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

    sync_only = guard_tool(
        guard=_guard(_Transport()),
        tool=original,
        action="lookup.called",
        on_guard_error="allow",
    )

    with pytest.raises(TypeError, match="awaitable guard"):
        asyncio.run(sync_only.ainvoke(cast(Any, {"value": "one"})))
