from __future__ import annotations

import asyncio
from typing import Any, cast

import pytest
from langchain_core.tools import StructuredTool

from arcjet.guard import ArcjetGuard, ArcjetGuardSync, ModerateContent, server_input
from arcjet.guard.langchain import (
    ArcjetToolDeniedError,
    ArcjetToolUnavailableError,
    guard_tool,
)
from arcjet.guard.proto.decide.v2 import decide_pb2 as pb


class _Transport:
    def __init__(
        self, conclusion: pb.GuardConclusion = pb.GUARD_CONCLUSION_ALLOW
    ) -> None:
        self.conclusion = conclusion
        self.request: pb.GuardRequest | None = None

    def guard(self, request: pb.GuardRequest, **_kwargs: Any) -> pb.GuardResponse:
        self.request = request
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
    def __init__(self) -> None:
        self.request: pb.GuardRequest | None = None

    async def guard(self, request: pb.GuardRequest, **_kwargs: Any) -> pb.GuardResponse:
        self.request = request
        return pb.GuardResponse(
            decision=pb.GuardDecision(
                id="gdec_async", conclusion=pb.GUARD_CONCLUSION_ALLOW
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
